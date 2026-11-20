//! Decoded scalar MMIO plans. Device effects occur only after this validation.
use super::guest_translation::{Paging, PhysicalMemory};
use crate::isa::x86_64::instruction_metadata::{
    self as metadata, Flow, Instruction, Operand, OperandKind,
};
use serde::{Deserialize, Serialize};

const EFER_LMA: u64 = 1 << 10;

pub(crate) fn code_width(efer: u64, cs_long: bool, cs_default_big: bool) -> u32 {
    if efer & EFER_LMA != 0 && cs_long {
        64
    } else if cs_default_big {
        32
    } else {
        16
    }
}

#[path = "mmio/rmw.rs"]
mod rmw;
pub(crate) use rmw::RmwInput;
#[path = "mmio/alu_read.rs"]
mod alu_read;
pub(crate) use alu_read::AluReadInput;
#[path = "mmio/divide.rs"]
mod divide;
use divide::DivideInput;
#[path = "mmio/string.rs"]
mod string;
pub(crate) use string::{Load as StringLoad, Progress as StringProgress};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RegisterPart {
    pub(crate) index: usize,
    pub(crate) bits: u32,
    pub(crate) shift: u32,
}
impl RegisterPart {
    pub(crate) fn valid(self) -> bool {
        self.index < 16
            && matches!(self.bits, 8 | 16 | 32 | 64)
            && (self.shift == 0 || (self.shift == 8 && self.bits == 8 && self.index < 4))
    }
    pub(crate) fn parse(name: &str) -> Option<Self> {
        const NAMES: [[&str; 8]; 4] = [
            ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"],
            ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"],
            ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"],
            ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"],
        ];
        for (class, names) in NAMES.iter().enumerate() {
            if let Some(index) = names.iter().position(|n| *n == name) {
                return Some(Self {
                    index,
                    bits: 8 << class,
                    shift: 0,
                });
            }
        }
        if let Some(index) = ["ah", "ch", "dh", "bh"].iter().position(|n| *n == name) {
            return Some(Self {
                index,
                bits: 8,
                shift: 8,
            });
        }
        let digits = name.strip_prefix('r')?;
        let (digits, bits) = if let Some(s) = digits.strip_suffix('b') {
            (s, 8)
        } else if let Some(s) = digits.strip_suffix('w') {
            (s, 16)
        } else if let Some(s) = digits.strip_suffix('d') {
            (s, 32)
        } else {
            (digits, 64)
        };
        let index = digits.parse::<usize>().ok()?;
        (8..16).contains(&index).then_some(Self {
            index,
            bits,
            shift: 0,
        })
    }
    fn mask(self) -> u64 {
        if self.bits == 64 {
            u64::MAX
        } else {
            (1 << self.bits) - 1
        }
    }
    fn value(self, registers: &[u64; 16]) -> u64 {
        (registers[self.index] >> self.shift) & self.mask()
    }
    pub(crate) fn merge(self, original: u64, value: u64) -> u64 {
        if self.bits == 32 {
            return value & 0xffff_ffff;
        }
        let mask = self.mask() << self.shift;
        (original & !mask) | ((value << self.shift) & mask)
    }
}

/// How the native processor executes the F3-prefixed BSF and BSR encodings.
#[derive(Clone, Copy, Default)]
pub(crate) struct BitCountDecoding {
    pub(crate) tzcnt: bool,
    pub(crate) lzcnt: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct Context {
    pub(crate) registers: [u64; 16],
    /// ES, CS, SS, DS, FS, GS bases from the active VMCS.
    pub(crate) segments: [u64; 6],
    pub(crate) code_bits: u32,
    pub(crate) rip: u64,
    pub(crate) rflags: u64,
    pub(crate) paging: Paging,
    pub(crate) bit_count: BitCountDecoding,
}
#[derive(Clone, Copy)]
pub(crate) struct ExitRecord {
    pub(crate) qualification: u64,
    pub(crate) linear: u64,
    pub(crate) physical: u64,
    pub(crate) vectoring_information: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Extension {
    Plain,
    Zero,
    Signed,
    ByteSwap,
    Unselected { clear_upper: bool },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Input {
    pub(crate) destination: RegisterPart,
    pub(crate) original: u64,
    pub(crate) size: u8,
    pub(crate) extension: Extension,
    pub(crate) length: u64,
}
impl Input {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !matches!(self.size, 1 | 2 | 4 | 8)
            || !(1..=15).contains(&self.length)
            || !self.destination.valid()
        {
            return Err("invalid HVF MMIO input descriptor".into());
        }
        let source_bits = u32::from(self.size) * 8;
        let valid_extension = match self.extension {
            Extension::Plain => self.destination.bits == source_bits,
            Extension::ByteSwap => self.size > 1 && self.destination.bits == source_bits,
            Extension::Zero | Extension::Signed => {
                self.destination.shift == 0 && self.destination.bits > source_bits
            }
            Extension::Unselected { clear_upper } => {
                self.destination.bits == source_bits
                    && self.size > 1
                    && (!clear_upper || self.size == 4)
            }
        };
        if !valid_extension {
            return Err("HVF MMIO input extension differs from its register width".into());
        }
        Ok(())
    }

    pub(crate) fn value(&self, data: &[u8]) -> Result<u64, String> {
        self.validate()?;
        if !matches!(self.size, 1 | 2 | 4 | 8) || data.len() != usize::from(self.size) {
            return Err(format!(
                "HVF MMIO input expected {} bytes, received {}",
                self.size,
                data.len()
            ));
        }
        if let Extension::Unselected { clear_upper } = self.extension {
            return Ok(if clear_upper {
                self.original & u64::from(u32::MAX)
            } else {
                self.original
            });
        }
        let mut bytes = [0; 8];
        let source = &mut bytes[..data.len()];
        source.copy_from_slice(data);
        if self.extension == Extension::ByteSwap {
            source.reverse();
        }
        let raw = u64::from_le_bytes(bytes);
        let extended = if self.extension == Extension::Signed && self.size < 8 {
            let shift = 64 - u32::from(self.size) * 8;
            ((raw << shift) as i64 >> shift) as u64
        } else {
            raw
        };
        Ok(self.destination.merge(self.original, extended))
    }
}
/// A scalar MOVD/MOVQ transfer involving the low bytes of an XMM register.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct XmmTransfer {
    pub(crate) index: u8,
    pub(crate) size: u8,
    pub(crate) length: u64,
}

impl XmmTransfer {
    fn validate(&self) -> Result<(), String> {
        if self.index >= 16 || !matches!(self.size, 4 | 8) || !(1..=15).contains(&self.length) {
            return Err("invalid HVF MMIO XMM transfer descriptor".into());
        }
        Ok(())
    }

    fn load(&self, data: &[u8]) -> Result<[u8; 16], String> {
        self.validate()?;
        if data.len() != usize::from(self.size) {
            return Err(format!(
                "HVF MMIO XMM input expected {} bytes, received {}",
                self.size,
                data.len()
            ));
        }
        let mut value = [0; 16];
        value[..data.len()].copy_from_slice(data);
        Ok(value)
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Action {
    Read(Input),
    Write(Vec<u8>),
    Rmw(RmwInput),
    AluRead(AluReadInput),
    Divide(DivideInput),
    XmmRead {
        input: XmmTransfer,
        zero_upper: bool,
    },
    XmmWrite(XmmTransfer),
    StringLoad(StringLoad),
    StringStore {
        data: Vec<u8>,
        progress: StringProgress,
    },
}
#[derive(Clone, Debug)]
pub(crate) struct Plan {
    pub(crate) physical: u64,
    pub(crate) linear: u64,
    pub(crate) length: u64,
    pub(crate) action: Action,
}

fn memory_address(context: &Context, operand: &Operand) -> Result<u64, String> {
    let mask = match operand.address_bits {
        16 => 0xffff,
        32 => 0xffff_ffff,
        64 => u64::MAX,
        _ => return Err("unsupported MMIO address width".into()),
    };
    let read = |name: &str| -> Result<u64, String> {
        if name.is_empty() {
            Ok(0)
        } else {
            RegisterPart::parse(name)
                .map(|r| r.value(&context.registers))
                .ok_or_else(|| format!("unsupported MMIO address register {name}"))
        }
    };
    let offset = read(&operand.base)?
        .wrapping_add(read(&operand.index)?.wrapping_mul(u64::from(operand.scale)))
        .wrapping_add(operand.displacement)
        & mask;
    let segment = match operand.segment.as_str() {
        "es" => 0,
        "cs" => 1,
        "ss" => 2,
        "ds" | "" => 3,
        "fs" => 4,
        "gs" => 5,
        _ => return Err("unsupported MMIO segment".into()),
    };
    let base = if context.code_bits == 64 && segment < 4 {
        0
    } else {
        context.segments[segment]
    };
    let linear = base.wrapping_add(offset);
    Ok(if context.code_bits == 64 {
        linear
    } else {
        linear & 0xffff_ffff
    })
}

fn fetch<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
) -> Result<(Instruction, Vec<u8>), String> {
    if !matches!(context.code_bits, 16 | 32 | 64) {
        return Err("unsupported MMIO code width".into());
    }
    let mut bytes = Vec::with_capacity(15);
    for offset in 0..15 {
        let ip = if context.code_bits == 64 {
            context.rip.wrapping_add(offset)
        } else {
            context.rip.wrapping_add(offset) & 0xffff_ffff
        };
        let linear = if context.code_bits == 64 {
            ip
        } else {
            context.segments[1].wrapping_add(ip) & 0xffff_ffff
        };
        let physical = context.paging.translate(memory, linear)?;
        let mut byte = [0];
        memory.read_physical(physical, &mut byte)?;
        bytes.push(byte[0]);
        match metadata::decode(context.code_bits, context.rip, &bytes) {
            Ok(instruction) => return Ok((instruction, bytes)),
            Err(metadata::DecodeFailure::Unsupported) => {
                return Err("MMIO instruction metadata is unsupported".into());
            }
            Err(metadata::DecodeFailure::Invalid) => {}
        }
    }
    Err("invalid or truncated MMIO instruction".into())
}

fn validate_memory<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
    record: ExitRecord,
    operand: &Operand,
    size: u8,
) -> Result<(), String> {
    let linear = memory_address(context, operand)?;
    if linear != record.linear {
        return Err(format!(
            "decoded MMIO address {linear:#x} disagrees with exit GLA {:#x}",
            record.linear
        ));
    }
    context.paging.validate_linear(linear)?;
    if context.paging.cr0 & (1 << 31) == 0 && record.physical != linear {
        return Err("nonpaged MMIO exit GLA/GPA disagree".into());
    }
    let physical_mask = context.paging.address_mask()? | 0xfff;
    let last = record
        .physical
        .checked_add(u64::from(size) - 1)
        .ok_or("MMIO physical range overflows")?;
    if record.physical & !physical_mask != 0 || last & !physical_mask != 0 {
        return Err("MMIO exit physical address exceeds configured width".into());
    }
    if linear & 0xfff != record.physical & 0xfff {
        return Err("MMIO exit GLA/GPA page offsets disagree".into());
    }
    let first_page = linear & !0xfff;
    for offset in 0..u64::from(size) {
        let address = if context.code_bits == 64 {
            linear.wrapping_add(offset)
        } else {
            linear.wrapping_add(offset) & 0xffff_ffff
        };
        let expected = record.physical + offset;
        // Table29-7's translated data record identifies the completed guest
        // translation. A peer can replace its PTE before this inspection; a
        // new walk is not evidence against the hardware's first-page GPA.
        let physical = if address & !0xfff == first_page {
            expected
        } else {
            context.paging.translate(memory, address)?
        };
        if physical != expected {
            return Err("MMIO operand spans noncontiguous guest physical addresses".into());
        }
        if memory.contains_ram(physical, 1) {
            return Err("EPT violation targets guest RAM, not an MMIO hole".into());
        }
    }
    Ok(())
}

fn prepare_xmm<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
    record: ExitRecord,
    instruction: &Instruction,
    read: bool,
) -> Result<Plan, String> {
    let [destination, source] = instruction.operands.as_slice() else {
        return Err("XMM MMIO transfer requires two operands".into());
    };
    let (xmm, operand) = if read {
        (destination, source)
    } else {
        (source, destination)
    };
    let size = if matches!(instruction.mnemonic.as_str(), "movd" | "vmovd") {
        4
    } else {
        8
    };
    if !instruction.operands_complete
        || instruction.flow != Flow::Next
        || operand.kind != OperandKind::Memory
        || operand.width_bits != 8 * u32::from(size)
        || operand.read != read
        || operand.write == read
        || operand.conditional
        || xmm.kind != OperandKind::Register
        || xmm.width_bits != 128
        || xmm.read == read
        || xmm.write != read
        || xmm.conditional
    {
        return Err("wrong operands or direction for scalar XMM MMIO transfer".into());
    }
    let index = xmm
        .reg
        .strip_prefix("xmm")
        .and_then(|index| index.parse().ok())
        .ok_or("invalid XMM register index")?;
    let length = u64::from(instruction.size);
    let transfer = XmmTransfer {
        index,
        size,
        length,
    };
    transfer.validate()?;
    validate_memory(context, memory, record, operand, size)?;
    Ok(Plan {
        physical: record.physical,
        linear: record.linear,
        length,
        action: if read {
            Action::XmmRead {
                input: transfer,
                zero_upper: matches!(instruction.mnemonic.as_str(), "vmovd" | "vmovq"),
            }
        } else {
            Action::XmmWrite(transfer)
        },
    })
}

pub(crate) fn prepare<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
    record: ExitRecord,
) -> Result<Plan, String> {
    if record.vectoring_information & (1 << 31) != 0 {
        return Err("EPT violation interrupted event delivery, not a scalar instruction".into());
    }
    // Table29-7: IRET NMI-unblocking, shadow-stack, guest-paging
    // verification and asynchronous PT/PEBS/user-interrupt accesses are not
    // ordinary scalar instruction data. Undefined permission bits are ignored.
    if record.qualification & ((1 << 12) | (1 << 13) | (1 << 15) | (1 << 16)) != 0 {
        return Err("EPT violation is outside ordinary scalar data execution".into());
    }
    let read = record.qualification & 1 != 0;
    let write = record.qualification & 2 != 0;
    if (!read && !write) || record.qualification & 4 != 0 || record.qualification & 0x180 != 0x180 {
        return Err("EPT violation is not a translated scalar data access".into());
    }
    // Guest TF is retained in the captured flags. Input completion and output
    // acknowledgment reach the owner's common debug-retirement boundary only
    // after the device effect succeeds; preparing a plan never retires it.
    let (instruction, encoded) = fetch(context, memory)?;
    if let Some(plan) = rmw::prepare(context, memory, record, &instruction)? {
        return Ok(plan);
    }
    if read == write {
        return Err("scalar MMIO direction disagrees with instruction effects".into());
    }
    if let Some(plan) = string::prepare(context, memory, record, &instruction, &encoded, read)? {
        return Ok(plan);
    }
    if matches!(
        instruction.mnemonic.as_str(),
        "movd" | "movq" | "vmovd" | "vmovq"
    ) {
        return prepare_xmm(context, memory, record, &instruction, read);
    }
    if matches!(instruction.mnemonic.as_str(), "div" | "idiv") {
        return divide::prepare(context, memory, record, &instruction);
    }
    if let Some(plan) = alu_read::prepare(context, memory, record, &instruction)? {
        return Ok(plan);
    }
    if let [operand] = instruction.operands.as_slice()
        && let Some(value) = instruction.setcc_value(context.rflags)
    {
        if !instruction.operands_complete
            || instruction.flow != Flow::Next
            || !write
            || operand.kind != OperandKind::Memory
            || operand.width_bits != 8
            || operand.read
            || !operand.write
            || operand.conditional
        {
            return Err("SETcc MMIO requires one translated byte write".into());
        }
        validate_memory(context, memory, record, operand, 1)?;
        return Ok(Plan {
            physical: record.physical,
            linear: record.linear,
            length: u64::from(instruction.size),
            action: Action::Write(vec![value]),
        });
    }
    if let Some(selected) = instruction.cmov_condition(context.rflags) {
        let [target, operand] = instruction.operands.as_slice() else {
            return Err("CMOVcc MMIO needs two operands".into());
        };
        if !instruction.operands_complete
            || instruction.flow != Flow::Next
            || !read
            || target.kind != OperandKind::Register
            || !target.read
            || !target.write
            || !target.conditional
            || operand.kind != OperandKind::Memory
            || !operand.read
            || operand.write
            || operand.conditional
        {
            return Err("CMOVcc MMIO requires an unconditional memory read".into());
        }
        let destination = RegisterPart::parse(&target.reg).ok_or("invalid CMOVcc register")?;
        if !matches!(destination.bits, 16 | 32 | 64)
            || destination.bits != target.width_bits
            || destination.bits != operand.width_bits
        {
            return Err("inconsistent CMOVcc MMIO widths".into());
        }
        let size = (destination.bits / 8) as u8;
        validate_memory(context, memory, record, operand, size)?;
        let length = u64::from(instruction.size);
        let extension = if selected {
            Extension::Plain
        } else {
            Extension::Unselected {
                clear_upper: destination.bits == 32 && context.paging.efer & EFER_LMA != 0,
            }
        };
        return Ok(Plan {
            physical: record.physical,
            linear: record.linear,
            length,
            action: Action::Read(Input {
                destination,
                original: context.registers[destination.index],
                size,
                extension,
                length,
            }),
        });
    }
    if !instruction.operands_complete
        || instruction.flow != Flow::Next
        || !matches!(
            instruction.mnemonic.as_str(),
            "mov" | "movbe" | "movnti" | "movsx" | "movsxd" | "movzx"
        )
        || instruction.operands.len() != 2
    {
        return Err("unsupported MMIO instruction operands or effects".into());
    }
    let operands = &instruction.operands;
    let (memory_operand, other) = if operands[0].kind == OperandKind::Memory {
        (&operands[0], &operands[1])
    } else if operands[1].kind == OperandKind::Memory {
        (&operands[1], &operands[0])
    } else {
        return Err("MMIO instruction has no represented memory operand".into());
    };
    if other.kind == OperandKind::Memory
        || memory_operand.read != read
        || memory_operand.write != write
        || memory_operand.conditional
        || other.conditional
    {
        return Err("MMIO instruction direction/effects disagree with EPT record".into());
    }
    let mnemonic = instruction.mnemonic.as_str();
    let size = match (memory_operand.width_bits, mnemonic) {
        (8, "movbe" | "movnti") | (16, "movnti") => {
            return Err("unsupported MMIO transfer width".into());
        }
        (8, _) => 1,
        (16, _) => 2,
        (32, _) => 4,
        (64, _) => 8,
        _ => return Err("unsupported MMIO transfer width".into()),
    };
    validate_memory(context, memory, record, memory_operand, size)?;
    let length = u64::from(instruction.size);
    let action = if read {
        if operands[0].kind != OperandKind::Register
            || other.kind != OperandKind::Register
            || !other.write
            || other.read
        {
            return Err("unsupported MMIO load destination".into());
        }
        let destination =
            RegisterPart::parse(&other.reg).ok_or("unsupported MMIO destination register")?;
        if destination.bits != other.width_bits {
            return Err("inconsistent MMIO register width".into());
        }
        let extension = match mnemonic {
            "mov" | "movsxd" if destination.bits == memory_operand.width_bits => Extension::Plain,
            "movbe" if destination.bits == memory_operand.width_bits => Extension::ByteSwap,
            "movsxd" if destination.bits == 64 && memory_operand.width_bits == 32 => {
                Extension::Signed
            }
            "movsx" if destination.shift == 0 && destination.bits > memory_operand.width_bits => {
                Extension::Signed
            }
            "movzx" if destination.shift == 0 && destination.bits > memory_operand.width_bits => {
                Extension::Zero
            }
            _ => return Err("unsupported MMIO load width/extension".into()),
        };
        Action::Read(Input {
            destination,
            original: context.registers[destination.index],
            size,
            extension,
            length,
        })
    } else {
        if operands[0].kind != OperandKind::Memory
            || !matches!(mnemonic, "mov" | "movbe" | "movnti")
            || !other.read
            || other.write
        {
            return Err("unsupported MMIO store effects".into());
        }
        let value = match other.kind {
            OperandKind::Immediate if mnemonic == "mov" => other.value,
            OperandKind::Register => {
                let source =
                    RegisterPart::parse(&other.reg).ok_or("unsupported MMIO source register")?;
                if source.bits != memory_operand.width_bits || source.bits != other.width_bits {
                    return Err("inconsistent MMIO store width".into());
                }
                source.value(&context.registers)
            }
            _ => return Err("unsupported MMIO store source".into()),
        };
        let mut data = value.to_le_bytes()[..usize::from(size)].to_vec();
        if mnemonic == "movbe" {
            data.reverse();
        }
        Action::Write(data)
    };
    Ok(Plan {
        physical: record.physical,
        linear: record.linear,
        length,
        action,
    })
}

pub(crate) trait CompletionAccess {
    type Error: std::fmt::Display;
    fn write_gpr(&mut self, index: usize, value: u64) -> Result<(), Self::Error>;
    fn write_rflags(&mut self, flags: u64) -> Result<(), Self::Error>;
    fn write_xmm(&mut self, _index: u8, _value: [u8; 16], _zero_upper: bool) -> Result<(), String> {
        Err("MMIO host cannot write an XMM register".into())
    }
    fn finish_instruction(&mut self, length: u64) -> Result<(), Self::Error>;
    fn finish_string_iteration(&mut self) -> Result<(), String> {
        Err("MMIO host cannot finish a partial string instruction".into())
    }
    fn publish_divide_breakpoints(&mut self, _causes: u64) -> Result<(), String> {
        Err("MMIO host cannot publish divide breakpoint causes".into())
    }
    fn inject_divide_error(&mut self) -> Result<(), String> {
        Err("MMIO host cannot deliver a divide error".into())
    }
}

type Completion = ([Option<(usize, u64)>; 2], Option<u64>, u64);

enum Effect {
    Scalar(Completion),
    Xmm {
        index: u8,
        value: [u8; 16],
        zero_upper: bool,
        length: u64,
    },
    StringLoad {
        accumulator: u64,
        updates: string::GprWrites,
        length: Option<u64>,
    },
    DivideError,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Pending {
    Read(Input),
    Rmw(RmwInput),
    AluRead(AluReadInput),
    Divide {
        input: DivideInput,
        data_causes: u64,
    },
    Xmm(XmmTransfer),
    StringLoad(StringLoad),
    // Appending preserves both legacy XMM and string-load records.
    VexXmm(XmmTransfer),
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct InputState {
    pending: Option<Pending>,
    failure: Option<String>,
    reply: Option<Vec<u8>>,
}
impl InputState {
    pub(crate) fn hold_failure(&mut self, data: &[u8], failure: String) {
        if self.failure.is_some() {
            return;
        }
        if self
            .descriptor()
            .is_some_and(|(size, _)| data.len() == usize::from(size))
        {
            self.reply = Some(data.to_vec());
        }
        self.failure = Some(failure);
    }
    pub(crate) fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }
    pub(crate) fn descriptor(&self) -> Option<(u8, Option<crate::devices::bus::MmioRmwOp>)> {
        self.pending.as_ref().map(|pending| match pending {
            Pending::Read(input) => (input.size, None),
            Pending::StringLoad(input) => (input.size, None),
            Pending::AluRead(input) => (input.size, None),
            Pending::Divide { input, .. } => (input.size, None),
            Pending::Rmw(input) => (input.size, Some(input.operation)),
            Pending::Xmm(input) | Pending::VexXmm(input) => (input.size, None),
        })
    }
    pub(crate) fn validate_checkpoint(&self) -> Result<(), String> {
        if self
            .failure
            .as_ref()
            .is_some_and(|error| error.len() > 16 * 1024)
        {
            return Err("HVF MMIO error exceeds record limit".into());
        }
        match self.pending.as_ref() {
            Some(Pending::Read(input)) => Self::default().begin(input.clone())?,
            Some(Pending::Rmw(input)) => input.validate()?,
            Some(Pending::StringLoad(input)) => input.validate()?,
            Some(Pending::AluRead(input)) => input.validate()?,
            Some(Pending::Xmm(input) | Pending::VexXmm(input)) => input.validate()?,
            Some(Pending::Divide { input, data_causes }) => {
                Self::validate_divide(input, *data_causes)?;
            }
            None => (),
        }
        if let Some(reply) = &self.reply {
            let (size, _) = self.descriptor().ok_or("MMIO reply has no request")?;
            if reply.len() != usize::from(size) || self.failure.is_none() {
                return Err("invalid retained MMIO reply".into());
            }
        }
        Ok(())
    }
    pub(crate) fn pending(&self) -> bool {
        self.pending.is_some()
    }
    pub(crate) fn ready(&self) -> Result<(), &str> {
        if let Some(error) = self.failure.as_deref() {
            return Err(error);
        }
        if self.pending.is_some() {
            return Err("HVF MMIO input completion is pending");
        }
        Ok(())
    }
    pub(crate) fn begin(&mut self, input: Input) -> Result<(), String> {
        self.ready().map_err(str::to_owned)?;
        input.validate()?;
        self.pending = Some(Pending::Read(input));
        Ok(())
    }
    pub(crate) fn begin_string_load(&mut self, input: StringLoad) -> Result<(), String> {
        self.ready().map_err(str::to_owned)?;
        input.validate()?;
        self.pending = Some(Pending::StringLoad(input));
        Ok(())
    }
    pub(crate) fn string_load(&self) -> Option<&StringLoad> {
        match self.pending.as_ref() {
            Some(Pending::StringLoad(input)) => Some(input),
            _ => None,
        }
    }
    pub(crate) fn string_scan(&self) -> Option<&AluReadInput> {
        match self.pending.as_ref() {
            Some(Pending::AluRead(input)) if input.is_string_scan() => Some(input),
            _ => None,
        }
    }
    pub(crate) fn begin_rmw(&mut self, input: RmwInput) -> Result<(), String> {
        self.ready().map_err(str::to_owned)?;
        input.validate()?;
        self.pending = Some(Pending::Rmw(input));
        Ok(())
    }
    pub(crate) fn begin_alu_read(&mut self, input: AluReadInput) -> Result<(), String> {
        self.ready().map_err(str::to_owned)?;
        input.validate()?;
        self.pending = Some(Pending::AluRead(input));
        Ok(())
    }
    pub(crate) fn begin_xmm(&mut self, input: XmmTransfer, zero_upper: bool) -> Result<(), String> {
        self.ready().map_err(str::to_owned)?;
        input.validate()?;
        self.pending = Some(if zero_upper {
            Pending::VexXmm(input)
        } else {
            Pending::Xmm(input)
        });
        Ok(())
    }
    fn validate_divide(input: &DivideInput, data_causes: u64) -> Result<(), String> {
        input.validate()?;
        // Pending-debug B0–B3 plus the enabled-breakpoint bit. Every
        // nonempty matched set carries both kinds of bits.
        if data_causes != 0 && (data_causes & !0xf != 1 << 12 || data_causes & 0xf == 0) {
            return Err("invalid MMIO divide breakpoint causes".into());
        }
        Ok(())
    }
    pub(crate) fn begin_divide(
        &mut self,
        input: DivideInput,
        data_causes: u64,
    ) -> Result<(), String> {
        self.ready().map_err(str::to_owned)?;
        Self::validate_divide(&input, data_causes)?;
        self.pending = Some(Pending::Divide { input, data_causes });
        Ok(())
    }
    pub(crate) fn complete<T: CompletionAccess>(&mut self, host: &mut T, data: &[u8]) {
        if self.failure.is_some() {
            return;
        }
        let Some(input) = self.pending.as_ref() else {
            self.failure = Some("unexpected HVF MMIO completion without a pending request".into());
            return;
        };
        let computed = match input {
            Pending::Read(input) => input.value(data).map(|value| {
                let register = (!matches!(
                    input.extension,
                    Extension::Unselected { clear_upper: false }
                ))
                .then_some((input.destination.index, value));
                Effect::Scalar(([register, None], None, input.length))
            }),
            Pending::Rmw(input) => input.completion(data).map(Effect::Scalar),
            Pending::StringLoad(input) => input.value(data).map(|accumulator| {
                let (updates, length) = input.progress.updates(input.size, true);
                Effect::StringLoad {
                    accumulator,
                    updates,
                    length,
                }
            }),
            Pending::AluRead(input) => input.completion(data).map(Effect::Scalar),
            Pending::Divide { input, .. } => input
                .completion(data)
                .map(|value| value.map_or(Effect::DivideError, Effect::Scalar)),
            Pending::Xmm(transfer) | Pending::VexXmm(transfer) => {
                transfer.load(data).map(|value| Effect::Xmm {
                    index: transfer.index,
                    value,
                    zero_upper: matches!(input, Pending::VexXmm(_)),
                    length: transfer.length,
                })
            }
        };
        let completion = match computed {
            Ok(v) => v,
            Err(e) => {
                self.failure = Some(e);
                return;
            }
        };
        self.reply = Some(data.to_vec());
        let mut apply = || -> Result<(), String> {
            let (registers, flags, length) = match completion {
                Effect::Scalar(completion) => completion,
                Effect::DivideError => return host.inject_divide_error(),
                Effect::StringLoad {
                    accumulator,
                    updates,
                    length,
                } => {
                    host.write_gpr(0, accumulator)
                        .map_err(|error| error.to_string())?;
                    for (index, value) in updates.into_iter().flatten() {
                        host.write_gpr(index, value)
                            .map_err(|error| error.to_string())?;
                    }
                    return match length {
                        Some(length) => host
                            .finish_instruction(length)
                            .map_err(|error| error.to_string()),
                        None => host.finish_string_iteration(),
                    };
                }
                Effect::Xmm {
                    index,
                    value,
                    zero_upper,
                    length,
                } => {
                    host.write_xmm(index, value, zero_upper)?;
                    return host
                        .finish_instruction(length)
                        .map_err(|error| error.to_string());
                }
            };
            if let Pending::Divide { data_causes, .. } = input
                && *data_causes != 0
            {
                host.publish_divide_breakpoints(*data_causes)?;
            }
            for (index, value) in registers.into_iter().flatten() {
                host.write_gpr(index, value)
                    .map_err(|error| error.to_string())?;
            }
            if let Some(flags) = flags {
                host.write_rflags(flags)
                    .map_err(|error| error.to_string())?;
            }
            host.finish_instruction(length)
                .map_err(|error| error.to_string())
        };
        if let Err(error) = apply() {
            self.failure = Some(format!("HVF MMIO completion failed: {error}"));
            return;
        }
        self.pending = None;
        self.reply = None;
    }
}

pub(crate) trait RetirementAccess {
    type Error;
    fn rflags(&mut self) -> Result<u64, Self::Error>;
    fn advance_instruction(&mut self, length: u64) -> Result<(), Self::Error>;
    fn write_rflags(&mut self, flags: u64) -> Result<(), Self::Error>;
}
/// EPT exits outside IDT delivery save RF1. Emulated completion must clear it;
/// ordinary configured instruction exits already save RF0 (SDM29.3.3).
pub(crate) fn retire<T: RetirementAccess>(host: &mut T, length: u64) -> Result<(), T::Error> {
    let flags = host.rflags()?;
    host.advance_instruction(length)?;
    if flags & (1 << 16) != 0 {
        host.write_rflags(flags & !(1 << 16))?;
    }
    Ok(())
}
