//! One device access per scalar or repeated LODS, STOS or SCAS iteration.
use super::{
    Action, Context, ExitRecord, Extension, Input, Instruction, Operand, OperandKind,
    PhysicalMemory, Plan, RegisterPart, validate_memory,
};
use serde::{Deserialize, Serialize};

pub(super) const DIRECTION: u64 = 1 << 10;
pub(super) type GprWrites = [Option<(usize, u64)>; 2];

/// Pre-access registers remain live until the device operation completes.
/// A REP iteration with elements left stays at the original RIP.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Progress {
    width: u32,
    index: u64,
    count: Option<u64>,
    backwards: bool,
    pub(crate) length: u64,
}

impl Progress {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !matches!(self.width, 16 | 32 | 64) || !(1..=15).contains(&self.length) {
            return Err("invalid MMIO string register width or length".into());
        }
        if self.count.is_some_and(|count| count & self.low_mask() == 0) {
            return Err("MMIO string checkpoint has an exhausted repeat count".into());
        }
        Ok(())
    }

    fn low_mask(&self) -> u64 {
        self.register(1).mask()
    }

    fn register(&self, index: usize) -> RegisterPart {
        RegisterPart {
            index,
            bits: self.width,
            shift: 0,
        }
    }

    pub(crate) fn matches_frontier(&self, index: u64, count: u64, flags: u64, code: u32) -> bool {
        let override_width = if code == 32 { 16 } else { 32 };
        (self.width == code || self.width == override_width)
            && self.index == index
            && self.count.is_none_or(|recorded| recorded == count)
            && self.backwards == (flags & DIRECTION != 0)
    }

    pub(crate) fn updates(&self, size: u8, load: bool) -> (GprWrites, Option<u64>) {
        let index = if load { 6 } else { 7 };
        let movement = u64::from(size);
        let next = if self.backwards {
            self.index.wrapping_sub(movement)
        } else {
            self.index.wrapping_add(movement)
        };
        let index_update = self.register(index).merge(self.index, next);
        let (count, length) = self.count.map_or((None, Some(self.length)), |count| {
            let remaining = (count & self.low_mask()) - 1;
            (
                Some((1, self.register(1).merge(count, remaining))),
                (remaining == 0).then_some(self.length),
            )
        });
        ([Some((index, index_update)), count], length)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Load {
    pub(crate) progress: Progress,
    pub(crate) original_rax: u64,
    pub(crate) size: u8,
}

impl Load {
    pub(super) fn validate(&self) -> Result<(), String> {
        self.progress.validate()?;
        if !matches!(self.size, 1 | 2 | 4 | 8) {
            return Err("invalid MMIO LODS width".into());
        }
        Ok(())
    }

    pub(super) fn value(&self, bytes: &[u8]) -> Result<u64, String> {
        self.validate()?;
        Input {
            destination: accumulator(self.size),
            original: self.original_rax,
            size: self.size,
            extension: Extension::Plain,
            length: self.progress.length,
        }
        .value(bytes)
    }
}

fn accumulator(size: u8) -> RegisterPart {
    RegisterPart {
        index: 0,
        bits: u32::from(size) * 8,
        shift: 0,
    }
}

enum Operation {
    Load,
    Store,
    Scan,
}

pub(super) fn prepare<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
    record: ExitRecord,
    instruction: &Instruction,
    encoded: &[u8],
    read: bool,
) -> Result<Option<Plan>, String> {
    let (operation, size) = match instruction.mnemonic.as_str() {
        "lodsb" => (Operation::Load, 1),
        "lodsw" => (Operation::Load, 2),
        "lodsd" => (Operation::Load, 4),
        "lodsq" => (Operation::Load, 8),
        "stosb" => (Operation::Store, 1),
        "stosw" => (Operation::Store, 2),
        "stosd" => (Operation::Store, 4),
        "stosq" => (Operation::Store, 8),
        "scasb" => (Operation::Scan, 1),
        "scasw" => (Operation::Scan, 2),
        "scasd" => (Operation::Scan, 4),
        "scasq" => (Operation::Scan, 8),
        _ => return Ok(None),
    };
    let load = matches!(operation, Operation::Load);
    // Metadata already decoded operand size and rejected LOCK. These opcodes
    // have neither a ModR/M byte nor immediate. Reject encodings outside
    // the legacy prefix space. F2 is admitted for the conditional scan.
    let Some((&opcode, prefixes)) = encoded.split_last() else {
        return Err("missing MMIO string opcode".into());
    };
    let scan = matches!(operation, Operation::Scan);
    let repeat = prefixes
        .iter()
        .rev()
        .copied()
        .find(|&byte| matches!(byte, 0xf2 | 0xf3));
    if !matches!(opcode, 0xaa..=0xaf)
        || prefixes.iter().any(|&byte| {
            !matches!(byte, 0x26 | 0x2e | 0x36 | 0x3e | 0x64..=0x67 | 0xf3)
                && !(scan && byte == 0xf2)
                && !(context.code_bits == 64 && matches!(byte, 0x40..=0x4f))
        })
        || matches!(operation, Operation::Store) == read
    {
        return Err("MMIO string encoding or direction differs from the access".into());
    }
    let width = if prefixes.contains(&0x67) {
        if context.code_bits == 32 { 16 } else { 32 }
    } else {
        context.code_bits
    };
    let segment = if load {
        prefixes
            .iter()
            .rev()
            .find_map(|byte| match byte {
                0x26 => Some("es"),
                0x2e => Some("cs"),
                0x36 => Some("ss"),
                0x3e => Some("ds"),
                0x64 => Some("fs"),
                0x65 => Some("gs"),
                _ => None,
            })
            .unwrap_or("ds")
    } else {
        "es"
    };
    let base = match (load, width) {
        (true, 16) => "si",
        (true, 32) => "esi",
        (true, 64) => "rsi",
        (false, 16) => "di",
        (false, 32) => "edi",
        (false, 64) => "rdi",
        _ => return Err("invalid MMIO string address size".into()),
    };
    let length = u64::from(instruction.size);
    let progress = Progress {
        width,
        index: context.registers[if load { 6 } else { 7 }],
        count: repeat.map(|_| context.registers[1]),
        backwards: context.rflags & DIRECTION != 0,
        length,
    };
    progress.validate()?;
    let operand = Operand {
        kind: OperandKind::Memory,
        width_bits: u32::from(size) * 8,
        address_bits: width,
        base: base.into(),
        segment: segment.into(),
        read,
        write: !read,
        ..Operand::default()
    };
    validate_memory(context, memory, record, &operand, size)?;
    let action = match operation {
        Operation::Load => Action::StringLoad(Load {
            progress,
            original_rax: context.registers[0],
            size,
        }),
        Operation::Store => {
            let bytes = context.registers[0].to_le_bytes();
            Action::StringStore {
                data: bytes[..usize::from(size)].to_vec(),
                progress,
            }
        }
        Operation::Scan => Action::AluRead(super::AluReadInput::string_scan(
            context,
            progress.register(7),
            size,
            length,
            repeat.map(|prefix| prefix == 0xf3),
        )),
    };
    Ok(Some(Plan {
        physical: record.physical,
        linear: record.linear,
        length,
        action,
    }))
}
