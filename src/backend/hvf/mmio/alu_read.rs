//! Read-only device operands for integer arithmetic, comparisons and bit tests.
use super::{
    Completion, Context, Effect, ExitRecord, Flow, Instruction, Operand, OperandKind,
    PhysicalMemory, Plan, RegisterPart,
};
use crate::isa::x86_64::flags::{self, bits};
use serde::{Deserialize, Serialize};

#[path = "../../../isa/x86_64/execute/bmi1.rs"]
mod bmi1;
// Share the architectural recurrence with direct execution and its portable
// MMIO harness, which compiles this planner without the native backend.
#[path = "../../../isa/x86_64/execute/crc32.rs"]
mod crc32;
#[path = "../../../isa/x86_64/execute/imul.rs"]
mod imul;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Operation {
    Add,
    Adc,
    Sub,
    Sbb,
    And,
    Or,
    Xor,
    Compare,
    Test,
    BitTest(u8),
    PopulationCount,
    BitScanForward,
    BitScanReverse,
    CountTrailingZeros,
    CountLeadingZeros,
    Adcx,
    Adox,
    Crc32,
    Imul,
    ImplicitMultiply { signed: bool, rdx_before: u64 },
    // Appended for compatibility with existing pending inputs.
    StringScan,
    RepeatStringScan { count: u64, while_equal: bool },
    Bmi1(bmi1::Operation),
}

impl Operation {
    fn is_bit_scan(self) -> bool {
        matches!(self, Self::BitScanForward | Self::BitScanReverse)
    }

    fn is_unary(self) -> bool {
        self.is_bit_scan()
            || matches!(
                self,
                Self::PopulationCount | Self::CountTrailingZeros | Self::CountLeadingZeros
            )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct AluReadInput {
    pub(crate) size: u8,
    length: u64,
    operation: Operation,
    other: u64,
    memory_left: bool,
    flags_before: u64,
    destination: Option<(RegisterPart, u64)>,
}

impl AluReadInput {
    pub(super) fn string_scan(
        context: &Context,
        index: RegisterPart,
        size: u8,
        length: u64,
        repeat_while_equal: Option<bool>,
    ) -> Self {
        Self {
            size,
            length,
            operation: repeat_while_equal.map_or(Operation::StringScan, |while_equal| {
                Operation::RepeatStringScan {
                    count: context.registers[1],
                    while_equal,
                }
            }),
            other: context.registers[0],
            memory_left: false,
            flags_before: context.rflags,
            destination: Some((index, context.registers[7])),
        }
    }

    pub(super) fn is_string_scan(&self) -> bool {
        matches!(
            self.operation,
            Operation::StringScan | Operation::RepeatStringScan { .. }
        )
    }

    pub(crate) fn matches_scan_frontier(
        &self,
        rax: u64,
        rcx: u64,
        rdi: u64,
        rflags: u64,
        code: u32,
    ) -> bool {
        let override_width = if code == 32 { 16 } else { 32 };
        self.other == rax
            && self.flags_before == rflags
            && !matches!(self.operation, Operation::RepeatStringScan { count, .. } if count != rcx)
            && self.destination.is_some_and(|(part, original)| {
                original == rdi && (part.bits == code || part.bits == override_width)
            })
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if !matches!(self.size, 1 | 2 | 4 | 8) || !(1..=15).contains(&self.length) {
            return Err("invalid MMIO ALU read width/length".into());
        }
        if let Operation::ImplicitMultiply { rdx_before, .. } = self.operation {
            let width = u32::from(self.size.max(2)) * 8;
            if !matches!(self.destination, Some((RegisterPart { index: 0, shift: 0, bits }, _)) if bits == width)
                || self.memory_left
                || self.other != 0
                || (self.size == 1 && rdx_before != 0)
            {
                return Err("invalid MMIO implicit multiply operands".into());
            }
            return Ok(());
        }
        if self.is_string_scan() {
            let Some((part, _)) = self.destination else {
                return Err("missing MMIO SCAS destination".into());
            };
            if self.memory_left
                || part.index != 7
                || part.shift != 0
                || !matches!(part.bits, 16 | 32 | 64)
            {
                return Err("invalid MMIO SCAS destination".into());
            }
            if matches!(self.operation, Operation::RepeatStringScan { count, .. } if count & part.mask() == 0)
            {
                return Err("MMIO SCAS repeat count is exhausted".into());
            }
            return Ok(());
        }
        let flags_only = matches!(
            self.operation,
            Operation::Compare | Operation::Test | Operation::BitTest(_)
        );
        if self.destination.is_none() != flags_only || (!flags_only && self.memory_left) {
            return Err("invalid MMIO ALU result destination".into());
        }
        if let Operation::BitTest(bit) = self.operation {
            if self.size == 1
                || u32::from(bit) >= u32::from(self.size) * 8
                || !self.memory_left
                || self.other != 0
            {
                return Err("invalid MMIO bit-test descriptor".into());
            }
        }
        if self.operation.is_unary() && (self.size == 1 || self.other != 0) {
            return Err("invalid MMIO unary ALU read descriptor".into());
        }
        if matches!(self.operation, Operation::Imul) && self.size == 1 {
            return Err("invalid MMIO IMUL operand width".into());
        }
        if matches!(self.operation, Operation::Adcx | Operation::Adox)
            && !matches!(self.size, 4 | 8)
        {
            return Err("invalid MMIO ADX operand width".into());
        }
        if let Operation::Bmi1(operation) = self.operation {
            let uses_other = matches!(
                operation,
                bmi1::Operation::AndNot | bmi1::Operation::Extract
            );
            if !matches!(self.size, 4 | 8)
                || self.length < 5
                || self.other & !(u64::MAX >> (64 - u32::from(self.size) * 8)) != 0
                || (!uses_other && self.other != 0)
            {
                return Err("invalid MMIO BMI1 operands".into());
            }
        }
        if let Some((part, original)) = self.destination {
            if !part.valid() {
                return Err("invalid MMIO ALU register part".into());
            }
            if matches!(self.operation, Operation::Crc32) {
                if !matches!((self.size, part.bits), (1, 32 | 64) | (2 | 4, 32) | (8, 64))
                    || self.other != u64::from(original as u32)
                {
                    return Err("invalid MMIO CRC32 operand widths or accumulator".into());
                }
            } else if part.bits != u32::from(self.size) * 8 {
                return Err("invalid MMIO ALU register part".into());
            }
        }
        Ok(())
    }

    pub(crate) fn completion(&self, data: &[u8]) -> Result<Completion, String> {
        self.validate()?;
        if data.len() != usize::from(self.size) {
            return Err("MMIO ALU completion width differs from request".into());
        }
        let mut bytes = [0; 8];
        bytes[..data.len()].copy_from_slice(data);
        let memory = u64::from_le_bytes(bytes);
        if self.operation.is_bit_scan() && memory == 0 {
            // Keep the entire previous register for the architecturally
            // undefined zero-source destination, including its upper half.
            return Ok((
                [None, None],
                Some(self.flags_before | bits::ZF),
                self.length,
            ));
        }
        let width_bits = u32::from(self.size) * 8;
        let mask = u64::MAX >> (64 - width_bits);
        let other = self.other & mask;
        let (left, right) = if self.memory_left {
            (memory, other)
        } else {
            (other, memory)
        };
        let carry_flag = if matches!(self.operation, Operation::Adox) {
            bits::OF
        } else {
            bits::CF
        };
        let carry = self.flags_before & carry_flag != 0;
        let mut updated = self.flags_before;
        let result = match self.operation {
            Operation::Add => left.wrapping_add(right),
            Operation::Adc | Operation::Adcx | Operation::Adox => {
                left.wrapping_add(right).wrapping_add(u64::from(carry))
            }
            Operation::Sub
            | Operation::Compare
            | Operation::StringScan
            | Operation::RepeatStringScan { .. } => left.wrapping_sub(right),
            Operation::Sbb => left.wrapping_sub(right).wrapping_sub(u64::from(carry)),
            Operation::And | Operation::Test => left & right,
            Operation::Or => left | right,
            Operation::Xor => left ^ right,
            Operation::BitTest(bit) => (memory >> bit) & 1,
            Operation::PopulationCount => u64::from(memory.count_ones()),
            Operation::BitScanForward => u64::from(memory.trailing_zeros()),
            Operation::BitScanReverse => u64::from(63 - memory.leading_zeros()),
            Operation::CountTrailingZeros => u64::from(memory.trailing_zeros().min(width_bits)),
            Operation::CountLeadingZeros => u64::from(memory.leading_zeros() - (64 - width_bits)),
            Operation::Crc32 => u64::from(crc32::crc32c(self.other as u32, memory, self.size)),
            Operation::Imul => {
                let (product, overflow) = imul::truncated_product(left, right, self.size);
                flags::set_cf_of(&mut updated, overflow, overflow);
                product
            }
            Operation::ImplicitMultiply { signed, rdx_before } => {
                return self
                    .complete_implicit_multiply(memory, width_bits, mask, signed, rdx_before);
            }
            Operation::Bmi1(operation) => {
                let (value, flags) = operation.apply(width_bits, memory, other, updated);
                updated = flags;
                value
            }
        };
        match self.operation {
            Operation::Add => flags::update_flags_add(&mut updated, left, right, result, self.size),
            Operation::Adc => {
                flags::update_flags_adc(&mut updated, left, right, carry, result, self.size)
            }
            Operation::Adcx | Operation::Adox => {
                // ADOX stores the unsigned carry-out in OF. Both forms
                // preserve every flag other than their own carry flag.
                let sum = u128::from(left) + u128::from(right) + u128::from(carry);
                updated &= !carry_flag;
                if sum > u128::from(mask) {
                    updated |= carry_flag;
                }
            }
            Operation::Sub
            | Operation::Compare
            | Operation::StringScan
            | Operation::RepeatStringScan { .. } => {
                flags::update_flags_sub(&mut updated, left, right, result, self.size)
            }
            Operation::Sbb => {
                flags::update_flags_sbb(&mut updated, left, right, carry, result, self.size)
            }
            Operation::BitTest(_) => updated = (updated & !bits::CF) | result,
            Operation::BitScanForward | Operation::BitScanReverse => updated &= !bits::ZF,
            Operation::CountTrailingZeros | Operation::CountLeadingZeros => {
                updated &= !(bits::CF | bits::ZF);
                if memory == 0 {
                    updated |= bits::CF;
                }
                if result == 0 {
                    updated |= bits::ZF;
                }
            }
            Operation::PopulationCount => {
                updated &= !(bits::CF | bits::PF | bits::AF | bits::ZF | bits::SF | bits::OF);
                if memory == 0 {
                    updated |= bits::ZF;
                }
            }
            Operation::Crc32 | Operation::Imul | Operation::Bmi1(_) => {}
            _ => flags::update_flags_logic(&mut updated, result, self.size),
        }
        let register = self.destination.map(|(part, original)| {
            let value = if self.is_string_scan() {
                if self.flags_before & super::string::DIRECTION != 0 {
                    original.wrapping_sub(u64::from(self.size))
                } else {
                    original.wrapping_add(u64::from(self.size))
                }
            } else {
                result
            };
            (part.index, part.merge(original, value))
        });
        let flags = (!matches!(self.operation, Operation::Crc32)).then_some(updated);
        Ok(([register, None], flags, self.length))
    }

    pub(super) fn effect(&self, data: &[u8]) -> Result<Effect, String> {
        let (mut registers, flags, length) = self.completion(data)?;
        if let Operation::RepeatStringScan { count, while_equal } = self.operation {
            let (index, _) = self.destination.expect("validated SCAS index");
            let counter = RegisterPart { index: 1, ..index };
            let remaining = (count & counter.mask()) - 1;
            registers[1] = Some((counter.index, counter.merge(count, remaining)));
            let equal = flags.expect("SCAS comparison flags") & bits::ZF != 0;
            if remaining != 0 && equal == while_equal {
                // Keep the entry flags through the next iteration. A later
                // fault reports those flags with the completed count/index.
                return Ok(Effect::PartialString(registers));
            }
        }
        Ok(Effect::Scalar((registers, flags, length)))
    }

    fn complete_implicit_multiply(
        &self,
        memory: u64,
        width_bits: u32,
        mask: u64,
        signed: bool,
        rdx_before: u64,
    ) -> Result<Completion, String> {
        let (accumulator, rax_before) = self.destination.ok_or("missing multiply accumulator")?;
        let (product, overflow) = if signed {
            let shift = 64 - width_bits;
            let extend = |value: u64| i128::from(((value << shift) as i64) >> shift);
            let product = extend(rax_before) * extend(memory);
            (product as u128, product != extend(product as u64))
        } else {
            let product = u128::from(rax_before & mask) * u128::from(memory);
            (product, product >> width_bits != 0)
        };
        // MUL/IMUL r/m8 writes the full AX; wider encodings use DX:AX,
        // EDX:EAX or RDX:RAX. RegisterPart handles partial-lane retention.
        let low = Some((0, accumulator.merge(rax_before, product as u64)));
        let high = (self.size != 1).then(|| {
            let part = RegisterPart {
                index: 2,
                ..accumulator
            };
            (2, part.merge(rdx_before, (product >> width_bits) as u64))
        });
        let mut flags = self.flags_before;
        flags::set_cf_of(&mut flags, overflow, overflow);
        Ok(([low, high], Some(flags), self.length))
    }
}

fn prepare_implicit_multiply<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
    record: ExitRecord,
    instruction: &Instruction,
    operand: &Operand,
) -> Result<Plan, String> {
    if !instruction.operands_complete
        || instruction.flow != Flow::Next
        || operand.kind != OperandKind::Memory
        || !operand.read
        || operand.write
        || operand.conditional
        || record.qualification & 3 != 1
    {
        return Err("implicit multiply MMIO requires one translated read".into());
    }
    let size = match operand.width_bits {
        8 => 1,
        16 => 2,
        32 => 4,
        64 => 8,
        _ => return Err("invalid MMIO implicit multiply operand width".into()),
    };
    super::validate_memory(context, memory, record, operand, size)?;
    let length = u64::from(instruction.size);
    let input = AluReadInput {
        size,
        length,
        operation: Operation::ImplicitMultiply {
            signed: instruction.mnemonic == "imul",
            rdx_before: if size == 1 { 0 } else { context.registers[2] },
        },
        other: 0,
        memory_left: false,
        flags_before: context.rflags,
        destination: Some((
            RegisterPart {
                index: 0,
                bits: u32::from(size.max(2)) * 8,
                shift: 0,
            },
            context.registers[0],
        )),
    };
    input.validate()?;
    Ok(Plan {
        physical: record.physical,
        linear: record.linear,
        length,
        action: super::Action::AluRead(input),
    })
}

pub(super) fn prepare<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
    record: ExitRecord,
    instruction: &Instruction,
) -> Result<Option<Plan>, String> {
    let bmi1 = match instruction.mnemonic.as_str() {
        "andn" => Some(bmi1::Operation::AndNot),
        "bextr" => Some(bmi1::Operation::Extract),
        "blsi" => Some(bmi1::Operation::IsolateLowest),
        "blsmsk" => Some(bmi1::Operation::MaskThroughLowest),
        "blsr" => Some(bmi1::Operation::ResetLowest),
        _ => None,
    };
    if let Some(operation) = bmi1 {
        return prepare_bmi1(context, memory, record, instruction, operation).map(Some);
    }
    if matches!(instruction.mnemonic.as_str(), "mul" | "imul")
        && let [operand] = instruction.operands.as_slice()
    {
        return prepare_implicit_multiply(context, memory, record, instruction, operand).map(Some);
    }
    let operation = match instruction.mnemonic.as_str() {
        "add" => Operation::Add,
        "adc" => Operation::Adc,
        "adcx" => Operation::Adcx,
        "adox" => Operation::Adox,
        "crc32" => Operation::Crc32,
        "imul" => Operation::Imul,
        "sub" => Operation::Sub,
        "sbb" => Operation::Sbb,
        "and" => Operation::And,
        "or" => Operation::Or,
        "xor" => Operation::Xor,
        "cmp" => Operation::Compare,
        "test" => Operation::Test,
        "bt" => Operation::BitTest(0),
        "popcnt" => Operation::PopulationCount,
        "tzcnt" if context.bit_count.tzcnt => Operation::CountTrailingZeros,
        "lzcnt" if context.bit_count.lzcnt => Operation::CountLeadingZeros,
        "bsf" | "tzcnt" => Operation::BitScanForward,
        "bsr" | "lzcnt" => Operation::BitScanReverse,
        _ => return Ok(None),
    };
    if !instruction.operands_complete
        || instruction.flow != Flow::Next
        || instruction.operands.iter().any(|o| o.conditional)
    {
        return Err("incomplete MMIO ALU read effects".into());
    }
    let memory_left = instruction
        .operands
        .first()
        .is_some_and(|operand| operand.kind == OperandKind::Memory);
    let unary = operation.is_unary();
    let crc32 = matches!(operation, Operation::Crc32);
    let (operand, other, immediate) = match instruction.operands.as_slice() {
        [first, second] if memory_left => (first, second, None),
        [first, second] => (second, first, None),
        [target, source, immediate]
            if matches!(operation, Operation::Imul)
                && immediate.kind == OperandKind::Immediate
                && immediate.read
                && !immediate.write =>
        {
            (source, target, Some(immediate.value))
        }
        _ => return Err("unsupported MMIO ALU operand shape".into()),
    };
    if operand.kind != OperandKind::Memory
        || !operand.read
        || operand.write
        || other.read == (unary || immediate.is_some())
        || record.qualification & 3 != 1
    {
        return Err("MMIO ALU read effects disagree with the EPT access".into());
    }
    let size = match operand.width_bits {
        8 if !unary => 1,
        16 => 2,
        32 => 4,
        64 => 8,
        _ => return Err("unsupported MMIO ALU read width".into()),
    };
    let (value, part) = match other.kind {
        OperandKind::Immediate => (other.value, None),
        OperandKind::Register => {
            let part = RegisterPart::parse(&other.reg).ok_or("unsupported MMIO ALU register")?;
            if part.bits != other.width_bits || (!crc32 && part.bits != operand.width_bits) {
                return Err("inconsistent MMIO ALU register width".into());
            }
            (part.value(&context.registers), Some(part))
        }
        _ => return Err("unsupported MMIO ALU source".into()),
    };
    let bit_test = matches!(operation, Operation::BitTest(_));
    let operation = if bit_test {
        if size == 1 || !memory_left {
            return Err("unsupported MMIO bit-test operands".into());
        }
        Operation::BitTest((value & (u64::from(size) * 8 - 1)) as u8)
    } else {
        operation
    };
    let flags_only = matches!(
        operation,
        Operation::Compare | Operation::Test | Operation::BitTest(_)
    );
    let destination = if flags_only {
        if other.write {
            return Err("flag-only MMIO operation modifies a source".into());
        }
        None
    } else {
        if memory_left || !other.write {
            return Err("MMIO ALU read needs a register destination".into());
        }
        let part = part.ok_or("MMIO ALU result must be a register")?;
        Some((part, context.registers[part.index]))
    };
    let mut addressed = operand.clone();
    if bit_test && other.kind == OperandKind::Register {
        // Register offsets address a signed bit string. Immediate offsets
        // select a bit within the addressed word and never move its base.
        let shift = 64 - u32::from(size) * 8;
        let signed = ((value << shift) as i64) >> shift;
        let words = signed.div_euclid(i64::from(size) * 8);
        addressed.displacement = addressed
            .displacement
            .wrapping_add((words * i64::from(size)) as u64);
    }
    super::validate_memory(context, memory, record, &addressed, size)?;
    let input = AluReadInput {
        size,
        length: u64::from(instruction.size),
        operation,
        other: if let Some(immediate) = immediate {
            immediate
        } else if bit_test || unary {
            0
        } else if crc32 {
            u64::from(value as u32)
        } else {
            value
        },
        memory_left,
        flags_before: context.rflags,
        destination,
    };
    input.validate()?;
    Ok(Some(Plan {
        physical: record.physical,
        linear: record.linear,
        length: u64::from(instruction.size),
        action: super::Action::AluRead(input),
    }))
}

fn prepare_bmi1<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
    record: ExitRecord,
    instruction: &Instruction,
    operation: bmi1::Operation,
) -> Result<Plan, String> {
    let (destination, source, other) = match (operation, instruction.operands.as_slice()) {
        (bmi1::Operation::AndNot, [dest, other, mem])
        | (bmi1::Operation::Extract, [dest, mem, other]) => (dest, mem, Some(other)),
        (
            bmi1::Operation::IsolateLowest
            | bmi1::Operation::MaskThroughLowest
            | bmi1::Operation::ResetLowest,
            [dest, mem],
        ) => (dest, mem, None),
        _ => return Err("unsupported MMIO BMI1 operand shape".into()),
    };
    let width = source.width_bits;
    if !instruction.operands_complete
        || instruction.flow != Flow::Next
        || instruction
            .operands
            .iter()
            .any(|operand| operand.conditional)
        || record.qualification & 3 != 1
        || source.kind != OperandKind::Memory
        || !source.read
        || source.write
        || !matches!(width, 32 | 64)
        || destination.read
        || !destination.write
    {
        return Err("MMIO BMI1 effects disagree with the EPT read".into());
    }
    let register = |operand: &Operand| {
        RegisterPart::parse(&operand.reg)
            .filter(|part| {
                operand.kind == OperandKind::Register
                    && operand.width_bits == width
                    && part.bits == width
            })
            .ok_or("invalid MMIO BMI1 register")
    };
    let destination = register(destination)?;
    let other = if let Some(operand) = other {
        if !operand.read || operand.write {
            return Err("invalid MMIO BMI1 register source".into());
        }
        register(operand)?.value(&context.registers)
    } else {
        0
    };
    let size = (width / 8) as u8;
    super::validate_memory(context, memory, record, source, size)?;
    let length = u64::from(instruction.size);
    let input = AluReadInput {
        size,
        length,
        operation: Operation::Bmi1(operation),
        other,
        memory_left: false,
        flags_before: context.rflags,
        destination: Some((destination, context.registers[destination.index])),
    };
    input.validate()?;
    Ok(Plan {
        physical: record.physical,
        linear: record.linear,
        length,
        action: super::Action::AluRead(input),
    })
}
