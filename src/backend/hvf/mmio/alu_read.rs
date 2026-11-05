//! Read-only device operands for integer arithmetic, comparisons and bit tests.
use super::{
    Context, ExitRecord, Flow, Instruction, OperandKind, PhysicalMemory, Plan, RegisterPart,
};
use crate::isa::x86_64::flags::{self, bits};
use serde::{Deserialize, Serialize};

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
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !matches!(self.size, 1 | 2 | 4 | 8) || !(1..=15).contains(&self.length) {
            return Err("invalid MMIO ALU read width/length".into());
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
        if let Some((part, _)) = self.destination {
            if !part.valid() || part.bits != u32::from(self.size) * 8 {
                return Err("invalid MMIO ALU register part".into());
            }
        }
        Ok(())
    }

    pub(crate) fn completion(
        &self,
        data: &[u8],
    ) -> Result<(Option<(usize, u64)>, Option<u64>, u64), String> {
        self.validate()?;
        if data.len() != usize::from(self.size) {
            return Err("MMIO ALU completion width differs from request".into());
        }
        let mut bytes = [0; 8];
        bytes[..data.len()].copy_from_slice(data);
        let memory = u64::from_le_bytes(bytes);
        let mask = u64::MAX >> (64 - u32::from(self.size) * 8);
        let other = self.other & mask;
        let (left, right) = if self.memory_left {
            (memory, other)
        } else {
            (other, memory)
        };
        let carry = self.flags_before & bits::CF != 0;
        let result = match self.operation {
            Operation::Add => left.wrapping_add(right),
            Operation::Adc => left.wrapping_add(right).wrapping_add(u64::from(carry)),
            Operation::Sub | Operation::Compare => left.wrapping_sub(right),
            Operation::Sbb => left.wrapping_sub(right).wrapping_sub(u64::from(carry)),
            Operation::And | Operation::Test => left & right,
            Operation::Or => left | right,
            Operation::Xor => left ^ right,
            Operation::BitTest(bit) => (memory >> bit) & 1,
        };
        let mut updated = self.flags_before;
        match self.operation {
            Operation::Add => flags::update_flags_add(&mut updated, left, right, result, self.size),
            Operation::Adc => {
                flags::update_flags_adc(&mut updated, left, right, carry, result, self.size)
            }
            Operation::Sub | Operation::Compare => {
                flags::update_flags_sub(&mut updated, left, right, result, self.size)
            }
            Operation::Sbb => {
                flags::update_flags_sbb(&mut updated, left, right, carry, result, self.size)
            }
            Operation::BitTest(_) => updated = (updated & !bits::CF) | result,
            _ => flags::update_flags_logic(&mut updated, result, self.size),
        }
        let register = self
            .destination
            .map(|(part, original)| (part.index, part.merge(original, result)));
        Ok((register, Some(updated), self.length))
    }
}

pub(super) fn prepare<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
    record: ExitRecord,
    instruction: &Instruction,
) -> Result<Option<Plan>, String> {
    let operation = match instruction.mnemonic.as_str() {
        "add" => Operation::Add,
        "adc" => Operation::Adc,
        "sub" => Operation::Sub,
        "sbb" => Operation::Sbb,
        "and" => Operation::And,
        "or" => Operation::Or,
        "xor" => Operation::Xor,
        "cmp" => Operation::Compare,
        "test" => Operation::Test,
        "bt" => Operation::BitTest(0),
        _ => return Ok(None),
    };
    if !instruction.operands_complete
        || instruction.flow != Flow::Next
        || instruction.operands.len() != 2
        || instruction.operands.iter().any(|o| o.conditional)
    {
        return Err("incomplete MMIO ALU read effects".into());
    }
    let operands = &instruction.operands;
    let memory_left = operands[0].kind == OperandKind::Memory;
    let (operand, other) = if memory_left {
        (&operands[0], &operands[1])
    } else {
        (&operands[1], &operands[0])
    };
    if operand.kind != OperandKind::Memory
        || !operand.read
        || operand.write
        || !other.read
        || record.qualification & 3 != 1
    {
        return Err("MMIO ALU read effects disagree with the EPT access".into());
    }
    let size = match operand.width_bits {
        8 => 1,
        16 => 2,
        32 => 4,
        64 => 8,
        _ => return Err("unsupported MMIO ALU read width".into()),
    };
    let (value, part) = match other.kind {
        OperandKind::Immediate => (other.value, None),
        OperandKind::Register => {
            let part = RegisterPart::parse(&other.reg).ok_or("unsupported MMIO ALU register")?;
            if part.bits != operand.width_bits || part.bits != other.width_bits {
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
        other: if bit_test { 0 } else { value },
        memory_left,
        flags_before: context.rflags,
        destination,
    };
    input.validate()?;
    Ok(Some(Plan {
        physical: record.physical,
        length: u64::from(instruction.size),
        action: super::Action::AluRead(input),
    }))
}
