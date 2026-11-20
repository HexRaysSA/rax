//! Legacy DIV and IDIV with one translated device operand.
use super::{Action, RegisterPart};
use super::{
    Completion, Context, ExitRecord, Flow, Instruction, OperandKind, PhysicalMemory, Plan,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DivideInput {
    pub(crate) size: u8,
    length: u64,
    signed: bool,
    low: u64,
    high: u64,
}

impl DivideInput {
    pub(super) fn validate(&self) -> Result<(), String> {
        if !matches!(self.size, 1 | 2 | 4 | 8)
            || !(2..=15).contains(&self.length)
            || (self.size == 1 && self.high != 0)
        {
            return Err("invalid MMIO divide operands".into());
        }
        Ok(())
    }

    /// A valid reply with no quotient produces the guest's divide error.
    pub(super) fn completion(&self, data: &[u8]) -> Result<Option<Completion>, String> {
        self.validate()?;
        if data.len() != usize::from(self.size) {
            return Err("MMIO divide completion width differs from request".into());
        }
        let mut bytes = [0; 8];
        bytes[..data.len()].copy_from_slice(data);
        let divisor = u64::from_le_bytes(bytes);
        let bits = u32::from(self.size) * 8;
        let mask = u64::MAX >> (64 - bits);
        let dividend = if self.size == 1 {
            u128::from(self.low as u16)
        } else {
            (u128::from(self.high & mask) << bits) | u128::from(self.low & mask)
        };
        let Some((quotient, remainder)) = divide(dividend, divisor, bits, self.signed) else {
            return Ok(None);
        };
        // Byte division returns quotient in AL and remainder in AH.
        let wide = self.size != 1;
        let low = if wide {
            quotient
        } else {
            quotient | (remainder << 8)
        };
        let accumulator = RegisterPart {
            index: 0,
            bits: bits.max(16),
            shift: 0,
        };
        let high = wide.then(|| {
            let part = RegisterPart {
                index: 2,
                ..accumulator
            };
            (2, part.merge(self.high, remainder))
        });
        Ok(Some((
            [Some((0, accumulator.merge(self.low, low))), high],
            None,
            self.length,
        )))
    }
}

fn divide(dividend: u128, divisor: u64, bits: u32, signed: bool) -> Option<(u64, u64)> {
    let mask = u64::MAX >> (64 - bits);
    if signed {
        let extend = |value: u128, width| {
            let shift = 128 - width;
            ((value << shift) as i128) >> shift
        };
        let dividend = extend(dividend, bits * 2);
        let divisor = extend(u128::from(divisor), bits);
        let quotient = dividend.checked_div(divisor)?;
        if quotient != extend((quotient as u64 & mask).into(), bits) {
            return None;
        }
        let remainder = dividend % divisor;
        Some((quotient as u64 & mask, remainder as u64 & mask))
    } else {
        let divisor = u128::from(divisor);
        let quotient = dividend.checked_div(divisor)?;
        (quotient <= u128::from(mask)).then(|| (quotient as u64, (dividend % divisor) as u64))
    }
}

pub(super) fn prepare<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
    record: ExitRecord,
    instruction: &Instruction,
) -> Result<Plan, String> {
    let [operand] = instruction.operands.as_slice() else {
        return Err("MMIO divide needs one explicit memory operand".into());
    };
    if !instruction.operands_complete
        || instruction.flow != Flow::Next
        || operand.kind != OperandKind::Memory
        || !operand.read
        || operand.write
        || operand.conditional
        || record.qualification & 3 != 1
    {
        return Err("MMIO divide requires one translated read".into());
    }
    let size = match operand.width_bits {
        8 => 1,
        16 => 2,
        32 => 4,
        64 => 8,
        _ => return Err("invalid MMIO divide width".into()),
    };
    super::validate_memory(context, memory, record, operand, size)?;
    let length = u64::from(instruction.size);
    let input = DivideInput {
        size,
        length,
        signed: instruction.mnemonic == "idiv",
        low: context.registers[0],
        high: if size == 1 { 0 } else { context.registers[2] },
    };
    input.validate()?;
    Ok(Plan {
        physical: record.physical,
        linear: record.linear,
        length,
        action: Action::Divide(input),
    })
}
