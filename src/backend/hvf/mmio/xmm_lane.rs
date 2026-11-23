//! Eight-byte SSE/SSE2 and AVX transfers retain the other XMM lane.
use super::{Action, Context, ExitRecord, Flow, Instruction, Operand, OperandKind, Plan};
use super::{PhysicalMemory, validate_memory};
use serde::{Deserialize, Serialize};

pub(crate) const BYTES: u8 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Lane {
    Low,
    High,
}

impl Lane {
    fn range(self) -> std::ops::Range<usize> {
        match self {
            Self::Low => 0..8,
            Self::High => 8..16,
        }
    }

    pub(crate) fn preserved(self) -> Self {
        match self {
            Self::Low => Self::High,
            Self::High => Self::Low,
        }
    }

    pub(crate) fn bytes(self, value: &[u8; 16]) -> [u8; 8] {
        value[self.range()].try_into().unwrap()
    }

    pub(super) fn load(self, data: &[u8], preserved: [u8; 8]) -> Result<[u8; 16], String> {
        if data.len() != usize::from(BYTES) {
            return Err(format!(
                "HVF MMIO XMM lane input expected {BYTES} bytes, received {}",
                data.len()
            ));
        }
        let mut value = [0; 16];
        value[self.range()].copy_from_slice(data);
        value[self.preserved().range()].copy_from_slice(&preserved);
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub(crate) struct Transfer {
    pub(crate) index: u8,
    pub(crate) lane: Lane,
    pub(crate) length: u64,
}

impl Transfer {
    pub(super) fn validate(self) -> Result<(), String> {
        if self.index >= 16 || !(1..=15).contains(&self.length) {
            return Err("invalid HVF MMIO XMM lane descriptor".into());
        }
        Ok(())
    }
}

fn register(operand: &Operand, read: bool, write: bool) -> Result<u8, String> {
    if operand.kind != OperandKind::Register
        || operand.width_bits != 128
        || operand.read != read
        || operand.write != write
        || operand.conditional
    {
        return Err("wrong XMM lane register effects".into());
    }
    operand
        .reg
        .strip_prefix("xmm")
        .and_then(|index| index.parse().ok())
        .filter(|index| *index < 16)
        .ok_or_else(|| "invalid XMM lane register".into())
}

pub(super) fn prepare<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
    record: ExitRecord,
    instruction: &Instruction,
    read: bool,
) -> Result<Option<Plan>, String> {
    let name = instruction.mnemonic.as_str();
    let merge = name.strip_prefix('v');
    let lane = match merge.unwrap_or(name) {
        "movlps" | "movlpd" => Lane::Low,
        "movhps" | "movhpd" => Lane::High,
        _ => return Ok(None),
    };
    let vex = merge.is_some();
    let (vector, merger, operand) = match instruction.operands.as_slice() {
        [vector, merger, operand] if read && vex => (vector, Some(merger), operand),
        [vector, operand] if read && !vex => (vector, None, operand),
        [operand, vector] if !read => (vector, None, operand),
        _ => return Err("wrong XMM lane MMIO operands or direction".into()),
    };
    if !instruction.operands_complete
        || instruction.flow != Flow::Next
        || operand.kind != OperandKind::Memory
        || operand.width_bits != 8 * u32::from(BYTES)
        || operand.read != read
        || operand.write == read
        || operand.conditional
    {
        return Err("wrong XMM lane MMIO operand effects".into());
    }
    let index = register(vector, !read || !vex, read)?;
    let length = u64::from(instruction.size);
    let transfer = Transfer {
        index,
        lane,
        length,
    };
    transfer.validate()?;
    let action = if read {
        let source = merger.map_or(Ok(index), |operand| register(operand, true, false))?;
        Action::XmmLaneRead {
            transfer,
            source,
            zero_upper: vex,
        }
    } else {
        Action::XmmLaneWrite(transfer)
    };
    validate_memory(context, memory, record, operand, BYTES)?;
    Ok(Some(Plan {
        physical: record.physical,
        linear: record.linear,
        length,
        action,
    }))
}
