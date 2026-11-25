//! Packed vector instructions whose only data operand is the MMIO reply.
use super::vector_logic::{Encoding, read_element, register, shuffle_control};
use super::*;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Operation {
    Doublewords,
    HighWords,
    LowWords,
    // Append to retain the discriminants in saved immediate shuffle reads.
    Absolute(AbsoluteWidth),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum AbsoluteWidth {
    Byte,
    Word,
    Doubleword,
}

impl AbsoluteWidth {
    fn bytes(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Doubleword => 4,
        }
    }

    fn result<const N: usize>(self, data: &[u8]) -> [u8; N] {
        let width = self.bytes();
        let mut result = [0; N];
        for (source, target) in data.chunks_exact(width).zip(result.chunks_exact_mut(width)) {
            let value = read_element(source);
            let magnitude = if source[width - 1] & 0x80 != 0 {
                value.wrapping_neg()
            } else {
                value
            };
            target.copy_from_slice(&magnitude.to_le_bytes()[..width]);
        }
        result
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Input {
    pub(super) index: u8,
    pub(crate) encoding: Encoding,
    length: u64,
    #[serde(rename = "shuffle")]
    operation: Operation,
    control: u8,
}

impl Input {
    pub(super) fn validate(&self) -> Result<(), String> {
        if self.index >= 16
            || !(1..=15).contains(&self.length)
            || matches!(self.operation, Operation::Absolute(_)) && self.control != 0
        {
            return Err("invalid HVF MMIO unary vector descriptor".into());
        }
        Ok(())
    }

    fn result<const N: usize>(&self, data: &[u8]) -> [u8; N] {
        let (first, width) = match self.operation {
            Operation::Doublewords => (0, 4),
            Operation::HighWords => (8, 2),
            Operation::LowWords => (0, 2),
            Operation::Absolute(width) => return width.result(data),
        };
        let mut result = [0; N];
        result.copy_from_slice(data);
        for (source, target) in data.chunks_exact(16).zip(result.chunks_exact_mut(16)) {
            for output in 0..4 {
                let select = usize::from((self.control >> (2 * output)) & 3);
                let src = first + select * width;
                let dst = first + output * width;
                target[dst..dst + width].copy_from_slice(&source[src..src + width]);
            }
        }
        result
    }

    pub(super) fn effect(&self, data: &[u8]) -> Result<Effect, String> {
        let size = self.encoding.size();
        if data.len() != usize::from(size) {
            return Err(format!(
                "HVF MMIO unary vector expected {size} bytes, received {}",
                data.len()
            ));
        }
        Ok(if self.encoding == Encoding::Vex256 {
            Effect::Ymm {
                index: self.index,
                value: self.result(data),
                length: self.length,
            }
        } else {
            Effect::Xmm {
                index: self.index,
                value: self.result(data),
                zero_upper: self.encoding == Encoding::Vex128,
                length: self.length,
            }
        })
    }
}

pub(super) fn prepare<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
    record: ExitRecord,
    instruction: &Instruction,
    read: bool,
) -> Result<Option<Plan>, String> {
    let mnemonic = instruction.mnemonic.as_str();
    let operation = match mnemonic.strip_prefix('v').unwrap_or(mnemonic) {
        "pshufd" => Operation::Doublewords,
        "pshufhw" => Operation::HighWords,
        "pshuflw" => Operation::LowWords,
        "pabsb" => Operation::Absolute(AbsoluteWidth::Byte),
        "pabsw" => Operation::Absolute(AbsoluteWidth::Word),
        "pabsd" => Operation::Absolute(AbsoluteWidth::Doubleword),
        _ => return Ok(None),
    };
    let (target, device, control) = match (operation, instruction.operands.as_slice()) {
        (Operation::Absolute(_), [target, device]) => (target, device, 0),
        (
            Operation::Doublewords | Operation::HighWords | Operation::LowWords,
            [target, device, immediate],
        ) => (target, device, shuffle_control(immediate)?),
        _ => return Err("wrong operands for unary vector MMIO".into()),
    };
    let encoding = if !mnemonic.starts_with('v') {
        Encoding::Legacy
    } else if target.width_bits == 256 {
        Encoding::Vex256
    } else {
        Encoding::Vex128
    };
    let size = encoding.size();
    let width = u32::from(size) * 8;
    if !read
        || !instruction.operands_complete
        || instruction.flow != Flow::Next
        || device.kind != OperandKind::Memory
        || device.width_bits != width
        || !device.read
        || device.write
        || device.conditional
    {
        return Err("unary vector MMIO requires a complete device read operand".into());
    }
    let index = register(target, width, false, true).ok_or("invalid unary vector destination")?;
    if encoding == Encoding::Legacy && record.linear & 15 != 0 {
        return Err("misaligned legacy unary vector MMIO input".into());
    }
    validate_memory(context, memory, record, device, size)?;
    let length = u64::from(instruction.size);
    let input = Input {
        index,
        encoding,
        length,
        operation,
        control,
    };
    input.validate()?;
    Ok(Some(Plan {
        physical: record.physical,
        linear: record.linear,
        length,
        action: Action::UnaryVector(input),
    }))
}
