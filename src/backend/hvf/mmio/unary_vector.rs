//! Packed vector instructions whose only data operand is the MMIO reply.
use super::super::aes;
use super::vector_logic::{Encoding, byte_control, read_element, register};
use super::*;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Operation {
    Doublewords,
    HighWords,
    LowWords,
    // Append new operations to retain the saved transaction discriminants.
    Absolute(AbsoluteWidth),
    Widen { shape: Widening, signed: bool },
    PermuteQuadwords,
    PermuteLaneQuadwords,
    AesInverseMix,
    AesKeySchedule,
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Widening {
    ByteToWord,
    ByteToDoubleword,
    ByteToQuadword,
    WordToDoubleword,
    WordToQuadword,
    DoublewordToQuadword,
}

impl Widening {
    fn widths(self) -> (u8, u8) {
        match self {
            Self::ByteToWord => (1, 2),
            Self::ByteToDoubleword => (1, 4),
            Self::ByteToQuadword => (1, 8),
            Self::WordToDoubleword => (2, 4),
            Self::WordToQuadword => (2, 8),
            Self::DoublewordToQuadword => (4, 8),
        }
    }

    fn result<const N: usize>(self, data: &[u8], signed: bool) -> [u8; N] {
        let (from, to) = self.widths();
        let from = usize::from(from);
        let mut result = [0; N];
        for (source, target) in data
            .chunks_exact(from)
            .zip(result.chunks_exact_mut(usize::from(to)))
        {
            target[..from].copy_from_slice(source);
            if signed && source[from - 1] & 0x80 != 0 {
                target[from..].fill(0xff);
            }
        }
        result
    }
}

impl Operation {
    fn memory_size(self, encoding: Encoding) -> u8 {
        match self {
            Self::Widen { shape, .. } => {
                let (from, to) = shape.widths();
                encoding.size() / to * from
            }
            _ => encoding.size(),
        }
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
            || matches!(
                self.operation,
                Operation::Absolute(_) | Operation::Widen { .. } | Operation::AesInverseMix
            ) && self.control != 0
        {
            return Err("invalid HVF MMIO unary vector descriptor".into());
        }
        if matches!(self.operation, Operation::PermuteQuadwords)
            && self.encoding != Encoding::Vex256
        {
            return Err("invalid 256-bit permutation descriptor".into());
        }
        if matches!(
            self.operation,
            Operation::AesInverseMix | Operation::AesKeySchedule
        ) && self.encoding == Encoding::Vex256
        {
            return Err("invalid AES transform width".into());
        }
        if matches!(self.operation, Operation::PermuteLaneQuadwords)
            && self.encoding == Encoding::Legacy
        {
            return Err("invalid VPERMILPD immediate descriptor".into());
        }
        Ok(())
    }

    pub(crate) fn memory_size(&self) -> u8 {
        self.operation.memory_size(self.encoding)
    }

    fn result<const N: usize>(&self, data: &[u8]) -> [u8; N] {
        let (first, width) = match self.operation {
            Operation::Doublewords => (0, 4),
            Operation::HighWords => (8, 2),
            Operation::LowWords => (0, 2),
            Operation::Absolute(width) => return width.result(data),
            Operation::Widen { shape, signed } => return shape.result(data, signed),
            Operation::AesInverseMix | Operation::AesKeySchedule => {
                let (low, high) = data.split_at(8);
                let low = read_element(low);
                let high = read_element(high);
                let (low, high) = if matches!(self.operation, Operation::AesInverseMix) {
                    aes::aesimc(low, high)
                } else {
                    aes::aeskeygenassist(low, high, self.control)
                };
                let mut result = [0; N];
                result[..8].copy_from_slice(&low.to_le_bytes());
                result[8..16].copy_from_slice(&high.to_le_bytes());
                return result;
            }
            Operation::PermuteQuadwords => {
                return std::array::from_fn(|byte| {
                    let index = usize::from((self.control >> (2 * (byte / 8))) & 3);
                    data[index * 8 + byte % 8]
                });
            }
            Operation::PermuteLaneQuadwords => {
                return std::array::from_fn(|byte| {
                    let lane_start = byte / 16 * 16;
                    let index = usize::from((self.control >> (byte / 8)) & 1);
                    data[lane_start + index * 8 + byte % 8]
                });
            }
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
        let size = self.memory_size();
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
    let name = mnemonic.strip_prefix('v').unwrap_or(mnemonic);
    let operation = match name {
        "permq" | "permpd" if mnemonic.starts_with('v') => Operation::PermuteQuadwords,
        "pshufd" | "permilps" => Operation::Doublewords,
        "permilpd" => Operation::PermuteLaneQuadwords,
        "pshufhw" => Operation::HighWords,
        "pshuflw" => Operation::LowWords,
        "pabsb" => Operation::Absolute(AbsoluteWidth::Byte),
        "pabsw" => Operation::Absolute(AbsoluteWidth::Word),
        "pabsd" => Operation::Absolute(AbsoluteWidth::Doubleword),
        "aesimc" => Operation::AesInverseMix,
        "aeskeygenassist" => Operation::AesKeySchedule,
        _ => {
            let (shape, signed) = if let Some(shape) = name.strip_prefix("pmovsx") {
                (shape, true)
            } else if let Some(shape) = name.strip_prefix("pmovzx") {
                (shape, false)
            } else {
                return Ok(None);
            };
            let shape = match shape {
                "bw" => Widening::ByteToWord,
                "bd" => Widening::ByteToDoubleword,
                "bq" => Widening::ByteToQuadword,
                "wd" => Widening::WordToDoubleword,
                "wq" => Widening::WordToQuadword,
                "dq" => Widening::DoublewordToQuadword,
                _ => return Ok(None),
            };
            Operation::Widen { shape, signed }
        }
    };
    let (target, device, control) = match (operation, instruction.operands.as_slice()) {
        (
            Operation::Absolute(_) | Operation::Widen { .. } | Operation::AesInverseMix,
            [target, device],
        ) => (target, device, 0),
        (
            Operation::Doublewords
            | Operation::HighWords
            | Operation::LowWords
            | Operation::PermuteQuadwords
            | Operation::PermuteLaneQuadwords
            | Operation::AesKeySchedule,
            [target, device, immediate],
        ) => (
            target,
            device,
            byte_control(immediate, "invalid vector shuffle control")?,
        ),
        _ => return Err("wrong operands for unary vector MMIO".into()),
    };
    let encoding = if !mnemonic.starts_with('v') {
        Encoding::Legacy
    } else if target.width_bits == 256 {
        Encoding::Vex256
    } else {
        Encoding::Vex128
    };
    let size = operation.memory_size(encoding);
    if !read
        || !instruction.operands_complete
        || instruction.flow != Flow::Next
        || device.kind != OperandKind::Memory
        || device.width_bits != u32::from(size) * 8
        || !device.read
        || device.write
        || device.conditional
    {
        return Err("unary vector MMIO requires a complete device read operand".into());
    }
    let index = register(target, u32::from(encoding.size()) * 8, false, true)
        .ok_or("invalid unary vector destination")?;
    if encoding == Encoding::Legacy
        && !matches!(operation, Operation::Widen { .. })
        && record.linear & 15 != 0
    {
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
