//! Legacy SSE and VEX packed binary operations with a device source.
use super::*;
use std::cmp::Ordering;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Element {
    Byte,
    Word,
    Doubleword,
    Quadword,
}

impl Element {
    fn bytes(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Doubleword => 4,
            Self::Quadword => 8,
        }
    }
}

fn read_element(lane: &[u8]) -> u64 {
    let mut bytes = [0; 8];
    bytes[..lane.len()].copy_from_slice(lane);
    u64::from_le_bytes(bytes)
}

fn map_integer_lanes<const N: usize>(
    left: &[u8; 32],
    right: &[u8],
    width: usize,
    lane_result: impl Fn(u64, u64) -> u64,
) -> [u8; N] {
    let mut result = [0; N];
    for ((left, right), target) in left
        .chunks_exact(width)
        .zip(right.chunks_exact(width))
        .zip(result.chunks_exact_mut(width))
    {
        let lane = lane_result(read_element(left), read_element(right));
        target.copy_from_slice(&lane.to_le_bytes()[..width]);
    }
    result
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Saturation {
    SignedByte,
    SignedWord,
    UnsignedByte,
    UnsignedWord,
}

impl Saturation {
    fn bytes(self) -> usize {
        match self {
            Self::SignedByte | Self::UnsignedByte => 1,
            Self::SignedWord | Self::UnsignedWord => 2,
        }
    }

    fn lane(self, left: u64, right: u64, subtract: bool) -> u64 {
        let (left, right, min, max) = match self {
            Self::SignedByte => (left as i8 as i32, right as i8 as i32, -128, 127),
            Self::SignedWord => (left as i16 as i32, right as i16 as i32, -32768, 32767),
            Self::UnsignedByte => (left as i32, right as i32, 0, 255),
            Self::UnsignedWord => (left as i32, right as i32, 0, 65535),
        };
        let result = if subtract { left - right } else { left + right };
        result.clamp(min, max) as u64
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Comparison {
    Equal,
    SignedGreater,
}

impl Comparison {
    fn matches(self, left: &[u8], right: &[u8]) -> bool {
        match self {
            Self::Equal => left == right,
            Self::SignedGreater => {
                let (&left_high, left_low) = left.split_last().unwrap();
                let (&right_high, right_low) = right.split_last().unwrap();
                (left_high as i8)
                    .cmp(&(right_high as i8))
                    .then_with(|| left_low.iter().rev().cmp(right_low.iter().rev()))
                    .is_gt()
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum MinMaxLane {
    SignedByte,
    UnsignedByte,
    SignedWord,
    UnsignedWord,
    SignedDoubleword,
    UnsignedDoubleword,
}

impl MinMaxLane {
    fn bytes(self) -> usize {
        match self {
            Self::SignedByte | Self::UnsignedByte => 1,
            Self::SignedWord | Self::UnsignedWord => 2,
            Self::SignedDoubleword | Self::UnsignedDoubleword => 4,
        }
    }

    fn compare(self, left: u64, right: u64) -> Ordering {
        match self {
            Self::SignedByte => (left as i8).cmp(&(right as i8)),
            Self::SignedWord => (left as i16).cmp(&(right as i16)),
            Self::SignedDoubleword => (left as i32).cmp(&(right as i32)),
            Self::UnsignedByte | Self::UnsignedWord | Self::UnsignedDoubleword => left.cmp(&right),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Shift {
    LeftWord,
    LeftDoubleword,
    LeftQuadword,
    RightWord,
    RightDoubleword,
    RightQuadword,
    ArithmeticWord,
    ArithmeticDoubleword,
}

impl Shift {
    fn bytes(self) -> usize {
        match self {
            Self::LeftWord | Self::RightWord | Self::ArithmeticWord => 2,
            Self::LeftDoubleword | Self::RightDoubleword | Self::ArithmeticDoubleword => 4,
            Self::LeftQuadword | Self::RightQuadword => 8,
        }
    }

    fn lane(self, value: u64, count: u64) -> u64 {
        let bits = (self.bytes() * 8) as u64;
        if count >= bits && !matches!(self, Self::ArithmeticWord | Self::ArithmeticDoubleword) {
            return 0;
        }
        let count = count.min(bits - 1);
        match self {
            Self::LeftWord | Self::LeftDoubleword | Self::LeftQuadword => value << count,
            Self::RightWord | Self::RightDoubleword | Self::RightQuadword => value >> count,
            Self::ArithmeticWord => ((value as i16) >> count) as u64,
            Self::ArithmeticDoubleword => ((value as i32) >> count) as u64,
        }
    }

    fn uniform<const N: usize>(self, left: &[u8; 32], count: u64) -> [u8; N] {
        let width = self.bytes();
        let mut result = [0; N];
        for (lane, output) in left.chunks_exact(width).zip(result.chunks_exact_mut(width)) {
            let shifted = self.lane(read_element(lane), count);
            output.copy_from_slice(&shifted.to_le_bytes()[..width]);
        }
        result
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Operation {
    And,
    AndNot,
    Or,
    Xor,
    // Keep wire discriminants stable by appending new operations.
    Compare(Comparison, Element),
    Add(Element),
    Subtract(Element),
    SaturatingAdd(Saturation),
    SaturatingSubtract(Saturation),
    Minimum(MinMaxLane),
    Maximum(MinMaxLane),
    UniformShift(Shift),
    VariableShift(Shift),
    UnpackLow(Element),
    UnpackHigh(Element),
}

impl Operation {
    fn mnemonic(name: &str) -> Option<Self> {
        match name {
            "vpsrlvd" => return Some(Self::VariableShift(Shift::RightDoubleword)),
            "vpsrlvq" => return Some(Self::VariableShift(Shift::RightQuadword)),
            "vpsravd" => return Some(Self::VariableShift(Shift::ArithmeticDoubleword)),
            "vpsllvd" => return Some(Self::VariableShift(Shift::LeftDoubleword)),
            "vpsllvq" => return Some(Self::VariableShift(Shift::LeftQuadword)),
            _ => {}
        }
        Some(match name.strip_prefix('v').unwrap_or(name) {
            "andps" | "andpd" | "pand" => Self::And,
            "andnps" | "andnpd" | "pandn" => Self::AndNot,
            "orps" | "orpd" | "por" => Self::Or,
            "xorps" | "xorpd" | "pxor" => Self::Xor,
            "punpcklbw" => Self::UnpackLow(Element::Byte),
            "punpcklwd" => Self::UnpackLow(Element::Word),
            "punpckldq" => Self::UnpackLow(Element::Doubleword),
            "punpcklqdq" => Self::UnpackLow(Element::Quadword),
            "punpckhbw" => Self::UnpackHigh(Element::Byte),
            "punpckhwd" => Self::UnpackHigh(Element::Word),
            "punpckhdq" => Self::UnpackHigh(Element::Doubleword),
            "punpckhqdq" => Self::UnpackHigh(Element::Quadword),
            "pcmpeqb" => Self::Compare(Comparison::Equal, Element::Byte),
            "pcmpeqw" => Self::Compare(Comparison::Equal, Element::Word),
            "pcmpeqd" => Self::Compare(Comparison::Equal, Element::Doubleword),
            "pcmpeqq" => Self::Compare(Comparison::Equal, Element::Quadword),
            "pcmpgtb" => Self::Compare(Comparison::SignedGreater, Element::Byte),
            "pcmpgtw" => Self::Compare(Comparison::SignedGreater, Element::Word),
            "pcmpgtd" => Self::Compare(Comparison::SignedGreater, Element::Doubleword),
            "pcmpgtq" => Self::Compare(Comparison::SignedGreater, Element::Quadword),
            "paddb" => Self::Add(Element::Byte),
            "paddw" => Self::Add(Element::Word),
            "paddd" => Self::Add(Element::Doubleword),
            "paddq" => Self::Add(Element::Quadword),
            "psubb" => Self::Subtract(Element::Byte),
            "psubw" => Self::Subtract(Element::Word),
            "psubd" => Self::Subtract(Element::Doubleword),
            "psubq" => Self::Subtract(Element::Quadword),
            "paddsb" => Self::SaturatingAdd(Saturation::SignedByte),
            "paddsw" => Self::SaturatingAdd(Saturation::SignedWord),
            "paddusb" => Self::SaturatingAdd(Saturation::UnsignedByte),
            "paddusw" => Self::SaturatingAdd(Saturation::UnsignedWord),
            "psubsb" => Self::SaturatingSubtract(Saturation::SignedByte),
            "psubsw" => Self::SaturatingSubtract(Saturation::SignedWord),
            "psubusb" => Self::SaturatingSubtract(Saturation::UnsignedByte),
            "psubusw" => Self::SaturatingSubtract(Saturation::UnsignedWord),
            "pminsb" => Self::Minimum(MinMaxLane::SignedByte),
            "pminub" => Self::Minimum(MinMaxLane::UnsignedByte),
            "pminsw" => Self::Minimum(MinMaxLane::SignedWord),
            "pminuw" => Self::Minimum(MinMaxLane::UnsignedWord),
            "pminsd" => Self::Minimum(MinMaxLane::SignedDoubleword),
            "pminud" => Self::Minimum(MinMaxLane::UnsignedDoubleword),
            "pmaxsb" => Self::Maximum(MinMaxLane::SignedByte),
            "pmaxub" => Self::Maximum(MinMaxLane::UnsignedByte),
            "pmaxsw" => Self::Maximum(MinMaxLane::SignedWord),
            "pmaxuw" => Self::Maximum(MinMaxLane::UnsignedWord),
            "pmaxsd" => Self::Maximum(MinMaxLane::SignedDoubleword),
            "pmaxud" => Self::Maximum(MinMaxLane::UnsignedDoubleword),
            "psllw" => Self::UniformShift(Shift::LeftWord),
            "pslld" => Self::UniformShift(Shift::LeftDoubleword),
            "psllq" => Self::UniformShift(Shift::LeftQuadword),
            "psrlw" => Self::UniformShift(Shift::RightWord),
            "psrld" => Self::UniformShift(Shift::RightDoubleword),
            "psrlq" => Self::UniformShift(Shift::RightQuadword),
            "psraw" => Self::UniformShift(Shift::ArithmeticWord),
            "psrad" => Self::UniformShift(Shift::ArithmeticDoubleword),
            _ => return None,
        })
    }

    fn memory_size(self, encoding: Encoding) -> u8 {
        match self {
            Self::UniformShift(_) => 16,
            _ => encoding.size(),
        }
    }

    fn result<const N: usize>(self, left: &[u8; 32], right: &[u8]) -> [u8; N] {
        match self {
            Self::And => std::array::from_fn(|i| left[i] & right[i]),
            Self::AndNot => std::array::from_fn(|i| !left[i] & right[i]),
            Self::Or => std::array::from_fn(|i| left[i] | right[i]),
            Self::Xor => std::array::from_fn(|i| left[i] ^ right[i]),
            Self::Compare(comparison, element) => {
                let width = element.bytes();
                let mut result = [0; N];
                for ((left, right), target) in left
                    .chunks_exact(width)
                    .zip(right.chunks_exact(width))
                    .zip(result.chunks_exact_mut(width))
                {
                    target.fill(if comparison.matches(left, right) {
                        0xff
                    } else {
                        0
                    });
                }
                result
            }
            Self::Add(element) | Self::Subtract(element) => {
                let subtract = matches!(self, Self::Subtract(_));
                map_integer_lanes(left, right, element.bytes(), |left, right| {
                    if subtract {
                        left.wrapping_sub(right)
                    } else {
                        left.wrapping_add(right)
                    }
                })
            }
            Self::SaturatingAdd(saturation) | Self::SaturatingSubtract(saturation) => {
                let subtract = matches!(self, Self::SaturatingSubtract(_));
                map_integer_lanes(left, right, saturation.bytes(), |left, right| {
                    saturation.lane(left, right, subtract)
                })
            }
            Self::Minimum(lane) | Self::Maximum(lane) => {
                let select_right = if matches!(self, Self::Minimum(_)) {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
                map_integer_lanes(left, right, lane.bytes(), |left, right| {
                    if lane.compare(left, right) == select_right {
                        right
                    } else {
                        left
                    }
                })
            }
            Self::UniformShift(shift) => shift.uniform(left, read_element(&right[..8])),
            Self::VariableShift(shift) => {
                map_integer_lanes(left, right, shift.bytes(), |value, count| {
                    shift.lane(value, count)
                })
            }
            Self::UnpackLow(element) | Self::UnpackHigh(element) => {
                let width = element.bytes();
                let start = if matches!(self, Self::UnpackHigh(_)) {
                    8
                } else {
                    0
                };
                let mut result = [0; N];
                // VEX.256 applies the same interleave independently to each 128-bit lane.
                for ((left, right), lane) in left
                    .chunks_exact(16)
                    .zip(right.chunks_exact(16))
                    .zip(result.chunks_exact_mut(16))
                {
                    for ((left, right), pair) in left[start..start + 8]
                        .chunks_exact(width)
                        .zip(right[start..start + 8].chunks_exact(width))
                        .zip(lane.chunks_exact_mut(2 * width))
                    {
                        pair[..width].copy_from_slice(left);
                        pair[width..].copy_from_slice(right);
                    }
                }
                result
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Encoding {
    Legacy,
    Vex128,
    Vex256,
}

impl Encoding {
    pub(crate) fn size(self) -> u8 {
        if self == Self::Vex256 { YMM_BYTES } else { 16 }
    }

    pub(crate) fn needs_avx(self) -> bool {
        self != Self::Legacy
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Input {
    pub(crate) index: u8,
    pub(crate) encoding: Encoding,
    pub(crate) length: u64,
    operation: Operation,
}

impl Input {
    pub(crate) fn memory_size(&self) -> u8 {
        self.operation.memory_size(self.encoding)
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        if self.index >= 16 || !(1..=15).contains(&self.length) {
            return Err("invalid HVF MMIO vector logic descriptor".into());
        }
        if let Operation::VariableShift(shift) = self.operation
            && (self.encoding == Encoding::Legacy || shift.bytes() == 2)
        {
            return Err("invalid AVX2 variable shift descriptor".into());
        }
        Ok(())
    }

    pub(super) fn effect(&self, left: &[u8; 32], data: &[u8]) -> Result<Effect, String> {
        let size = self.memory_size();
        if data.len() != usize::from(size) {
            return Err(format!(
                "HVF MMIO vector logic expected {size} bytes, received {}",
                data.len()
            ));
        }
        if self.encoding == Encoding::Vex256 {
            Ok(Effect::Ymm {
                index: self.index,
                value: self.operation.result(left, data),
                length: self.length,
            })
        } else {
            Ok(Effect::Xmm {
                index: self.index,
                value: self.operation.result(left, data),
                zero_upper: self.encoding == Encoding::Vex128,
                length: self.length,
            })
        }
    }
}

pub(super) fn register(operand: &Operand, width: u32, read: bool, write: bool) -> Option<u8> {
    if operand.kind != OperandKind::Register
        || operand.width_bits != width
        || operand.read != read
        || operand.write != write
        || operand.conditional
    {
        return None;
    }
    let bank = if width == 256 { "ymm" } else { "xmm" };
    let index = operand.reg.strip_prefix(bank)?.parse().ok()?;
    (index < 16).then_some(index)
}

pub(super) fn prepare<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
    record: ExitRecord,
    instruction: &Instruction,
    read: bool,
) -> Result<Option<Plan>, String> {
    let Some(operation) = Operation::mnemonic(&instruction.mnemonic) else {
        return Ok(None);
    };
    let vex = instruction.mnemonic.starts_with('v');
    let (encoding, target, left, right) = match (vex, instruction.operands.as_slice()) {
        (false, [target, right]) => (Encoding::Legacy, target, target, right),
        (true, [target, left, right]) => {
            let encoding = if target.width_bits == 256 {
                Encoding::Vex256
            } else {
                Encoding::Vex128
            };
            (encoding, target, left, right)
        }
        _ => return Err("wrong operands for vector logic MMIO".into()),
    };
    let width = u32::from(encoding.size()) * 8;
    let memory_size = operation.memory_size(encoding);
    if !read
        || !instruction.operands_complete
        || instruction.flow != Flow::Next
        || right.kind != OperandKind::Memory
        || right.width_bits != u32::from(memory_size) * 8
        || !right.read
        || right.write
        || right.conditional
    {
        return Err("vector logic MMIO requires a complete device read operand".into());
    }
    let index = register(target, width, !vex, true).ok_or("invalid vector logic destination")?;
    let source = register(left, width, true, !vex).ok_or("invalid vector logic source")?;
    if !vex && record.linear & 15 != 0 {
        return Err("misaligned legacy vector logic MMIO input".into());
    }
    validate_memory(context, memory, record, right, memory_size)?;
    let length = u64::from(instruction.size);
    let input = Input {
        index,
        encoding,
        length,
        operation,
    };
    input.validate()?;
    Ok(Some(Plan {
        physical: record.physical,
        linear: record.linear,
        length,
        action: Action::VectorLogic { input, source },
    }))
}
