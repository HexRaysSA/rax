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
        let (left, right) = match self {
            Self::SignedByte => (left as i8 as i32, right as i8 as i32),
            Self::SignedWord => (left as i16 as i32, right as i16 as i32),
            Self::UnsignedByte | Self::UnsignedWord => (left as i32, right as i32),
        };
        let result = if subtract { left - right } else { left + right };
        let (min, max) = self.bounds();
        result.clamp(min, max) as u64
    }

    fn bounds(self) -> (i32, i32) {
        match self {
            Self::SignedByte => (i8::MIN.into(), i8::MAX.into()),
            Self::SignedWord => (i16::MIN.into(), i16::MAX.into()),
            Self::UnsignedByte => (0, u8::MAX.into()),
            Self::UnsignedWord => (0, u16::MAX.into()),
        }
    }

    fn pack<const N: usize>(self, left: &[u8; 32], right: &[u8]) -> [u8; N] {
        let width = self.bytes();
        let source_width = width * 2;
        let (min, max) = self.bounds();
        let mut result = [0; N];
        // Each 128-bit lane packs the signed register elements first, then the
        // signed device elements, even when the destination elements are unsigned.
        for ((left, right), lane) in left
            .chunks_exact(16)
            .zip(right.chunks_exact(16))
            .zip(result.chunks_exact_mut(16))
        {
            let sources = left
                .chunks_exact(source_width)
                .chain(right.chunks_exact(source_width));
            for (source, target) in sources.zip(lane.chunks_exact_mut(width)) {
                let raw = read_element(source);
                let signed = if source_width == 2 {
                    i32::from(raw as i16)
                } else {
                    raw as i32
                };
                target.copy_from_slice(&signed.clamp(min, max).to_le_bytes()[..width]);
            }
        }
        result
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
enum Multiply {
    LowWord,
    HighSignedWord,
    HighUnsignedWord,
    LowDoubleword,
    EvenSignedDoubleword,
    EvenUnsignedDoubleword,
    RoundedSignedWord,
    PairSignedWords,
    PairUnsignedSignedBytes,
}

impl Multiply {
    fn lane_bytes(self) -> usize {
        match self {
            Self::LowWord
            | Self::HighSignedWord
            | Self::HighUnsignedWord
            | Self::RoundedSignedWord
            | Self::PairUnsignedSignedBytes => 2,
            Self::LowDoubleword | Self::PairSignedWords => 4,
            Self::EvenSignedDoubleword | Self::EvenUnsignedDoubleword => 8,
        }
    }

    fn lane(self, left: u64, right: u64) -> u64 {
        let signed_word_product =
            |left: u64, right: u64| i32::from(left as i16) * i32::from(right as i16);
        match self {
            // Low products are independent of operand signedness. The caller
            // retains only the low word or doubleword.
            Self::LowWord | Self::LowDoubleword => left * right,
            Self::HighSignedWord => (signed_word_product(left, right) >> 16) as u64,
            Self::HighUnsignedWord => (left * right) >> 16,
            // Each quadword contains one even doubleword and one ignored odd
            // doubleword. Only the product of the even elements is written.
            Self::EvenSignedDoubleword => (i64::from(left as i32) * i64::from(right as i32)) as u64,
            Self::EvenUnsignedDoubleword => u64::from(left as u32) * u64::from(right as u32),
            // PMULHRSW rounds at bit 14 and takes the low 16 bits. The
            // -32768 times -32768 case thus yields 0x8000.
            Self::RoundedSignedWord => ((signed_word_product(left, right) + 0x4000) >> 15) as u64,
            Self::PairSignedWords => signed_word_product(left, right)
                .wrapping_add(signed_word_product(left >> 16, right >> 16))
                as u64,
            Self::PairUnsignedSignedBytes => {
                let first = i32::from(left as u8) * i32::from(right as i8);
                let second = i32::from((left >> 8) as u8) * i32::from((right >> 8) as i8);
                (first + second).clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as u64
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum ImmediateShuffle {
    PackedSingle,
    PackedDouble,
    AlignBytes,
}

impl ImmediateShuffle {
    fn mnemonic(name: &str) -> Option<Self> {
        Some(match name.strip_prefix('v').unwrap_or(name) {
            "shufps" => Self::PackedSingle,
            "shufpd" => Self::PackedDouble,
            "palignr" => Self::AlignBytes,
            _ => return None,
        })
    }

    fn result<const N: usize>(self, left: &[u8; 32], right: &[u8], control: u8) -> [u8; N] {
        std::array::from_fn(|i| {
            let lane = i / 16;
            let start = lane * 16;
            let byte = i % 16;
            match self {
                Self::PackedSingle => {
                    let element = byte / 4;
                    let source = if element < 2 { &left[..] } else { right };
                    let selected = usize::from((control >> (2 * element)) & 3);
                    source[start + 4 * selected + byte % 4]
                }
                Self::PackedDouble => {
                    let element = byte / 8;
                    let source = if element == 0 { &left[..] } else { right };
                    let selected = usize::from((control >> (2 * lane + element)) & 1);
                    source[start + 8 * selected + byte % 8]
                }
                Self::AlignBytes => match usize::from(control) + byte {
                    shift @ 0..=15 => right[start + shift],
                    shift @ 16..=31 => left[start + shift - 16],
                    _ => 0,
                },
            }
        })
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
    Multiply(Multiply),
    ShuffleBytes,
    ShuffleImmediate(ImmediateShuffle, u8),
    Pack(Saturation),
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
            "pshufb" => Self::ShuffleBytes,
            "punpcklbw" => Self::UnpackLow(Element::Byte),
            "punpcklwd" => Self::UnpackLow(Element::Word),
            "punpckldq" => Self::UnpackLow(Element::Doubleword),
            "punpcklqdq" => Self::UnpackLow(Element::Quadword),
            "punpckhbw" => Self::UnpackHigh(Element::Byte),
            "punpckhwd" => Self::UnpackHigh(Element::Word),
            "punpckhdq" => Self::UnpackHigh(Element::Doubleword),
            "punpckhqdq" => Self::UnpackHigh(Element::Quadword),
            "packsswb" => Self::Pack(Saturation::SignedByte),
            "packssdw" => Self::Pack(Saturation::SignedWord),
            "packuswb" => Self::Pack(Saturation::UnsignedByte),
            "packusdw" => Self::Pack(Saturation::UnsignedWord),
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
            "pmullw" => Self::Multiply(Multiply::LowWord),
            "pmulhw" => Self::Multiply(Multiply::HighSignedWord),
            "pmulhuw" => Self::Multiply(Multiply::HighUnsignedWord),
            "pmulld" => Self::Multiply(Multiply::LowDoubleword),
            "pmuldq" => Self::Multiply(Multiply::EvenSignedDoubleword),
            "pmuludq" => Self::Multiply(Multiply::EvenUnsignedDoubleword),
            "pmulhrsw" => Self::Multiply(Multiply::RoundedSignedWord),
            "pmaddwd" => Self::Multiply(Multiply::PairSignedWords),
            "pmaddubsw" => Self::Multiply(Multiply::PairUnsignedSignedBytes),
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
            Self::ShuffleBytes => std::array::from_fn(|i| {
                let control = right[i];
                if control & 0x80 != 0 {
                    0
                } else {
                    let lane_start = i / 16 * 16;
                    left[lane_start + usize::from(control & 0xf)]
                }
            }),
            Self::ShuffleImmediate(shuffle, control) => shuffle.result(left, right, control),
            Self::Pack(saturation) => saturation.pack(left, right),
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
            Self::Multiply(operation) => {
                map_integer_lanes(left, right, operation.lane_bytes(), |left, right| {
                    operation.lane(left, right)
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

pub(super) fn shuffle_control(control: &Operand) -> Result<u8, String> {
    if control.kind != OperandKind::Immediate
        || control.width_bits != 8
        || !control.read
        || control.write
        || control.conditional
    {
        return Err("invalid vector shuffle control".into());
    }
    u8::try_from(control.value).map_err(|_| "invalid vector shuffle control".into())
}

pub(super) fn prepare<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
    record: ExitRecord,
    instruction: &Instruction,
    read: bool,
) -> Result<Option<Plan>, String> {
    let mnemonic = instruction.mnemonic.as_str();
    let operands = instruction.operands.as_slice();
    let (operation, operands) = if let Some(shuffle) = ImmediateShuffle::mnemonic(mnemonic) {
        let (control, operands) = operands
            .split_last()
            .ok_or("missing vector shuffle control")?;
        (
            Operation::ShuffleImmediate(shuffle, shuffle_control(control)?),
            operands,
        )
    } else if let Some(operation) = Operation::mnemonic(mnemonic) {
        (operation, operands)
    } else {
        return Ok(None);
    };
    let vex = mnemonic.starts_with('v');
    let (encoding, target, left, right) = match (vex, operands) {
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
