//! Legacy SSE and VEX packed logical operations and comparisons with a device source.
use super::*;

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
enum Operation {
    And,
    AndNot,
    Or,
    Xor,
    // Appended after the four original wire discriminants.
    Compare(Comparison, Element),
}

impl Operation {
    fn mnemonic(name: &str) -> Option<Self> {
        Some(match name.strip_prefix('v').unwrap_or(name) {
            "andps" | "andpd" | "pand" => Self::And,
            "andnps" | "andnpd" | "pandn" => Self::AndNot,
            "orps" | "orpd" | "por" => Self::Or,
            "xorps" | "xorpd" | "pxor" => Self::Xor,
            "pcmpeqb" => Self::Compare(Comparison::Equal, Element::Byte),
            "pcmpeqw" => Self::Compare(Comparison::Equal, Element::Word),
            "pcmpeqd" => Self::Compare(Comparison::Equal, Element::Doubleword),
            "pcmpeqq" => Self::Compare(Comparison::Equal, Element::Quadword),
            "pcmpgtb" => Self::Compare(Comparison::SignedGreater, Element::Byte),
            "pcmpgtw" => Self::Compare(Comparison::SignedGreater, Element::Word),
            "pcmpgtd" => Self::Compare(Comparison::SignedGreater, Element::Doubleword),
            "pcmpgtq" => Self::Compare(Comparison::SignedGreater, Element::Quadword),
            _ => return None,
        })
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
    pub(super) fn validate(&self) -> Result<(), String> {
        if self.index >= 16 || !(1..=15).contains(&self.length) {
            return Err("invalid HVF MMIO vector logic descriptor".into());
        }
        Ok(())
    }

    pub(super) fn effect(&self, left: &[u8; 32], data: &[u8]) -> Result<Effect, String> {
        let size = self.encoding.size();
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
    let size = encoding.size();
    let width = u32::from(size) * 8;
    if !read
        || !instruction.operands_complete
        || instruction.flow != Flow::Next
        || right.kind != OperandKind::Memory
        || right.width_bits != width
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
    validate_memory(context, memory, record, right, size)?;
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
