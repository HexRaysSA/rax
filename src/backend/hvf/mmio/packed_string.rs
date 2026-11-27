//! SSE4.2 packed-string comparisons with one device memory source.
use super::vector_logic::{Encoding, register};
use super::*;
use crate::isa::x86_64::flags::bits;

pub(crate) const BYTES: u8 = 16;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Input {
    pub(crate) encoding: Encoding,
    length: u64,
    control: u8,
    mask: bool,
    explicit_lengths: Option<[i64; 2]>,
    flags: u64,
}

impl Input {
    pub(super) fn validate(&self) -> Result<(), String> {
        if !(6..=15).contains(&self.length) || self.encoding == Encoding::Vex256 {
            return Err("invalid HVF MMIO packed-string descriptor".into());
        }
        Ok(())
    }

    pub(super) fn effect(&self, left: &[u8; 16], data: &[u8]) -> Result<Effect, String> {
        let right: [u8; 16] = data.try_into().map_err(|_| {
            format!(
                "HVF MMIO packed string expected {BYTES} bytes, received {}",
                data.len()
            )
        })?;
        let [left_lo, left_hi] = qwords(left);
        let [right_lo, right_hi] = qwords(&right);
        let [len1, len2] = self.explicit_lengths.unwrap_or_else(|| {
            [
                pcmpxstrx::find_null_terminator(left_lo, left_hi, self.control),
                pcmpxstrx::find_null_terminator(right_lo, right_hi, self.control),
            ]
        });
        let result = pcmpxstrx::evaluate(
            left_lo,
            left_hi,
            right_lo,
            right_hi,
            len1,
            len2,
            self.control,
            self.mask,
        );
        let status = bits::CF | bits::PF | bits::AF | bits::ZF | bits::SF | bits::OF;
        let flags = (self.flags & !status)
            | if result.cf { bits::CF } else { 0 }
            | if result.zf { bits::ZF } else { 0 }
            | if result.sf { bits::SF } else { 0 }
            | if result.of { bits::OF } else { 0 };
        Ok(if self.mask {
            Effect::XmmAndFlags {
                value: result.value.to_le_bytes(),
                zero_upper: self.encoding == Encoding::Vex128,
                flags,
                length: self.length,
            }
        } else {
            Effect::Scalar((
                [Some((1, result.value as u64)), None],
                Some(flags),
                self.length,
            ))
        })
    }
}

fn qwords(bytes: &[u8; 16]) -> [u64; 2] {
    [
        u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..].try_into().unwrap()),
    ]
}

pub(super) fn prepare<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
    record: ExitRecord,
    instruction: &Instruction,
    read: bool,
) -> Result<Option<Plan>, String> {
    let name = instruction.mnemonic.as_str();
    let encoding = if name.starts_with('v') {
        Encoding::Vex128
    } else {
        Encoding::Legacy
    };
    let (explicit, mask) = match name.strip_prefix('v').unwrap_or(name) {
        "pcmpestrm" => (true, true),
        "pcmpestri" => (true, false),
        "pcmpistrm" => (false, true),
        "pcmpistri" => (false, false),
        _ => return Ok(None),
    };
    let [left, right, control, _destination, lengths @ ..] = instruction.operands.as_slice() else {
        return Err("wrong operands for packed-string MMIO".into());
    };
    if !read
        || !instruction.operands_complete
        || instruction.flow != Flow::Next
        || right.kind != OperandKind::Memory
        || right.width_bits != u32::from(BYTES) * 8
        || !right.read
        || right.write
        || right.conditional
        || control.kind != OperandKind::Immediate
        || control.width_bits != 8
    {
        return Err("packed-string MMIO requires one complete device read operand".into());
    }
    let source = register(left, 128, true, false).ok_or("invalid packed-string source")?;
    let [rax, _, rdx, ..] = context.registers;
    let explicit_lengths = match (explicit, lengths) {
        (false, []) => None,
        (true, [first, second]) => Some(match (first.reg.as_str(), second.reg.as_str()) {
            ("eax", "edx") => [i64::from(rax as i32), i64::from(rdx as i32)],
            ("rax", "rdx") => [rax as i64, rdx as i64],
            _ => return Err("invalid packed-string length operands".into()),
        }),
        _ => return Err("missing or unexpected packed-string length operands".into()),
    };
    validate_memory(context, memory, record, right, BYTES)?;
    let length = u64::from(instruction.size);
    let input = Input {
        encoding,
        length,
        control: control.value as u8,
        mask,
        explicit_lengths,
        flags: context.rflags,
    };
    input.validate()?;
    Ok(Some(Plan {
        physical: record.physical,
        linear: record.linear,
        length,
        action: Action::PackedString { input, source },
    }))
}
