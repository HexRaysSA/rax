//! Packed bit tests read one vector from a device and publish only status flags.
use super::vector_logic::{Encoding, register};
use super::*;
use crate::isa::x86_64::flags::bits;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum ComparedBits {
    All,
    SingleSign,
    DoubleSign,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Input {
    pub(crate) encoding: Encoding,
    pub(crate) length: u64,
    compared: ComparedBits,
    flags: u64,
}

impl Input {
    pub(super) fn validate(&self) -> Result<(), String> {
        if !(1..=15).contains(&self.length)
            || self.encoding == Encoding::Legacy && self.compared != ComparedBits::All
        {
            return Err("invalid HVF MMIO packed bit-test descriptor".into());
        }
        Ok(())
    }

    pub(super) fn effect(&self, left: &[u8; 32], right: &[u8]) -> Result<Effect, String> {
        let size = usize::from(self.encoding.size());
        if right.len() != size {
            return Err(format!(
                "HVF MMIO packed bit test expected {size} bytes, received {}",
                right.len()
            ));
        }
        let (stride, mask) = match self.compared {
            ComparedBits::All => (1, 0xff),
            ComparedBits::SingleSign => (4, 0x80),
            ComparedBits::DoubleSign => (8, 0x80),
        };
        let mut overlap = 0;
        let mut missing = 0;
        for byte in (stride - 1..size).step_by(stride) {
            overlap |= left[byte] & right[byte] & mask;
            missing |= !left[byte] & right[byte] & mask;
        }
        let status = bits::CF | bits::PF | bits::AF | bits::ZF | bits::SF | bits::OF;
        let mut flags = self.flags & !status;
        if overlap == 0 {
            flags |= bits::ZF;
        }
        if missing == 0 {
            flags |= bits::CF;
        }
        Ok(Effect::Scalar(([None; 2], Some(flags), self.length)))
    }
}

pub(super) fn prepare<M: PhysicalMemory>(
    context: &Context,
    memory: &mut M,
    record: ExitRecord,
    instruction: &Instruction,
    read: bool,
) -> Result<Option<Plan>, String> {
    let compared = match instruction.mnemonic.as_str() {
        "ptest" | "vptest" => ComparedBits::All,
        "vtestps" => ComparedBits::SingleSign,
        "vtestpd" => ComparedBits::DoubleSign,
        _ => return Ok(None),
    };
    let [left, right] = instruction.operands.as_slice() else {
        return Err("wrong operands for packed bit-test MMIO".into());
    };
    let encoding = if instruction.mnemonic == "ptest" {
        Encoding::Legacy
    } else if left.width_bits == 256 {
        Encoding::Vex256
    } else {
        Encoding::Vex128
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
        return Err("packed bit-test MMIO requires a complete device read operand".into());
    }
    let source = register(left, width, true, false).ok_or("invalid packed bit-test source")?;
    if encoding == Encoding::Legacy && record.linear & 15 != 0 {
        return Err("misaligned legacy packed bit-test MMIO input".into());
    }
    validate_memory(context, memory, record, right, size)?;
    let length = u64::from(instruction.size);
    let input = Input {
        encoding,
        length,
        compared,
        flags: context.rflags,
    };
    input.validate()?;
    Ok(Some(Plan {
        physical: record.physical,
        linear: record.linear,
        length,
        action: Action::VectorBitTest { input, source },
    }))
}
