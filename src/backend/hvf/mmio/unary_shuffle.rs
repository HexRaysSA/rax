//! Packed immediate shuffles whose only data operand is the MMIO reply.
use super::vector_logic::{Encoding, register, shuffle_control};
use super::*;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Shuffle {
    Doublewords,
    HighWords,
    LowWords,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Input {
    pub(super) index: u8,
    pub(crate) encoding: Encoding,
    length: u64,
    shuffle: Shuffle,
    control: u8,
}

impl Input {
    pub(super) fn validate(&self) -> Result<(), String> {
        if self.index >= 16 || !(1..=15).contains(&self.length) {
            return Err("invalid HVF MMIO packed shuffle descriptor".into());
        }
        Ok(())
    }

    fn result<const N: usize>(&self, data: &[u8]) -> [u8; N] {
        let (first, width) = match self.shuffle {
            Shuffle::Doublewords => (0, 4),
            Shuffle::HighWords => (8, 2),
            Shuffle::LowWords => (0, 2),
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
                "HVF MMIO packed shuffle expected {size} bytes, received {}",
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
    let shuffle = match mnemonic.strip_prefix('v').unwrap_or(mnemonic) {
        "pshufd" => Shuffle::Doublewords,
        "pshufhw" => Shuffle::HighWords,
        "pshuflw" => Shuffle::LowWords,
        _ => return Ok(None),
    };
    let [target, device, control] = instruction.operands.as_slice() else {
        return Err("wrong operands for packed shuffle MMIO".into());
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
        return Err("packed shuffle MMIO requires a complete device read operand".into());
    }
    let index = register(target, width, false, true).ok_or("invalid packed shuffle destination")?;
    let control = shuffle_control(control)?;
    if encoding == Encoding::Legacy && record.linear & 15 != 0 {
        return Err("misaligned legacy packed shuffle MMIO input".into());
    }
    validate_memory(context, memory, record, device, size)?;
    let length = u64::from(instruction.size);
    let input = Input {
        index,
        encoding,
        length,
        shuffle,
        control,
    };
    input.validate()?;
    Ok(Some(Plan {
        physical: record.physical,
        linear: record.linear,
        length,
        action: Action::UnaryShuffle(input),
    }))
}
