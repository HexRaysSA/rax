//! Instruction length, format and opcode recognition, with a decode cache.

use super::generated::opcodes::{self, Opcode};

/// Instruction formats of the core. Each has a single slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    X24,
    X16a,
    X16b,
    F32,
}

impl Format {
    /// The format of the instruction whose first byte is `byte0`.
    #[inline]
    pub fn of(byte0: u32) -> Format {
        if byte0 & 0x8 == 0 {
            Format::X24
        } else if byte0 & 0xc == 0x8 {
            Format::X16a
        } else if byte0 & 0xe == 0xc {
            Format::X16b
        } else {
            Format::F32
        }
    }

    #[inline]
    pub fn len(self) -> u32 {
        match self {
            Format::X24 => 3,
            Format::X16a | Format::X16b => 2,
            Format::F32 => 4,
        }
    }
}

/// A decoded instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub op: Option<Opcode>,
    pub format: Format,
    /// The instruction word, masked to its length.
    pub word: u32,
    /// Highest group of four AR registers (window-relative) that the operands name.
    pub ar_group: u8,
}

impl Insn {
    #[inline]
    pub fn len(&self) -> u32 {
        self.format.len()
    }
}

/// Decodes the instruction in the low bytes of `word` (little-endian fetch of four bytes).
pub fn decode(word: u32) -> Insn {
    let format = Format::of(word);
    let (op, word, mask) = match format {
        Format::X24 => {
            let w = word & 0x00ff_ffff;
            let op = opcodes::decode_x24(w);
            (op, w, op.map_or(0, |op| opcodes::ar_mask_x24(op, w)))
        }
        Format::X16a => {
            let w = word & 0xffff;
            let op = opcodes::decode_x16a(w);
            (op, w, op.map_or(0, |op| opcodes::ar_mask_x16a(op, w)))
        }
        Format::X16b => {
            let w = word & 0xffff;
            let op = opcodes::decode_x16b(w);
            (op, w, op.map_or(0, |op| opcodes::ar_mask_x16b(op, w)))
        }
        Format::F32 => {
            let slot = opcodes::slot_format_32(word);
            let op = opcodes::decode_f32(slot);
            (op, word, op.map_or(0, |op| opcodes::ar_mask_f32(op, slot)))
        }
    };
    let ar_group = if mask == 0 {
        0
    } else {
        ((31 - mask.leading_zeros()) / 4) as u8
    };
    Insn {
        op,
        format,
        word,
        ar_group,
    }
}

const CACHE_BITS: u32 = 15;
const NO_OPCODE: u16 = u16::MAX;

#[derive(Clone, Copy)]
struct Entry {
    word: u32,
    op: u16,
    format: u8,
    ar_group: u8,
}

/// Direct-mapped cache of decoded instructions, indexed by address and checked
/// against the instruction word (so it stays valid when code changes).
pub struct DecodeCache {
    entries: Box<[Entry]>,
}

impl Default for DecodeCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DecodeCache {
    pub fn new() -> Self {
        // An entry whose format byte is 0xff never matches.
        let empty = Entry {
            word: 0,
            op: NO_OPCODE,
            format: 0xff,
            ar_group: 0,
        };
        DecodeCache {
            entries: vec![empty; 1 << CACHE_BITS].into_boxed_slice(),
        }
    }

    #[inline]
    pub fn decode(&mut self, pc: u32, fetched: u32) -> Insn {
        let format = Format::of(fetched);
        let word = match format {
            Format::X24 => fetched & 0x00ff_ffff,
            Format::X16a | Format::X16b => fetched & 0xffff,
            Format::F32 => fetched,
        };
        // Instructions are at least two bytes apart.
        let index = (pc >> 1) as usize & ((1 << CACHE_BITS) - 1);
        let e = self.entries[index];
        if e.word == word && e.format == format as u8 {
            return Insn {
                op: if e.op == NO_OPCODE {
                    None
                } else {
                    Opcode::from_index(e.op as usize)
                },
                format,
                word,
                ar_group: e.ar_group,
            };
        }
        let insn = decode(fetched);
        self.entries[index] = Entry {
            word,
            op: insn.op.map_or(NO_OPCODE, |op| op as u16),
            format: format as u8,
            ar_group: insn.ar_group,
        };
        insn
    }
}
