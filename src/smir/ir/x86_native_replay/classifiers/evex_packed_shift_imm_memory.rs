//! Exact EVEX immediate packed-shift memory encodings.

use super::X86InstructionBytes;
use super::evex_memory::{memory_operand_end, vector_legacy_prefix_len};
use crate::smir::ir::types::{ShiftOp, VecElementType, VecWidth};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum X86EvexPackedShiftImmMemoryReplay {
    /// An unconditional full-vector helper load, including masked word shifts
    /// whose E4NF.nb exception class does not suppress memory faults.
    Vector {
        scratch: u8,
        register_instruction: X86InstructionBytes,
    },
    Broadcast {
        stack_instruction: X86InstructionBytes,
    },
    MaskedVector {
        stack_instruction: X86InstructionBytes,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86EvexPackedShiftImmMemoryEncoding {
    pub(crate) width: VecWidth,
    pub(crate) elem: VecElementType,
    pub(crate) destination: u8,
    pub(crate) writemask: Option<u8>,
    pub(crate) zeroing: bool,
    pub(crate) shift: ShiftOp,
    pub(crate) immediate: u8,
    pub(crate) byte_lane: bool,
    pub(crate) replay: X86EvexPackedShiftImmMemoryReplay,
    pub(crate) needs_avx512vl: bool,
}

impl X86InstructionBytes {
    /// Intel SDM Vol. 2, PSLLW/PSLLD/PSLLQ, PSRAW/PSRAD/PSRAQ,
    /// PSRLW/PSRLD/PSRLQ, PSLLDQ and PSRLDQ: EVEX.66.0F 71–73 /n ib.
    /// The destination uses vvvv/V', not ModR/M.reg. Word and byte-lane
    /// shifts are WIG and E4NF.nb; doubleword/quadword shifts are E4 and
    /// permit scalar memory broadcast. Address extensions stay in the helper.
    pub(crate) fn evex_packed_shift_imm_memory_encoding(
        &self,
    ) -> Option<X86EvexPackedShiftImmMemoryEncoding> {
        let bytes = self.as_slice();
        let start = vector_legacy_prefix_len(bytes);
        if bytes.get(start) != Some(&0x62) {
            return None;
        }
        let p0 = *bytes.get(start + 1)?;
        let p1 = *bytes.get(start + 2)?;
        let p2 = *bytes.get(start + 3)?;
        let opcode = *bytes.get(start + 4)?;
        let modrm = *bytes.get(start + 5)?;
        let end = memory_operand_end(bytes, start + 5)?;
        let immediate = *bytes.get(end)?;
        if p0 & 7 != 1
            || p1 & 3 != 1
            || modrm >> 6 == 3
            || p2 & 0x60 == 0x60
            || end + 1 != bytes.len()
        {
            return None;
        }
        let group = (modrm >> 3) & 7;
        let w = p1 & 0x80 != 0;
        let (elem, shift, byte_lane) = match (opcode, group, w) {
            (0x71, 2, _) => (VecElementType::I16, ShiftOp::Lsr, false),
            (0x71, 4, _) => (VecElementType::I16, ShiftOp::Asr, false),
            (0x71, 6, _) => (VecElementType::I16, ShiftOp::Lsl, false),
            (0x72, 2, false) => (VecElementType::I32, ShiftOp::Lsr, false),
            (0x72, 4, false) => (VecElementType::I32, ShiftOp::Asr, false),
            (0x72, 6, false) => (VecElementType::I32, ShiftOp::Lsl, false),
            (0x72, 4, true) => (VecElementType::I64, ShiftOp::Asr, false),
            (0x73, 2, true) => (VecElementType::I64, ShiftOp::Lsr, false),
            (0x73, 6, true) => (VecElementType::I64, ShiftOp::Lsl, false),
            (0x73, 3, _) => (VecElementType::I8, ShiftOp::Lsr, true),
            (0x73, 7, _) => (VecElementType::I8, ShiftOp::Lsl, true),
            _ => return None,
        };
        let mask = p2 & 7;
        let zeroing = p2 & 0x80 != 0;
        let broadcast = p2 & 0x10 != 0;
        let e4nf = byte_lane || elem == VecElementType::I16;
        if (zeroing && mask == 0) || (byte_lane && mask != 0) || (e4nf && broadcast) {
            return None;
        }
        let width = match (p2 >> 5) & 3 {
            0 => VecWidth::V128,
            1 => VecWidth::V256,
            2 => VecWidth::V512,
            _ => return None,
        };
        let destination = ((!p1 >> 3) & 15) | (u8::from(p2 & 8 == 0) << 4);
        let stack_instruction = || {
            X86InstructionBytes::new(&[
                0x62,
                (p0 & 0x97) | 0x60,
                p1 | 4,
                p2,
                opcode,
                (modrm & 0x38) | 4,
                0x24,
                immediate,
            ])
            .expect("8-byte stack replay")
        };
        let replay = if broadcast {
            X86EvexPackedShiftImmMemoryReplay::Broadcast {
                stack_instruction: stack_instruction(),
            }
        } else if !e4nf && mask != 0 {
            X86EvexPackedShiftImmMemoryReplay::MaskedVector {
                stack_instruction: stack_instruction(),
            }
        } else {
            let scratch = if destination == 0 { 1 } else { 0 };
            let register_instruction = X86InstructionBytes::new(&[
                0x62,
                (p0 & 0x97) | 0x60,
                p1 | 4,
                p2,
                opcode,
                0xC0 | (modrm & 0x38) | scratch,
                immediate,
            ])
            .expect("7-byte register replay");
            // Revalidate the arithmetic/logical register form independently.
            // The existing classifier intentionally excludes PSLLDQ/PSRLDQ;
            // their WIG /3,/7, unmasked encoding is already checked above.
            if !byte_lane
                && register_instruction.evex_register_immediate_count_shift_needs_vl()
                    != Some(width != VecWidth::V512)
            {
                return None;
            }
            X86EvexPackedShiftImmMemoryReplay::Vector {
                scratch,
                register_instruction,
            }
        };
        Some(X86EvexPackedShiftImmMemoryEncoding {
            width,
            elem,
            destination,
            writemask: (mask != 0).then_some(mask),
            zeroing,
            shift,
            immediate,
            byte_lane,
            replay,
            needs_avx512vl: width != VecWidth::V512,
        })
    }
}
