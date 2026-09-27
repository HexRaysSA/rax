//! Advanced SIMD two registers and a shift amount (right shifts, narrowing
//! shifts, `VMOVL`, and fixed-point conversions), and one register and a
//! modified immediate.

use super::super::*;

impl Aarch32Decoder {
    pub(crate) fn decode_neon_fp_fixed_convert(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 23) & 1) != 1
            || ((raw >> 8) & 0xE) != 0b1110
            || ((raw >> 7) & 1) != 0
            || ((raw >> 4) & 1) != 1
        {
            return None;
        }

        let imm6 = (raw >> 16) & 0x3F;
        if imm6 < 32 {
            return None;
        }

        let unsigned = ((raw >> 24) & 1) != 0;
        let mnemonic = match (((raw >> 8) & 1) != 0, unsigned) {
            (false, false) => Mnemonic::VCVT_F32_S32_FIXED,
            (false, true) => Mnemonic::VCVT_F32_U32_FIXED,
            (true, false) => Mnemonic::VCVT_S32_F32_FIXED,
            (true, true) => Mnemonic::VCVT_U32_F32_FIXED,
        };

        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vm = raw & 0xF;
        if q && ((vd | vm) & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_modified_immediate(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 23) & 1) != 1
            || ((raw >> 7) & 1) != 0
            || ((raw >> 4) & 1) != 1
        {
            return None;
        }

        let cmode = (raw >> 8) & 0xF;
        let op = ((raw >> 5) & 1) != 0;
        let mnemonic = match (cmode, op) {
            (0b1111, false) => Mnemonic::VMOV,
            (0b1111, true) => return None,
            (0b1110, _) => Mnemonic::VMOV,
            (0b1100 | 0b1101, false) => Mnemonic::VMOV,
            (0b1100 | 0b1101, true) => Mnemonic::VMVN,
            (cmode, false) if (cmode & 1) == 0 => Mnemonic::VMOV,
            (cmode, false) if (cmode & 1) != 0 => Mnemonic::VORR,
            (cmode, true) if (cmode & 1) == 0 => Mnemonic::VMVN,
            (cmode, true) if (cmode & 1) != 0 => Mnemonic::VBIC,
            _ => return None,
        };

        let q = ((raw >> 6) & 1) != 0;
        let vd = ((raw >> 22) & 1) << 4 | ((raw >> 12) & 0xF);
        if q && (vd & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_shift_right_immediate(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001 || ((raw >> 23) & 1) != 1 || ((raw >> 4) & 1) != 1 {
            return None;
        }

        let mnemonic = match (raw >> 8) & 0xF {
            0b0000 => Mnemonic::VSHR,
            0b0001 => Mnemonic::VSRA,
            0b0010 => Mnemonic::VRSHR,
            0b0011 => Mnemonic::VRSRA,
            0b0100 => Mnemonic::VSRI,
            0b0101 if ((raw >> 24) & 1) == 0 => Mnemonic::VSHL,
            0b0101 => Mnemonic::VSLI,
            0b0110 if ((raw >> 24) & 1) != 0 => Mnemonic::VQSHLU,
            0b0111 => Mnemonic::VQSHL,
            _ => return None,
        };

        let imm = (raw >> 16) & 0x3F;
        let valid_imm = (8..64).contains(&imm);
        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vm = raw & 0xF;
        if !valid_imm {
            return None;
        }
        if q && ((vd | vm) & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_widen_move(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 23) & 1) != 1
            || ((raw >> 8) & 0xF) != 0b1010
            || ((raw >> 4) & 1) != 1
        {
            return None;
        }

        let imm = (raw >> 16) & 0x3F;
        let valid_imm = matches!(imm, 8 | 16 | 32);
        let d = (((raw >> 22) & 1) << 4) | ((raw >> 12) & 0xF);
        let m = (((raw >> 5) & 1) << 4) | (raw & 0xF);
        if !valid_imm || (d & 1) != 0 || d + 1 >= 32 || m >= 32 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(
            Mnemonic::VMOVL,
            ExecutionState::Aarch32,
            raw,
            4,
        ))
    }

    pub(crate) fn decode_neon_shift_narrow_immediate(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001 || ((raw >> 23) & 1) != 1 || ((raw >> 4) & 1) != 1 {
            return None;
        }

        let unsigned = ((raw >> 24) & 1) != 0;
        let rounding = ((raw >> 6) & 1) != 0;
        let mnemonic = match ((raw >> 8) & 0xF, unsigned, rounding) {
            (0b1000, false, false) => Mnemonic::VSHRN,
            (0b1000, false, true) => Mnemonic::VRSHRN,
            (0b1000, true, false) => Mnemonic::VQSHRUN,
            (0b1000, true, true) => Mnemonic::VQRSHRUN,
            (0b1001, false, false) => Mnemonic::VQSHRN,
            (0b1001, false, true) => Mnemonic::VQRSHRN,
            (0b1001, true, false) => Mnemonic::VQSHRN,
            (0b1001, true, true) => Mnemonic::VQRSHRN,
            _ => return None,
        };
        let imm = (raw >> 16) & 0x3F;
        let valid_imm = (8..64).contains(&imm);
        let m = (((raw >> 5) & 1) << 4) | (raw & 0xF);
        if !valid_imm {
            return None;
        }
        if (m & 1) != 0 || m + 1 >= 32 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }
}
