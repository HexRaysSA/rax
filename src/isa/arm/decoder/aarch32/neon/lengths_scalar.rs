//! Advanced SIMD three registers of different lengths (long, wide, and
//! narrow arithmetic and multiplies), and two registers and a scalar.

use super::super::*;

impl Aarch32Decoder {
    pub(crate) fn decode_neon_saturating_doubling_mulh_scalar(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 23) & 1) != 1
            || ((raw >> 6) & 1) != 1
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let mnemonic = match (raw >> 8) & 0xF {
            0b1100 => Mnemonic::VQDMULH,
            0b1101 => Mnemonic::VQRDMULH,
            _ => return None,
        };

        let size = (raw >> 20) & 0x3;
        let q = ((raw >> 24) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        if size == 0b00 || size == 0b11 || (q && ((vd | vn) & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_fp_multiply_scalar(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 23) & 1) != 1
            || !matches!((raw >> 20) & 0x3, 0b01 | 0b10)
            || ((raw >> 6) & 1) != 1
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let mnemonic = match (raw >> 8) & 0xF {
            0b0001 => Mnemonic::VMLA,
            0b0101 => Mnemonic::VMLS,
            0b1001 => Mnemonic::VMUL,
            _ => return None,
        };

        let q = ((raw >> 24) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        if q && ((vd | vn) & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_integer_absdiff_long(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001 || ((raw >> 23) & 1) != 1 || ((raw >> 4) & 1) != 0 {
            return None;
        }

        let mnemonic = match (raw >> 8) & 0xF {
            0b0111 => Mnemonic::VABDL,
            0b0101 => Mnemonic::VABAL,
            _ => return None,
        };

        let size = (raw >> 20) & 0x3;
        let vd = (raw >> 12) & 0xF;
        if size == 0b11 || (vd & 1) != 0 || ((raw >> 6) & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_long_wide_add_sub(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001 || ((raw >> 23) & 1) != 1 || ((raw >> 4) & 1) != 0 {
            return None;
        }

        let mnemonic = match (raw >> 8) & 0xF {
            0b0000 => Mnemonic::VADDL,
            0b0001 => Mnemonic::VADDW,
            0b0010 => Mnemonic::VSUBL,
            0b0011 => Mnemonic::VSUBW,
            _ => return None,
        };

        let size = (raw >> 20) & 0x3;
        let d = (((raw >> 22) & 1) << 4) | ((raw >> 12) & 0xF);
        let n = (((raw >> 7) & 1) << 4) | ((raw >> 16) & 0xF);
        let m = (((raw >> 5) & 1) << 4) | (raw & 0xF);
        let wide_n = matches!(mnemonic, Mnemonic::VADDW | Mnemonic::VSUBW);
        if size == 0b11 || (d & 1) != 0 || (wide_n && (n & 1) != 0) || d + 1 >= 32 || m >= 32 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        if !wide_n && n >= 32 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        if wide_n && n + 1 >= 32 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_narrow_add_sub(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 23) & 1) != 1
            || ((raw >> 6) & 1) != 0
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let round = ((raw >> 24) & 1) != 0;
        let mnemonic = match ((raw >> 8) & 0xF, round) {
            (0b0100, false) => Mnemonic::VADDHN,
            (0b0100, true) => Mnemonic::VRADDHN,
            (0b0110, false) => Mnemonic::VSUBHN,
            (0b0110, true) => Mnemonic::VRSUBHN,
            _ => return None,
        };

        let size = (raw >> 20) & 0x3;
        let n = (((raw >> 7) & 1) << 4) | ((raw >> 16) & 0xF);
        let m = (((raw >> 5) & 1) << 4) | (raw & 0xF);
        if size == 0b11 || (n & 1) != 0 || (m & 1) != 0 || n + 1 >= 32 || m + 1 >= 32 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_integer_multiply_scalar(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 23) & 1) != 1
            || ((raw >> 6) & 1) != 1
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let mnemonic = match (raw >> 8) & 0xF {
            0b0000 => Mnemonic::VMLA,
            0b0100 => Mnemonic::VMLS,
            0b1000 => Mnemonic::VMUL,
            _ => return None,
        };

        let size = (raw >> 20) & 0x3;
        let q = ((raw >> 24) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        if size == 0b00 || size == 0b11 || (q && ((vd | vn) & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_long_multiply_scalar(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 23) & 1) != 1
            || ((raw >> 6) & 1) != 1
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let mnemonic = match (raw >> 8) & 0xF {
            0b0010 => Mnemonic::VMLAL,
            0b0011 => Mnemonic::VQDMLAL,
            0b0110 => Mnemonic::VMLSL,
            0b0111 => Mnemonic::VQDMLSL,
            0b1010 => Mnemonic::VMULL,
            0b1011 => Mnemonic::VQDMULL,
            _ => return None,
        };

        let size = (raw >> 20) & 0x3;
        let d = (((raw >> 22) & 1) << 4) | ((raw >> 12) & 0xF);
        let saturating_doubling = matches!(
            mnemonic,
            Mnemonic::VQDMULL | Mnemonic::VQDMLAL | Mnemonic::VQDMLSL
        );
        if size == 0b00
            || size == 0b11
            || (saturating_doubling && ((raw >> 24) & 1) != 0)
            || (d & 1) != 0
            || d + 1 >= 32
        {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_polynomial_multiply_long(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 23) & 1) != 1
            || ((raw >> 20) & 0x3) != 0
            || ((raw >> 8) & 0xF) != 0b1110
            || ((raw >> 6) & 1) != 0
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let d = (((raw >> 22) & 1) << 4) | ((raw >> 12) & 0xF);
        if (d & 1) != 0 || d + 1 >= 32 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(
            Mnemonic::VMULL,
            ExecutionState::Aarch32,
            raw,
            4,
        ))
    }

    pub(crate) fn decode_neon_long_multiply(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 23) & 1) != 1
            || ((raw >> 6) & 1) != 0
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let mnemonic = match (raw >> 8) & 0xF {
            0b1000 => Mnemonic::VMLAL,
            0b1001 => Mnemonic::VQDMLAL,
            0b1010 => Mnemonic::VMLSL,
            0b1011 => Mnemonic::VQDMLSL,
            0b1100 => Mnemonic::VMULL,
            0b1101 => Mnemonic::VQDMULL,
            _ => return None,
        };

        let size = (raw >> 20) & 0x3;
        let d = (((raw >> 22) & 1) << 4) | ((raw >> 12) & 0xF);
        let n = (((raw >> 7) & 1) << 4) | ((raw >> 16) & 0xF);
        let m = (((raw >> 5) & 1) << 4) | (raw & 0xF);
        let saturating_doubling = matches!(
            mnemonic,
            Mnemonic::VQDMULL | Mnemonic::VQDMLAL | Mnemonic::VQDMLSL
        );
        if size == 0b11
            || (saturating_doubling && size == 0b00)
            || (d & 1) != 0
            || d + 1 >= 32
            || n >= 32
            || m >= 32
        {
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
