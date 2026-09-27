//! Advanced SIMD three registers of the same length: integer, polynomial,
//! and floating-point arithmetic, comparisons, shifts by register, logical
//! operations, and the `VFMAL`/`VFMSL` long multiply-accumulates.

use super::super::*;

impl Aarch32Decoder {
    pub(crate) fn decode_neon_saturating_add_sub(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001 || ((raw >> 23) & 1) != 0 || ((raw >> 4) & 1) != 1 {
            return None;
        }

        let mnemonic = match (raw >> 8) & 0xF {
            0b0000 => Mnemonic::VQADD,
            0b0010 => Mnemonic::VQSUB,
            _ => return None,
        };

        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if q && ((vd | vn | vm) & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_saturating_doubling_mulh(raw: u32) -> Option<DecodedInsn> {
        if ((raw >> 23) & 1) != 0 || ((raw >> 8) & 0xF) != 0b1011 || ((raw >> 4) & 1) != 0 {
            return None;
        }

        let mnemonic = match (raw >> 24) & 0xFF {
            0xF2 => Mnemonic::VQDMULH,
            0xF3 => Mnemonic::VQRDMULH,
            _ => return None,
        };

        let size = (raw >> 20) & 0x3;
        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if size == 0b00 || size == 0b11 || (q && ((vd | vn | vm) & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_fp_minmax(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 24) != 0xF2
            || ((raw >> 23) & 1) != 0
            || ((raw >> 8) & 0xF) != 0b1111
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if q && ((vd | vn | vm) & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(
            if ((raw >> 21) & 1) == 0 {
                Mnemonic::VMAX
            } else {
                Mnemonic::VMIN
            },
            ExecutionState::Aarch32,
            raw,
            4,
        ))
    }

    pub(crate) fn decode_neon_fp_pairwise(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 24) & 1) != 1
            || ((raw >> 23) & 1) != 0
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let mnemonic = match (((raw >> 8) & 0xF), ((raw >> 21) & 1)) {
            (0b1101, 0) => Mnemonic::VPADD,
            (0b1111, 0) => Mnemonic::VPMAX,
            (0b1111, 1) => Mnemonic::VPMIN,
            _ => return None,
        };

        if ((raw >> 6) & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_fp_add_sub(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 24) & 1) != 0
            || ((raw >> 23) & 1) != 0
            || ((raw >> 8) & 0xF) != 0b1101
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let mnemonic = if ((raw >> 21) & 1) == 0 {
            Mnemonic::VADD
        } else {
            Mnemonic::VSUB
        };

        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if q && ((vd | vn | vm) & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_fp_absdiff(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 24) != 0xF3
            || ((raw >> 23) & 1) != 0
            || ((raw >> 21) & 1) != 1
            || ((raw >> 8) & 0xF) != 0b1101
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if q && ((vd | vn | vm) & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(
            Mnemonic::VABD,
            ExecutionState::Aarch32,
            raw,
            4,
        ))
    }

    pub(crate) fn decode_neon_fp_fma(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 24) & 1) != 0
            || ((raw >> 23) & 1) != 0
            || ((raw >> 20) & 1) != 0
            || ((raw >> 8) & 0xF) != 0b1100
            || ((raw >> 4) & 1) != 1
        {
            return None;
        }

        let mnemonic = if ((raw >> 21) & 1) == 0 {
            Mnemonic::VFMA
        } else {
            Mnemonic::VFMS
        };

        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if q && ((vd | vn | vm) & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_fp_multiply(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 23) & 1) != 0
            || ((raw >> 8) & 0xF) != 0b1101
            || ((raw >> 4) & 1) != 1
        {
            return None;
        }

        let mnemonic = match (((raw >> 24) & 1) != 0, ((raw >> 21) & 1) != 0) {
            (true, false) => Mnemonic::VMUL,
            (false, false) => Mnemonic::VMLA,
            (false, true) => Mnemonic::VMLS,
            _ => return None,
        };

        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if q && ((vd | vn | vm) & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_fp16_fused_multiply_long(raw: u32) -> Option<DecodedInsn> {
        let vector = (raw >> 24) == 0xFC
            && ((raw >> 21) & 1) == 1
            && ((raw >> 20) & 1) == 0
            && ((raw >> 8) & 0xF) == 0b1000
            && ((raw >> 4) & 1) == 1;
        let indexed = (raw >> 24) == 0xFE
            && ((raw >> 23) & 1) == 0
            && ((raw >> 21) & 1) == 0
            && ((raw >> 8) & 0xF) == 0b1000
            && ((raw >> 4) & 1) == 1;
        if !vector && !indexed {
            return None;
        }

        let subtract = if vector {
            ((raw >> 23) & 1) != 0
        } else {
            ((raw >> 20) & 1) != 0
        };
        let mnemonic = if subtract {
            Mnemonic::VFMLS
        } else {
            Mnemonic::VFMAL
        };

        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
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

    pub(crate) fn decode_neon_integer_absdiff_accum(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001 || ((raw >> 23) & 1) != 0 || ((raw >> 8) & 0xF) != 0b0111 {
            return None;
        }

        let mnemonic = if ((raw >> 4) & 1) == 0 {
            Mnemonic::VABD
        } else {
            Mnemonic::VABA
        };

        let size = (raw >> 20) & 0x3;
        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if size == 0b11 || (q && ((vd | vn | vm) & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_integer_minmax(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001 || ((raw >> 23) & 1) != 0 || ((raw >> 8) & 0xF) != 0b0110 {
            return None;
        }

        let mnemonic = if ((raw >> 4) & 1) == 0 {
            Mnemonic::VMAX
        } else {
            Mnemonic::VMIN
        };

        let size = (raw >> 20) & 0x3;
        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if size == 0b11 || (q && ((vd | vn | vm) & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_integer_compare(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001 || ((raw >> 23) & 1) != 0 {
            return None;
        }

        let op8 = (raw >> 8) & 0xF;
        let bit4 = (raw >> 4) & 1;
        let bit24 = (raw >> 24) & 1;
        let mnemonic = match (op8, bit4, bit24) {
            (0b1000, 1, 0) => Mnemonic::VTST,
            (0b1000, 1, 1) => Mnemonic::VCEQ,
            (0b0011, 0, _) => Mnemonic::VCGT,
            (0b0011, 1, _) => Mnemonic::VCGE,
            _ => return None,
        };

        let size = (raw >> 20) & 0x3;
        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if size == 0b11 || (q && ((vd | vn | vm) & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_fp_compare(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001 || ((raw >> 23) & 1) != 0 || ((raw >> 8) & 0xF) != 0b1110 {
            return None;
        }

        let bit24 = (raw >> 24) & 1;
        let bit21 = (raw >> 21) & 1;
        let bit20 = (raw >> 20) & 1;
        let absolute = ((raw >> 4) & 1) != 0;
        let mnemonic = match (absolute, bit24, bit21, bit20) {
            (false, 0, 0, 0 | 1) => Mnemonic::VCEQ,
            (false, 1, 0, 0 | 1) => Mnemonic::VCGE,
            (false, 1, 1, 0 | 1) => Mnemonic::VCGT,
            (true, 1, 0, 0 | 1) => Mnemonic::VACGE,
            (true, 1, 1, 0 | 1) => Mnemonic::VACGT,
            _ => return None,
        };

        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if q && ((vd | vn | vm) & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_recip_step(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 24) & 1) != 0
            || ((raw >> 23) & 1) != 0
            || ((raw >> 8) & 0xF) != 0b1111
            || ((raw >> 4) & 1) != 1
        {
            return None;
        }

        let mnemonic = if ((raw >> 21) & 1) == 0 {
            Mnemonic::VRECPS
        } else {
            Mnemonic::VRSQRTS
        };

        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if q && ((vd | vn | vm) & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_halving_add_sub(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001 || ((raw >> 23) & 1) != 0 || ((raw >> 4) & 1) != 0 {
            return None;
        }

        let mnemonic = match (raw >> 8) & 0xF {
            0b0000 => Mnemonic::VHADD,
            0b0001 => Mnemonic::VRHADD,
            0b0010 => Mnemonic::VHSUB,
            _ => return None,
        };

        let size = (raw >> 20) & 0x3;
        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if size == 0b11 || (q && ((vd | vn | vm) & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_pairwise_integer(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001 || ((raw >> 23) & 1) != 0 {
            return None;
        }

        let mnemonic = match ((raw >> 8) & 0xF, (raw >> 4) & 1) {
            (0b1010, 0) => Mnemonic::VPMAX,
            (0b1010, 1) => Mnemonic::VPMIN,
            (0b1011, 1) => Mnemonic::VPADD,
            _ => return None,
        };

        let size = (raw >> 20) & 0x3;
        if size == 0b11 || ((raw >> 6) & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_integer_multiply(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001 || ((raw >> 23) & 1) != 0 || ((raw >> 8) & 0xF) != 0b1001 {
            return None;
        }

        let accumulate = ((raw >> 4) & 1) == 0;
        let bit24 = ((raw >> 24) & 1) != 0;
        let mnemonic = match (accumulate, bit24) {
            (true, false) => Mnemonic::VMLA,
            (true, true) => Mnemonic::VMLS,
            (false, false) => Mnemonic::VMUL,
            (false, true) => return None,
        };

        let size = (raw >> 20) & 0x3;
        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if size == 0b11 || (q && ((vd | vn | vm) & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_polynomial_multiply(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 24) & 1) != 1
            || ((raw >> 23) & 1) != 0
            || ((raw >> 20) & 0x3) != 0
            || ((raw >> 8) & 0xF) != 0b1001
            || ((raw >> 4) & 1) != 1
        {
            return None;
        }

        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if q && ((vd | vn | vm) & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(
            Mnemonic::VMUL,
            ExecutionState::Aarch32,
            raw,
            4,
        ))
    }

    pub(crate) fn decode_neon_shift_register(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001 || ((raw >> 23) & 1) != 0 {
            return None;
        }

        let saturating = ((raw >> 4) & 1) != 0;
        let mnemonic = match ((raw >> 8) & 0xF, saturating) {
            (0b0100, false) => Mnemonic::VSHL,
            (0b0101, false) => Mnemonic::VRSHL,
            (0b0100, true) => Mnemonic::VQSHL,
            (0b0101, true) => Mnemonic::VQRSHL,
            _ => return None,
        };

        let size = (raw >> 20) & 0x3;
        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if size == 0b11 || (q && ((vd | vn | vm) & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_integer_add_sub(raw: u32) -> Option<DecodedInsn> {
        if ((raw >> 23) & 1) != 0 || ((raw >> 8) & 0xF) != 0b1000 || ((raw >> 4) & 1) != 0 {
            return None;
        }

        let mnemonic = match (raw >> 24) & 0xFF {
            0xF2 => Mnemonic::VADD,
            0xF3 => Mnemonic::VSUB,
            _ => return None,
        };

        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if q && ((vd | vn | vm) & 1) != 0 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_logical_register(raw: u32) -> Option<DecodedInsn> {
        if ((raw >> 23) & 1) != 0 || ((raw >> 8) & 0xF) != 0b0001 || ((raw >> 4) & 1) != 1 {
            return None;
        }

        let opcode = (raw >> 20) & 0x3;
        let mnemonic = match ((raw >> 24) & 0xFF, opcode) {
            (0xF2, 0b00) => Mnemonic::VAND,
            (0xF2, 0b01) => Mnemonic::VBIC,
            (0xF2, 0b10) => Mnemonic::VORR,
            (0xF2, 0b11) => Mnemonic::VORN,
            (0xF3, 0b00) => Mnemonic::VEOR,
            (0xF3, 0b01) => Mnemonic::VBSL,
            (0xF3, 0b10) => Mnemonic::VBIT,
            (0xF3, 0b11) => Mnemonic::VBIF,
            _ => return None,
        };

        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        if q && ((vd | vn | vm) & 1) != 0 {
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
