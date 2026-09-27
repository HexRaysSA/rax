//! Advanced SIMD two-register miscellaneous operations (`VMVN`, `VREV`,
//! `VSWP`, comparisons with zero, reciprocal estimates, `VRINT`,
//! conversions, pairwise long adds, permutes, `VABS`/`VNEG` and their
//! saturating forms, counts, and narrowing moves), and `VEXT`,
//! `VTBL`/`VTBX`, and `VDUP` (scalar).

use super::super::*;

impl Aarch32Decoder {
    pub(crate) fn decode_neon_vext(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 23) != 0b111100101 || ((raw >> 20) & 0x3) != 0b11 || ((raw >> 4) & 1) != 0 {
            return None;
        }

        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vn = (raw >> 16) & 0xF;
        let vm = raw & 0xF;
        let imm4 = (raw >> 8) & 0xF;
        if (!q && imm4 > 7) || (q && ((vd | vn | vm) & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(
            Mnemonic::VEXT,
            ExecutionState::Aarch32,
            raw,
            4,
        ))
    }

    pub(crate) fn decode_neon_table_lookup(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 24) != 0xF3
            || ((raw >> 23) & 1) != 1
            || ((raw >> 20) & 0x3) != 0b11
            || ((raw >> 10) & 0x3) != 0b10
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let op = ((raw >> 6) & 1) != 0;
        let len = ((raw >> 8) & 0x3) as u8;
        let n = (((raw >> 7) & 1) as u8) << 4 | (((raw >> 16) & 0xF) as u8);
        if n + len + 1 > 32 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(
            if op { Mnemonic::VTBX } else { Mnemonic::VTBL },
            ExecutionState::Aarch32,
            raw,
            4,
        ))
    }

    pub(crate) fn decode_neon_vmvn_register(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 23) != 0b111100111
            || ((raw >> 20) & 0x3) != 0b11
            || ((raw >> 16) & 0x3) != 0
            || ((raw >> 11) & 1) != 0
            || ((raw >> 7) & 0xF) != 0b1011
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

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

        Some(DecodedInsn::new(
            Mnemonic::VMVN,
            ExecutionState::Aarch32,
            raw,
            4,
        ))
    }

    pub(crate) fn decode_neon_vrev_register(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 23) != 0b111100111
            || ((raw >> 20) & 0x3) != 0b11
            || ((raw >> 16) & 0x3) != 0
            || ((raw >> 11) & 1) != 0
            || ((raw >> 9) & 0x3) != 0
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let op = (raw >> 7) & 0x3;
        let size = (raw >> 18) & 0x3;
        let mnemonic = match op {
            0b00 => Mnemonic::VREV64,
            0b01 => Mnemonic::VREV32,
            0b10 => Mnemonic::VREV16,
            _ => Mnemonic::UNDEFINED,
        };

        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vm = raw & 0xF;
        if op + size >= 3 || (q && ((vd | vm) & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_vswp(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 23) != 0b111100111
            || ((raw >> 20) & 0x3) != 0b11
            || ((raw >> 18) & 0x3) != 0
            || ((raw >> 16) & 0x3) != 0b10
            || ((raw >> 11) & 1) != 0
            || ((raw >> 7) & 0xF) != 0
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

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

        Some(DecodedInsn::new(
            Mnemonic::VSWP,
            ExecutionState::Aarch32,
            raw,
            4,
        ))
    }

    pub(crate) fn decode_neon_compare_zero(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 23) != 0b111100111
            || ((raw >> 20) & 0x3) != 0b11
            || ((raw >> 16) & 0x3) != 0b01
            || !matches!((raw >> 10) & 0x3, 0 | 1)
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let mnemonic = match (raw >> 7) & 0x7 {
            0b000 => Mnemonic::VCGT,
            0b001 => Mnemonic::VCGE,
            0b010 => Mnemonic::VCEQ,
            0b011 => Mnemonic::VCLE,
            0b100 => Mnemonic::VCLT,
            _ => return None,
        };

        let size = (raw >> 18) & 0x3;
        let fp = ((raw >> 10) & 0x3) == 1;
        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vm = raw & 0xF;
        if size == 0b11 || (fp && size == 0b00) || (q && ((vd | vm) & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_recip_estimate(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 23) != 0b111100111
            || ((raw >> 20) & 0x3) != 0b11
            || ((raw >> 16) & 0x3) != 0b11
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let mnemonic = match (raw >> 7) & 0x1F {
            0b01000 | 0b01010 => Mnemonic::VRECPE,
            0b01001 | 0b01011 => Mnemonic::VRSQRTE,
            _ => return None,
        };

        let size = (raw >> 18) & 0x3;
        let fp = matches!((raw >> 7) & 0x1F, 0b01010 | 0b01011);
        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vm = raw & 0xF;
        if (!fp && size != 0b10)
            || (fp && !matches!(size, 0b01 | 0b10))
            || (q && ((vd | vm) & 1) != 0)
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

    pub(crate) fn decode_neon_vrint(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 24) != 0xF3
            || ((raw >> 23) & 1) != 1
            || ((raw >> 21) & 1) != 1
            || ((raw >> 20) & 1) != 1
            || ((raw >> 16) & 0x3) != 0b10
            || ((raw >> 10) & 0x3) != 0b01
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let size = (raw >> 18) & 0x3;
        let op = (raw >> 7) & 0x7;
        let mnemonic = match (op, size) {
            (0b000, 0b01) => Mnemonic::VRINTN_F16,
            (0b000, 0b10) => Mnemonic::VRINTN_F32,
            (0b010, 0b01) => Mnemonic::VRINTA_F16,
            (0b010, 0b10) => Mnemonic::VRINTA_F32,
            (0b101, 0b01) => Mnemonic::VRINTM_F16,
            (0b101, 0b10) => Mnemonic::VRINTM_F32,
            (0b111, 0b01) => Mnemonic::VRINTP_F16,
            (0b111, 0b10) => Mnemonic::VRINTP_F32,
            (0b001, 0b01) => Mnemonic::VRINTX_F16,
            (0b001, 0b10) => Mnemonic::VRINTX_F32,
            (0b011, 0b01) => Mnemonic::VRINTZ_F16,
            (0b011, 0b10) => Mnemonic::VRINTZ_F32,
            (0b000 | 0b001 | 0b010 | 0b011 | 0b101 | 0b111, 0b00 | 0b11) => Mnemonic::UNDEFINED,
            _ => return None,
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

    pub(crate) fn decode_neon_directed_convert(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 24) != 0xF3
            || ((raw >> 23) & 1) != 1
            || ((raw >> 21) & 1) != 1
            || ((raw >> 20) & 1) != 1
            || ((raw >> 16) & 0x3) != 0b11
            || ((raw >> 10) & 0x3) != 0
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let size = (raw >> 18) & 0x3;
        let unsigned = ((raw >> 7) & 1) != 0;
        let mnemonic = match ((raw >> 8) & 0x3, size, unsigned) {
            (0b00, 0b01, false) => Mnemonic::VCVTN_S32_F16,
            (0b00, 0b01, true) => Mnemonic::VCVTN_U32_F16,
            (0b00, 0b10, false) => Mnemonic::VCVTN_S32_F32,
            (0b00, 0b10, true) => Mnemonic::VCVTN_U32_F32,
            (0b01, 0b01, false) => Mnemonic::VCVTP_S32_F16,
            (0b01, 0b01, true) => Mnemonic::VCVTP_U32_F16,
            (0b01, 0b10, false) => Mnemonic::VCVTP_S32_F32,
            (0b01, 0b10, true) => Mnemonic::VCVTP_U32_F32,
            (0b10, 0b01, false) => Mnemonic::VCVTM_S32_F16,
            (0b10, 0b01, true) => Mnemonic::VCVTM_U32_F16,
            (0b10, 0b10, false) => Mnemonic::VCVTM_S32_F32,
            (0b10, 0b10, true) => Mnemonic::VCVTM_U32_F32,
            (0b11, 0b01, false) => Mnemonic::VCVT_S32_F16,
            (0b11, 0b01, true) => Mnemonic::VCVT_U32_F16,
            (0b11, 0b10, false) => Mnemonic::VCVT_S32_F32,
            (0b11, 0b10, true) => Mnemonic::VCVT_U32_F32,
            (_, 0b00 | 0b11, _) => Mnemonic::UNDEFINED,
            _ => return None,
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

    pub(crate) fn decode_neon_vdup_scalar(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 24) != 0xF3
            || ((raw >> 23) & 1) != 1
            || ((raw >> 20) & 0x3) != 0b11
            || ((raw >> 8) & 0xF) != 0b1100
            || ((raw >> 7) & 1) != 0
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let imm4 = (raw >> 16) & 0xF;
        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        if (imm4 & 0b0111) == 0 || (q && (vd & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(
            Mnemonic::VDUP,
            ExecutionState::Aarch32,
            raw,
            4,
        ))
    }

    pub(crate) fn decode_neon_fp_convert(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 24) & 1) != 1
            || ((raw >> 23) & 1) != 1
            || ((raw >> 21) & 0x7) != 0b101
            || ((raw >> 20) & 1) != 1
            || ((raw >> 16) & 0xF) != 0b1011
            || ((raw >> 8) & 0xE) != 0b0110
            || ((raw >> 5) & 1) != 0
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let unsigned = ((raw >> 7) & 1) != 0;
        let mnemonic = match (((raw >> 8) & 1) != 0, unsigned) {
            (false, false) => Mnemonic::VCVT_F32_S32,
            (false, true) => Mnemonic::VCVT_F32_U32,
            (true, false) => Mnemonic::VCVT_S32_F32,
            (true, true) => Mnemonic::VCVT_U32_F32,
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

    pub(crate) fn decode_neon_fp16_convert(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 25) != 0b1111001
            || ((raw >> 24) & 1) != 1
            || ((raw >> 23) & 1) != 1
            || ((raw >> 20) & 0x7) != 0b011
            || ((raw >> 16) & 0xF) != 0b0110
            || ((raw >> 7) & 1) != 0
            || ((raw >> 6) & 1) != 0
            || ((raw >> 5) & 1) != 0
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let mnemonic = match (raw >> 8) & 0xF {
            0b0110 => Mnemonic::VCVT_F16_F32,
            0b0111 => Mnemonic::VCVT_F32_F16,
            _ => return None,
        };

        let vd = (((raw >> 22) & 1) << 4) | ((raw >> 12) & 0xF);
        let vm = raw & 0xF;
        if (mnemonic == Mnemonic::VCVT_F16_F32 && (vm & 1) != 0)
            || (mnemonic == Mnemonic::VCVT_F32_F16 && (vd & 1) != 0)
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

    pub(crate) fn decode_neon_pairwise_add_long(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 23) != 0b111100111
            || ((raw >> 20) & 0x3) != 0b11
            || ((raw >> 16) & 0x3) != 0
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let mnemonic = match (raw >> 7) & 0x1E {
            0b00100 => Mnemonic::VPADDL,
            0b01100 => Mnemonic::VPADAL,
            _ => return None,
        };

        let size = (raw >> 18) & 0x3;
        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vm = raw & 0xF;
        if size == 0b11 || (q && ((vd | vm) & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_pairwise_permute(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 23) != 0b111100111
            || ((raw >> 20) & 0x3) != 0b11
            || ((raw >> 16) & 0x3) != 0b10
            || ((raw >> 11) & 1) != 0
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let size = (raw >> 18) & 0x3;
        let q = ((raw >> 6) & 1) != 0;
        let op = (raw >> 7) & 0xF;
        let mnemonic = match op {
            0b0001 => Mnemonic::VTRN,
            0b0010 if !q && size == 0b10 => Mnemonic::VTRN,
            0b0010 => Mnemonic::VUZP,
            0b0011 if !q && size == 0b10 => Mnemonic::VTRN,
            0b0011 => Mnemonic::VZIP,
            _ => return None,
        };

        let vd = (raw >> 12) & 0xF;
        let vm = raw & 0xF;
        if size == 0b11 || (q && ((vd | vm) & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_saturating_abs_neg(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 23) != 0b111100111
            || ((raw >> 20) & 0x3) != 0b11
            || ((raw >> 16) & 0x3) != 0
            || ((raw >> 11) & 1) != 0
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let mnemonic = match (raw >> 7) & 0xF {
            0b1110 => Mnemonic::VQABS,
            0b1111 => Mnemonic::VQNEG,
            _ => return None,
        };

        let size = (raw >> 18) & 0x3;
        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vm = raw & 0xF;
        if size == 0b11 || (q && ((vd | vm) & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_abs_neg(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 23) != 0b111100111
            || ((raw >> 20) & 0x3) != 0b11
            || ((raw >> 16) & 0x3) != 0b01
            || ((raw >> 11) & 1) != 0
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let size = (raw >> 18) & 0x3;
        let op = (raw >> 7) & 0xF;
        let fp = match op {
            0b0110 | 0b0111 => false,
            0b1110 | 0b1111 if matches!(size, 0b01 | 0b10) => true,
            _ => return None,
        };
        let mnemonic = match op & 1 {
            0 => Mnemonic::VABS,
            _ => Mnemonic::VNEG,
        };

        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vm = raw & 0xF;
        if (!fp && size == 0b11) || (q && ((vd | vm) & 1) != 0) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        Some(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    pub(crate) fn decode_neon_count_register(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 23) != 0b111100111
            || ((raw >> 20) & 0x3) != 0b11
            || ((raw >> 16) & 0x3) != 0
            || ((raw >> 11) & 1) != 0
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let mnemonic = match (raw >> 7) & 0xF {
            0b1000 => Mnemonic::VCLS,
            0b1001 => Mnemonic::VCLZ,
            0b1010 => Mnemonic::VCNT,
            _ => return None,
        };

        let size = (raw >> 18) & 0x3;
        let q = ((raw >> 6) & 1) != 0;
        let vd = (raw >> 12) & 0xF;
        let vm = raw & 0xF;
        if ((mnemonic == Mnemonic::VCLS || mnemonic == Mnemonic::VCLZ) && size == 0b11)
            || (mnemonic == Mnemonic::VCNT && size != 0)
            || (q && ((vd | vm) & 1) != 0)
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

    pub(crate) fn decode_neon_narrow_move(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 23) != 0b111100111
            || ((raw >> 20) & 0x3) != 0b11
            || ((raw >> 16) & 0x3) != 0b10
            || ((raw >> 10) & 0x3) != 0
            || ((raw >> 4) & 1) != 0
        {
            return None;
        }

        let op = (raw >> 7) & 0xF;
        let unsigned = ((raw >> 6) & 1) != 0;
        let mnemonic = match (op, unsigned) {
            (0b0100, false) => Mnemonic::VMOVN,
            (0b0100, true) => Mnemonic::VQMOVUN,
            (0b0101, _) => Mnemonic::VQMOVN,
            _ => return None,
        };

        let size = (raw >> 18) & 0x3;
        let d = (((raw >> 22) & 1) << 4) | ((raw >> 12) & 0xF);
        let m = (((raw >> 5) & 1) << 4) | (raw & 0xF);
        if size == 0b11 || d >= 32 || (m & 1) != 0 || m + 1 >= 32 {
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
