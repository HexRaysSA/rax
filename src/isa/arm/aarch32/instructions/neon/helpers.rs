//! helpers.rs

use crate::isa::arm::ExecutionState;
use crate::isa::arm::aarch32::cpu::{
    ArmMemory, Armv7Cpu, MemoryError, ProcessorMode, Psr, add_with_carry, compute_n_flag,
    compute_z_flag, condition_passed, expand_imm_c, shift_c, sign_extend,
};
use crate::isa::arm::aarch32::instructions::neon::*;
use crate::isa::arm::aarch32::instructions::*;
use crate::isa::arm::aarch32::vfp::{
    Fpscr, NeonSize, RoundingMode, vabs_f16_bits, vabs_f32, vabs_f64, vadd_f16_bits, vadd_f32,
    vadd_f64, vadd_i, vand, vbic, vcls_i, vclz_i, vcmp_f16_bits_with_exception,
    vcmp_f32_with_exception, vcmp_f64_with_exception, vcnt_i8, vcvt_f16_bits_f32,
    vcvt_f32_f16_bits, vcvt_f32_f64, vcvt_f32_s32, vcvt_f32_s32_fixed, vcvt_f32_u32,
    vcvt_f32_u32_fixed, vcvt_f64_f32, vcvt_f64_s32, vcvt_f64_s32_fixed, vcvt_f64_u32,
    vcvt_f64_u32_fixed, vcvt_s32_f32, vcvt_s32_f32_fixed, vcvt_s32_f32_round, vcvt_s32_f64,
    vcvt_s32_f64_fixed, vcvt_s32_f64_round, vcvt_u32_f32, vcvt_u32_f32_fixed, vcvt_u32_f32_round,
    vcvt_u32_f64, vcvt_u32_f64_fixed, vcvt_u32_f64_round, vcvtr_s32_f32, vcvtr_s32_f64,
    vcvtr_u32_f32, vcvtr_u32_f64, vdiv_f16_bits, vdiv_f32, vdiv_f64, veor, vfma_f16_bits, vfma_f32,
    vfma_f64, vfms_f16_bits, vfms_f32, vfms_f64, vfnma_f16_bits, vfnma_f32, vfnma_f64,
    vfnms_f16_bits, vfnms_f32, vfnms_f64, vfp_expand_imm_f16, vfp_expand_imm_f32,
    vfp_expand_imm_f64, vmaxnm_f16_bits, vmaxnm_f32, vmaxnm_f64, vminnm_f16_bits, vminnm_f32,
    vminnm_f64, vmla_f16_bits, vmla_f32, vmla_f64, vmls_f16_bits, vmls_f32, vmls_f64,
    vmul_f16_bits, vmul_f32, vmul_f64, vmvn, vneg_f16_bits, vneg_f32, vneg_f64, vnmla_f16_bits,
    vnmla_f32, vnmla_f64, vnmls_f16_bits, vnmls_f32, vnmls_f64, vnmul_f16_bits, vnmul_f32,
    vnmul_f64, vorn, vorr, vrev, vrint_f16_bits, vrint_f32, vrint_f64, vsqrt_f16_bits, vsqrt_f32,
    vsqrt_f64, vsub_f16_bits, vsub_f32, vsub_f64, vsub_i,
};
use crate::isa::arm::decoder::{Condition, DecodeError, DecodedInsn, Mnemonic, ShiftType};

impl<'a, M: ArmMemory> Executor<'a, M> {
    pub(crate) fn is_neon_abs_neg(raw: u32) -> bool {
        if (raw >> 23) != 0b111100111
            || ((raw >> 20) & 0x3) != 0b11
            || ((raw >> 16) & 0x3) != 0b01
            || ((raw >> 11) & 1) != 0
            || ((raw >> 4) & 1) != 0
        {
            return false;
        }

        let size = (raw >> 18) & 0x3;
        match (raw >> 7) & 0xF {
            0b0110 | 0b0111 => size != 0b11,
            0b1110 | 0b1111 => matches!(size, 0b01 | 0b10),
            _ => false,
        }
    }

    pub(crate) fn is_neon_integer_multiply_shape(raw: u32) -> bool {
        (raw >> 25) == 0b1111001
            && ((raw >> 23) & 1) == 0
            && ((raw >> 8) & 0xF) == 0b1001
            && (((raw >> 4) & 1) == 0 || ((raw >> 24) & 1) == 0)
    }

    pub(crate) fn is_neon_polynomial_multiply_shape(raw: u32) -> bool {
        (raw >> 25) == 0b1111001
            && ((raw >> 24) & 1) == 1
            && ((raw >> 23) & 1) == 0
            && ((raw >> 20) & 0x3) == 0
            && ((raw >> 8) & 0xF) == 0b1001
            && ((raw >> 4) & 1) == 1
    }

    pub(crate) fn is_neon_integer_multiply_scalar_shape(raw: u32) -> bool {
        if (raw >> 25) != 0b1111001
            || ((raw >> 23) & 1) != 1
            || ((raw >> 6) & 1) != 1
            || ((raw >> 4) & 1) != 0
        {
            return false;
        }

        matches!((raw >> 8) & 0xF, 0b0000 | 0b0100 | 0b1000)
    }

    pub(crate) fn is_neon_long_multiply_shape(raw: u32) -> bool {
        (raw >> 25) == 0b1111001
            && ((raw >> 23) & 1) == 1
            && ((raw >> 6) & 1) == 0
            && ((raw >> 4) & 1) == 0
            && matches!(
                (raw >> 8) & 0xF,
                0b1000 | 0b1001 | 0b1010 | 0b1011 | 0b1100 | 0b1101
            )
    }

    pub(crate) fn is_neon_long_multiply_scalar_shape(raw: u32) -> bool {
        if (raw >> 25) != 0b1111001
            || ((raw >> 23) & 1) != 1
            || ((raw >> 6) & 1) != 1
            || ((raw >> 4) & 1) != 0
        {
            return false;
        }

        matches!(
            (raw >> 8) & 0xF,
            0b0010 | 0b0011 | 0b0110 | 0b0111 | 0b1010 | 0b1011
        )
    }

    pub(crate) fn is_neon_polynomial_multiply_long_shape(raw: u32) -> bool {
        (raw >> 25) == 0b1111001
            && ((raw >> 24) & 1) == 0
            && ((raw >> 23) & 1) == 1
            && ((raw >> 20) & 0x3) == 0
            && ((raw >> 8) & 0xF) == 0b1110
            && ((raw >> 6) & 1) == 0
            && ((raw >> 4) & 1) == 0
    }

    pub(crate) fn is_neon_modified_immediate_shape(raw: u32) -> bool {
        (raw >> 25) == 0b1111001
            && ((raw >> 23) & 1) == 1
            && ((raw >> 7) & 1) == 0
            && ((raw >> 4) & 1) == 1
            && (((raw >> 8) & 0xF) != 0b1111 || ((raw >> 5) & 1) == 0)
    }

    pub(crate) fn is_neon_directed_convert_shape(raw: u32) -> bool {
        (raw >> 24) == 0xF3
            && ((raw >> 23) & 1) == 1
            && ((raw >> 21) & 1) == 1
            && ((raw >> 20) & 1) == 1
            && ((raw >> 16) & 0x3) == 0b11
            && ((raw >> 10) & 0x3) == 0
            && ((raw >> 4) & 1) == 0
    }

    pub(crate) fn decode_vfp_mem(&mut self, insn: &DecodedInsn) -> Option<(u32, u32, u8)> {
        let u = (insn.raw >> 23) & 1;
        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let rn = ((insn.raw >> 16) & 0xF) as usize;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let size = (insn.raw >> 8) & 0x3;
        let size = (insn.raw >> 8) & 0x3;
        let scale = if size == 1 { 2 } else { 4 };
        let imm = (insn.raw & 0xFF).wrapping_mul(scale);
        let base = if rn == 15 {
            self.cpu.get_pc() & !3
        } else {
            self.reg(rn)
        };
        let addr = if u == 1 {
            base.wrapping_add(imm)
        } else {
            base.wrapping_sub(imm)
        };
        match size {
            1 => Some((addr, 16, (vd << 1) | d_bit)),
            2 => Some((addr, 32, (vd << 1) | d_bit)),
            3 => Some((addr, 64, (d_bit << 4) | vd)),
            _ => None,
        }
    }

    pub(crate) fn decode_vfp_block_mem(
        &mut self,
        insn: &DecodedInsn,
    ) -> Option<(u32, u32, u32, u8, u8, bool, usize)> {
        let p = (insn.raw >> 24) & 1;
        let u = (insn.raw >> 23) & 1;
        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let w = ((insn.raw >> 21) & 1) != 0;
        let rn = ((insn.raw >> 16) & 0xF) as usize;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let size = (insn.raw >> 8) & 0x3;
        let words = (insn.raw & 0xFF) as u8;
        if words == 0 || !matches!((p, u, w), (0, 1, _) | (1, 0, true)) {
            return None;
        }

        let (elem_size, first, count) = match size {
            2 => (32, (vd << 1) | d_bit, words),
            3 if (words & 1) == 0 => (64, (d_bit << 4) | vd, words / 2),
            _ => return None,
        };
        if count == 0
            || first.checked_add(count - 1)? >= 32
            || size == 3 && count > 16
            || rn == 15 && (w || insn.state.is_thumb())
        {
            return None;
        }

        let byte_count = (words as u32).wrapping_mul(4);
        let base = if rn == 15 {
            self.cpu.get_pc() & !3
        } else {
            self.reg(rn)
        };
        let start = match (p, u) {
            (0, 1) => base,
            (1, 0) => base.wrapping_sub(byte_count),
            _ => return None,
        };
        let final_addr = if u == 1 {
            base.wrapping_add(byte_count)
        } else {
            base.wrapping_sub(byte_count)
        };

        Some((start, final_addr, elem_size, first, count, w, rn))
    }

    pub(crate) fn decode_vfp_cond_select_regs(
        &self,
        insn: &DecodedInsn,
    ) -> Option<(u8, u8, u8, u32)> {
        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let n_bit = ((insn.raw >> 7) & 1) as u8;
        let vn = ((insn.raw >> 16) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;
        match (insn.raw >> 8) & 0x3 {
            1 => Some(((vd << 1) | d_bit, (vn << 1) | n_bit, (vm << 1) | m_bit, 16)),
            2 => Some(((vd << 1) | d_bit, (vn << 1) | n_bit, (vm << 1) | m_bit, 32)),
            3 => Some(((d_bit << 4) | vd, (n_bit << 4) | vn, (m_bit << 4) | vm, 64)),
            _ => None,
        }
    }

    pub(crate) fn decode_vfp_ternary_regs(&self, insn: &DecodedInsn) -> Option<(u8, u8, u8, u32)> {
        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let n_bit = ((insn.raw >> 7) & 1) as u8;
        let vn = ((insn.raw >> 16) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;
        match (insn.raw >> 8) & 0x3 {
            1 => Some(((vd << 1) | d_bit, (vn << 1) | n_bit, (vm << 1) | m_bit, 16)),
            2 => Some(((vd << 1) | d_bit, (vn << 1) | n_bit, (vm << 1) | m_bit, 32)),
            3 => Some(((d_bit << 4) | vd, (n_bit << 4) | vn, (m_bit << 4) | vm, 64)),
            _ => None,
        }
    }

    pub(crate) fn decode_vfp_unary_regs(&self, insn: &DecodedInsn) -> Option<(u8, u8, u32)> {
        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;
        match (insn.raw >> 8) & 0x3 {
            1 => Some(((vd << 1) | d_bit, (vm << 1) | m_bit, 16)),
            2 => Some(((vd << 1) | d_bit, (vm << 1) | m_bit, 32)),
            3 => Some(((d_bit << 4) | vd, (m_bit << 4) | vm, 64)),
            _ => None,
        }
    }
}
