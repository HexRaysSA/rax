//! NEON shifts: by an immediate (VSHR, VSRA, VRSHR, VRSRA, VSRI, VSHL,
//! VSLI, VQSHL, VQSHLU), by a register (VSHL, VRSHL, VQSHL, VQRSHL), and
//! narrowing (VSHRN, VRSHRN, VQSHRN, VQRSHRN, VQSHRUN, VQRSHRUN).

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
    pub(crate) fn exec_neon_shift_immediate(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 25) != 0b1111001
            || ((insn.raw >> 23) & 1) != 1
            || ((insn.raw >> 4) & 1) != 1
        {
            return ExecResult::Undefined;
        }

        let imm = (insn.raw >> 16) & 0x3F;
        let size = match imm {
            8..=15 => NeonSize::B8,
            16..=31 => NeonSize::H16,
            32..=63 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        let ebytes = (size.bits() / 8) as u8;
        let unsigned = ((insn.raw >> 24) & 1) != 0;
        let op = match insn.mnemonic {
            Mnemonic::VSHR => 0,
            Mnemonic::VRSHR => 1,
            Mnemonic::VSRA => 2,
            Mnemonic::VRSRA => 3,
            Mnemonic::VSHL => 4,
            Mnemonic::VSLI => 5,
            Mnemonic::VSRI => 6,
            _ => return ExecResult::Undefined,
        };

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;
        let q = ((insn.raw >> 6) & 1) != 0;
        let regs = if q { 2 } else { 1 };

        let d = (d_bit << 4) | vd;
        let m = (m_bit << 4) | vm;
        if q && ((d | m) & 1) != 0 {
            return ExecResult::Undefined;
        }
        if d + regs > 32 || m + regs > 32 {
            return ExecResult::Undefined;
        }

        let mask = if size.bits() == 32 {
            u64::from(u32::MAX)
        } else {
            (1u64 << size.bits()) - 1
        };
        let right_shift = (size.bits() * 2) - imm;
        let left_shift = imm - size.bits();
        if matches!(
            insn.mnemonic,
            Mnemonic::VSHR | Mnemonic::VRSHR | Mnemonic::VSRA | Mnemonic::VRSRA | Mnemonic::VSRI
        ) && (right_shift == 0 || right_shift > size.bits())
        {
            return ExecResult::Undefined;
        }
        if matches!(insn.mnemonic, Mnemonic::VSHL | Mnemonic::VSLI)
            && (left_shift == 0 || left_shift > size.bits())
        {
            return ExecResult::Undefined;
        }
        let round_const = if matches!(insn.mnemonic, Mnemonic::VRSHR | Mnemonic::VRSRA) {
            1i128 << (right_shift - 1)
        } else {
            0
        };
        for reg in 0..regs {
            let elements = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let old_elements = if matches!(
                insn.mnemonic,
                Mnemonic::VSRA | Mnemonic::VRSRA | Mnemonic::VSLI | Mnemonic::VSRI
            ) {
                self.neon_read_vector_elements_u64(d + reg, 1, ebytes)
            } else {
                vec![0; elements.len()]
            };
            let mut out = Vec::with_capacity(elements.len());
            for (elem, old_elem) in elements.into_iter().zip(old_elements.into_iter()) {
                let result = match op {
                    0..=3 => {
                        if unsigned {
                            let shifted = ((elem as i128 + round_const) >> right_shift) as u64;
                            if matches!(op, 2 | 3) {
                                old_elem.wrapping_add(shifted) & mask
                            } else {
                                shifted
                            }
                        } else {
                            let value =
                                Self::neon_sign_extend_elem_u64(elem, size.bits()) + round_const;
                            let shifted =
                                Self::neon_pack_signed_elem_i128(value >> right_shift, size.bits());
                            if matches!(op, 2 | 3) {
                                old_elem.wrapping_add(shifted) & mask
                            } else {
                                shifted
                            }
                        }
                    }
                    4 => (elem << left_shift) & mask,
                    5 => {
                        let insert_mask = (mask << left_shift) & mask;
                        (old_elem & !insert_mask) | ((elem << left_shift) & insert_mask)
                    }
                    6 => {
                        let insert_mask = mask >> right_shift;
                        (old_elem & !insert_mask) | ((elem >> right_shift) & insert_mask)
                    }
                    _ => return ExecResult::Undefined,
                };
                out.push(result);
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_vshl(&mut self, insn: &DecodedInsn) -> ExecResult {
        if (insn.raw >> 25) == 0b1111001
            && ((insn.raw >> 23) & 1) == 0
            && ((insn.raw >> 8) & 0xF) == 0b0100
            && ((insn.raw >> 4) & 1) == 0
        {
            return self.exec_neon_shift_register(insn);
        }

        self.exec_neon_shift_immediate(insn)
    }

    pub(crate) fn exec_vqshl(&mut self, insn: &DecodedInsn) -> ExecResult {
        if (insn.raw >> 25) == 0b1111001
            && ((insn.raw >> 23) & 1) == 0
            && ((insn.raw >> 8) & 0xF) == 0b0100
            && ((insn.raw >> 4) & 1) == 1
        {
            return self.exec_neon_shift_register(insn);
        }

        self.exec_neon_saturating_shift_left_immediate(insn)
    }

    pub(crate) fn exec_neon_saturating_shift_left_immediate(
        &mut self,
        insn: &DecodedInsn,
    ) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 25) != 0b1111001
            || ((insn.raw >> 23) & 1) != 1
            || ((insn.raw >> 4) & 1) != 1
        {
            return ExecResult::Undefined;
        }

        let op8 = (insn.raw >> 8) & 0xF;
        let unsigned_bit = ((insn.raw >> 24) & 1) != 0;
        let signed_to_unsigned = match (insn.mnemonic, op8, unsigned_bit) {
            (Mnemonic::VQSHL, 0b0111, _) => false,
            (Mnemonic::VQSHLU, 0b0110, true) => true,
            _ => return ExecResult::Undefined,
        };

        let imm = (insn.raw >> 16) & 0x3F;
        let size = match imm {
            8..=15 => NeonSize::B8,
            16..=31 => NeonSize::H16,
            32..=63 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        let shift = imm - size.bits();
        if shift == 0 || shift > size.bits() {
            return ExecResult::Undefined;
        }
        let ebytes = (size.bits() / 8) as u8;

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;
        let q = ((insn.raw >> 6) & 1) != 0;
        let regs = if q { 2 } else { 1 };

        let d = (d_bit << 4) | vd;
        let m = (m_bit << 4) | vm;
        if q && ((d | m) & 1) != 0 {
            return ExecResult::Undefined;
        }
        if d + regs > 32 || m + regs > 32 {
            return ExecResult::Undefined;
        }

        for reg in 0..regs {
            let elements = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let mut out = Vec::with_capacity(elements.len());
            for elem in elements {
                let (result, saturated) = if signed_to_unsigned {
                    let value = Self::neon_sign_extend_elem_u64(elem, size.bits()) << shift;
                    Self::neon_unsigned_saturate(value, size.bits())
                } else if unsigned_bit {
                    Self::neon_unsigned_saturate((elem as i128) << shift, size.bits())
                } else {
                    let value = Self::neon_sign_extend_elem_u64(elem, size.bits()) << shift;
                    let (value, saturated) = Self::neon_signed_saturate_i128(value, size.bits());
                    (
                        Self::neon_pack_signed_elem_i128(value, size.bits()),
                        saturated,
                    )
                };
                if saturated {
                    self.cpu.vfp.fpscr.set_qc(true);
                }
                out.push(result);
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_shift_register(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 25) != 0b1111001 || ((insn.raw >> 23) & 1) != 0 {
            return ExecResult::Undefined;
        }

        let saturating = ((insn.raw >> 4) & 1) != 0;
        let rounding = match (insn.mnemonic, (insn.raw >> 8) & 0xF, saturating) {
            (Mnemonic::VSHL, 0b0100, false) => false,
            (Mnemonic::VRSHL, 0b0101, false) => true,
            (Mnemonic::VQSHL, 0b0100, true) => false,
            (Mnemonic::VQRSHL, 0b0101, true) => true,
            _ => return ExecResult::Undefined,
        };
        let size = match (insn.raw >> 20) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => NeonSize::D64,
        };
        let ebytes = (size.bits() / 8) as u8;
        let unsigned = ((insn.raw >> 24) & 1) != 0;

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let n_bit = ((insn.raw >> 7) & 1) as u8;
        let vn = ((insn.raw >> 16) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;
        let q = ((insn.raw >> 6) & 1) != 0;
        let regs = if q { 2 } else { 1 };

        let d = (d_bit << 4) | vd;
        let n = (n_bit << 4) | vn;
        let m = (m_bit << 4) | vm;
        if q && ((d | n | m) & 1) != 0 {
            return ExecResult::Undefined;
        }
        if d + regs > 32 || n + regs > 32 || m + regs > 32 {
            return ExecResult::Undefined;
        }

        for reg in 0..regs {
            let counts = self.neon_read_vector_elements_u64(n + reg, 1, ebytes);
            let values = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let mut out = Vec::with_capacity(values.len());
            for (count, value) in counts.into_iter().zip(values) {
                let (result, sat) = Self::neon_shift_register_elem(
                    value,
                    count,
                    size.bits(),
                    unsigned,
                    rounding,
                    saturating,
                );
                if sat {
                    self.cpu.vfp.fpscr.set_qc(true);
                }
                out.push(result);
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        ExecResult::Continue
    }

    /// One element of a shift by a register (`aarch32_VSHL_r_A`,
    /// `aarch32_VRSHL_A`, `aarch32_VQSHL_r_A`, `aarch32_VQRSHL_A`): the
    /// `esize`-bit `value` shifted by the signed low byte of `count` (right
    /// when negative, adding `2^(-count-1)` first when `rounding`) as an
    /// integer, then truncated to the element, or saturated when
    /// `saturating` (with whether it was).
    pub(crate) fn neon_shift_register_elem(
        value: u64,
        count: u64,
        esize: u32,
        unsigned: bool,
        rounding: bool,
        saturating: bool,
    ) -> (u64, bool) {
        let shift = i32::from(count as u8 as i8);
        let operand = if unsigned {
            i128::from(value)
        } else {
            Self::neon_sign_extend_elem_u64(value, esize)
        };
        let result = if shift >= 64 {
            // No bit of the operand stays in any element: only its sign
            // matters (for saturation).
            operand.signum() << 64
        } else if shift >= 0 {
            operand << shift
        } else {
            // Past 65 bits the result is the same (0 or -1, and 0 when
            // rounding: the constant then exceeds every operand).
            let r = (-shift).min(65) as u32;
            let round = if rounding { 1i128 << (r - 1) } else { 0 };
            (operand + round) >> r
        };
        if !saturating {
            (Self::neon_pack_signed_elem_i128(result, esize), false)
        } else if unsigned {
            Self::neon_unsigned_saturate(result, esize)
        } else {
            let (v, sat) = Self::neon_signed_saturate_i128(result, esize);
            (Self::neon_pack_signed_elem_i128(v, esize), sat)
        }
    }

    pub(crate) fn exec_neon_shift_narrow_immediate(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 25) != 0b1111001
            || ((insn.raw >> 23) & 1) != 1
            || ((insn.raw >> 4) & 1) != 1
        {
            return ExecResult::Undefined;
        }

        let imm = (insn.raw >> 16) & 0x3F;
        let dest_size = match imm {
            8..=15 => NeonSize::B8,
            16..=31 => NeonSize::H16,
            32..=63 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        let source_bits = dest_size.bits() * 2;
        let shift = source_bits - imm;
        if shift == 0 || shift > source_bits {
            return ExecResult::Undefined;
        }
        let dest_ebytes = (dest_size.bits() / 8) as u8;
        let source_ebytes = dest_ebytes * 2;
        let op8 = (insn.raw >> 8) & 0xF;
        let unsigned_bit = ((insn.raw >> 24) & 1) != 0;
        let rounding_bit = ((insn.raw >> 6) & 1) != 0;
        let (rounding, saturating, unsigned_source, unsigned_dest) = match insn.mnemonic {
            Mnemonic::VSHRN if op8 == 0b1000 && !unsigned_bit && !rounding_bit => {
                (false, false, true, true)
            }
            Mnemonic::VRSHRN if op8 == 0b1000 && !unsigned_bit && rounding_bit => {
                (true, false, true, true)
            }
            Mnemonic::VQSHRUN if op8 == 0b1000 && unsigned_bit && !rounding_bit => {
                (false, true, false, true)
            }
            Mnemonic::VQRSHRUN if op8 == 0b1000 && unsigned_bit && rounding_bit => {
                (true, true, false, true)
            }
            Mnemonic::VQSHRN if op8 == 0b1001 && !rounding_bit => {
                (false, true, unsigned_bit, unsigned_bit)
            }
            Mnemonic::VQRSHRN if op8 == 0b1001 && rounding_bit => {
                (true, true, unsigned_bit, unsigned_bit)
            }
            _ => return ExecResult::Undefined,
        };

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;
        let d = (d_bit << 4) | vd;
        let m = (m_bit << 4) | vm;
        if d >= 32 || (m & 1) != 0 || m + 2 > 32 {
            return ExecResult::Undefined;
        }

        let round_const = if rounding { 1i128 << (shift - 1) } else { 0 };
        let elements = self.neon_read_vector_elements_u64(m, 2, source_ebytes);
        let mut out = Vec::with_capacity(elements.len());
        for elem in elements {
            let result = if saturating {
                let shifted = if unsigned_source {
                    ((elem as i128) + round_const) >> shift
                } else {
                    (Self::neon_sign_extend_elem_u64(elem, source_bits) + round_const) >> shift
                };
                let (result, saturated) = if unsigned_dest {
                    Self::neon_unsigned_saturate(shifted, dest_size.bits())
                } else {
                    let (result, saturated) =
                        Self::neon_signed_saturate_i128(shifted, dest_size.bits());
                    (
                        Self::neon_pack_signed_elem_i128(result, dest_size.bits()),
                        saturated,
                    )
                };
                if saturated {
                    self.cpu.vfp.fpscr.set_qc(true);
                }
                result
            } else {
                ((elem as u128).wrapping_add(round_const as u128) >> shift) as u64
            };
            out.push(result);
        }
        self.neon_write_vector_elements_u64(d, 1, dest_ebytes, &out);

        ExecResult::Continue
    }
}
