//! ops.rs

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
    pub(crate) fn exec_vadd_vsub(&mut self, insn: &DecodedInsn) -> ExecResult {
        if Self::is_neon_fp_add_sub_shape(insn.raw) {
            self.exec_neon_fp_add_sub(insn)
        } else if Self::neon_integer_add_sub_size(insn).is_some() {
            self.exec_neon_integer_add_sub(insn)
        } else {
            self.exec_vfp_binop(insn)
        }
    }

    pub(crate) fn neon_integer_add_sub_size(insn: &DecodedInsn) -> Option<NeonSize> {
        if !matches!(insn.mnemonic, Mnemonic::VADD | Mnemonic::VSUB)
            || ((insn.raw >> 28) & 0xF) != 0xF
            || !matches!((insn.raw >> 24) & 0xFF, 0xF2 | 0xF3)
            || ((insn.raw >> 23) & 1) != 0
            || ((insn.raw >> 8) & 0xF) != 0b1000
            || ((insn.raw >> 4) & 1) != 0
        {
            return None;
        }

        match (insn.raw >> 20) & 0x3 {
            0 => Some(NeonSize::B8),
            1 => Some(NeonSize::H16),
            2 => Some(NeonSize::S32),
            3 => Some(NeonSize::D64),
            _ => None,
        }
    }

    pub(crate) fn exec_neon_integer_add_sub(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        let Some(size) = Self::neon_integer_add_sub_size(insn) else {
            return ExecResult::Undefined;
        };

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

        for index in 0..regs {
            let n_bits = self.cpu.vfp.read_d_bits(n + index);
            let m_bits = self.cpu.vfp.read_d_bits(m + index);
            let result = match insn.mnemonic {
                Mnemonic::VADD => vadd_i(n_bits, m_bits, size),
                Mnemonic::VSUB => vsub_i(n_bits, m_bits, size),
                _ => return ExecResult::Undefined,
            };
            self.cpu.vfp.write_d_bits(d + index, result);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_logical_register(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if Self::is_neon_modified_immediate_shape(insn.raw) {
            return self.exec_neon_modified_immediate(insn);
        }

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

        for index in 0..regs {
            let d_bits = self.cpu.vfp.read_d_bits(d + index);
            let n_bits = self.cpu.vfp.read_d_bits(n + index);
            let m_bits = self.cpu.vfp.read_d_bits(m + index);
            let result = match insn.mnemonic {
                Mnemonic::VAND => vand(n_bits, m_bits),
                Mnemonic::VBIC => vbic(n_bits, m_bits),
                Mnemonic::VORR => vorr(n_bits, m_bits),
                Mnemonic::VORN => vorn(n_bits, m_bits),
                Mnemonic::VEOR => veor(n_bits, m_bits),
                Mnemonic::VBSL => (n_bits & d_bits) | (m_bits & !d_bits),
                Mnemonic::VBIT => (n_bits & m_bits) | (d_bits & !m_bits),
                Mnemonic::VBIF => (d_bits & m_bits) | (n_bits & !m_bits),
                _ => return ExecResult::Undefined,
            };
            self.cpu.vfp.write_d_bits(d + index, result);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_vmvn_register(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if Self::is_neon_modified_immediate_shape(insn.raw) {
            return self.exec_neon_modified_immediate(insn);
        }

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

        for index in 0..regs {
            let bits = self.cpu.vfp.read_d_bits(m + index);
            self.cpu.vfp.write_d_bits(d + index, vmvn(bits));
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_vrev_register(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }

        let size = match (insn.raw >> 18) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        let op = (insn.raw >> 7) & 0x3;
        let container_bits = match insn.mnemonic {
            Mnemonic::VREV64 if op == 0b00 => 64,
            Mnemonic::VREV32 if op == 0b01 => 32,
            Mnemonic::VREV16 if op == 0b10 => 16,
            _ => return ExecResult::Undefined,
        };
        if op + ((insn.raw >> 18) & 0x3) >= 3 {
            return ExecResult::Undefined;
        }

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

        for index in 0..regs {
            let bits = self.cpu.vfp.read_d_bits(m + index);
            self.cpu
                .vfp
                .write_d_bits(d + index, vrev(bits, size, container_bits));
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_vswp(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }

        if ((insn.raw >> 18) & 0x3) != 0 {
            return ExecResult::Undefined;
        }

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
        if d == m {
            return ExecResult::Continue;
        }

        for index in 0..regs {
            let d_bits = self.cpu.vfp.read_d_bits(d + index);
            let m_bits = self.cpu.vfp.read_d_bits(m + index);
            self.cpu.vfp.write_d_bits(d + index, m_bits);
            self.cpu.vfp.write_d_bits(m + index, d_bits);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_vdup(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }

        let scalar_form = (insn.raw >> 28) == 0xF;
        let (d, regs, ebytes, scalar) = if scalar_form {
            let imm4 = ((insn.raw >> 16) & 0xF) as u8;
            let q = ((insn.raw >> 6) & 1) != 0;
            let d_bit = ((insn.raw >> 22) & 1) as u8;
            let vd = ((insn.raw >> 12) & 0xF) as u8;
            let m_bit = ((insn.raw >> 5) & 1) as u8;
            let vm = (insn.raw & 0xF) as u8;
            let (ebytes, lane) = match imm4 {
                imm if (imm & 0b0001) != 0 => (1, imm >> 1),
                imm if (imm & 0b0011) == 0b0010 => (2, imm >> 2),
                imm if (imm & 0b0111) == 0b0100 => (4, imm >> 3),
                _ => return ExecResult::Undefined,
            };

            let d = (d_bit << 4) | vd;
            let m = (m_bit << 4) | vm;
            let regs = if q { 2 } else { 1 };
            if (q && (d & 1) != 0) || d + regs > 32 || lane as usize >= 8 / ebytes as usize {
                return ExecResult::Undefined;
            }
            (d, regs, ebytes, self.neon_read_d_elem_u64(m, lane, ebytes))
        } else {
            let b = (insn.raw >> 22) & 1;
            let e = (insn.raw >> 5) & 1;
            let q = ((insn.raw >> 21) & 1) != 0;
            let d_bit = ((insn.raw >> 7) & 1) as u8;
            let vd = ((insn.raw >> 16) & 0xF) as u8;
            let rt = ((insn.raw >> 12) & 0xF) as u8;
            let ebytes = match (b, e) {
                (0, 0) => 4,
                (0, 1) => 2,
                (1, 0) => 1,
                _ => return ExecResult::Undefined,
            };

            let d = (d_bit << 4) | vd;
            let regs = if q { 2 } else { 1 };
            if rt == 15 || (q && (d & 1) != 0) || d + regs > 32 {
                return ExecResult::Undefined;
            }
            (d, regs, ebytes, self.cpu.regs[rt as usize] as u64)
        };

        let lane_count = 8 / ebytes;
        for reg in 0..regs {
            for lane in 0..lane_count {
                self.neon_write_d_elem_u64(d + reg, lane as u8, ebytes, scalar);
            }
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_pairwise_permute(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }

        let size = match (insn.raw >> 18) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
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
        if d == m {
            return ExecResult::Continue;
        }

        match insn.mnemonic {
            Mnemonic::VTRN => {
                let elements = size.elements_per_d();
                let half = elements / 2;
                for index in 0..regs {
                    let d_elems = self.neon_read_vector_elements(d + index, 1, ebytes);
                    let m_elems = self.neon_read_vector_elements(m + index, 1, ebytes);
                    let mut out_d = d_elems.clone();
                    let mut out_m = m_elems.clone();
                    for elem in 0..half {
                        out_d[(2 * elem) + 1] = m_elems[2 * elem];
                        out_m[2 * elem] = d_elems[(2 * elem) + 1];
                    }
                    self.neon_write_vector_elements(d + index, 1, ebytes, &out_d);
                    self.neon_write_vector_elements(m + index, 1, ebytes, &out_m);
                }
            }
            Mnemonic::VUZP => {
                if !q && size == NeonSize::S32 {
                    return ExecResult::Undefined;
                }
                let d_elems = self.neon_read_vector_elements(d, regs, ebytes);
                let m_elems = self.neon_read_vector_elements(m, regs, ebytes);
                let mut zipped = Vec::with_capacity(d_elems.len() + m_elems.len());
                zipped.extend_from_slice(&d_elems);
                zipped.extend_from_slice(&m_elems);

                let elements = d_elems.len();
                let mut out_d = Vec::with_capacity(elements);
                let mut out_m = Vec::with_capacity(elements);
                for elem in 0..elements {
                    out_d.push(zipped[2 * elem]);
                    out_m.push(zipped[(2 * elem) + 1]);
                }
                self.neon_write_vector_elements(d, regs, ebytes, &out_d);
                self.neon_write_vector_elements(m, regs, ebytes, &out_m);
            }
            Mnemonic::VZIP => {
                if !q && size == NeonSize::S32 {
                    return ExecResult::Undefined;
                }
                let d_elems = self.neon_read_vector_elements(d, regs, ebytes);
                let m_elems = self.neon_read_vector_elements(m, regs, ebytes);
                let elements = d_elems.len();
                let mut zipped = Vec::with_capacity(elements * 2);
                for elem in 0..elements {
                    zipped.push(d_elems[elem]);
                    zipped.push(m_elems[elem]);
                }

                self.neon_write_vector_elements(d, regs, ebytes, &zipped[..elements]);
                self.neon_write_vector_elements(m, regs, ebytes, &zipped[elements..]);
            }
            _ => return ExecResult::Undefined,
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_pairwise_integer(&mut self, insn: &DecodedInsn) -> ExecResult {
        if Self::is_neon_fp_pairwise_shape(insn.raw) {
            return self.exec_neon_fp_pairwise(insn);
        }

        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 25) != 0b1111001 || ((insn.raw >> 23) & 1) != 0 {
            return ExecResult::Undefined;
        }

        let valid_shape = matches!(
            (
                ((insn.raw >> 8) & 0xF),
                ((insn.raw >> 4) & 1),
                insn.mnemonic
            ),
            (0b1010, 0, Mnemonic::VPMAX)
                | (0b1010, 1, Mnemonic::VPMIN)
                | (0b1011, 1, Mnemonic::VPADD)
        );
        if !valid_shape || ((insn.raw >> 6) & 1) != 0 {
            return ExecResult::Undefined;
        }

        let size = match (insn.raw >> 20) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        let ebytes = (size.bits() / 8) as u8;
        let unsigned = ((insn.raw >> 24) & 1) != 0;

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let n_bit = ((insn.raw >> 7) & 1) as u8;
        let vn = ((insn.raw >> 16) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;

        let d = (d_bit << 4) | vd;
        let n = (n_bit << 4) | vn;
        let m = (m_bit << 4) | vm;
        if d >= 32 || n >= 32 || m >= 32 {
            return ExecResult::Undefined;
        }

        let n_elements = self.neon_read_vector_elements_u64(n, 1, ebytes);
        let m_elements = self.neon_read_vector_elements_u64(m, 1, ebytes);
        let half = n_elements.len() / 2;
        let mut out = Vec::with_capacity(n_elements.len());

        for elements in [&n_elements, &m_elements] {
            for pair in 0..half {
                let lhs = elements[2 * pair];
                let rhs = elements[(2 * pair) + 1];
                let result = match insn.mnemonic {
                    Mnemonic::VPADD => lhs.wrapping_add(rhs),
                    Mnemonic::VPMAX if unsigned => lhs.max(rhs),
                    Mnemonic::VPMIN if unsigned => lhs.min(rhs),
                    Mnemonic::VPMAX => {
                        let lhs = Self::neon_sign_extend_elem_u64(lhs, size.bits());
                        let rhs = Self::neon_sign_extend_elem_u64(rhs, size.bits());
                        Self::neon_pack_signed_elem_i128(lhs.max(rhs), size.bits())
                    }
                    Mnemonic::VPMIN => {
                        let lhs = Self::neon_sign_extend_elem_u64(lhs, size.bits());
                        let rhs = Self::neon_sign_extend_elem_u64(rhs, size.bits());
                        Self::neon_pack_signed_elem_i128(lhs.min(rhs), size.bits())
                    }
                    _ => return ExecResult::Undefined,
                };
                out.push(result);
            }
        }

        self.neon_write_vector_elements_u64(d, 1, ebytes, &out);
        ExecResult::Continue
    }

    pub(crate) fn exec_neon_pairwise_add_long(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 23) != 0b111100111
            || ((insn.raw >> 20) & 0x3) != 0b11
            || ((insn.raw >> 16) & 0x3) != 0
            || ((insn.raw >> 4) & 1) != 0
        {
            return ExecResult::Undefined;
        }

        let op = (insn.raw >> 7) & 0x1F;
        let (accumulate, unsigned) = match (insn.mnemonic, op & 0x1E) {
            (Mnemonic::VPADDL, 0b00100) => (false, (op & 1) != 0),
            (Mnemonic::VPADAL, 0b01100) => (true, (op & 1) != 0),
            _ => return ExecResult::Undefined,
        };

        let narrow_size = match (insn.raw >> 18) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        let narrow_ebytes = (narrow_size.bits() / 8) as u8;
        let wide_bits = narrow_size.bits() * 2;
        let wide_ebytes = narrow_ebytes * 2;

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

        let elements = self.neon_read_vector_elements_u64(m, regs, narrow_ebytes);
        let old_elements = if accumulate {
            self.neon_read_vector_elements_u64(d, regs, wide_ebytes)
        } else {
            vec![0; elements.len() / 2]
        };
        let mut out = Vec::with_capacity(elements.len() / 2);
        for (pair, old) in elements.chunks_exact(2).zip(old_elements.into_iter()) {
            let lhs = pair[0];
            let rhs = pair[1];
            let sum = if unsigned {
                lhs as i128 + rhs as i128
            } else {
                Self::neon_sign_extend_elem_u64(lhs, narrow_size.bits())
                    + Self::neon_sign_extend_elem_u64(rhs, narrow_size.bits())
            };
            out.push(old.wrapping_add(Self::neon_pack_signed_elem_i128(sum, wide_bits)));
        }
        self.neon_write_vector_elements_u64(d, regs, wide_ebytes, &out);

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_widen_move(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 25) != 0b1111001
            || ((insn.raw >> 23) & 1) != 1
            || ((insn.raw >> 8) & 0xF) != 0b1010
            || ((insn.raw >> 4) & 1) != 1
        {
            return ExecResult::Undefined;
        }

        let narrow_size = match (insn.raw >> 16) & 0x3F {
            8 => NeonSize::B8,
            16 => NeonSize::H16,
            32 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        let narrow_ebytes = (narrow_size.bits() / 8) as u8;
        let wide_bits = narrow_size.bits() * 2;
        let wide_ebytes = narrow_ebytes * 2;
        let unsigned = ((insn.raw >> 24) & 1) != 0;

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;
        let d = (d_bit << 4) | vd;
        let m = (m_bit << 4) | vm;
        if (d & 1) != 0 || d + 2 > 32 || m >= 32 {
            return ExecResult::Undefined;
        }

        let elements = self.neon_read_vector_elements_u64(m, 1, narrow_ebytes);
        let mut out = Vec::with_capacity(elements.len());
        for elem in elements {
            let result = if unsigned {
                elem
            } else {
                Self::neon_pack_signed_elem_i128(
                    Self::neon_sign_extend_elem_u64(elem, narrow_size.bits()),
                    wide_bits,
                )
            };
            out.push(result);
        }
        self.neon_write_vector_elements_u64(d, 2, wide_ebytes, &out);
        ExecResult::Continue
    }

    pub(crate) fn exec_neon_narrow_move(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 23) != 0b111100111
            || ((insn.raw >> 20) & 0x3) != 0b11
            || ((insn.raw >> 16) & 0x3) != 0b10
            || ((insn.raw >> 10) & 0x3) != 0
            || ((insn.raw >> 4) & 1) != 0
        {
            return ExecResult::Undefined;
        }

        let op = (insn.raw >> 7) & 0xF;
        let unsigned = ((insn.raw >> 6) & 1) != 0;
        let (saturating, unsigned_source, unsigned_dest) = match (insn.mnemonic, op) {
            (Mnemonic::VMOVN, 0b0100) if !unsigned => (false, true, true),
            (Mnemonic::VQMOVN, 0b0101) if !unsigned => (true, false, false),
            (Mnemonic::VQMOVN, 0b0101) => (true, true, true),
            (Mnemonic::VQMOVUN, 0b0100) if unsigned => (true, false, true),
            _ => return ExecResult::Undefined,
        };

        let dest_size = match (insn.raw >> 18) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        let dest_bits = dest_size.bits();
        let source_bits = dest_bits * 2;
        let dest_ebytes = (dest_bits / 8) as u8;
        let source_ebytes = dest_ebytes * 2;

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;
        let d = (d_bit << 4) | vd;
        let m = (m_bit << 4) | vm;
        if d >= 32 || (m & 1) != 0 || m + 2 > 32 {
            return ExecResult::Undefined;
        }

        let elements = self.neon_read_vector_elements_u64(m, 2, source_ebytes);
        let mut out = Vec::with_capacity(elements.len());
        for elem in elements {
            let result = if saturating {
                let value = if unsigned_source {
                    elem as i128
                } else {
                    Self::neon_sign_extend_elem_u64(elem, source_bits)
                };
                let (result, saturated) = if unsigned_dest {
                    Self::neon_unsigned_saturate(value, dest_bits)
                } else {
                    let (value, saturated) = Self::neon_signed_saturate_i128(value, dest_bits);
                    (
                        Self::neon_pack_signed_elem_i128(value, dest_bits),
                        saturated,
                    )
                };
                if saturated {
                    self.cpu.vfp.fpscr.set_qc(true);
                }
                result
            } else {
                elem
            };
            out.push(result);
        }
        self.neon_write_vector_elements_u64(d, 1, dest_ebytes, &out);
        ExecResult::Continue
    }

    pub(crate) fn exec_neon_saturating_abs_neg(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }

        let size = match (insn.raw >> 18) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
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

        for index in 0..regs {
            let elements = self.neon_read_vector_elements(m + index, 1, ebytes);
            let mut out = Vec::with_capacity(elements.len());
            for elem in elements {
                let value = Self::neon_sign_extend_elem(elem, size.bits());
                let (result, saturated) = match insn.mnemonic {
                    Mnemonic::VQABS => Self::neon_signed_saturate(value.abs(), size.bits()),
                    Mnemonic::VQNEG => Self::neon_signed_saturate(-value, size.bits()),
                    _ => return ExecResult::Undefined,
                };
                if saturated {
                    self.cpu.vfp.fpscr.set_qc(true);
                }
                out.push(Self::neon_pack_signed_elem(result, size.bits()));
            }
            self.neon_write_vector_elements(d + index, 1, ebytes, &out);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_abs_neg(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if !Self::is_neon_abs_neg(insn.raw) {
            return ExecResult::Undefined;
        }

        let size_bits = match (insn.raw >> 18) & 0x3 {
            0b00 => 8,
            0b01 => 16,
            0b10 => 32,
            _ => return ExecResult::Undefined,
        };
        let ebytes = (size_bits / 8) as u8;
        let op = (insn.raw >> 7) & 0xF;
        let fp = op >= 0b1110;
        if fp && !matches!(size_bits, 16 | 32) {
            return ExecResult::Undefined;
        }

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

        for index in 0..regs {
            let elements = self.neon_read_vector_elements_u64(m + index, 1, ebytes);
            let mut out = Vec::with_capacity(elements.len());
            for elem in elements {
                let result = if fp {
                    let sign_mask = 1u64 << (size_bits - 1);
                    let value_mask = if size_bits == 32 {
                        u64::from(u32::MAX)
                    } else {
                        u64::from(u16::MAX)
                    };
                    match insn.mnemonic {
                        Mnemonic::VABS => elem & !sign_mask & value_mask,
                        Mnemonic::VNEG => (elem ^ sign_mask) & value_mask,
                        _ => return ExecResult::Undefined,
                    }
                } else {
                    let value = Self::neon_sign_extend_elem_u64(elem, size_bits);
                    let result = match insn.mnemonic {
                        Mnemonic::VABS => value.abs(),
                        Mnemonic::VNEG => -value,
                        _ => return ExecResult::Undefined,
                    };
                    Self::neon_pack_signed_elem_i128(result, size_bits)
                };
                out.push(result);
            }
            self.neon_write_vector_elements_u64(d + index, 1, ebytes, &out);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_halving_add_sub(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 25) != 0b1111001
            || ((insn.raw >> 23) & 1) != 0
            || ((insn.raw >> 4) & 1) != 0
        {
            return ExecResult::Undefined;
        }

        let size = match (insn.raw >> 20) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
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

        let mask = if size.bits() == 32 {
            u64::from(u32::MAX)
        } else {
            (1u64 << size.bits()) - 1
        };

        for reg in 0..regs {
            let n_elements = self.neon_read_vector_elements_u64(n + reg, 1, ebytes);
            let m_elements = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let mut out = Vec::with_capacity(n_elements.len());
            for (n_elem, m_elem) in n_elements.into_iter().zip(m_elements.into_iter()) {
                let result = if unsigned {
                    let lhs = n_elem;
                    let rhs = m_elem;
                    let value = match insn.mnemonic {
                        Mnemonic::VHADD => (lhs + rhs) >> 1,
                        Mnemonic::VRHADD => (lhs + rhs + 1) >> 1,
                        Mnemonic::VHSUB => ((lhs.wrapping_sub(rhs)) & mask) >> 1,
                        _ => return ExecResult::Undefined,
                    };
                    value
                } else {
                    let lhs = Self::neon_sign_extend_elem_u64(n_elem, size.bits());
                    let rhs = Self::neon_sign_extend_elem_u64(m_elem, size.bits());
                    let value = match insn.mnemonic {
                        Mnemonic::VHADD => (lhs + rhs) >> 1,
                        Mnemonic::VRHADD => (lhs + rhs + 1) >> 1,
                        Mnemonic::VHSUB => (lhs - rhs) >> 1,
                        _ => return ExecResult::Undefined,
                    };
                    Self::neon_pack_signed_elem_i128(value, size.bits())
                };
                out.push(result);
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_saturating_add_sub(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }

        let size = match (insn.raw >> 20) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            0b11 => NeonSize::D64,
            _ => return ExecResult::Undefined,
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

        for index in 0..regs {
            let n_elements = self.neon_read_vector_elements_u64(n + index, 1, ebytes);
            let m_elements = self.neon_read_vector_elements_u64(m + index, 1, ebytes);
            let mut out = Vec::with_capacity(n_elements.len());
            for (n_elem, m_elem) in n_elements.into_iter().zip(m_elements.into_iter()) {
                let (packed, saturated) = if unsigned {
                    let lhs = n_elem as i128;
                    let rhs = m_elem as i128;
                    let value = match insn.mnemonic {
                        Mnemonic::VQADD => lhs + rhs,
                        Mnemonic::VQSUB => lhs - rhs,
                        _ => return ExecResult::Undefined,
                    };
                    Self::neon_unsigned_saturate(value, size.bits())
                } else {
                    let lhs = Self::neon_sign_extend_elem_u64(n_elem, size.bits());
                    let rhs = Self::neon_sign_extend_elem_u64(m_elem, size.bits());
                    let value = match insn.mnemonic {
                        Mnemonic::VQADD => lhs + rhs,
                        Mnemonic::VQSUB => lhs - rhs,
                        _ => return ExecResult::Undefined,
                    };
                    let (result, saturated) = Self::neon_signed_saturate_i128(value, size.bits());
                    (
                        Self::neon_pack_signed_elem_i128(result, size.bits()),
                        saturated,
                    )
                };
                if saturated {
                    self.cpu.vfp.fpscr.set_qc(true);
                }
                out.push(packed);
            }
            self.neon_write_vector_elements_u64(d + index, 1, ebytes, &out);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_long_wide_add_sub(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 25) != 0b1111001
            || ((insn.raw >> 23) & 1) != 1
            || ((insn.raw >> 4) & 1) != 0
        {
            return ExecResult::Undefined;
        }

        let narrow_size = match (insn.raw >> 20) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        let narrow_ebytes = (narrow_size.bits() / 8) as u8;
        let wide_ebytes = narrow_ebytes * 2;
        let wide_bits = narrow_size.bits() * 2;
        let unsigned = ((insn.raw >> 24) & 1) != 0;
        let add = match insn.mnemonic {
            Mnemonic::VADDL | Mnemonic::VADDW => true,
            Mnemonic::VSUBL | Mnemonic::VSUBW => false,
            _ => return ExecResult::Undefined,
        };
        let wide_n = matches!(insn.mnemonic, Mnemonic::VADDW | Mnemonic::VSUBW);

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let n_bit = ((insn.raw >> 7) & 1) as u8;
        let vn = ((insn.raw >> 16) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;

        let d = (d_bit << 4) | vd;
        let n = (n_bit << 4) | vn;
        let m = (m_bit << 4) | vm;
        if (d & 1) != 0 || (wide_n && (n & 1) != 0) {
            return ExecResult::Undefined;
        }
        if d + 2 > 32 || m >= 32 || (!wide_n && n >= 32) || (wide_n && n + 2 > 32) {
            return ExecResult::Undefined;
        }

        let n_elements = if wide_n {
            self.neon_read_vector_elements_u64(n, 2, wide_ebytes)
        } else {
            self.neon_read_vector_elements_u64(n, 1, narrow_ebytes)
        };
        let m_elements = self.neon_read_vector_elements_u64(m, 1, narrow_ebytes);
        if n_elements.len() != m_elements.len() {
            return ExecResult::Undefined;
        }

        let mut out = Vec::with_capacity(n_elements.len());
        for (n_elem, m_elem) in n_elements.into_iter().zip(m_elements.into_iter()) {
            let lhs = if unsigned {
                n_elem as i128
            } else {
                let bits = if wide_n {
                    wide_bits
                } else {
                    narrow_size.bits()
                };
                Self::neon_sign_extend_elem_u64(n_elem, bits) as i128
            };
            let rhs = if unsigned {
                m_elem as i128
            } else {
                Self::neon_sign_extend_elem_u64(m_elem, narrow_size.bits()) as i128
            };
            let value = if add { lhs + rhs } else { lhs - rhs };
            out.push(Self::neon_pack_signed_elem_i128(value, wide_bits));
        }

        self.neon_write_vector_elements_u64(d, 2, wide_ebytes, &out);
        ExecResult::Continue
    }

    pub(crate) fn exec_neon_narrow_add_sub(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 25) != 0b1111001
            || ((insn.raw >> 23) & 1) != 1
            || ((insn.raw >> 6) & 1) != 0
            || ((insn.raw >> 4) & 1) != 0
        {
            return ExecResult::Undefined;
        }

        let dest_size = match (insn.raw >> 20) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        let dest_ebytes = (dest_size.bits() / 8) as u8;
        let source_ebytes = dest_ebytes * 2;
        let source_bits = dest_size.bits() * 2;
        let round = ((insn.raw >> 24) & 1) != 0;
        let add = match insn.mnemonic {
            Mnemonic::VADDHN | Mnemonic::VRADDHN => true,
            Mnemonic::VSUBHN | Mnemonic::VRSUBHN => false,
            _ => return ExecResult::Undefined,
        };

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let n_bit = ((insn.raw >> 7) & 1) as u8;
        let vn = ((insn.raw >> 16) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;

        let d = (d_bit << 4) | vd;
        let n = (n_bit << 4) | vn;
        let m = (m_bit << 4) | vm;
        if (n & 1) != 0 || (m & 1) != 0 {
            return ExecResult::Undefined;
        }
        if d >= 32 || n + 2 > 32 || m + 2 > 32 {
            return ExecResult::Undefined;
        }

        let mask = if source_bits == 64 {
            u64::MAX as u128
        } else {
            (1u128 << source_bits) - 1
        };
        let round_const = if round {
            1u128 << (dest_size.bits() - 1)
        } else {
            0
        };

        let n_elements = self.neon_read_vector_elements_u64(n, 2, source_ebytes);
        let m_elements = self.neon_read_vector_elements_u64(m, 2, source_ebytes);
        if n_elements.len() != m_elements.len() {
            return ExecResult::Undefined;
        }

        let mut out = Vec::with_capacity(n_elements.len());
        for (n_elem, m_elem) in n_elements.into_iter().zip(m_elements.into_iter()) {
            let value = if add {
                (n_elem as u128)
                    .wrapping_add(m_elem as u128)
                    .wrapping_add(round_const)
            } else {
                (n_elem as u128)
                    .wrapping_sub(m_elem as u128)
                    .wrapping_add(round_const)
            } & mask;
            out.push((value >> dest_size.bits()) as u64);
        }

        self.neon_write_vector_elements_u64(d, 1, dest_ebytes, &out);
        ExecResult::Continue
    }
}
