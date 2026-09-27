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
        if !self.cpu.vfp.is_enabled() {
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
        if !self.cpu.vfp.is_enabled() {
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
        if !self.cpu.vfp.is_enabled() {
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
        if !self.cpu.vfp.is_enabled() {
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
        if !self.cpu.vfp.is_enabled() {
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
        if !self.cpu.vfp.is_enabled() {
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
        if !self.cpu.vfp.is_enabled() {
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

        if !self.cpu.vfp.is_enabled() {
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
        if !self.cpu.vfp.is_enabled() {
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
        if !self.cpu.vfp.is_enabled() {
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
        if !self.cpu.vfp.is_enabled() {
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
        if !self.cpu.vfp.is_enabled() {
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
        if !self.cpu.vfp.is_enabled() {
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
        if !self.cpu.vfp.is_enabled() {
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
        if !self.cpu.vfp.is_enabled() {
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
        if !self.cpu.vfp.is_enabled() {
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
        if !self.cpu.vfp.is_enabled() {
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

    pub(crate) fn exec_vmul(&mut self, insn: &DecodedInsn) -> ExecResult {
        if Self::is_neon_fp_multiply_shape(insn.raw)
            || Self::is_neon_fp_multiply_scalar_shape(insn.raw)
        {
            return self.exec_neon_fp_multiply(insn);
        }
        if Self::is_neon_polynomial_multiply_shape(insn.raw) {
            return self.exec_neon_polynomial_multiply(insn);
        }
        if Self::is_neon_integer_multiply_shape(insn.raw)
            || Self::is_neon_integer_multiply_scalar_shape(insn.raw)
        {
            return self.exec_neon_integer_multiply(insn);
        }

        self.exec_vfp_binop(insn)
    }

    pub(crate) fn exec_vmla_vmls(&mut self, insn: &DecodedInsn) -> ExecResult {
        if Self::is_neon_fp_multiply_shape(insn.raw)
            || Self::is_neon_fp_multiply_scalar_shape(insn.raw)
            || Self::is_neon_fp_fma_shape(insn.raw)
        {
            return self.exec_neon_fp_multiply(insn);
        }
        if Self::is_neon_integer_multiply_shape(insn.raw)
            || Self::is_neon_integer_multiply_scalar_shape(insn.raw)
        {
            return self.exec_neon_integer_multiply(insn);
        }
        if Self::is_neon_long_multiply_shape(insn.raw) {
            return self.exec_neon_long_multiply(insn);
        }
        if Self::is_neon_long_multiply_scalar_shape(insn.raw) {
            return self.exec_neon_long_multiply(insn);
        }

        self.exec_vfp_accop(insn)
    }

    pub(crate) fn exec_neon_polynomial_multiply(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if !Self::is_neon_polynomial_multiply_shape(insn.raw) {
            return ExecResult::Undefined;
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

        for reg in 0..regs {
            let n_elements = self.neon_read_vector_elements_u64(n + reg, 1, 1);
            let m_elements = self.neon_read_vector_elements_u64(m + reg, 1, 1);
            let mut out = Vec::with_capacity(n_elements.len());
            for (n_elem, m_elem) in n_elements.into_iter().zip(m_elements.into_iter()) {
                out.push(u64::from(
                    Self::neon_polynomial_mul_u8(n_elem as u8, m_elem as u8) as u8,
                ));
            }
            self.neon_write_vector_elements_u64(d + reg, 1, 1, &out);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_integer_multiply(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        let scalar = Self::is_neon_integer_multiply_scalar_shape(insn.raw);
        if !Self::is_neon_integer_multiply_shape(insn.raw) && !scalar {
            return ExecResult::Undefined;
        }

        let size = match (insn.raw >> 20) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        let ebytes = (size.bits() / 8) as u8;
        let (accumulate, subtract) = if scalar {
            match (insn.raw >> 8) & 0xF {
                0b0000 => (true, false),
                0b0100 => (true, true),
                0b1000 => (false, false),
                _ => return ExecResult::Undefined,
            }
        } else {
            let accumulate = ((insn.raw >> 4) & 1) == 0;
            let subtract = ((insn.raw >> 24) & 1) != 0;
            if !accumulate && subtract {
                return ExecResult::Undefined;
            }
            (accumulate, subtract)
        };

        match (insn.mnemonic, accumulate, subtract) {
            (Mnemonic::VMUL, false, false)
            | (Mnemonic::VMLA, true, false)
            | (Mnemonic::VMLS, true, true) => {}
            _ => return ExecResult::Undefined,
        }

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let n_bit = ((insn.raw >> 7) & 1) as u8;
        let vn = ((insn.raw >> 16) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;
        let q = if scalar {
            ((insn.raw >> 24) & 1) != 0
        } else {
            ((insn.raw >> 6) & 1) != 0
        };
        let regs = if q { 2 } else { 1 };

        let d = (d_bit << 4) | vd;
        let n = (n_bit << 4) | vn;
        let m = (m_bit << 4) | vm;
        if q && ((d | n | if scalar { 0 } else { m }) & 1) != 0 {
            return ExecResult::Undefined;
        }
        if d + regs > 32 || n + regs > 32 || (!scalar && m + regs > 32) {
            return ExecResult::Undefined;
        }

        let scalar_elem = if scalar {
            let (scalar_reg, scalar_index) = match size {
                NeonSize::H16 => (vm & 0x7, (m_bit << 1) | (vm >> 3)),
                NeonSize::S32 => (vm, m_bit),
                _ => return ExecResult::Undefined,
            };
            if scalar_reg >= 32 || scalar_index as usize >= size.elements_per_d() {
                return ExecResult::Undefined;
            }
            Some(self.neon_read_d_elem_u64(scalar_reg, scalar_index, ebytes))
        } else {
            None
        };

        let mask = if size.bits() == 32 {
            u64::from(u32::MAX)
        } else {
            (1u64 << size.bits()) - 1
        };

        for reg in 0..regs {
            let n_elements = self.neon_read_vector_elements_u64(n + reg, 1, ebytes);
            let m_elements = if let Some(elem) = scalar_elem {
                vec![elem; n_elements.len()]
            } else {
                self.neon_read_vector_elements_u64(m + reg, 1, ebytes)
            };
            let d_elements = if accumulate {
                self.neon_read_vector_elements_u64(d + reg, 1, ebytes)
            } else {
                vec![0; n_elements.len()]
            };
            let mut out = Vec::with_capacity(n_elements.len());
            for ((n_elem, m_elem), d_elem) in n_elements
                .into_iter()
                .zip(m_elements.into_iter())
                .zip(d_elements.into_iter())
            {
                let product = n_elem.wrapping_mul(m_elem) & mask;
                let result = if accumulate {
                    if subtract {
                        d_elem.wrapping_sub(product)
                    } else {
                        d_elem.wrapping_add(product)
                    }
                } else {
                    product
                } & mask;
                out.push(result);
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_long_multiply(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if Self::is_neon_polynomial_multiply_long_shape(insn.raw) {
            return self.exec_neon_polynomial_multiply_long(insn);
        }
        let scalar = Self::is_neon_long_multiply_scalar_shape(insn.raw);
        if !Self::is_neon_long_multiply_shape(insn.raw) && !scalar {
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
        let saturating_doubling = matches!(
            insn.mnemonic,
            Mnemonic::VQDMULL | Mnemonic::VQDMLAL | Mnemonic::VQDMLSL
        );
        if scalar && narrow_size == NeonSize::B8 {
            return ExecResult::Undefined;
        }
        if saturating_doubling && narrow_size == NeonSize::B8 {
            return ExecResult::Undefined;
        }
        let unsigned = ((insn.raw >> 24) & 1) != 0 && !saturating_doubling;
        if scalar && saturating_doubling && ((insn.raw >> 24) & 1) != 0 {
            return ExecResult::Undefined;
        }
        let (accumulate, subtract) = match (insn.mnemonic, scalar, (insn.raw >> 8) & 0xF) {
            (Mnemonic::VMLAL, true, 0b0010) => (true, false),
            (Mnemonic::VQDMLAL, true, 0b0011) => (true, false),
            (Mnemonic::VMLSL, true, 0b0110) => (true, true),
            (Mnemonic::VQDMLSL, true, 0b0111) => (true, true),
            (Mnemonic::VMULL, true, 0b1010) => (false, false),
            (Mnemonic::VQDMULL, true, 0b1011) => (false, false),
            (Mnemonic::VMULL | Mnemonic::VQDMULL, false, _) => (false, false),
            (Mnemonic::VMLAL | Mnemonic::VQDMLAL, false, _) => (true, false),
            (Mnemonic::VMLSL | Mnemonic::VQDMLSL, false, _) => (true, true),
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
        if (d & 1) != 0 || d + 2 > 32 || n >= 32 || m >= 32 {
            return ExecResult::Undefined;
        }

        let scalar_elem = if scalar {
            let (scalar_reg, scalar_index) = match narrow_size {
                NeonSize::H16 => (vm & 0x7, (m_bit << 1) | (vm >> 3)),
                NeonSize::S32 => (vm, m_bit),
                _ => return ExecResult::Undefined,
            };
            if scalar_reg >= 32 || scalar_index as usize >= narrow_size.elements_per_d() {
                return ExecResult::Undefined;
            }
            Some(self.neon_read_d_elem_u64(scalar_reg, scalar_index, narrow_ebytes))
        } else {
            None
        };

        let n_elements = self.neon_read_vector_elements_u64(n, 1, narrow_ebytes);
        let m_elements = if let Some(elem) = scalar_elem {
            vec![elem; n_elements.len()]
        } else {
            self.neon_read_vector_elements_u64(m, 1, narrow_ebytes)
        };
        let d_elements = if accumulate {
            self.neon_read_vector_elements_u64(d, 2, wide_ebytes)
        } else {
            vec![0; n_elements.len()]
        };
        if n_elements.len() != m_elements.len() || n_elements.len() != d_elements.len() {
            return ExecResult::Undefined;
        }

        let mut out = Vec::with_capacity(n_elements.len());
        for ((n_elem, m_elem), d_elem) in n_elements
            .into_iter()
            .zip(m_elements.into_iter())
            .zip(d_elements.into_iter())
        {
            let mut product = if unsigned {
                (n_elem as i128) * (m_elem as i128)
            } else {
                let lhs = Self::neon_sign_extend_elem_u64(n_elem, narrow_size.bits());
                let rhs = Self::neon_sign_extend_elem_u64(m_elem, narrow_size.bits());
                lhs * rhs
            };
            if saturating_doubling {
                product <<= 1;
            }
            let acc = if unsigned {
                d_elem as i128
            } else {
                Self::neon_sign_extend_elem_u64(d_elem, wide_bits)
            };
            let value = if accumulate {
                if subtract {
                    acc - product
                } else {
                    acc + product
                }
            } else {
                product
            };
            if saturating_doubling {
                let (value, saturated) = Self::neon_signed_saturate_i128(value, wide_bits);
                if saturated {
                    self.cpu.vfp.fpscr.set_qc(true);
                }
                out.push(Self::neon_pack_signed_elem_i128(value, wide_bits));
            } else {
                out.push(Self::neon_pack_signed_elem_i128(value, wide_bits));
            }
        }

        self.neon_write_vector_elements_u64(d, 2, wide_ebytes, &out);
        ExecResult::Continue
    }

    pub(crate) fn exec_neon_polynomial_multiply_long(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !Self::is_neon_polynomial_multiply_long_shape(insn.raw) {
            return ExecResult::Undefined;
        }

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let n_bit = ((insn.raw >> 7) & 1) as u8;
        let vn = ((insn.raw >> 16) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;

        let d = (d_bit << 4) | vd;
        let n = (n_bit << 4) | vn;
        let m = (m_bit << 4) | vm;
        if (d & 1) != 0 || d + 2 > 32 || n >= 32 || m >= 32 {
            return ExecResult::Undefined;
        }

        let n_elements = self.neon_read_vector_elements_u64(n, 1, 1);
        let m_elements = self.neon_read_vector_elements_u64(m, 1, 1);
        let mut out = Vec::with_capacity(n_elements.len());
        for (n_elem, m_elem) in n_elements.into_iter().zip(m_elements.into_iter()) {
            out.push(u64::from(Self::neon_polynomial_mul_u8(
                n_elem as u8,
                m_elem as u8,
            )));
        }
        self.neon_write_vector_elements_u64(d, 2, 2, &out);
        ExecResult::Continue
    }

    pub(crate) fn neon_polynomial_mul_u8(lhs: u8, rhs: u8) -> u16 {
        let mut product = 0u16;
        for bit in 0..8 {
            if ((rhs >> bit) & 1) != 0 {
                product ^= (lhs as u16) << bit;
            }
        }
        product
    }

    pub(crate) fn exec_neon_saturating_doubling_mulh(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }

        let scalar = ((insn.raw >> 23) & 1) != 0;
        let size = match (insn.raw >> 20) & 0x3 {
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        let ebytes = (size.bits() / 8) as u8;

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let n_bit = ((insn.raw >> 7) & 1) as u8;
        let vn = ((insn.raw >> 16) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;
        let q = if scalar {
            ((insn.raw >> 24) & 1) != 0
        } else {
            ((insn.raw >> 6) & 1) != 0
        };
        let regs = if q { 2 } else { 1 };

        let d = (d_bit << 4) | vd;
        let n = (n_bit << 4) | vn;
        let m = (m_bit << 4) | vm;
        if q && ((d | n | if scalar { 0 } else { m }) & 1) != 0 {
            return ExecResult::Undefined;
        }
        if d + regs > 32 || n + regs > 32 || (!scalar && m + regs > 32) {
            return ExecResult::Undefined;
        }

        let scalar_elem = if scalar {
            let (scalar_reg, scalar_index) = match size {
                NeonSize::H16 => (vm & 0x7, (m_bit << 1) | (vm >> 3)),
                NeonSize::S32 => (vm, m_bit),
                _ => return ExecResult::Undefined,
            };
            if scalar_reg >= 32 || scalar_index as usize >= size.elements_per_d() {
                return ExecResult::Undefined;
            }
            Some(self.neon_read_d_elem_u64(scalar_reg, scalar_index, ebytes))
        } else {
            None
        };

        for index in 0..regs {
            let n_elements = self.neon_read_vector_elements_u64(n + index, 1, ebytes);
            let m_elements = if let Some(elem) = scalar_elem {
                vec![elem; n_elements.len()]
            } else {
                self.neon_read_vector_elements_u64(m + index, 1, ebytes)
            };
            let mut out = Vec::with_capacity(n_elements.len());
            for (n_elem, m_elem) in n_elements.into_iter().zip(m_elements.into_iter()) {
                let (packed, saturated) = Self::neon_doubling_mulh_elem(
                    n_elem,
                    m_elem,
                    size.bits(),
                    insn.mnemonic == Mnemonic::VQRDMULH,
                );
                if saturated {
                    self.cpu.vfp.fpscr.set_qc(true);
                }
                out.push(packed);
            }
            self.neon_write_vector_elements_u64(d + index, 1, ebytes, &out);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_count_register(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }

        let size = match (insn.raw >> 18) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        if insn.mnemonic == Mnemonic::VCNT && size != NeonSize::B8 {
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
            let result = match insn.mnemonic {
                Mnemonic::VCLS => vcls_i(bits, size),
                Mnemonic::VCLZ => vclz_i(bits, size),
                Mnemonic::VCNT => vcnt_i8(bits),
                _ => return ExecResult::Undefined,
            };
            self.cpu.vfp.write_d_bits(d + index, result);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_recip_estimate(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 23) != 0b111100111
            || ((insn.raw >> 20) & 0x3) != 0b11
            || ((insn.raw >> 16) & 0x3) != 0b11
            || ((insn.raw >> 4) & 1) != 0
        {
            return ExecResult::Undefined;
        }

        let size = (insn.raw >> 18) & 0x3;
        let fp = match ((insn.raw >> 7) & 0x1F, insn.mnemonic) {
            (0b01000, Mnemonic::VRECPE) | (0b01001, Mnemonic::VRSQRTE) => false,
            (0b01010, Mnemonic::VRECPE) | (0b01011, Mnemonic::VRSQRTE) => true,
            _ => return ExecResult::Undefined,
        };
        if (!fp && size != 0b10) || (fp && !matches!(size, 0b01 | 0b10)) {
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

        let ebytes = if fp && size == 0b01 { 2 } else { 4 };
        for reg in 0..regs {
            let elements = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let mut out = Vec::with_capacity(elements.len());
            for elem in elements {
                let result = match (insn.mnemonic, fp) {
                    (Mnemonic::VRECPE, false) => {
                        u64::from(Self::neon_unsigned_recip_estimate(elem as u32))
                    }
                    (Mnemonic::VRSQRTE, false) => {
                        u64::from(Self::neon_unsigned_rsqrt_estimate(elem as u32))
                    }
                    (Mnemonic::VRECPE, true) if size == 0b01 => {
                        let input = vcvt_f32_f16_bits(elem as u16).to_bits();
                        let result = f32::from_bits(Self::neon_fp_recip_estimate_f32(input));
                        // The estimate uses StandardFPSCRValue and must not
                        // raise cumulative exceptions; discard the narrowing's
                        // flag side effects via a throwaway FPSCR.
                        let mut standard_fpscr = Fpscr::default();
                        u64::from(vcvt_f16_bits_f32(result, &mut standard_fpscr))
                    }
                    (Mnemonic::VRSQRTE, true) if size == 0b01 => {
                        let input = vcvt_f32_f16_bits(elem as u16).to_bits();
                        let result = f32::from_bits(Self::neon_fp_rsqrt_estimate_f32(input));
                        let mut standard_fpscr = Fpscr::default();
                        u64::from(vcvt_f16_bits_f32(result, &mut standard_fpscr))
                    }
                    (Mnemonic::VRECPE, true) => {
                        u64::from(Self::neon_fp_recip_estimate_f32(elem as u32))
                    }
                    (Mnemonic::VRSQRTE, true) => {
                        u64::from(Self::neon_fp_rsqrt_estimate_f32(elem as u32))
                    }
                    _ => return ExecResult::Undefined,
                };
                out.push(result);
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        ExecResult::Continue
    }

    pub(crate) fn neon_recip_estimate(a: u32) -> u32 {
        let a = a * 2 + 1;
        let b = (1u32 << 19) / a;
        (b + 1) >> 1
    }

    pub(crate) fn neon_recip_sqrt_estimate(mut a: u32) -> u32 {
        if a < 256 {
            a = a * 2 + 1;
        } else {
            a = (a >> 1) << 1;
            a = (a + 1) * 2;
        }
        let a = a as u64;
        let mut b: u64 = 512;
        while a * (b + 1) * (b + 1) < (1u64 << 28) {
            b += 1;
        }
        ((b + 1) >> 1) as u32
    }

    pub(crate) fn neon_unsigned_recip_estimate(op: u32) -> u32 {
        if op & 0x8000_0000 == 0 {
            return u32::MAX;
        }
        let estimate = Self::neon_recip_estimate((op >> 23) & 0x1FF);
        (estimate & 0x1FF) << 23
    }

    pub(crate) fn neon_unsigned_rsqrt_estimate(op: u32) -> u32 {
        if op & 0xC000_0000 == 0 {
            return u32::MAX;
        }
        let estimate = Self::neon_recip_sqrt_estimate((op >> 23) & 0x1FF);
        (estimate & 0x1FF) << 23
    }

    pub(crate) fn exec_neon_vext(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let n_bit = ((insn.raw >> 7) & 1) as u8;
        let vn = ((insn.raw >> 16) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;
        let q = ((insn.raw >> 6) & 1) != 0;
        let imm = ((insn.raw >> 8) & 0xF) as usize;
        let regs = if q { 2 } else { 1 };

        let d = (d_bit << 4) | vd;
        let n = (n_bit << 4) | vn;
        let m = (m_bit << 4) | vm;
        if (!q && imm > 7) || (q && ((d | n | m) & 1) != 0) {
            return ExecResult::Undefined;
        }
        if d + regs > 32 || n + regs > 32 || m + regs > 32 {
            return ExecResult::Undefined;
        }

        let bytes = regs as usize * 8;
        let mut source = [0u8; 32];
        for index in 0..regs {
            let offset = index as usize * 8;
            source[offset..offset + 8]
                .copy_from_slice(&self.cpu.vfp.read_d_bits(n + index).to_le_bytes());
            source[bytes + offset..bytes + offset + 8]
                .copy_from_slice(&self.cpu.vfp.read_d_bits(m + index).to_le_bytes());
        }

        for index in 0..regs {
            let offset = index as usize * 8;
            let mut out = [0u8; 8];
            out.copy_from_slice(&source[imm + offset..imm + offset + 8]);
            self.cpu
                .vfp
                .write_d_bits(d + index, u64::from_le_bytes(out));
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_table_lookup(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }

        let d_bit = ((insn.raw >> 22) & 1) as u8;
        let vd = ((insn.raw >> 12) & 0xF) as u8;
        let n_bit = ((insn.raw >> 7) & 1) as u8;
        let vn = ((insn.raw >> 16) & 0xF) as u8;
        let m_bit = ((insn.raw >> 5) & 1) as u8;
        let vm = (insn.raw & 0xF) as u8;
        let length = (((insn.raw >> 8) & 0x3) as u8) + 1;

        let d = (d_bit << 4) | vd;
        let n = (n_bit << 4) | vn;
        let m = (m_bit << 4) | vm;
        if d >= 32 || m >= 32 || n + length > 32 {
            return ExecResult::Undefined;
        }

        let mut table = [0u8; 32];
        for reg in 0..length {
            let offset = reg as usize * 8;
            table[offset..offset + 8]
                .copy_from_slice(&self.cpu.vfp.read_d_bits(n + reg).to_le_bytes());
        }

        let indexes = self.cpu.vfp.read_d_bits(m).to_le_bytes();
        let mut out = self.cpu.vfp.read_d_bits(d).to_le_bytes();
        let table_len = length as usize * 8;
        for lane in 0..8 {
            let index = indexes[lane] as usize;
            if index < table_len {
                out[lane] = table[index];
            } else if insn.mnemonic == Mnemonic::VTBL {
                out[lane] = 0;
            }
        }
        self.cpu.vfp.write_d_bits(d, u64::from_le_bytes(out));

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_minmax(&mut self, insn: &DecodedInsn) -> ExecResult {
        if (insn.raw >> 25) == 0b1111001
            && ((insn.raw >> 23) & 1) == 0
            && ((insn.raw >> 8) & 0xF) == 0b0110
        {
            return self.exec_neon_integer_minmax(insn);
        }

        self.exec_neon_fp_minmax(insn)
    }

    pub(crate) fn exec_neon_integer_minmax(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 25) != 0b1111001
            || ((insn.raw >> 23) & 1) != 0
            || ((insn.raw >> 8) & 0xF) != 0b0110
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

        for reg in 0..regs {
            let n_elements = self.neon_read_vector_elements_u64(n + reg, 1, ebytes);
            let m_elements = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let mut out = Vec::with_capacity(n_elements.len());
            for (n_elem, m_elem) in n_elements.into_iter().zip(m_elements.into_iter()) {
                let result = if unsigned {
                    match insn.mnemonic {
                        Mnemonic::VMAX => n_elem.max(m_elem),
                        Mnemonic::VMIN => n_elem.min(m_elem),
                        _ => return ExecResult::Undefined,
                    }
                } else {
                    let lhs = Self::neon_sign_extend_elem_u64(n_elem, size.bits());
                    let rhs = Self::neon_sign_extend_elem_u64(m_elem, size.bits());
                    let value = match insn.mnemonic {
                        Mnemonic::VMAX => lhs.max(rhs),
                        Mnemonic::VMIN => lhs.min(rhs),
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

    pub(crate) fn exec_neon_integer_compare(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 25) != 0b1111001 || ((insn.raw >> 23) & 1) != 0 {
            return ExecResult::Undefined;
        }

        let op8 = (insn.raw >> 8) & 0xF;
        let bit4 = (insn.raw >> 4) & 1;
        let bit24 = (insn.raw >> 24) & 1;
        match (insn.mnemonic, op8, bit4, bit24) {
            (Mnemonic::VTST, 0b1000, 1, 0)
            | (Mnemonic::VCEQ, 0b1000, 1, 1)
            | (Mnemonic::VCGT, 0b0011, 0, _)
            | (Mnemonic::VCGE, 0b0011, 1, _) => {}
            _ => return ExecResult::Undefined,
        }

        let size = match (insn.raw >> 20) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        let ebytes = (size.bits() / 8) as u8;
        let unsigned = bit24 != 0;

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

        let true_mask = if size.bits() == 32 {
            u64::from(u32::MAX)
        } else {
            (1u64 << size.bits()) - 1
        };
        for reg in 0..regs {
            let n_elements = self.neon_read_vector_elements_u64(n + reg, 1, ebytes);
            let m_elements = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let mut out = Vec::with_capacity(n_elements.len());
            for (n_elem, m_elem) in n_elements.into_iter().zip(m_elements.into_iter()) {
                let condition = match insn.mnemonic {
                    Mnemonic::VTST => (n_elem & m_elem) != 0,
                    Mnemonic::VCEQ => n_elem == m_elem,
                    Mnemonic::VCGT if unsigned => n_elem > m_elem,
                    Mnemonic::VCGE if unsigned => n_elem >= m_elem,
                    Mnemonic::VCGT => {
                        let lhs = Self::neon_sign_extend_elem_u64(n_elem, size.bits());
                        let rhs = Self::neon_sign_extend_elem_u64(m_elem, size.bits());
                        lhs > rhs
                    }
                    Mnemonic::VCGE => {
                        let lhs = Self::neon_sign_extend_elem_u64(n_elem, size.bits());
                        let rhs = Self::neon_sign_extend_elem_u64(m_elem, size.bits());
                        lhs >= rhs
                    }
                    _ => return ExecResult::Undefined,
                };
                out.push(if condition { true_mask } else { 0 });
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_compare(&mut self, insn: &DecodedInsn) -> ExecResult {
        if (insn.raw >> 23) == 0b111100111
            && ((insn.raw >> 20) & 0x3) == 0b11
            && ((insn.raw >> 16) & 0x3) == 0b01
            && matches!((insn.raw >> 10) & 0x3, 0 | 1)
            && ((insn.raw >> 4) & 1) == 0
        {
            return self.exec_neon_compare_zero(insn);
        }

        if (insn.raw >> 25) == 0b1111001
            && ((insn.raw >> 23) & 1) == 0
            && ((insn.raw >> 8) & 0xF) == 0b1110
        {
            return self.exec_neon_fp_compare(insn);
        }

        self.exec_neon_integer_compare(insn)
    }

    pub(crate) fn exec_neon_compare_zero(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 23) != 0b111100111
            || ((insn.raw >> 20) & 0x3) != 0b11
            || ((insn.raw >> 16) & 0x3) != 0b01
            || !matches!((insn.raw >> 10) & 0x3, 0 | 1)
            || ((insn.raw >> 4) & 1) != 0
        {
            return ExecResult::Undefined;
        }

        let op = (insn.raw >> 7) & 0x7;
        let fp = ((insn.raw >> 8) & 0x7) >= 0b100;
        match (insn.mnemonic, op) {
            (Mnemonic::VCGT, 0b000)
            | (Mnemonic::VCGE, 0b001)
            | (Mnemonic::VCEQ, 0b010)
            | (Mnemonic::VCLE, 0b011)
            | (Mnemonic::VCLT, 0b100) => {}
            _ => return ExecResult::Undefined,
        }

        let size = match (insn.raw >> 18) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        if fp && !matches!(size, NeonSize::H16 | NeonSize::S32) {
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

        let true_mask = if size.bits() == 32 {
            u64::from(u32::MAX)
        } else {
            (1u64 << size.bits()) - 1
        };
        for reg in 0..regs {
            let elements = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let mut out = Vec::with_capacity(elements.len());
            for elem in elements {
                let condition = if fp {
                    let value = match size {
                        NeonSize::H16 => vcvt_f32_f16_bits(elem as u16),
                        NeonSize::S32 => f32::from_bits(elem as u32),
                        _ => return ExecResult::Undefined,
                    };
                    match insn.mnemonic {
                        Mnemonic::VCGT => value > 0.0,
                        Mnemonic::VCGE => value >= 0.0,
                        Mnemonic::VCEQ => value == 0.0,
                        Mnemonic::VCLE => value <= 0.0,
                        Mnemonic::VCLT => value < 0.0,
                        _ => return ExecResult::Undefined,
                    }
                } else {
                    let value = Self::neon_sign_extend_elem_u64(elem, size.bits());
                    match insn.mnemonic {
                        Mnemonic::VCGT => value > 0,
                        Mnemonic::VCGE => value >= 0,
                        Mnemonic::VCEQ => value == 0,
                        Mnemonic::VCLE => value <= 0,
                        Mnemonic::VCLT => value < 0,
                        _ => return ExecResult::Undefined,
                    }
                };
                out.push(if condition { true_mask } else { 0 });
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_recip_step(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 25) != 0b1111001
            || ((insn.raw >> 24) & 1) != 0
            || ((insn.raw >> 23) & 1) != 0
            || ((insn.raw >> 8) & 0xF) != 0b1111
            || ((insn.raw >> 4) & 1) != 1
        {
            return ExecResult::Undefined;
        }

        match (insn.mnemonic, (insn.raw >> 21) & 1) {
            (Mnemonic::VRECPS, 0) | (Mnemonic::VRSQRTS, 1) => {}
            _ => return ExecResult::Undefined,
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

        let size = if ((insn.raw >> 20) & 1) == 0 {
            NeonSize::S32
        } else {
            NeonSize::H16
        };
        let ebytes = (size.bits() / 8) as u8;

        for reg in 0..regs {
            let n_elements = self.neon_read_vector_elements_u64(n + reg, 1, ebytes);
            let m_elements = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let mut out = Vec::with_capacity(n_elements.len());
            for (n_elem, m_elem) in n_elements.into_iter().zip(m_elements.into_iter()) {
                let lhs = match size {
                    NeonSize::S32 => f32::from_bits(n_elem as u32),
                    NeonSize::H16 => vcvt_f32_f16_bits(n_elem as u16),
                    _ => return ExecResult::Undefined,
                };
                let rhs = match size {
                    NeonSize::S32 => f32::from_bits(m_elem as u32),
                    NeonSize::H16 => vcvt_f32_f16_bits(m_elem as u16),
                    _ => return ExecResult::Undefined,
                };
                let result = if lhs.is_nan() || rhs.is_nan() {
                    f32::NAN
                } else if insn.mnemonic == Mnemonic::VRECPS {
                    if (lhs.is_infinite() && rhs == 0.0) || (rhs.is_infinite() && lhs == 0.0) {
                        2.0
                    } else {
                        (-lhs).mul_add(rhs, 2.0)
                    }
                } else if (lhs.is_infinite() && rhs == 0.0) || (rhs.is_infinite() && lhs == 0.0) {
                    1.5
                } else {
                    (-lhs).mul_add(rhs, 3.0) * 0.5
                };
                let result = match size {
                    NeonSize::S32 => u64::from(result.to_bits()),
                    NeonSize::H16 => u64::from(vcvt_f16_bits_f32(result, &mut self.cpu.vfp.fpscr)),
                    _ => return ExecResult::Undefined,
                };
                out.push(result);
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_absdiff(&mut self, insn: &DecodedInsn) -> ExecResult {
        if (insn.raw >> 25) == 0b1111001
            && ((insn.raw >> 23) & 1) == 0
            && ((insn.raw >> 8) & 0xF) == 0b0111
        {
            return self.exec_neon_integer_absdiff_accum(insn);
        }

        self.exec_neon_fp_absdiff(insn)
    }

    pub(crate) fn exec_neon_integer_absdiff_accum(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 25) != 0b1111001
            || ((insn.raw >> 23) & 1) != 0
            || ((insn.raw >> 8) & 0xF) != 0b0111
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
        let accumulate = match insn.mnemonic {
            Mnemonic::VABD => false,
            Mnemonic::VABA => true,
            _ => return ExecResult::Undefined,
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

        let mask = if size.bits() == 32 {
            u64::from(u32::MAX)
        } else {
            (1u64 << size.bits()) - 1
        };

        for reg in 0..regs {
            let n_elements = self.neon_read_vector_elements_u64(n + reg, 1, ebytes);
            let m_elements = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let d_elements = if accumulate {
                self.neon_read_vector_elements_u64(d + reg, 1, ebytes)
            } else {
                vec![0; n_elements.len()]
            };
            let mut out = Vec::with_capacity(n_elements.len());
            for ((n_elem, m_elem), d_elem) in n_elements
                .into_iter()
                .zip(m_elements.into_iter())
                .zip(d_elements.into_iter())
            {
                let diff = if unsigned {
                    n_elem.abs_diff(m_elem)
                } else {
                    let lhs = Self::neon_sign_extend_elem_u64(n_elem, size.bits());
                    let rhs = Self::neon_sign_extend_elem_u64(m_elem, size.bits());
                    lhs.abs_diff(rhs) as u64
                };
                let result = if accumulate {
                    d_elem.wrapping_add(diff) & mask
                } else {
                    diff & mask
                };
                out.push(result);
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_neon_integer_absdiff_long(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if (insn.raw >> 25) != 0b1111001
            || ((insn.raw >> 23) & 1) != 1
            || ((insn.raw >> 4) & 1) != 0
        {
            return ExecResult::Undefined;
        }

        let accumulate = match ((insn.raw >> 8) & 0xF, insn.mnemonic) {
            (0b0111, Mnemonic::VABDL) => false,
            (0b0101, Mnemonic::VABAL) => true,
            _ => return ExecResult::Undefined,
        };

        let size = match (insn.raw >> 20) & 0x3 {
            0b00 => NeonSize::B8,
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        let src_ebytes = (size.bits() / 8) as u8;
        let dest_ebytes = src_ebytes * 2;
        let dest_bits = size.bits() * 2;
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
        if (d & 1) != 0 || ((insn.raw >> 6) & 1) != 0 {
            return ExecResult::Undefined;
        }
        if d + 2 > 32 || n >= 32 || m >= 32 {
            return ExecResult::Undefined;
        }

        let n_elements = self.neon_read_vector_elements_u64(n, 1, src_ebytes);
        let m_elements = self.neon_read_vector_elements_u64(m, 1, src_ebytes);
        let d_elements = if accumulate {
            self.neon_read_vector_elements_u64(d, 2, dest_ebytes)
        } else {
            vec![0; n_elements.len()]
        };
        let mask = if dest_bits == 64 {
            u64::MAX
        } else {
            (1u64 << dest_bits) - 1
        };

        let mut out = Vec::with_capacity(n_elements.len());
        for ((n_elem, m_elem), d_elem) in n_elements
            .into_iter()
            .zip(m_elements.into_iter())
            .zip(d_elements.into_iter())
        {
            let diff = if unsigned {
                n_elem.abs_diff(m_elem)
            } else {
                let lhs = Self::neon_sign_extend_elem_u64(n_elem, size.bits());
                let rhs = Self::neon_sign_extend_elem_u64(m_elem, size.bits());
                lhs.abs_diff(rhs) as u64
            };
            let result = if accumulate {
                d_elem.wrapping_add(diff)
            } else {
                diff
            };
            out.push(result & mask);
        }
        self.neon_write_vector_elements_u64(d, 2, dest_ebytes, &out);

        ExecResult::Continue
    }

    pub(crate) fn exec_vmov(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if Self::is_neon_modified_immediate_shape(insn.raw) {
            return self.exec_neon_modified_immediate(insn);
        }
        if ((insn.raw >> 4) & 1) == 1
            && matches!((insn.raw >> 8) & 0xF, 0b1010 | 0b1011)
            && ((insn.raw >> 21) & 0x7) == 0b010
            && (insn.raw & 0xC0) == 0
        {
            let rt = ((insn.raw >> 12) & 0xF) as usize;
            let rt2 = ((insn.raw >> 16) & 0xF) as usize;
            if rt == 15 || rt2 == 15 {
                return ExecResult::Undefined;
            }
            let coproc = (insn.raw >> 8) & 0xF;
            let to_core = ((insn.raw >> 20) & 1) == 1;
            if coproc == 0b1010 {
                let sreg = ((insn.raw & 0xF) as u8) << 1;
                if to_core {
                    self.cpu.regs[rt] = self.cpu.vfp.read_s_bits(sreg);
                    self.cpu.regs[rt2] = self.cpu.vfp.read_s_bits(sreg + 1);
                } else {
                    let lo = self.reg(rt);
                    let hi = self.reg(rt2);
                    self.cpu.vfp.write_s_bits(sreg, lo);
                    self.cpu.vfp.write_s_bits(sreg + 1, hi);
                }
            } else {
                let dreg = (((insn.raw >> 5) & 1) << 4) as u8 | (insn.raw & 0xF) as u8;
                if to_core {
                    let bits = self.cpu.vfp.read_d_bits(dreg);
                    self.cpu.regs[rt] = bits as u32;
                    self.cpu.regs[rt2] = (bits >> 32) as u32;
                } else {
                    let bits = (self.reg(rt) as u64) | ((self.reg(rt2) as u64) << 32);
                    self.cpu.vfp.write_d_bits(dreg, bits);
                }
            }
            return ExecResult::Continue;
        }
        if ((insn.raw >> 4) & 1) == 1 && matches!((insn.raw >> 8) & 0xF, 0b1010 | 0b1011) {
            let rt = ((insn.raw >> 12) & 0xF) as usize;
            if rt == 15 {
                return ExecResult::Undefined;
            }
            let to_core = ((insn.raw >> 20) & 1) == 1;
            let coproc = (insn.raw >> 8) & 0xF;
            let opc1 = ((insn.raw >> 21) & 0x3) as u8;
            let opc2 = ((insn.raw >> 5) & 0x3) as u8;
            let v = ((insn.raw >> 16) & 0xF) as u8;
            if coproc == 0b1011 {
                let u = ((insn.raw >> 23) & 1) != 0;
                let dreg = ((((insn.raw >> 7) & 1) << 4) as u8) | v;
                let shape = if (opc1 & 0b10) != 0 {
                    Some((1, ((opc1 & 1) << 2) | opc2))
                } else if (opc2 & 1) != 0 {
                    Some((2, ((opc1 & 1) << 1) | (opc2 >> 1)))
                } else if !u && opc2 == 0 {
                    Some((4, opc1 & 1))
                } else {
                    None
                };
                let Some((ebytes, lane)) = shape else {
                    return ExecResult::Undefined;
                };

                if to_core {
                    let elem = self.neon_read_d_elem_u64(dreg, lane, ebytes);
                    self.cpu.regs[rt] = if u {
                        elem as u32
                    } else if ebytes < 4 {
                        Self::neon_sign_extend_elem_u64(elem, ebytes as u32 * 8) as u32
                    } else {
                        elem as u32
                    };
                } else {
                    if u {
                        return ExecResult::Undefined;
                    }
                    self.neon_write_d_elem_u64(dreg, lane, ebytes, self.reg(rt) as u64);
                }
            } else if coproc == 0b1010 {
                if opc2 != 0 || (opc1 & 0b10) != 0 {
                    return ExecResult::Undefined;
                }
                if opc1 != 0 || (insn.raw & 0xF) != 0 {
                    return ExecResult::Undefined;
                }
                let sreg = (v << 1) | (((insn.raw >> 7) & 1) as u8);
                if to_core {
                    self.cpu.regs[rt] = self.cpu.vfp.read_s_bits(sreg);
                } else {
                    let value = self.reg(rt);
                    self.cpu.vfp.write_s_bits(sreg, value);
                }
            } else {
                return ExecResult::Undefined;
            }
            return ExecResult::Continue;
        }

        if ((insn.raw >> 4) & 1) == 0
            && ((insn.raw >> 23) & 1) == 1
            && ((insn.raw >> 21) & 1) == 1
            && ((insn.raw >> 20) & 1) == 1
            && ((insn.raw >> 7) & 1) == 0
            && ((insn.raw >> 6) & 1) == 0
        {
            let size = (insn.raw >> 8) & 0x3;
            let vd = ((insn.raw >> 12) & 0xF) as u8;
            let d_bit = ((insn.raw >> 22) & 1) as u8;
            let imm8 = ((((insn.raw >> 16) & 0xF) << 4) | (insn.raw & 0xF)) as u8;
            return match size {
                1 => {
                    self.cpu
                        .vfp
                        .write_h_bits((vd << 1) | d_bit, vfp_expand_imm_f16(imm8));
                    ExecResult::Continue
                }
                2 => {
                    self.cpu
                        .vfp
                        .write_s_bits((vd << 1) | d_bit, vfp_expand_imm_f32(imm8));
                    ExecResult::Continue
                }
                3 => {
                    self.cpu
                        .vfp
                        .write_d_bits((d_bit << 4) | vd, vfp_expand_imm_f64(imm8));
                    ExecResult::Continue
                }
                _ => ExecResult::Undefined,
            };
        }

        let Some((d, m, size)) = self.decode_vfp_unary_regs(insn) else {
            return ExecResult::Undefined;
        };
        match size {
            16 => {
                let bits = self.cpu.vfp.read_h_bits(m);
                self.cpu.vfp.write_h_bits(d, bits);
            }
            32 => {
                let bits = self.cpu.vfp.read_s_bits(m);
                self.cpu.vfp.write_s_bits(d, bits);
            }
            64 => {
                let bits = self.cpu.vfp.read_d_bits(m);
                self.cpu.vfp.write_d_bits(d, bits);
            }
            _ => return ExecResult::Undefined,
        }
        ExecResult::Continue
    }

    pub(crate) fn neon_expand_modified_immediate(raw: u32) -> Option<u64> {
        let cmode = (raw >> 8) & 0xF;
        let imm8 = ((((raw >> 24) & 1) << 7) | (((raw >> 16) & 0x7) << 4) | (raw & 0xF)) as u64;

        let imm32 = match cmode {
            0b0000 | 0b0001 => imm8 as u32,
            0b0010 | 0b0011 => (imm8 << 8) as u32,
            0b0100 | 0b0101 => (imm8 << 16) as u32,
            0b0110 | 0b0111 => (imm8 << 24) as u32,
            0b1000 | 0b1001 => {
                let imm16 = imm8 as u32;
                imm16 | (imm16 << 16)
            }
            0b1010 | 0b1011 => {
                let imm16 = (imm8 << 8) as u32;
                imm16 | (imm16 << 16)
            }
            0b1100 => ((imm8 << 8) | 0xFF) as u32,
            0b1101 => ((imm8 << 16) | 0xFFFF) as u32,
            0b1110 if ((raw >> 5) & 1) == 0 => {
                let byte = imm8 as u32;
                byte | (byte << 8) | (byte << 16) | (byte << 24)
            }
            0b1110 => {
                let mut imm64 = 0u64;
                for byte in 0..8 {
                    if ((imm8 >> byte) & 1) != 0 {
                        imm64 |= 0xFFu64 << (byte * 8);
                    }
                }
                return Some(imm64);
            }
            0b1111 if ((raw >> 5) & 1) == 0 => vfp_expand_imm_f32(imm8 as u8),
            _ => return None,
        };

        Some(u64::from(imm32) | (u64::from(imm32) << 32))
    }

    pub(crate) fn exec_neon_modified_immediate(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }

        let Some(imm) = Self::neon_expand_modified_immediate(insn.raw) else {
            return ExecResult::Undefined;
        };
        let d = (((insn.raw >> 22) & 1) << 4 | ((insn.raw >> 12) & 0xF)) as u8;
        let q = ((insn.raw >> 6) & 1) != 0;
        let regs = if q { 2 } else { 1 };
        if q && (d & 1) != 0 {
            return ExecResult::Undefined;
        }
        if d + regs > 32 {
            return ExecResult::Undefined;
        }

        for index in 0..regs {
            let old = self.cpu.vfp.read_d_bits(d + index);
            let result = match insn.mnemonic {
                Mnemonic::VMOV => imm,
                Mnemonic::VMVN => !imm,
                Mnemonic::VORR => old | imm,
                Mnemonic::VBIC => old & !imm,
                _ => return ExecResult::Undefined,
            };
            self.cpu.vfp.write_d_bits(d + index, result);
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_vfp_binop(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        let Some((d, n, m, size)) = self.decode_vfp_ternary_regs(insn) else {
            return ExecResult::Undefined;
        };
        match size {
            16 => {
                let n_val = self.cpu.vfp.read_h_bits(n);
                let m_val = self.cpu.vfp.read_h_bits(m);
                let fpscr = &mut self.cpu.vfp.fpscr;
                let result = match insn.mnemonic {
                    Mnemonic::VADD => vadd_f16_bits(n_val, m_val, fpscr),
                    Mnemonic::VSUB => vsub_f16_bits(n_val, m_val, fpscr),
                    Mnemonic::VMUL => vmul_f16_bits(n_val, m_val, fpscr),
                    Mnemonic::VDIV => vdiv_f16_bits(n_val, m_val, fpscr),
                    Mnemonic::VNMUL => vnmul_f16_bits(n_val, m_val, fpscr),
                    Mnemonic::VMAXNM_F16 => vmaxnm_f16_bits(n_val, m_val, fpscr),
                    Mnemonic::VMINNM_F16 => vminnm_f16_bits(n_val, m_val, fpscr),
                    _ => return ExecResult::Undefined,
                };
                self.cpu.vfp.write_h_bits(d, result);
            }
            32 => {
                let n_val = self.cpu.vfp.read_s(n);
                let m_val = self.cpu.vfp.read_s(m);
                let fpscr = &mut self.cpu.vfp.fpscr;
                let result = match insn.mnemonic {
                    Mnemonic::VADD => vadd_f32(n_val, m_val, fpscr),
                    Mnemonic::VSUB => vsub_f32(n_val, m_val, fpscr),
                    Mnemonic::VMUL => vmul_f32(n_val, m_val, fpscr),
                    Mnemonic::VDIV => vdiv_f32(n_val, m_val, fpscr),
                    Mnemonic::VNMUL => vnmul_f32(n_val, m_val, fpscr),
                    Mnemonic::VMAXNM_F32 => vmaxnm_f32(n_val, m_val, fpscr),
                    Mnemonic::VMINNM_F32 => vminnm_f32(n_val, m_val, fpscr),
                    _ => return ExecResult::Undefined,
                };
                self.cpu.vfp.write_s(d, result);
            }
            64 => {
                let n_val = self.cpu.vfp.read_d(n);
                let m_val = self.cpu.vfp.read_d(m);
                let fpscr = &mut self.cpu.vfp.fpscr;
                let result = match insn.mnemonic {
                    Mnemonic::VADD => vadd_f64(n_val, m_val, fpscr),
                    Mnemonic::VSUB => vsub_f64(n_val, m_val, fpscr),
                    Mnemonic::VMUL => vmul_f64(n_val, m_val, fpscr),
                    Mnemonic::VDIV => vdiv_f64(n_val, m_val, fpscr),
                    Mnemonic::VNMUL => vnmul_f64(n_val, m_val, fpscr),
                    Mnemonic::VMAXNM_F64 => vmaxnm_f64(n_val, m_val, fpscr),
                    Mnemonic::VMINNM_F64 => vminnm_f64(n_val, m_val, fpscr),
                    _ => return ExecResult::Undefined,
                };
                self.cpu.vfp.write_d(d, result);
            }
            _ => return ExecResult::Undefined,
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_vsel(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        let Some((d, n, m, size)) = self.decode_vfp_cond_select_regs(insn) else {
            return ExecResult::Undefined;
        };
        let fpscr = &self.cpu.vfp.fpscr;
        let take_n = match insn.mnemonic {
            Mnemonic::VSELEQ => fpscr.z(),
            Mnemonic::VSELVS => fpscr.v(),
            Mnemonic::VSELGE => fpscr.n() == fpscr.v(),
            Mnemonic::VSELGT => !fpscr.z() && fpscr.n() == fpscr.v(),
            _ => return ExecResult::Undefined,
        };

        match size {
            16 => {
                let value = if take_n {
                    self.cpu.vfp.read_h_bits(n)
                } else {
                    self.cpu.vfp.read_h_bits(m)
                };
                self.cpu.vfp.write_h_bits(d, value);
            }
            32 => {
                let value = if take_n {
                    self.cpu.vfp.read_s_bits(n)
                } else {
                    self.cpu.vfp.read_s_bits(m)
                };
                self.cpu.vfp.write_s_bits(d, value);
            }
            64 => {
                let value = if take_n {
                    self.cpu.vfp.read_d_bits(n)
                } else {
                    self.cpu.vfp.read_d_bits(m)
                };
                self.cpu.vfp.write_d_bits(d, value);
            }
            _ => return ExecResult::Undefined,
        }

        ExecResult::Continue
    }

    pub(crate) fn exec_vfp_accop(&mut self, insn: &DecodedInsn) -> ExecResult {
        if Self::is_neon_fp_fma_shape(insn.raw) {
            return self.exec_neon_fp_multiply(insn);
        }

        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        let Some((d, n, m, size)) = self.decode_vfp_ternary_regs(insn) else {
            return ExecResult::Undefined;
        };
        match size {
            16 => {
                let acc = self.cpu.vfp.read_h_bits(d);
                let n_val = self.cpu.vfp.read_h_bits(n);
                let m_val = self.cpu.vfp.read_h_bits(m);
                let fpscr = &mut self.cpu.vfp.fpscr;
                let result = match insn.mnemonic {
                    Mnemonic::VMLA => vmla_f16_bits(acc, n_val, m_val, fpscr),
                    Mnemonic::VMLS => vmls_f16_bits(acc, n_val, m_val, fpscr),
                    Mnemonic::VFMA => vfma_f16_bits(acc, n_val, m_val, fpscr),
                    Mnemonic::VFMS => vfms_f16_bits(acc, n_val, m_val, fpscr),
                    Mnemonic::VNMLA => vnmla_f16_bits(acc, n_val, m_val, fpscr),
                    Mnemonic::VNMLS => vnmls_f16_bits(acc, n_val, m_val, fpscr),
                    Mnemonic::VFNMA => vfnma_f16_bits(acc, n_val, m_val, fpscr),
                    Mnemonic::VFNMS => vfnms_f16_bits(acc, n_val, m_val, fpscr),
                    _ => return ExecResult::Undefined,
                };
                self.cpu.vfp.write_h_bits(d, result);
            }
            32 => {
                let acc = self.cpu.vfp.read_s(d);
                let n_val = self.cpu.vfp.read_s(n);
                let m_val = self.cpu.vfp.read_s(m);
                let fpscr = &mut self.cpu.vfp.fpscr;
                let result = match insn.mnemonic {
                    Mnemonic::VMLA => vmla_f32(acc, n_val, m_val, fpscr),
                    Mnemonic::VMLS => vmls_f32(acc, n_val, m_val, fpscr),
                    Mnemonic::VFMA => vfma_f32(acc, n_val, m_val, fpscr),
                    Mnemonic::VFMS => vfms_f32(acc, n_val, m_val, fpscr),
                    Mnemonic::VNMLA => vnmla_f32(acc, n_val, m_val, fpscr),
                    Mnemonic::VNMLS => vnmls_f32(acc, n_val, m_val, fpscr),
                    Mnemonic::VFNMA => vfnma_f32(acc, n_val, m_val, fpscr),
                    Mnemonic::VFNMS => vfnms_f32(acc, n_val, m_val, fpscr),
                    _ => return ExecResult::Undefined,
                };
                self.cpu.vfp.write_s(d, result);
            }
            64 => {
                let acc = self.cpu.vfp.read_d(d);
                let n_val = self.cpu.vfp.read_d(n);
                let m_val = self.cpu.vfp.read_d(m);
                let fpscr = &mut self.cpu.vfp.fpscr;
                let result = match insn.mnemonic {
                    Mnemonic::VMLA => vmla_f64(acc, n_val, m_val, fpscr),
                    Mnemonic::VMLS => vmls_f64(acc, n_val, m_val, fpscr),
                    Mnemonic::VFMA => vfma_f64(acc, n_val, m_val, fpscr),
                    Mnemonic::VFMS => vfms_f64(acc, n_val, m_val, fpscr),
                    Mnemonic::VNMLA => vnmla_f64(acc, n_val, m_val, fpscr),
                    Mnemonic::VNMLS => vnmls_f64(acc, n_val, m_val, fpscr),
                    Mnemonic::VFNMA => vfnma_f64(acc, n_val, m_val, fpscr),
                    Mnemonic::VFNMS => vfnms_f64(acc, n_val, m_val, fpscr),
                    _ => return ExecResult::Undefined,
                };
                self.cpu.vfp.write_d(d, result);
            }
            _ => return ExecResult::Undefined,
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_vfp_unop(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        let Some((d, m, size)) = self.decode_vfp_unary_regs(insn) else {
            return ExecResult::Undefined;
        };
        match size {
            16 => {
                let m_val = self.cpu.vfp.read_h_bits(m);
                let result = match insn.mnemonic {
                    Mnemonic::VABS => vabs_f16_bits(m_val),
                    Mnemonic::VNEG => vneg_f16_bits(m_val),
                    Mnemonic::VSQRT => vsqrt_f16_bits(m_val, &mut self.cpu.vfp.fpscr),
                    _ => return ExecResult::Undefined,
                };
                self.cpu.vfp.write_h_bits(d, result);
            }
            32 => {
                let m_val = self.cpu.vfp.read_s(m);
                let result = match insn.mnemonic {
                    Mnemonic::VABS => vabs_f32(m_val),
                    Mnemonic::VNEG => vneg_f32(m_val),
                    Mnemonic::VSQRT => vsqrt_f32(m_val, &mut self.cpu.vfp.fpscr),
                    _ => return ExecResult::Undefined,
                };
                self.cpu.vfp.write_s(d, result);
            }
            64 => {
                let m_val = self.cpu.vfp.read_d(m);
                let result = match insn.mnemonic {
                    Mnemonic::VABS => vabs_f64(m_val),
                    Mnemonic::VNEG => vneg_f64(m_val),
                    Mnemonic::VSQRT => vsqrt_f64(m_val, &mut self.cpu.vfp.fpscr),
                    _ => return ExecResult::Undefined,
                };
                self.cpu.vfp.write_d(d, result);
            }
            _ => return ExecResult::Undefined,
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_vcmp(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        let Some((d, m, size)) = self.decode_vfp_unary_regs(insn) else {
            return ExecResult::Undefined;
        };
        let with_zero = ((insn.raw >> 16) & 0xF) == 5;
        let signal_all_nans = insn.mnemonic == Mnemonic::VCMPE;
        match size {
            16 => {
                let rhs = if with_zero {
                    0
                } else {
                    self.cpu.vfp.read_h_bits(m)
                };
                vcmp_f16_bits_with_exception(
                    self.cpu.vfp.read_h_bits(d),
                    rhs,
                    signal_all_nans,
                    &mut self.cpu.vfp.fpscr,
                );
            }
            32 => {
                let rhs = if with_zero {
                    0.0
                } else {
                    self.cpu.vfp.read_s(m)
                };
                vcmp_f32_with_exception(
                    self.cpu.vfp.read_s(d),
                    rhs,
                    signal_all_nans,
                    &mut self.cpu.vfp.fpscr,
                );
            }
            64 => {
                let rhs = if with_zero {
                    0.0
                } else {
                    self.cpu.vfp.read_d(m)
                };
                vcmp_f64_with_exception(
                    self.cpu.vfp.read_d(d),
                    rhs,
                    signal_all_nans,
                    &mut self.cpu.vfp.fpscr,
                );
            }
            _ => return ExecResult::Undefined,
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_neon_directed_convert(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.cpu.vfp.is_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if !Self::is_neon_directed_convert_shape(insn.raw) {
            return ExecResult::Undefined;
        }

        let size = match (insn.raw >> 18) & 0x3 {
            0b01 => NeonSize::H16,
            0b10 => NeonSize::S32,
            _ => return ExecResult::Undefined,
        };
        let unsigned = ((insn.raw >> 7) & 1) != 0;
        let mode = match (insn.raw >> 8) & 0x3 {
            0b00 => RoundingMode::RoundNearest,
            0b01 => RoundingMode::RoundPlusInf,
            0b10 => RoundingMode::RoundMinusInf,
            0b11 => RoundingMode::RoundZero,
            _ => unreachable!(),
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

        let ebytes = (size.bits() / 8) as u8;
        for reg in 0..regs {
            let elements = self.neon_read_vector_elements_u64(m + reg, 1, ebytes);
            let mut out = Vec::with_capacity(elements.len());
            for elem in elements {
                let result = match size {
                    NeonSize::H16 => {
                        let value = vcvt_f32_f16_bits(elem as u16);
                        u64::from(Self::neon_float_to_int_lane(
                            value,
                            16,
                            unsigned,
                            mode,
                            &mut self.cpu.vfp.fpscr,
                        ))
                    }
                    NeonSize::S32 if unsigned => {
                        let value = vcvt_u32_f32_round(
                            f32::from_bits(elem as u32),
                            mode,
                            &mut self.cpu.vfp.fpscr,
                        );
                        u64::from(value)
                    }
                    NeonSize::S32 => {
                        let value = vcvt_s32_f32_round(
                            f32::from_bits(elem as u32),
                            mode,
                            &mut self.cpu.vfp.fpscr,
                        );
                        u64::from(value as u32)
                    }
                    _ => return ExecResult::Undefined,
                };
                out.push(result);
            }
            self.neon_write_vector_elements_u64(d + reg, 1, ebytes, &out);
        }

        ExecResult::Continue
    }

    pub(crate) fn neon_struct_writeback(&self, base: u32, regs: u8, streams: u8, rm: usize) -> u32 {
        if rm == 13 {
            base.wrapping_add((regs as u32) * (streams as u32) * 8)
        } else {
            base.wrapping_add(self.reg(rm))
        }
    }

    pub(crate) fn neon_lane_writeback(&self, base: u32, streams: u8, ebytes: u8, rm: usize) -> u32 {
        if rm == 13 {
            base.wrapping_add((streams as u32) * (ebytes as u32))
        } else {
            base.wrapping_add(self.reg(rm))
        }
    }

    pub(crate) fn neon_replicate_elem(value: u32, ebytes: u8) -> u64 {
        let bits = (ebytes * 8) as u32;
        let mask = if ebytes == 4 {
            u32::MAX as u64
        } else {
            (1u64 << bits) - 1
        };
        let elem = (value as u64) & mask;
        let mut out = 0u64;
        let lanes = 8 / ebytes;
        for lane in 0..lanes {
            out |= elem << ((lane * ebytes * 8) as u32);
        }
        out
    }

    pub(crate) fn neon_read_d_elem(&self, dreg: u8, element: u8, ebytes: u8) -> u32 {
        let shift = (element * ebytes * 8) as u32;
        let mask = if ebytes == 4 {
            u32::MAX as u64
        } else {
            (1u64 << (ebytes * 8)) - 1
        };
        ((self.cpu.vfp.read_d_bits(dreg) >> shift) & mask) as u32
    }

    pub(crate) fn neon_read_d_elem_u64(&self, dreg: u8, element: u8, ebytes: u8) -> u64 {
        let shift = (element * ebytes * 8) as u32;
        let mask = if ebytes == 8 {
            u64::MAX
        } else {
            (1u64 << (ebytes * 8)) - 1
        };
        (self.cpu.vfp.read_d_bits(dreg) >> shift) & mask
    }

    pub(crate) fn neon_sign_extend_elem(value: u32, bits: u32) -> i64 {
        let shift = 64 - bits;
        (((value as u64) << shift) as i64) >> shift
    }

    pub(crate) fn neon_sign_extend_elem_u64(value: u64, bits: u32) -> i128 {
        let shift = 128 - bits;
        ((value as i128) << shift) >> shift
    }

    pub(crate) fn neon_signed_saturate(value: i64, bits: u32) -> (i64, bool) {
        let min = -(1i64 << (bits - 1));
        let max = (1i64 << (bits - 1)) - 1;
        if value < min {
            (min, true)
        } else if value > max {
            (max, true)
        } else {
            (value, false)
        }
    }

    pub(crate) fn neon_signed_saturate_i128(value: i128, bits: u32) -> (i128, bool) {
        let min = -(1i128 << (bits - 1));
        let max = (1i128 << (bits - 1)) - 1;
        if value < min {
            (min, true)
        } else if value > max {
            (max, true)
        } else {
            (value, false)
        }
    }

    pub(crate) fn neon_unsigned_saturate(value: i128, bits: u32) -> (u64, bool) {
        let max = if bits == 64 {
            u64::MAX as i128
        } else {
            (1i128 << bits) - 1
        };
        if value < 0 {
            (0, true)
        } else if value > max {
            (max as u64, true)
        } else {
            (value as u64, false)
        }
    }

    pub(crate) fn neon_pack_signed_elem(value: i64, bits: u32) -> u32 {
        let mask = if bits == 32 {
            u32::MAX as u64
        } else {
            (1u64 << bits) - 1
        };
        (value as u64 & mask) as u32
    }

    pub(crate) fn neon_pack_signed_elem_i128(value: i128, bits: u32) -> u64 {
        let mask = if bits == 64 {
            u64::MAX as u128
        } else {
            (1u128 << bits) - 1
        };
        (value as u128 & mask) as u64
    }

    pub(crate) fn neon_doubling_mulh_elem(
        lhs: u64,
        rhs: u64,
        bits: u32,
        rounding: bool,
    ) -> (u64, bool) {
        let lhs = Self::neon_sign_extend_elem_u64(lhs, bits);
        let rhs = Self::neon_sign_extend_elem_u64(rhs, bits);
        let round_const = if rounding { 1i128 << (bits - 1) } else { 0 };
        let product = (2 * lhs * rhs) + round_const;
        let shifted = product >> bits;
        let (result, saturated) = Self::neon_signed_saturate_i128(shifted, bits);
        (Self::neon_pack_signed_elem_i128(result, bits), saturated)
    }

    pub(crate) fn neon_write_d_elem(&mut self, dreg: u8, element: u8, ebytes: u8, value: u32) {
        let shift = (element * ebytes * 8) as u32;
        let mask = if ebytes == 4 {
            u32::MAX as u64
        } else {
            (1u64 << (ebytes * 8)) - 1
        };
        let old = self.cpu.vfp.read_d_bits(dreg);
        let bits = (old & !(mask << shift)) | (((value as u64) & mask) << shift);
        self.cpu.vfp.write_d_bits(dreg, bits);
    }

    pub(crate) fn neon_write_d_elem_u64(&mut self, dreg: u8, element: u8, ebytes: u8, value: u64) {
        let shift = (element * ebytes * 8) as u32;
        let mask = if ebytes == 8 {
            u64::MAX
        } else {
            (1u64 << (ebytes * 8)) - 1
        };
        let old = self.cpu.vfp.read_d_bits(dreg);
        let bits = (old & !(mask << shift)) | ((value & mask) << shift);
        self.cpu.vfp.write_d_bits(dreg, bits);
    }

    pub(crate) fn neon_read_mem_elem(&self, addr: u32, ebytes: u8) -> Result<u32, MemoryError> {
        match ebytes {
            1 => self.mem.read_byte(addr).map(|v| v as u32),
            2 => self.mem.read_halfword(addr).map(|v| v as u32),
            4 => self.mem.read_word(addr),
            _ => Err(MemoryError::OutOfBounds(addr)),
        }
    }

    pub(crate) fn neon_write_mem_elem(
        &mut self,
        addr: u32,
        ebytes: u8,
        value: u32,
    ) -> Result<(), MemoryError> {
        match ebytes {
            1 => self.mem.write_byte(addr, value as u8),
            2 => self.mem.write_halfword(addr, value as u16),
            4 => self.mem.write_word(addr, value),
            _ => Err(MemoryError::OutOfBounds(addr)),
        }
    }
}
