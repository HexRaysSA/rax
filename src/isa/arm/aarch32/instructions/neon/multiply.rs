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
        if !self.fp_data_enabled() {
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
        if !self.fp_data_enabled() {
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
        if !self.fp_data_enabled() {
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
        if !self.fp_data_enabled() {
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
}
