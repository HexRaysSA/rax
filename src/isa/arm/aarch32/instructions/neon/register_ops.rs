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
    pub(crate) fn exec_neon_count_register(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
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

    pub(crate) fn exec_neon_vext(&mut self, insn: &DecodedInsn) -> ExecResult {
        if !self.fp_data_enabled() {
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
        if !self.fp_data_enabled() {
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
        if !self.fp_data_enabled() {
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
        if !self.fp_data_enabled() {
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
        if !self.fp_data_enabled() {
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
        if !self.fp_data_enabled() {
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
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        if Self::is_neon_modified_immediate_shape(insn.raw) {
            return self.exec_neon_modified_immediate(insn);
        }
        // Byte-lane transfers share these operation bits; only the 0xC
        // coprocessor load/store class transfers two core registers.
        if insn.raw & 0x0f00_0000 == 0x0c00_0000
            && ((insn.raw >> 4) & 1) == 1
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
                let sreg = (((insn.raw & 0xF) << 1) | ((insn.raw >> 5) & 1)) as u8;
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
                        .write_s_bits((vd << 1) | d_bit, u32::from(vfp_expand_imm_f16(imm8)));
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
        if !self.fp_data_enabled() {
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
        if !self.fp_data_enabled() {
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
                self.cpu.vfp.write_s_bits(d, u32::from(result));
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
        if !self.fp_data_enabled() {
            return ExecResult::Exception(ExceptionType::UndefinedInstruction);
        }
        let Some((d, n, m, size)) = self.decode_vfp_cond_select_regs(insn) else {
            return ExecResult::Undefined;
        };
        if !crate::isa::arm::decoder::Aarch32Decoder::decode_vfp_conditional_select(insn.raw)
            .is_some_and(|decoded| decoded.mnemonic == insn.mnemonic)
            || (self.cpu.cpsr.t && self.cpu.cpsr.in_it_block())
        {
            return ExecResult::Undefined;
        }
        let flags = &self.cpu.cpsr;
        let take_n = match insn.mnemonic {
            Mnemonic::VSELEQ => flags.z,
            Mnemonic::VSELVS => flags.v,
            Mnemonic::VSELGE => flags.n == flags.v,
            Mnemonic::VSELGT => !flags.z && flags.n == flags.v,
            _ => return ExecResult::Undefined,
        };

        match size {
            16 => {
                let value = if take_n {
                    self.cpu.vfp.read_h_bits(n)
                } else {
                    self.cpu.vfp.read_h_bits(m)
                };
                self.cpu.vfp.write_s_bits(d, u32::from(value));
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

        if !self.fp_data_enabled() {
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
                self.cpu.vfp.write_s_bits(d, u32::from(result));
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
        if !self.fp_data_enabled() {
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
                self.cpu.vfp.write_s_bits(d, u32::from(result));
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
        if !self.fp_data_enabled() {
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
