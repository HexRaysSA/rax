//! Data-processing (ALU, multiply, bitfield, saturate) execution

use crate::isa::arm::ExecutionState;
use crate::isa::arm::aarch32::cpu::{
    ArmMemory, Armv7Cpu, MemoryError, ProcessorMode, Psr, add_with_carry, compute_n_flag,
    compute_z_flag, condition_passed, expand_imm_c, shift_c, sign_extend,
};
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
    // =========================================================================
    // Data Processing - Arithmetic
    // =========================================================================

    /// ADR in Thumb state: T1 (decoded as ADD Rd with the offset as a
    /// label) and T3 and T2 (ADDW and SUBW with Rn = PC), whose base is
    /// Align(PC, 4); the flags are unchanged.
    fn thumb_adr(&self, insn: &DecodedInsn) -> Option<(usize, u32)> {
        use crate::isa::arm::decoder::Operand;
        if !insn.state.is_thumb() {
            return None;
        }
        let base = self.cpu.get_pc() & !3;
        match insn.operands.as_slice() {
            [Operand::Reg(d), Operand::Label(offset)] if insn.mnemonic == Mnemonic::ADD => {
                Some((d.num as usize, base.wrapping_add(*offset as u32)))
            }
            // Plain binary immediate (hw1 bit 9), not T32ExpandImm's.
            [Operand::Reg(d), Operand::Reg(n), Operand::Imm(imm)]
                if n.num == 15 && insn.size == 4 && insn.raw & 0x0200_0000 != 0 =>
            {
                let imm = imm.value as u32;
                match insn.mnemonic {
                    Mnemonic::ADD => Some((d.num as usize, base.wrapping_add(imm))),
                    Mnemonic::SUB => Some((d.num as usize, base.wrapping_sub(imm))),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    pub(crate) fn exec_add(&mut self, insn: &DecodedInsn) -> ExecResult {
        if let Some((d, address)) = self.thumb_adr(insn) {
            return self.set_reg_with_s(d, address, false);
        }
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self.cpu.add_with_carry(self.reg(n), operand2, false);

        if insn.sets_flags && d != 15 {
            self.set_flags_arithmetic(result);
        }
        self.set_reg_with_s(d, result, insn.sets_flags)
    }

    pub(crate) fn exec_adc(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self
            .cpu
            .add_with_carry(self.reg(n), operand2, self.cpu.cpsr.c);

        if insn.sets_flags && d != 15 {
            self.set_flags_arithmetic(result);
        }
        self.set_reg_with_s(d, result, insn.sets_flags)
    }

    pub(crate) fn exec_sub(&mut self, insn: &DecodedInsn) -> ExecResult {
        if let Some((d, address)) = self.thumb_adr(insn) {
            return self.set_reg_with_s(d, address, false);
        }
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self.cpu.add_with_carry(self.reg(n), !operand2, true);

        if insn.sets_flags && d != 15 {
            self.set_flags_arithmetic(result);
        }
        self.set_reg_with_s(d, result, insn.sets_flags)
    }

    pub(crate) fn exec_sbc(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self
            .cpu
            .add_with_carry(self.reg(n), !operand2, self.cpu.cpsr.c);

        if insn.sets_flags && d != 15 {
            self.set_flags_arithmetic(result);
        }
        self.set_reg_with_s(d, result, insn.sets_flags)
    }

    pub(crate) fn exec_rsb(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self.cpu.add_with_carry(!self.reg(n), operand2, true);

        if insn.sets_flags && d != 15 {
            self.set_flags_arithmetic(result);
        }
        self.set_reg_with_s(d, result, insn.sets_flags)
    }

    // =========================================================================
    // Data Processing - Logical
    // =========================================================================

    pub(crate) fn exec_and(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self.reg(n) & operand2;

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    pub(crate) fn exec_orr(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self.reg(n) | operand2;

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    pub(crate) fn exec_eor(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self.reg(n) ^ operand2;

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    pub(crate) fn exec_bic(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, operand2) = self.decode_dp_operands(insn);
        let result = self.reg(n) & !operand2;

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    // =========================================================================
    // Data Processing - Move
    // =========================================================================

    pub(crate) fn exec_mov(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, _, operand2) = self.decode_dp_operands(insn);
        let result = operand2;

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg_with_s(d, result, insn.sets_flags)
    }

    pub(crate) fn exec_mvn(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, _, operand2) = self.decode_dp_operands(insn);
        let result = !operand2;

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    pub(crate) fn exec_movw(&mut self, insn: &DecodedInsn) -> ExecResult {
        let d = ((insn.raw >> 12) & 0xF) as usize;
        let imm4 = (insn.raw >> 16) & 0xF;
        let imm12 = insn.raw & 0xFFF;
        let imm16 = (imm4 << 12) | imm12;
        self.cpu.regs[d] = imm16;
        ExecResult::Continue
    }

    pub(crate) fn exec_movt(&mut self, insn: &DecodedInsn) -> ExecResult {
        use crate::isa::arm::decoder::Operand;
        let (d, imm16) = if insn.state.is_thumb() {
            let (r, _) = Self::thumb_reg_ops(insn, 1);
            let imm = match insn.operands.last() {
                Some(Operand::Imm(i)) => i.value as u32 & 0xFFFF,
                _ => 0,
            };
            (r[0], imm)
        } else {
            let imm4 = (insn.raw >> 16) & 0xF;
            let imm12 = insn.raw & 0xFFF;
            (((insn.raw >> 12) & 0xF) as usize, (imm4 << 12) | imm12)
        };
        self.cpu.regs[d] = (self.cpu.regs[d] & 0xFFFF) | (imm16 << 16);
        ExecResult::Continue
    }

    // =========================================================================
    // Data Processing - Compare
    // =========================================================================

    pub(crate) fn exec_cmp(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (_, n, operand2) = self.decode_dp_operands(insn);
        let rn = self.reg(n);
        let result = self.cpu.add_with_carry(rn, !operand2, true);
        self.set_flags_arithmetic(result);
        ExecResult::Continue
    }

    pub(crate) fn exec_tst(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (_, n, operand2) = self.decode_dp_operands(insn);
        let result = self.reg(n) & operand2;
        self.set_flags_logical(result);
        ExecResult::Continue
    }

    pub(crate) fn exec_teq(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (_, n, operand2) = self.decode_dp_operands(insn);
        let result = self.reg(n) ^ operand2;
        self.set_flags_logical(result);
        ExecResult::Continue
    }

    // =========================================================================
    // Data Processing - Shift
    // =========================================================================

    pub(crate) fn exec_lsl(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m, shift_amount) = self.decode_shift_operands(insn);
        let result = self.cpu.shift_c(self.reg(m), ShiftType::LSL, shift_amount);

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    pub(crate) fn exec_lsr(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m, shift_amount) = self.decode_shift_operands(insn);
        let result = self.cpu.shift_c(self.reg(m), ShiftType::LSR, shift_amount);

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    pub(crate) fn exec_asr(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m, shift_amount) = self.decode_shift_operands(insn);
        let result = self.cpu.shift_c(self.reg(m), ShiftType::ASR, shift_amount);

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    pub(crate) fn exec_ror(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m, shift_amount) = self.decode_shift_operands(insn);
        let result = self.cpu.shift_c(self.reg(m), ShiftType::ROR, shift_amount);

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    pub(crate) fn exec_rrx(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m, _) = self.decode_shift_operands(insn);
        let result = self.cpu.shift_c(self.reg(m), ShiftType::RRX, 1);

        if insn.sets_flags && d != 15 {
            self.set_flags_logical(result);
        }
        self.set_reg(d, result)
    }

    // =========================================================================
    // Multiply Operations
    // =========================================================================

    pub(crate) fn exec_mul(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, m) = self.decode_mul_operands(insn);
        let result = self.reg(n).wrapping_mul(self.reg(m));

        if insn.sets_flags {
            self.cpu.cpsr.n = compute_n_flag(result);
            self.cpu.cpsr.z = compute_z_flag(result);
        }
        self.set_reg(d, result)
    }

    pub(crate) fn exec_mla(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, m, a) = self.decode_mla_operands(insn);
        let result = self
            .reg(n)
            .wrapping_mul(self.reg(m))
            .wrapping_add(self.reg(a));
        if insn.sets_flags {
            self.cpu.cpsr.n = compute_n_flag(result);
            self.cpu.cpsr.z = compute_z_flag(result);
        }
        self.set_reg(d, result)
    }

    pub(crate) fn exec_mls(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, m, a) = self.decode_mla_operands(insn);
        let result = self
            .reg(a)
            .wrapping_sub(self.reg(n).wrapping_mul(self.reg(m)));
        self.set_reg(d, result)
    }

    pub(crate) fn exec_umull(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (dlo, dhi, n, m) = self.decode_mull_operands(insn);
        let result = (self.reg(n) as u64).wrapping_mul(self.reg(m) as u64);

        self.cpu.regs[dlo] = result as u32;
        self.cpu.regs[dhi] = (result >> 32) as u32;

        if insn.sets_flags {
            self.cpu.cpsr.n = (result >> 63) != 0;
            self.cpu.cpsr.z = result == 0;
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_smull(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (dlo, dhi, n, m) = self.decode_mull_operands(insn);
        let result = (self.reg(n) as i32 as i64).wrapping_mul(self.reg(m) as i32 as i64) as u64;

        self.cpu.regs[dlo] = result as u32;
        self.cpu.regs[dhi] = (result >> 32) as u32;

        if insn.sets_flags {
            self.cpu.cpsr.n = (result >> 63) != 0;
            self.cpu.cpsr.z = result == 0;
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_umlal(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (dlo, dhi, n, m) = self.decode_mull_operands(insn);
        let addend = ((self.cpu.regs[dhi] as u64) << 32) | (self.cpu.regs[dlo] as u64);
        let result = (self.reg(n) as u64)
            .wrapping_mul(self.reg(m) as u64)
            .wrapping_add(addend);

        self.cpu.regs[dlo] = result as u32;
        self.cpu.regs[dhi] = (result >> 32) as u32;
        if insn.sets_flags {
            self.cpu.cpsr.n = (result >> 63) != 0;
            self.cpu.cpsr.z = result == 0;
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_smlal(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (dlo, dhi, n, m) = self.decode_mull_operands(insn);
        let addend = ((self.cpu.regs[dhi] as u64) << 32) | (self.cpu.regs[dlo] as u64);
        let result = ((self.reg(n) as i32 as i64).wrapping_mul(self.reg(m) as i32 as i64) as u64)
            .wrapping_add(addend);

        self.cpu.regs[dlo] = result as u32;
        self.cpu.regs[dhi] = (result >> 32) as u32;
        if insn.sets_flags {
            self.cpu.cpsr.n = (result >> 63) != 0;
            self.cpu.cpsr.z = result == 0;
        }
        ExecResult::Continue
    }

    /// UMAAL: RdHi:RdLo = Rn*Rm + RdHi + RdLo (all unsigned). No flags.
    pub(crate) fn exec_umaal(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (dlo, dhi, n, m) = self.decode_mull_operands(insn);
        let result = (self.reg(n) as u64)
            .wrapping_mul(self.reg(m) as u64)
            .wrapping_add(self.cpu.regs[dhi] as u64)
            .wrapping_add(self.cpu.regs[dlo] as u64);
        self.cpu.regs[dlo] = result as u32;
        self.cpu.regs[dhi] = (result >> 32) as u32;
        ExecResult::Continue
    }

    pub(crate) fn exec_sdiv(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, m) = self.decode_mul_operands(insn);

        let dividend = self.reg(n) as i32;
        let divisor = self.reg(m) as i32;

        let result = if divisor == 0 {
            0 // Division by zero returns 0 in ARM
        } else if dividend == i32::MIN && divisor == -1 {
            i32::MIN as u32 // Overflow case
        } else {
            (dividend / divisor) as u32
        };

        self.set_reg(d, result)
    }

    pub(crate) fn exec_udiv(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, m) = self.decode_mul_operands(insn);

        let dividend = self.reg(n);
        let divisor = self.reg(m);

        let result = if divisor == 0 { 0 } else { dividend / divisor };

        self.set_reg(d, result)
    }

    // =========================================================================
    // Bit Manipulation
    // =========================================================================

    pub(crate) fn exec_clz(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m) = self.dm_ops(insn);
        let result = self.reg(m).leading_zeros();
        self.set_reg(d, result)
    }

    pub(crate) fn exec_rev(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m) = self.dm_ops(insn);
        let result = self.reg(m).swap_bytes();
        self.set_reg(d, result)
    }

    pub(crate) fn exec_rev16(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m) = self.dm_ops(insn);
        let val = self.reg(m);
        let result = ((val >> 8) & 0x00FF00FF) | ((val << 8) & 0xFF00FF00);
        self.set_reg(d, result)
    }

    pub(crate) fn exec_revsh(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m) = self.dm_ops(insn);
        let val = self.reg(m);
        // Byte-reverse the low halfword and sign-extend
        let lo = ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
        let result = sign_extend(lo & 0xFFFF, 16);
        self.set_reg(d, result)
    }

    pub(crate) fn exec_rbit(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m) = self.dm_ops(insn);
        let result = self.reg(m).reverse_bits();
        self.set_reg(d, result)
    }

    pub(crate) fn exec_bfc(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, _, lsb, msb) = self.bitfield_fields(insn);
        if msb < lsb {
            return ExecResult::Undefined;
        }
        let width = msb - lsb + 1;
        if !Self::bitfield_range_valid(lsb, width) {
            return ExecResult::Undefined;
        }
        let Some(mask) = Self::bitfield_low_mask(width).map(|mask| mask << lsb) else {
            return ExecResult::Undefined;
        };
        self.cpu.regs[d] &= !mask;
        ExecResult::Continue
    }

    pub(crate) fn exec_bfi(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, lsb, msb) = self.bitfield_fields(insn);
        if msb < lsb {
            return ExecResult::Undefined;
        }
        let width = msb - lsb + 1;
        if !Self::bitfield_range_valid(lsb, width) {
            return ExecResult::Undefined;
        }
        let Some(mask) = Self::bitfield_low_mask(width).map(|mask| mask << lsb) else {
            return ExecResult::Undefined;
        };
        let src = (self.reg(n) << lsb) & mask;
        self.cpu.regs[d] = (self.cpu.regs[d] & !mask) | src;
        ExecResult::Continue
    }

    pub(crate) fn exec_ubfx(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, lsb, w) = self.bitfield_fields(insn);
        let width = w + 1;
        if !Self::bitfield_range_valid(lsb, width) {
            return ExecResult::Undefined;
        }
        let Some(mask) = Self::bitfield_low_mask(width) else {
            return ExecResult::Undefined;
        };
        let result = (self.reg(n) >> lsb) & mask;
        self.set_reg(d, result)
    }

    pub(crate) fn exec_sbfx(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, lsb, w) = self.bitfield_fields(insn);
        let width = w + 1;
        if !Self::bitfield_range_valid(lsb, width) {
            return ExecResult::Undefined;
        }
        let Some(mask) = Self::bitfield_low_mask(width) else {
            return ExecResult::Undefined;
        };
        let extracted = (self.reg(n) >> lsb) & mask;
        let result = sign_extend(extracted, width);
        self.set_reg(d, result)
    }

    // =========================================================================
    // Extension Operations
    // =========================================================================

    pub(crate) fn exec_sxtb(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m) = self.dm_ops(insn);
        let rotation = if insn.state.is_thumb() {
            0
        } else {
            ((insn.raw >> 10) & 3) * 8
        };
        let rotated = self.reg(m).rotate_right(rotation);
        let result = sign_extend(rotated & 0xFF, 8);
        self.set_reg(d, result)
    }

    pub(crate) fn exec_sxth(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m) = self.dm_ops(insn);
        let rotation = if insn.state.is_thumb() {
            0
        } else {
            ((insn.raw >> 10) & 3) * 8
        };
        let rotated = self.reg(m).rotate_right(rotation);
        let result = sign_extend(rotated & 0xFFFF, 16);
        self.set_reg(d, result)
    }

    pub(crate) fn exec_uxtb(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m) = self.dm_ops(insn);
        let rotation = if insn.state.is_thumb() {
            0
        } else {
            ((insn.raw >> 10) & 3) * 8
        };
        let rotated = self.reg(m).rotate_right(rotation);
        let result = rotated & 0xFF;
        self.set_reg(d, result)
    }

    pub(crate) fn exec_uxth(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, m) = self.dm_ops(insn);
        let rotation = if insn.state.is_thumb() {
            0
        } else {
            ((insn.raw >> 10) & 3) * 8
        };
        let rotated = self.reg(m).rotate_right(rotation);
        let result = rotated & 0xFFFF;
        self.set_reg(d, result)
    }

    pub(crate) fn exec_usat(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, sat_imm, sh, imm5) = self.sat_fields(insn);

        let shift_amount = if imm5 == 0 && sh { 32 } else { imm5 };
        let shift_type = if sh { ShiftType::ASR } else { ShiftType::LSL };
        let operand = shift_c(self.reg(n), shift_type, shift_amount, false).0;

        let max_val = (1u32 << sat_imm).saturating_sub(1);
        let signed_operand = operand as i32;

        let result = if signed_operand < 0 {
            self.cpu.cpsr.q = true;
            0
        } else if operand > max_val {
            self.cpu.cpsr.q = true;
            max_val
        } else {
            operand
        };

        self.set_reg(d, result)
    }

    pub(crate) fn exec_ssat(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, n, sat_imm0, sh, imm5) = self.sat_fields(insn);
        let sat_imm = sat_imm0 + 1;

        let shift_amount = if imm5 == 0 && sh { 32 } else { imm5 };
        let shift_type = if sh { ShiftType::ASR } else { ShiftType::LSL };
        let operand = shift_c(self.reg(n), shift_type, shift_amount, false).0 as i32;

        let max_val = (1i32 << (sat_imm - 1)) - 1;
        let min_val = -(1i32 << (sat_imm - 1));

        let result = if operand > max_val {
            self.cpu.cpsr.q = true;
            max_val as u32
        } else if operand < min_val {
            self.cpu.cpsr.q = true;
            min_val as u32
        } else {
            operand as u32
        };

        self.set_reg(d, result)
    }

    /// QADD / QSUB / QDADD / QDSUB.
    pub(crate) fn exec_a32_sat_addsub(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let (rd, rn, rm) = self.media_regs(insn);
        let n = self.reg(rn) as i32 as i64;
        let m = self.reg(rm) as i32 as i64;
        // Canonical kind: 0=QADD 1=QSUB 2=QDADD 3=QDSUB.
        let kind = if insn.state.is_thumb() {
            match (raw >> 4) & 0x3 {
                0 => 0,
                1 => 2,
                2 => 1,
                _ => 3,
            }
        } else {
            (raw >> 21) & 0x3
        };
        let result = match kind {
            0b00 => self.ssat32(m + n),
            0b01 => self.ssat32(m - n),
            0b10 => {
                let dbl = self.ssat32(2 * n) as i32 as i64;
                self.ssat32(m + dbl)
            }
            _ => {
                let dbl = self.ssat32(2 * n) as i32 as i64;
                self.ssat32(m - dbl)
            }
        };
        self.set_reg(rd, result)
    }

    /// SMLALD / SMLSLD.
    pub(crate) fn exec_a32_smlald(&mut self, insn: &DecodedInsn) -> ExecResult {
        let raw = insn.raw;
        let (dhi, dlo, rm, rn, swap, sub) = if insn.state.is_thumb() {
            (
                ((raw >> 8) & 0xF) as usize,  // RdHi = hw2[11:8]
                ((raw >> 12) & 0xF) as usize, // RdLo = hw2[15:12]
                (raw & 0xF) as usize,         // Rm = hw2[3:0]
                ((raw >> 16) & 0xF) as usize, // Rn = hw1[3:0]
                (raw >> 4) & 1 != 0,
                (raw >> 20) & 0x7 == 0b101, // op1==101 -> SMLSLD
            )
        } else {
            (
                ((raw >> 16) & 0xF) as usize,
                ((raw >> 12) & 0xF) as usize,
                ((raw >> 8) & 0xF) as usize,
                (raw & 0xF) as usize,
                (raw >> 5) & 1 != 0,
                (raw >> 6) & 1 != 0,
            )
        };
        let rn_v = self.reg(rn);
        let mut rm_v = self.reg(rm);
        if swap {
            rm_v = rm_v.rotate_right(16);
        }
        let p1 = (rn_v as u16 as i16 as i64) * (rm_v as u16 as i16 as i64);
        let p2 = ((rn_v >> 16) as u16 as i16 as i64) * ((rm_v >> 16) as u16 as i16 as i64);
        let prod = if sub { p1 - p2 } else { p1 + p2 };
        let acc = (((self.cpu.regs[dhi] as u64) << 32) | self.cpu.regs[dlo] as u64) as i64;
        let result = acc.wrapping_add(prod) as u64;
        self.cpu.regs[dlo] = result as u32;
        self.cpu.regs[dhi] = (result >> 32) as u32;
        ExecResult::Continue
    }

    /// SEL (select bytes by GE flags).
    pub(crate) fn exec_a32_sel(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (rd, rn, rm) = self.media_regs(insn);
        let n = self.reg(rn);
        let m = self.reg(rm);
        let ge = self.cpu.cpsr.ge;
        let mut result: u32 = 0;
        for i in 0..4u32 {
            let byte = if (ge >> i) & 1 != 0 {
                (n >> (i * 8)) & 0xFF
            } else {
                (m >> (i * 8)) & 0xFF
            };
            result |= byte << (i * 8);
        }
        self.set_reg(rd, result)
    }
}
