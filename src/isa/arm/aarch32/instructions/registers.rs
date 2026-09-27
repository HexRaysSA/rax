//! Register file and banked-register access

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
    /// Set register value, handling PC writes as branches.
    #[inline]
    pub(crate) fn set_reg(&mut self, r: usize, value: u32) -> ExecResult {
        if r == 15 {
            ExecResult::Branch(value)
        } else {
            self.cpu.regs[r] = value;
            ExecResult::Continue
        }
    }

    /// Set register value, with S bit handling for PC (exception return).
    pub(crate) fn set_reg_with_s(&mut self, r: usize, value: u32, s_bit: bool) -> ExecResult {
        let r = crate::isa::arm::aarch32::cpu::aarch32_reg_index(r);
        if r == 15 {
            if s_bit && !self.cpu.is_user_or_system() {
                // Exception return
                self.exception_return();
            }
            ExecResult::Branch(value)
        } else {
            self.cpu.regs[r] = value;
            ExecResult::Continue
        }
    }

    pub(crate) fn read_user_bank_reg(&self, r: usize) -> u32 {
        match r {
            8..=12 if ProcessorMode::from_bits(self.cpu.cpsr.mode) == Some(ProcessorMode::Fiq) => {
                self.cpu.regs_usr_high[r - 8]
            }
            13 => self.cpu.regs_usr[0],
            14 => self.cpu.regs_usr[1],
            15 => self.cpu.get_pc(),
            _ => self.cpu.regs[r],
        }
    }

    pub(crate) fn write_user_bank_reg(&mut self, r: usize, value: u32) {
        match r {
            8..=12 if ProcessorMode::from_bits(self.cpu.cpsr.mode) == Some(ProcessorMode::Fiq) => {
                self.cpu.regs_usr_high[r - 8] = value;
            }
            13 => self.cpu.regs_usr[0] = value,
            14 => self.cpu.regs_usr[1] = value,
            _ => self.cpu.regs[r] = value,
        }
    }

    /// Update APSR flags for logical operations (N, Z, C from shifter).
    pub(crate) fn set_flags_logical(&mut self, result: u32) {
        self.cpu.cpsr.n = compute_n_flag(result);
        self.cpu.cpsr.z = compute_z_flag(result);
        self.cpu.cpsr.c = self.cpu.carry_out;
    }

    /// Update APSR flags for arithmetic operations (N, Z, C, V).
    pub(crate) fn set_flags_arithmetic(&mut self, result: u32) {
        self.cpu.cpsr.n = compute_n_flag(result);
        self.cpu.cpsr.z = compute_z_flag(result);
        self.cpu.cpsr.c = self.cpu.carry_out;
        self.cpu.cpsr.v = self.cpu.overflow;
    }

    pub(crate) fn write_current_spsr_by_mask(&mut self, value: u32, mask: u32) {
        if let Some(spsr) = self.cpu.get_current_spsr_mut() {
            if (mask & 8) != 0 {
                spsr.n = (value >> 31) != 0;
                spsr.z = ((value >> 30) & 1) != 0;
                spsr.c = ((value >> 29) & 1) != 0;
                spsr.v = ((value >> 28) & 1) != 0;
                spsr.q = ((value >> 27) & 1) != 0;
            }
            if (mask & 4) != 0 {
                spsr.ge = ((value >> 16) & 0xF) as u8;
            }
            if (mask & 2) != 0 {
                spsr.e = ((value >> 9) & 1) != 0;
                spsr.a = ((value >> 8) & 1) != 0;
            }
            if (mask & 1) != 0 {
                spsr.i = ((value >> 7) & 1) != 0;
                spsr.f = ((value >> 6) & 1) != 0;
                spsr.t = ((value >> 5) & 1) != 0;
                spsr.mode = (value & 0x1F) as u8;
            }
        }
    }

    pub(crate) fn write_cpsr_by_mask(&mut self, value: u32, mask: u32) {
        if (mask & 8) != 0 {
            self.cpu.cpsr.n = (value >> 31) != 0;
            self.cpu.cpsr.z = ((value >> 30) & 1) != 0;
            self.cpu.cpsr.c = ((value >> 29) & 1) != 0;
            self.cpu.cpsr.v = ((value >> 28) & 1) != 0;
            self.cpu.cpsr.q = ((value >> 27) & 1) != 0;
        }
        // CPSRWriteByInstr: GE[3:0] at any privilege.
        if (mask & 4) != 0 {
            self.cpu.cpsr.ge = ((value >> 16) & 0xF) as u8;
        }
        if (mask & 2) != 0 {
            self.cpu.cpsr.e = ((value >> 9) & 1) != 0;
            if self.cpu.is_privileged() {
                self.cpu.cpsr.a = ((value >> 8) & 1) != 0;
            }
        }
        if (mask & 1) != 0 && self.cpu.is_privileged() {
            self.cpu.cpsr.i = ((value >> 7) & 1) != 0;
            self.cpu.cpsr.f = ((value >> 6) & 1) != 0;

            let new_mode = value & 0x1F;
            if let Some(mode) = ProcessorMode::from_bits(new_mode as u8) {
                if self.cpu.cpsr.mode != mode as u8 {
                    self.cpu.change_mode(mode);
                }
            }
        }
    }

    pub(crate) fn set_banked_sp(&mut self, mode_bits: u8, value: u32) {
        if mode_bits == self.cpu.cpsr.mode {
            self.cpu.regs[13] = value;
            return;
        }
        match ProcessorMode::from_bits(mode_bits) {
            Some(ProcessorMode::User) | Some(ProcessorMode::System) => {
                self.cpu.regs_usr[0] = value;
            }
            Some(ProcessorMode::Fiq) => self.cpu.regs_fiq[5] = value,
            Some(ProcessorMode::Irq) => self.cpu.regs_irq[0] = value,
            Some(ProcessorMode::Supervisor) => self.cpu.regs_svc[0] = value,
            Some(ProcessorMode::Monitor) => self.cpu.regs_mon[0] = value,
            Some(ProcessorMode::Abort) => self.cpu.regs_abt[0] = value,
            Some(ProcessorMode::Undefined) => self.cpu.regs_und[0] = value,
            _ => self.cpu.regs[13] = value,
        }
    }

    /// Raw bits of the current mode's SPSR (CPSR if none).
    pub(crate) fn current_spsr_bits(&self) -> u32 {
        match ProcessorMode::from_bits(self.cpu.cpsr.mode) {
            Some(ProcessorMode::Fiq) => self.cpu.spsr_fiq.to_u32(),
            Some(ProcessorMode::Irq) => self.cpu.spsr_irq.to_u32(),
            Some(ProcessorMode::Supervisor) => self.cpu.spsr_svc.to_u32(),
            Some(ProcessorMode::Monitor) => self.cpu.spsr_mon.to_u32(),
            Some(ProcessorMode::Abort) => self.cpu.spsr_abt.to_u32(),
            Some(ProcessorMode::Undefined) => self.cpu.spsr_und.to_u32(),
            _ => self.cpu.cpsr.to_u32(),
        }
    }

    /// Write CPSR including the mode field (exception-return semantics).
    pub(crate) fn write_cpsr_all(&mut self, value: u32) {
        let new_mode = (value & 0x1F) as u8;
        if let Some(mode) = ProcessorMode::from_bits(new_mode) {
            self.cpu.change_mode(mode);
        }
        self.cpu.cpsr = Psr::from_u32(value);
    }

    // =========================================================================
    // AArch32 media / DSP (A32 encodings; operation derived from the raw word)
    // =========================================================================

    /// (Rd, Rn, Rm) for 3-register media ops (A32 / T32 layouts).
    pub(crate) fn media_regs(&self, insn: &DecodedInsn) -> (usize, usize, usize) {
        let raw = insn.raw;
        if insn.state.is_thumb() {
            (
                ((raw >> 8) & 0xF) as usize,
                ((raw >> 16) & 0xF) as usize,
                (raw & 0xF) as usize,
            )
        } else {
            (
                ((raw >> 12) & 0xF) as usize,
                ((raw >> 16) & 0xF) as usize,
                (raw & 0xF) as usize,
            )
        }
    }

    /// (Rd, Ra, Rm, Rn) for 4-register DSP multiplies (A32 / T32 layouts).
    pub(crate) fn dsp4_regs(&self, insn: &DecodedInsn) -> (usize, usize, usize, usize) {
        let raw = insn.raw;
        if insn.state.is_thumb() {
            (
                ((raw >> 8) & 0xF) as usize,  // Rd = hw2[11:8]
                ((raw >> 12) & 0xF) as usize, // Ra = hw2[15:12]
                (raw & 0xF) as usize,         // Rm = hw2[3:0]
                ((raw >> 16) & 0xF) as usize, // Rn = hw1[3:0]
            )
        } else {
            (
                ((raw >> 16) & 0xF) as usize, // Rd = bits[19:16]
                ((raw >> 12) & 0xF) as usize, // Ra = bits[15:12]
                ((raw >> 8) & 0xF) as usize,  // Rm = bits[11:8]
                (raw & 0xF) as usize,         // Rn = bits[3:0]
            )
        }
    }
}
