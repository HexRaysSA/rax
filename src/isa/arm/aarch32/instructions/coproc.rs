//! Coprocessor register transfers: MCR and MRC (CP15, and the VFP system
//! registers through CP10), with what PL0 may reach.

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
    pub(crate) fn exec_mcr(&mut self, insn: &DecodedInsn) -> ExecResult {
        let t = ((insn.raw >> 12) & 0xF) as usize;
        let cp = ((insn.raw >> 8) & 0xF) as u8;
        let opc1 = ((insn.raw >> 21) & 7) as u8;
        let reg = ((insn.raw >> 16) & 0xF) as u8;

        if cp == 10 && opc1 == 0b111 {
            if t == 15 || (reg != 1 && !self.cpu.is_privileged()) {
                return ExecResult::Undefined;
            }
            let value = self.reg(t);
            return match reg {
                0 => ExecResult::Continue,
                1 => {
                    if !self.cpu.vfp.is_enabled() {
                        ExecResult::Exception(ExceptionType::UndefinedInstruction)
                    } else {
                        self.cpu.vfp.fpscr = Fpscr::from_bits(value);
                        ExecResult::Continue
                    }
                }
                8 => {
                    self.cpu.vfp.fpexc = value;
                    ExecResult::Continue
                }
                _ => ExecResult::Undefined,
            };
        }

        if cp == 15 {
            let crm = (insn.raw & 0xF) as u8;
            let opc2 = ((insn.raw >> 5) & 0x7) as u8;
            if !self.cpu.is_privileged() && !self.pl0_cp15(insn, false, reg, opc1, crm, opc2) {
                return ExecResult::Undefined;
            }
            let value = self.reg(t);
            // WFI (MCR p15, 0, Rt, c7, c0, 4): ARMv6 wait-for-interrupt.
            if opc1 == 0 && reg == 7 && crm == 0 && opc2 == 4 {
                self.cpu.is_halted = true;
                return ExecResult::Halt;
            }
            let enc = crate::isa::arm::common::sysreg::Cp15Encoding::new(reg, opc1, crm, opc2);
            // Cache/TLB maintenance (CRn 7/8) and unmodelled registers are
            // accepted as no-ops; everything modelled lands in Cp15State.
            let _ = self.cpu.cp15.write(enc, value);
            return ExecResult::Continue;
        }

        if !self.cpu.is_privileged() {
            return ExecResult::Undefined;
        }
        // For now, just consume the value (would write to coprocessor)
        let _value = self.reg(t);

        ExecResult::Continue
    }

    pub(crate) fn exec_mrc(&mut self, insn: &DecodedInsn) -> ExecResult {
        let t = ((insn.raw >> 12) & 0xF) as usize;
        let cp = ((insn.raw >> 8) & 0xF) as u8;
        let opc1 = ((insn.raw >> 21) & 7) as u8;
        let reg = ((insn.raw >> 16) & 0xF) as u8;

        if cp == 10 && opc1 == 0b111 {
            if t == 15 && reg != 1 {
                return ExecResult::Undefined;
            }
            // Only FPSCR is accessible at PL0 (VMRS: "Non-FPSCR registers
            // accessible only at PL1 or above").
            if reg != 1 && !self.cpu.is_privileged() {
                return ExecResult::Undefined;
            }
            let value = match reg {
                0 => self.cpu.vfp.fpsid,
                1 => {
                    if !self.cpu.vfp.is_enabled() {
                        return ExecResult::Exception(ExceptionType::UndefinedInstruction);
                    }
                    self.cpu.vfp.fpscr.bits()
                }
                5 => self.cpu.vfp.mvfr2,
                6 => self.cpu.vfp.mvfr1,
                7 => self.cpu.vfp.mvfr0,
                8 => self.cpu.vfp.fpexc,
                _ => return ExecResult::Undefined,
            };
            if t == 15 && reg == 1 {
                self.cpu.cpsr.n = (value & (1 << 31)) != 0;
                self.cpu.cpsr.z = (value & (1 << 30)) != 0;
                self.cpu.cpsr.c = (value & (1 << 29)) != 0;
                self.cpu.cpsr.v = (value & (1 << 28)) != 0;
            } else if t != 15 {
                self.cpu.regs[t] = value;
            }
            return ExecResult::Continue;
        }

        if cp == 15 {
            let crm = (insn.raw & 0xF) as u8;
            let opc2 = ((insn.raw >> 5) & 0x7) as u8;
            if !self.cpu.is_privileged() && !self.pl0_cp15(insn, true, reg, opc1, crm, opc2) {
                return ExecResult::Undefined;
            }
            let enc = crate::isa::arm::common::sysreg::Cp15Encoding::new(reg, opc1, crm, opc2);
            let value = self.cpu.cp15.read(enc).unwrap_or(0);
            if t != 15 {
                self.cpu.regs[t] = value;
            } else {
                // MRC with Rt=15 moves bits[31:28] into the CPSR flags.
                self.cpu.cpsr.n = (value & (1 << 31)) != 0;
                self.cpu.cpsr.z = (value & (1 << 30)) != 0;
                self.cpu.cpsr.c = (value & (1 << 29)) != 0;
                self.cpu.cpsr.v = (value & (1 << 28)) != 0;
            }
            return ExecResult::Continue;
        }

        if !self.cpu.is_privileged() {
            return ExecResult::Undefined;
        }
        // For now, return 0 (would read from coprocessor)
        if t != 15 {
            self.cpu.regs[t] = 0;
        }

        ExecResult::Continue
    }

    /// Whether PL0 may make a CP15 transfer: reading TPIDRURW and
    /// TPIDRURO, writing TPIDRURW, and the CP15DMB/CP15DSB/CP15ISB
    /// barriers when SCTLR.CP15BEN is set. The MCR2/MRC2 forms (bits
    /// 31:28 = 0b1111 in both A32 and T32) are none of them.
    fn pl0_cp15(
        &self,
        insn: &DecodedInsn,
        read: bool,
        crn: u8,
        opc1: u8,
        crm: u8,
        opc2: u8,
    ) -> bool {
        if insn.raw >> 28 == 0xF || opc1 != 0 {
            return false;
        }
        match (crn, crm, opc2) {
            (13, 0, 2) => true,
            (13, 0, 3) => read,
            (7, 10, 4) | (7, 10, 5) | (7, 5, 4) => !read && self.cpu.cp15.sctlr.cp15ben(),
            _ => false,
        }
    }
}
