//! Branch, exception, and system instruction execution

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
    pub(crate) fn exec_bl(&mut self, insn: &DecodedInsn) -> ExecResult {
        // The return address is the instruction after this BL. In Thumb state
        // LR must carry bit0 = 1 so the eventual `BX LR` resumes in Thumb.
        if insn.state.is_thumb() {
            self.cpu.regs[14] = self.cpu.regs[15].wrapping_add(4) | 1;
        } else {
            self.cpu.regs[14] = self.cpu.regs[15].wrapping_add(4);
        }

        if let Some(target) = self.decode_branch_target(insn) {
            ExecResult::Branch(target)
        } else {
            ExecResult::Undefined
        }
    }

    pub(crate) fn exec_bx(&mut self, insn: &DecodedInsn) -> ExecResult {
        if let Some(m) = self.decode_reg_operand(insn, 0) {
            let target = self.reg(m);
            self.cpu.cpsr.t = (target & 1) != 0;
            ExecResult::Branch(target & !1)
        } else {
            ExecResult::Undefined
        }
    }

    pub(crate) fn exec_blx(&mut self, insn: &DecodedInsn) -> ExecResult {
        let thumb = insn.state.is_thumb();

        if let Some(m) = self.decode_reg_operand(insn, 0) {
            // BLX Rm: target state comes from bit0 of Rm. Read the target
            // BEFORE writing LR (`blx lr`). The register form is 2 bytes in
            // Thumb, 4 in ARM.
            let target = self.reg(m);
            let ret = self.cpu.regs[15].wrapping_add(if thumb { 2 } else { 4 });
            self.cpu.regs[14] = if thumb { ret | 1 } else { ret };
            self.cpu.cpsr.t = (target & 1) != 0;
            ExecResult::Branch(target & !1)
        } else if let Some(target) = self.decode_branch_target(insn) {
            // BLX (immediate): always toggles instruction set. The 4-byte
            // encoding exists in both states.
            let ret = self.cpu.regs[15].wrapping_add(4);
            self.cpu.regs[14] = if thumb { ret | 1 } else { ret };
            if thumb {
                // Thumb → ARM: the branch target is word-aligned.
                self.cpu.cpsr.t = false;
                let align = self.cpu.regs[15].wrapping_add(4) & 3;
                ExecResult::Branch(target.wrapping_sub(align))
            } else {
                // ARM → Thumb.
                self.cpu.cpsr.t = true;
                ExecResult::Branch(target)
            }
        } else {
            ExecResult::Undefined
        }
    }

    pub(crate) fn exec_cbz(&mut self, insn: &DecodedInsn) -> ExecResult {
        // Thumb-2 only
        let n = (insn.raw & 0x7) as usize;
        if self.reg(n) == 0 {
            if let Some(target) = self.decode_branch_target(insn) {
                return ExecResult::Branch(target);
            }
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_cbnz(&mut self, insn: &DecodedInsn) -> ExecResult {
        // Thumb-2 only
        let n = (insn.raw & 0x7) as usize;
        if self.reg(n) != 0 {
            if let Some(target) = self.decode_branch_target(insn) {
                return ExecResult::Branch(target);
            }
        }
        ExecResult::Continue
    }

    pub(crate) fn exec_clrex(&mut self, _insn: &DecodedInsn) -> ExecResult {
        self.exclusive_monitor.clear();
        ExecResult::Continue
    }

    // =========================================================================
    // System Operations
    // =========================================================================

    /// SVC: A1's imm24, T1's imm8.
    pub(crate) fn exec_svc(&mut self, insn: &DecodedInsn) -> ExecResult {
        let imm = if insn.state.is_thumb() {
            insn.raw & 0xFF
        } else {
            insn.raw & 0x00FF_FFFF
        };
        ExecResult::Exception(ExceptionType::SupervisorCall(imm))
    }

    /// BKPT: A1's imm12:imm4 (bits 19:8 and 3:0), T1's imm8.
    pub(crate) fn exec_bkpt(&mut self, insn: &DecodedInsn) -> ExecResult {
        let imm = if insn.state.is_thumb() {
            insn.raw & 0xFF
        } else {
            ((insn.raw >> 4) & 0xFFF0) | (insn.raw & 0xF)
        };
        ExecResult::Exception(ExceptionType::Breakpoint(imm as u16))
    }

    /// MRS: A1 keeps Rd in bits 15:12 and R in bit 22, T1 Rd in 11:8 and
    /// R in 20.
    pub(crate) fn exec_mrs(&mut self, insn: &DecodedInsn) -> ExecResult {
        let (d, r) = if insn.state.is_thumb() {
            (((insn.raw >> 8) & 0xF) as usize, (insn.raw >> 20) & 1)
        } else {
            (((insn.raw >> 12) & 0xF) as usize, (insn.raw >> 22) & 1)
        };

        let value = if r != 0 {
            if let Some(spsr) = self.cpu.get_current_spsr() {
                spsr.to_u32()
            } else {
                return ExecResult::Undefined;
            }
        } else {
            self.cpu.cpsr.to_u32()
        };

        self.cpu.regs[d] = value;
        ExecResult::Continue
    }

    /// MSR: A1 (immediate) and A1 (register) keep R in bit 22, the mask in
    /// bits 19:16, and Rn in 3:0; T1 (register only) R in bit 20, the mask
    /// in 11:8, and Rn in 19:16.
    pub(crate) fn exec_msr(&mut self, insn: &DecodedInsn) -> ExecResult {
        if insn.state.is_thumb() {
            let r = (insn.raw >> 20) & 1;
            let mask = (insn.raw >> 8) & 0xF;
            let value = self.reg(((insn.raw >> 16) & 0xF) as usize);
            if r != 0 {
                self.write_current_spsr_by_mask(value, mask);
            } else {
                self.write_cpsr_by_mask(value, mask);
            }
            return ExecResult::Continue;
        }
        let r = (insn.raw >> 22) & 1;
        let mask = (insn.raw >> 16) & 0xF;

        let value = if (insn.raw >> 25) & 1 != 0 {
            let imm12 = insn.raw & 0xFFF;
            expand_imm_c(imm12, self.cpu.cpsr.c).0
        } else {
            let n = (insn.raw & 0xF) as usize;
            self.reg(n)
        };

        if r != 0 {
            self.write_current_spsr_by_mask(value, mask);
        } else {
            self.write_cpsr_by_mask(value, mask);
        }

        ExecResult::Continue
    }

    /// Execute IT (If-Then) instruction (Thumb-2).
    ///
    /// IT{x{y{z}}} cond
    ///
    /// Sets up IT state for conditional execution of up to 4 following instructions.
    /// The condition and mask determine which instructions execute and which are skipped.
    pub(crate) fn exec_it(&mut self, insn: &DecodedInsn) -> ExecResult {
        // IT instruction encoding (16-bit Thumb):
        // Bits 7:4 = firstcond (base condition code)
        // Bits 3:0 = mask (determines T/E pattern)
        let firstcond = ((insn.raw >> 4) & 0xF) as u8;
        let mask = (insn.raw & 0xF) as u8;

        // Mask of 0 is not allowed (would be NOP)
        if mask == 0 {
            return ExecResult::Undefined;
        }

        // Set IT state in CPSR
        self.cpu.cpsr.set_it_state(firstcond, mask);

        ExecResult::Continue
    }

    // =========================================================================
    // Coprocessor Operations
    // =========================================================================

    /// CPS: change processor state (ARMv6). NOP in user mode. A1 keeps imod
    /// in bits 19:18, M in 17, and A, I, F in 8:6; T2 imod in 10:9, M in
    /// 8, and A, I, F in 7:5; both the mode in 4:0. T1 has im (imod 1:im)
    /// in bit 4 and A, I, F in 2:0, and no mode.
    pub(crate) fn exec_cps(&mut self, insn: &DecodedInsn) -> ExecResult {
        if self.cpu.is_user_or_system() && self.cpu.cpsr.mode == ProcessorMode::User as u8 {
            return ExecResult::Continue;
        }
        let raw = insn.raw;
        let (imod, m, aif) = if insn.state.is_thumb() && insn.size == 2 {
            (0b10 | (raw >> 4) & 1, 0, 0)
        } else if insn.state.is_thumb() {
            ((raw >> 9) & 0x3, (raw >> 8) & 1, 5)
        } else {
            ((raw >> 18) & 0x3, (raw >> 17) & 1, 6)
        };
        let (a, i, f) = (
            (raw >> (aif + 2)) & 1,
            (raw >> (aif + 1)) & 1,
            (raw >> aif) & 1,
        );
        match imod {
            0b10 => {
                // CPSIE: enable = clear mask bits
                if a == 1 {
                    self.cpu.cpsr.a = false;
                }
                if i == 1 {
                    self.cpu.cpsr.i = false;
                }
                if f == 1 {
                    self.cpu.cpsr.f = false;
                }
            }
            0b11 => {
                // CPSID: disable = set mask bits
                if a == 1 {
                    self.cpu.cpsr.a = true;
                }
                if i == 1 {
                    self.cpu.cpsr.i = true;
                }
                if f == 1 {
                    self.cpu.cpsr.f = true;
                }
            }
            _ => {}
        }
        if m == 1 {
            if let Some(mode) = ProcessorMode::from_bits((raw & 0x1F) as u8) {
                self.cpu.change_mode(mode);
            }
        }
        ExecResult::Continue
    }
}
