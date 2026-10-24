//! Full guest-state helper calls under the identity-map AArch64 trampoline.

use super::*;
use crate::smir::lower::Aarch64GuestRegs;

impl Aarch64Lowerer {
    /// Enable only with `Aarch64PauthRuntime::run` or an equivalent scoped ABI.
    pub fn set_pauth_helpers(&mut self, enabled: bool) {
        self.pauth_helpers = enabled;
    }

    pub(super) fn emit_pauth_control_exit(&mut self) -> Result<(), LowerError> {
        self.emit_push_scratch(9);
        self.emit_mov_imm(9, A64_EXIT_VALID, OpWidth::W64)?;
        self.emit_ldst_unsigned(9, A64_STATE_REG, 3, 0, A64_GUEST_EXIT_FLAGS_OFFSET / 8);
        self.emit_pop_scratch(9);
        self.emit(0xd65f_03c0);
        Ok(())
    }

    fn pauth_spill(&mut self) -> Result<(), LowerError> {
        self.emit_mem_helper_spill()?;
        if self.pauth_fp_helpers {
            self.emit_simd_spill_all();
            self.emit_sysreg(9, ArmReg::Fpcr, true)?;
            self.emit_ldst_unsigned(
                9,
                A64_STATE_REG,
                3,
                0,
                Aarch64GuestRegs::FPCR_OFFSET as u32 / 8,
            );
            self.emit_sysreg(9, ArmReg::Fpsr, true)?;
            self.emit_ldst_unsigned(
                9,
                A64_STATE_REG,
                3,
                0,
                Aarch64GuestRegs::FPSR_OFFSET as u32 / 8,
            );
            self.emit_mov_imm(9, 0, OpWidth::W64)?;
            self.emit_sysreg(9, ArmReg::Fpcr, false)?;
            self.emit_sysreg(9, ArmReg::Fpsr, false)?;
        }
        // x18/x28/x30 are guest shadows, never identity-mapped live registers.
        for register in 19..=27 {
            self.emit_ldst_unsigned(register, A64_STATE_REG, 3, 0, u32::from(register));
        }
        Ok(())
    }

    fn pauth_reload(&mut self) -> Result<(), LowerError> {
        if self.pauth_fp_helpers {
            self.emit_simd_reload_all();
            self.emit_ldst_unsigned(
                9,
                A64_STATE_REG,
                3,
                1,
                Aarch64GuestRegs::FPCR_OFFSET as u32 / 8,
            );
            self.emit_sysreg(9, ArmReg::Fpcr, false)?;
            self.emit_ldst_unsigned(
                9,
                A64_STATE_REG,
                3,
                1,
                Aarch64GuestRegs::FPSR_OFFSET as u32 / 8,
            );
            self.emit_sysreg(9, ArmReg::Fpsr, false)?;
        }
        for register in 19..=27 {
            self.emit_ldst_unsigned(register, A64_STATE_REG, 3, 1, u32::from(register));
        }
        self.emit_mem_helper_reload()
    }

    pub(super) fn lower_pauth_helper(
        &mut self,
        phase: u64,
        raw: u32,
        pc: u64,
        features: u64,
    ) -> Result<(), LowerError> {
        if !self.pauth_helpers {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 PAuth scoped helper ABI is disabled".into(),
            });
        }
        self.pauth_spill()?;
        self.emit_ldst_unsigned(
            9,
            A64_STATE_REG,
            3,
            1,
            Aarch64GuestRegs::PAUTH_FN_OFFSET as u32 / 8,
        );
        let absent = self.code.position();
        self.emit(0xb400_0009); // cbz x9, absent
        self.emit_push_scratch(30); // host trampoline LR, not guest X30
        self.emit_mov_reg(0, A64_STATE_REG, OpWidth::W64)?;
        self.emit_mov_imm(1, phase as i64, OpWidth::W64)?;
        self.emit_mov_imm(2, i64::from(raw), OpWidth::W64)?;
        self.emit_mov_imm(3, pc as i64, OpWidth::W64)?;
        self.emit_mov_imm(4, features as i64, OpWidth::W64)?;
        self.emit_blr_reg(9);
        self.emit_pop_scratch(30);
        let failed = self.code.position();
        self.emit(0xb400_0000); // cbz x0, failed
        self.pauth_reload()?;
        let done = self.code.position();
        self.emit(0x1400_0000);
        self.patch_compare_branch_to_current(failed, 0, false)?;
        self.pauth_reload()?;
        // The helper has already recorded the exact fault/limit PC and exit.
        self.emit(0xd65f_03c0);
        self.patch_compare_branch_to_current(absent, 9, false)?;
        self.pauth_reload()?;
        self.emit_native_exit(pc)?;
        self.patch_branch_to_current(done)
    }
}
