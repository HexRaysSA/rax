//! Precise ERET/ERETAA/ERETAB control checks and architectural return commit.

use super::*;
use crate::isa::arm::aarch64::exception_return::{
    ExceptionReturnMode, aarch64_return_pstate, classify_exception_return,
};

impl AArch64Cpu {
    pub(super) fn check_exception_return_trap(
        &self,
        pac: bool,
        key_b: bool,
    ) -> Result<(), ArmError> {
        if self.current_el == 0 {
            return Err(ArmError::InvalidExceptionLevel(0));
        }
        let controls = self.pauth_controls();
        if self.current_el == 1
            && controls.el2_enabled()
            && self.config.features.contains(ArmFeatures::NV)
            && controls.hcr_el2 & (1 << 42) != 0
        {
            return Err(ArmError::ArchitecturalException {
                ec: 0x1a,
                iss: (u32::from(pac) << 1) | u32::from(pac && key_b),
                target_el: Some(2),
            });
        }
        Ok(())
    }

    pub(crate) fn exception_return(&mut self) -> Result<CpuExit, ArmError> {
        self.check_exception_return_trap(false, false)?;
        self.exception_return_to(None)
    }

    pub(super) fn exception_return_to(
        &mut self,
        authenticated_target: Option<u64>,
    ) -> Result<CpuExit, ArmError> {
        let bank = self.sysregs.bank(self.current_el);
        let saved = bank.spsr;
        let mut target = authenticated_target.unwrap_or(bank.elr);
        let mode =
            classify_exception_return(self.pauth_controls(), self.sysregs.id_aa64pfr0_el1, saved);
        let ss = crate::isa::arm::aarch64::exception_return::exception_return_ss(
            self.pauth_controls(),
            &self.sysregs,
            self.pstate_bits(),
            saved,
            mode,
        );
        let restored = match mode {
            ExceptionReturnMode::Aarch32 { .. } => {
                super::super::aarch32_state::return_pstate(saved, ss, self.pauth_controls())
            }
            _ => aarch64_return_pstate(self.pstate_bits(), saved, mode, ss),
        }
        .ok_or_else(|| ArmError::Internal("invalid exception-return state".into()))?;
        if mode == ExceptionReturnMode::Illegal && saved & 16 != 0 {
            // Arm permits arbitrary PC[63:32,1:0] on an illegal AArch32 return.
            target &= 0xffff_fffc;
        }
        self.set_pstate_bits(restored)?;
        self.clear_exclusive_monitor();
        self.event_register = true;
        self.pc = if self.aarch32.is_some() {
            super::super::aarch32_state::return_address(target, restored)
        } else {
            self.pauth_controls().branch_address(target)
        };
        self.update_mmu_config();
        Ok(CpuExit::Continue)
    }
}
