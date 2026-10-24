//! Complete exported architectural state and validated restore operations.

use super::*;
use crate::isa::arm::aarch64::exceptions::{build_spsr, parse_spsr};
use crate::vm::vcpu::Aarch64ExecutionState;

impl AArch64Cpu {
    /// Keep the modeled AArch64 startup mode consistent with lower-EL RW
    /// controls. Initial EL2 is non-secure unless secure EL2 is configured
    /// explicitly afterward. Authentication enables and keys remain reset.
    pub(super) fn initialize_reset_control_state(&mut self) {
        self.sysregs.hcr_el2 |= 1 << 31;
        self.sysregs.scr_el3 |= 1 << 10;
        if self.config.initial_el == 2 {
            self.sysregs.scr_el3 |= 1;
        }
    }

    /// Full modeled AArch64 PSTATE, including BTYPE and exception-return flags.
    pub fn pstate_bits(&self) -> u64 {
        if let Some(state) = self.aarch32 {
            return state.bits()
                | (u64::from(self.nzcv) << 28)
                | (u64::from(self.dit) << 24)
                | (u64::from(self.ssbs) << 23)
                | (u64::from(self.pan) << 22)
                | (u64::from(self.ss) << 21)
                | (u64::from(self.il) << 20)
                | (u64::from(self.daif & 7) << 6);
        }
        build_spsr(
            self.nzcv,
            self.daif,
            self.current_el,
            self.sp_sel,
            self.ssbs,
            self.pan,
            self.uao,
            self.dit,
            self.tco,
            self.btype,
            self.il,
            self.ss,
        )
    }

    /// Validate a 64-bit SPSR state image before mutating the CPU. Legal
    /// AArch32 destinations use their complete 32-bit saved-state layout.
    /// Monitor state is unavailable on the PE's AArch64-reset EL3.
    pub fn validate_pstate_bits(value: u64) -> Result<(), ArmError> {
        use crate::isa::arm::aarch64::exception_return::MODELED_AARCH64_PSTATE;
        if value & 16 != 0 {
            if value >> 32 == 0
                && value & 31 != 0x16
                && super::super::aarch32_state::Aarch32Pstate::from_spsr(value).is_some()
            {
                return Ok(());
            }
            return Err(ArmError::Internal(
                "unsupported AArch32 saved PSTATE image".into(),
            ));
        }
        if value & !MODELED_AARCH64_PSTATE != 0
            || !matches!(value & 31, 0 | 4 | 5 | 8 | 9 | 12 | 13)
        {
            return Err(ArmError::Internal(
                "unsupported AArch64 PSTATE image".to_string(),
            ));
        }
        Ok(())
    }

    /// Validate a saved width against its advertised EL support and controlling
    /// SCR/HCR, before a restore can mutate registers or reset the CPU.
    pub fn validate_saved_state(
        value: u64,
        system: &Aarch64SystemRegisters,
    ) -> Result<(), ArmError> {
        Self::validate_pstate_bits(value)?;
        if value & 16 == 0 {
            return Ok(());
        }
        let execution = system.execution.as_ref().ok_or_else(|| {
            ArmError::Configuration("AArch32 state requires complete execution controls".into())
        })?;
        let features = ArmFeatures::from_bits(execution.features).ok_or_else(|| {
            ArmError::Configuration("unknown AArch64 feature bits in state".into())
        })?;
        let environment = super::super::pauth_execution::PauthEnvironment::from_system_registers(
            features,
            execution.pauth,
            3,
            &execution.sysregs,
        );
        if !matches!(
            super::super::exception_return::classify_exception_return(
                environment.controls,
                execution.sysregs.id_aa64pfr0_el1,
                value,
            ),
            super::super::exception_return::ExceptionReturnMode::Aarch32 { .. }
        ) {
            return Err(ArmError::Configuration(
                "AArch32 PSTATE disagrees with ID/SCR/HCR execution controls".into(),
            ));
        }
        Ok(())
    }

    /// Last decoded/fetched instruction width, including a faulting Thumb
    /// instruction; used by exception consumers rather than assuming 4 bytes.
    pub fn instruction_size(&self) -> u8 {
        self.last_instruction_size
    }

    pub fn set_pstate_bits(&mut self, value: u64) -> Result<(), ArmError> {
        self.set_pstate_bits_from_native(value)?;
        self.clear_jit_cache();
        Ok(())
    }

    /// The native PAuth bridge changes PSTATE without changing compiled code
    /// assumptions about keys/features/controls. Mode-tag lookup and checked
    /// helper entry remain responsible for subsequent region admission.
    pub(super) fn set_pstate_bits_from_native(&mut self, value: u64) -> Result<(), ArmError> {
        Self::validate_pstate_bits(value)?;
        if value & 16 != 0 {
            let state = super::super::aarch32_state::Aarch32Pstate::from_spsr(value)
                .expect("validated AArch32 PSTATE");
            self.nzcv = ((value >> 28) & 15) as u8;
            self.daif = (self.daif & 8) | ((value >> 6) & 7) as u8;
            self.current_el = super::super::aarch32_state::mode_el(state.mode).unwrap();
            self.sp_sel = !matches!(state.mode, 0x10 | 0x1f);
            self.ssbs = value & (1 << 23) != 0;
            self.pan = value & (1 << 22) != 0;
            self.dit = value & (1 << 24) != 0;
            self.il = value & (1 << 20) != 0;
            self.ss = value & (1 << 21) != 0;
            self.btype = 0;
            self.aarch32 = Some(state);
            self.update_mmu_config();
            return Ok(());
        }
        self.aarch32 = None;
        let (nzcv, daif, el, sp_sel, ssbs, pan, uao, dit, tco, btype, il, ss) = parse_spsr(value);
        self.nzcv = nzcv;
        self.daif = daif;
        self.current_el = el;
        self.sp_sel = sp_sel;
        self.ssbs = ssbs;
        self.pan = pan;
        self.uao = uao;
        self.dit = dit;
        self.tco = tco;
        self.btype = btype;
        self.il = il;
        self.ss = ss;
        self.update_mmu_config();
        Ok(())
    }

    pub fn validate_sregs(&self, sregs: &Aarch64SystemRegisters) -> Result<(), ArmError> {
        const AUTH_ENABLES: u64 = (1 << 31) | (1 << 30) | (1 << 27) | (1 << 13);
        if sregs.execution.is_none() && sregs.sctlr_el1 & AUTH_ENABLES != 0 {
            return Err(ArmError::Internal(
                "enabled AArch64 authentication requires complete keyed state".to_string(),
            ));
        }
        if let Some(state) = &sregs.execution {
            if ArmFeatures::from_bits(state.features).is_none() {
                return Err(ArmError::Internal(
                    "unknown AArch64 feature bits in state".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Export the complete modeled AArch64 system state.
    pub fn export_sregs(&self) -> Aarch64SystemRegisters {
        Aarch64SystemRegisters {
            sctlr_el1: self.sysregs.el1.sctlr,
            tcr_el1: self.sysregs.el1.tcr,
            ttbr0_el1: self.sysregs.el1.ttbr0,
            ttbr1_el1: self.sysregs.el1.ttbr1,
            mair_el1: self.sysregs.el1.mair,
            vbar_el1: self.sysregs.el1.vbar,
            esr_el1: self.sysregs.el1.esr,
            far_el1: self.sysregs.el1.far,
            elr_el1: self.sysregs.el1.elr,
            spsr_el1: self.sysregs.el1.spsr,
            sp_el0: self.sp_el[0],
            sp_el1: self.sp_el[1],
            tpidr_el0: self.sysregs.tpidr_el0,
            tpidr_el1: self.sysregs.el1.tpidr,
            tpidrro_el0: self.sysregs.tpidrro_el0,
            cntp_ctl_el0: self.sysregs.cntp_ctl_el0 & 0x3,
            cntp_cval_el0: self.sysregs.cntp_cval_el0,
            cntv_ctl_el0: self.sysregs.cntv_ctl_el0 & 0x3,
            cntv_cval_el0: self.sysregs.cntv_cval_el0,
            execution: Some(Box::new(Aarch64ExecutionState {
                features: self.config.features.bits(),
                pauth: self.config.pauth,
                sysregs: self.sysregs.clone(),
                sp_el2: self.sp_el[2],
                sp_el3: self.sp_el[3],
            })),
        }
    }

    /// Import the complete modeled AArch64 system state.
    pub fn import_sregs(&mut self, sregs: &Aarch64SystemRegisters) -> Result<(), ArmError> {
        self.validate_sregs(sregs)?;
        if let Some(state) = &sregs.execution {
            // The feature bit pattern was checked before any mutation.
            self.config.features = ArmFeatures::from_bits_retain(state.features);
            self.config.pauth = state.pauth;
            self.sysregs = state.sysregs.clone();
            self.sp_el[2] = state.sp_el2;
            self.sp_el[3] = state.sp_el3;
        }
        self.sysregs.el1.sctlr = sregs.sctlr_el1;
        self.sysregs.el1.tcr = sregs.tcr_el1;
        self.sysregs.el1.ttbr0 = sregs.ttbr0_el1;
        self.sysregs.el1.ttbr1 = sregs.ttbr1_el1;
        self.sysregs.el1.mair = sregs.mair_el1;
        self.sysregs.el1.vbar = sregs.vbar_el1;
        self.sysregs.el1.esr = sregs.esr_el1;
        self.sysregs.el1.far = sregs.far_el1;
        self.sysregs.el1.elr = sregs.elr_el1;
        self.sysregs.el1.spsr = sregs.spsr_el1;
        self.sp_el[0] = sregs.sp_el0;
        self.sp_el[1] = sregs.sp_el1;
        self.sysregs.tpidr_el0 = sregs.tpidr_el0;
        self.sysregs.el1.tpidr = sregs.tpidr_el1;
        self.sysregs.tpidrro_el0 = sregs.tpidrro_el0;
        self.sysregs.cntp_ctl_el0 = sregs.cntp_ctl_el0 & 0x3;
        self.sysregs.cntp_cval_el0 = sregs.cntp_cval_el0;
        self.sysregs.cntv_ctl_el0 = sregs.cntv_ctl_el0 & 0x3;
        self.sysregs.cntv_cval_el0 = sregs.cntv_cval_el0;
        self.update_pauth_id_registers();
        self.update_mmu_config();
        self.clear_jit_cache();
        Ok(())
    }
}
