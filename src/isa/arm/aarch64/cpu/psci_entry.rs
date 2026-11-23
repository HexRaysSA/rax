//! PSCI entry resets the PE while retaining target-owned platform bindings.
use super::{AArch64Cpu, Aarch64SystemRegisters};
use crate::isa::arm::cpu_trait::{ArmCpu, ArmError};

fn set_psci_controls(scr: &mut u64, hcr: &mut u64, pstate: u64) {
    *scr |= 1 | (1 << 8);
    if pstate & 16 != 0 {
        *hcr &= !(1 << 31);
        if pstate & 31 == 0x1a {
            *scr &= !(1 << 10);
        }
    }
}

impl AArch64Cpu {
    pub(crate) fn configure_nonsecure_reset(&mut self) {
        self.nonsecure_reset = true;
        self.sysregs.scr_el3 |= 1 | (1 << 8);
    }

    pub(crate) fn validate_psci_pstate(
        pstate: u64,
        system: &Aarch64SystemRegisters,
    ) -> Result<(), ArmError> {
        if pstate & 16 == 0 {
            return Self::validate_pstate_bits(pstate);
        }
        let mut controls = system.clone();
        if let Some(execution) = controls.execution.as_mut() {
            set_psci_controls(
                &mut execution.sysregs.scr_el3,
                &mut execution.sysregs.hcr_el2,
                pstate,
            );
        }
        Self::validate_saved_state(pstate, &controls)
    }

    pub(crate) fn enter_psci(
        &mut self,
        pc: u64,
        context: u64,
        pstate: u64,
    ) -> Result<(), ArmError> {
        Self::validate_psci_pstate(pstate, &self.export_sregs())?;
        self.reset();
        set_psci_controls(&mut self.sysregs.scr_el3, &mut self.sysregs.hcr_el2, pstate);
        self.set_pstate_bits(pstate)?;
        self.set_pc(pc);
        self.set_gpr(0, context);
        Ok(())
    }
}
