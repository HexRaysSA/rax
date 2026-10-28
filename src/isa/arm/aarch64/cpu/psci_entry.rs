//! PSCI entry resets the PE while retaining target-owned platform bindings.
use super::AArch64Cpu;
use crate::isa::arm::cpu_trait::{ArmCpu, ArmError};

impl AArch64Cpu {
    pub(crate) fn configure_nonsecure_reset(&mut self) {
        self.nonsecure_reset = true;
        self.sysregs.scr_el3 |= 1 | (1 << 8);
    }

    pub(crate) fn enter_psci(
        &mut self,
        pc: u64,
        context: u64,
        pstate: u64,
    ) -> Result<(), ArmError> {
        let mut controls = self.export_sregs();
        if let Some(execution) = controls.execution.as_mut() {
            execution.sysregs.scr_el3 |= 1 | (1 << 8);
            if pstate & 16 != 0 {
                execution.sysregs.hcr_el2 &= !(1 << 31);
                if pstate & 31 == 0x1a {
                    execution.sysregs.scr_el3 &= !(1 << 10);
                }
            }
        }
        Self::validate_saved_state(pstate, &controls)?;
        self.reset();
        self.sysregs.scr_el3 |= 1 | (1 << 8);
        if pstate & 16 != 0 {
            self.sysregs.hcr_el2 &= !(1 << 31);
            if pstate & 31 == 0x1a {
                self.sysregs.scr_el3 &= !(1 << 10);
            }
        }
        self.set_pstate_bits(pstate)?;
        self.set_pc(pc);
        self.set_gpr(0, context);
        Ok(())
    }
}
