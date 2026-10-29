//! Guest FP permission checks and native requirements before optimization.
use super::*;
use crate::isa::arm::common::fp_access::{FpAccessClass, FpAccessControls};

impl AArch64Cpu {
    pub(super) fn fp_access_controls(&self) -> FpAccessControls {
        let controls = self.pauth_controls();
        let cptr = |op1| {
            self.sysregs
                .impl_defined
                .get(&Aarch64SysRegEncoding::new(3, op1, 1, 1, 2).encode())
                .copied()
                .unwrap_or(0)
        };
        FpAccessControls {
            current_el: self.current_el,
            el2_enabled: controls.el2_enabled(),
            have_el3: controls.implemented_els & 8 != 0,
            vhe: controls.vhe,
            hcr: controls.hcr_el2,
            cpacr: self.sysregs.el1.cpacr,
            cptr_el2: cptr(4),
            cptr_el3: cptr(6),
        }
    }

    pub(super) fn check_fp_access(&self, class: FpAccessClass) -> Result<(), ArmError> {
        match self.fp_access_controls().fault(class) {
            None => Ok(()),
            Some(fault) => Err(ArmError::ArchitecturalException {
                ec: fault.ec,
                iss: 0,
                // Preserve the existing direct local-EL1 fault representation.
                target_el: (fault.target_el != 1).then_some(fault.target_el),
            }),
        }
    }
}
