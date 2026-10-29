//! Guest FP permission checks and native requirements before optimization.
use super::*;
use crate::isa::arm::common::fp_access::{FpAccessClass, FpAccessControls, FpAccessRequirements};

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

    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    pub(super) fn native_fp_requirements(
        &self,
        function: &crate::smir::ir::SmirFunction,
        entry: u64,
        bytes: &[u8],
    ) -> Option<(FpAccessRequirements, ArmFeatures)> {
        let mut requirements = FpAccessRequirements::default();
        let mut features = ArmFeatures::empty();
        for op in function.blocks.iter().flat_map(|b| &b.ops) {
            let Some(offset) = op
                .guest_pc
                .checked_sub(entry)
                .and_then(|n| usize::try_from(n).ok())
            else {
                continue;
            };
            let Some(end) = offset.checked_add(4) else {
                continue;
            };
            if let Some(word) = bytes.get(offset..end) {
                let word = u32::from_le_bytes(word.try_into().unwrap());
                if !self.fp_instruction_version_supported(word) {
                    return None;
                }
                requirements.observe(word);
                features |= super::fp_profile::instruction_features(word)?;
            }
        }
        // Preserve the existing policy for helper-generated FP operations that
        // do not carry an instruction PC inside the supplied lift window.
        if !requirements.data
            && !requirements.system
            && crate::smir::lower::aarch64::uses_aarch64_fp_trampoline(function)
        {
            requirements.data = true;
        }
        Some((requirements, features))
    }
}
