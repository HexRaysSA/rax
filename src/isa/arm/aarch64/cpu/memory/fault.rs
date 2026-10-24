//! Virtual fault metadata from translation and physical backing failures.

use crate::isa::arm::aarch64::cpu::AArch64Cpu;
use crate::isa::arm::aarch64::mmu::TranslationFault;
use crate::isa::arm::common::cpu::{AccessType, ArmError, MemoryFaultInfo, MemoryFaultType};
use crate::isa::arm::common::features::ArmFeatures;
use crate::isa::arm::common::memory::MemoryError;

impl AArch64Cpu {
    /// Arm A64 XML 2025-12: AArch64_{Data,Instruction}Abort and
    /// SyncExternalAbortTarget for faults represented by MemoryFaultInfo.
    /// That record has no RME GPC fault or NV2-specific access descriptor;
    /// DoubleFault routing and AArch32 EL3 are not modeled by this path.
    pub(crate) fn abort_target_el(&self, info: &MemoryFaultInfo) -> u8 {
        let controls = self.pauth_controls();
        let external = matches!(
            info.fault_type,
            MemoryFaultType::External | MemoryFaultType::SyncExternal
        );
        if self.current_el == 3
            || (external && controls.implemented_els & 8 != 0 && controls.scr_el3 & (1 << 3) != 0)
        {
            return 3;
        }
        if self.current_el == 2 {
            return 2;
        }
        let tge = controls.hcr_el2 & (1 << 27) != 0;
        let tea =
            self.config.features.contains(ArmFeatures::RAS) && controls.hcr_el2 & (1 << 37) != 0;
        let route = if external {
            tea || info.stage2 || (self.current_el == 0 && tge)
        } else {
            tge || info.stage2
        };
        if controls.el2_enabled() && route {
            2
        } else {
            1
        }
    }

    /// Convert translation fault to ArmError.
    pub(crate) fn translation_fault_to_error(
        &self,
        fault: TranslationFault,
        access: AccessType,
    ) -> ArmError {
        use crate::isa::arm::aarch64::mmu::TranslationFaultType;

        let fault_type = match fault.fault_type {
            TranslationFaultType::Translation => MemoryFaultType::Translation,
            TranslationFaultType::Permission => MemoryFaultType::Permission,
            TranslationFaultType::Alignment => MemoryFaultType::Alignment,
            TranslationFaultType::AccessFlag => MemoryFaultType::AccessFlag,
            TranslationFaultType::AddressSize => MemoryFaultType::AddressSize,
            TranslationFaultType::ExternalAbort => MemoryFaultType::External,
        };

        self.last_fault_level
            .store(fault.level, std::sync::atomic::Ordering::Relaxed);

        ArmError::MemoryError(MemoryFaultInfo {
            address: fault.va,
            access,
            fault_type,
            stage2: fault.stage2,
        })
    }

    /// Preserve virtual address and access intent when physical backing fails.
    pub(in crate::isa::arm::aarch64::cpu) fn physical_memory_error(
        &self,
        error: MemoryError,
        va: u64,
        pa: u64,
        width: usize,
        access: AccessType,
    ) -> ArmError {
        // Once translation succeeded, a missing physical target is an
        // external abort, rather than another stage-1 translation fault.
        let missing_physical = self.mmu.is_enabled()
            && matches!(
                error,
                MemoryError::OutOfBounds { .. } | MemoryError::Unmapped { .. }
            );
        let mut error = ArmError::from(error);
        if let ArmError::MemoryError(info) = &mut error {
            let offset = info
                .address
                .checked_sub(pa)
                .filter(|offset| *offset < width as u64)
                .unwrap_or(0);
            info.address = va.wrapping_add(offset);
            info.access = access;
            if missing_physical {
                info.fault_type = MemoryFaultType::External;
            }
        }
        error
    }
}
