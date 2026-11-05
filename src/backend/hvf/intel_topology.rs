//! Per-VM CPUID geometry; one thread per core, up to64 cores per package.
use super::HvfCore;
use crate::error::{Error, Result};
use std::sync::atomic::Ordering;

impl HvfCore {
    pub(super) fn topology_cpuid(&self, leaf: u32, subleaf: u32) -> Result<(u32, u32, u32, u32)> {
        let mut value = self.cpuid_config.cpuid_for_cpu(leaf, subleaf, self.id);
        let configured = *self
            ._vm
            .configured
            .lock()
            .map_err(|_| Error::Emulator("Intel HVF configuration lock poisoned".into()))?;
        let Some((count, _)) = configured else {
            return Ok(value);
        };
        // Unconfigured SDK consumers and old checkpoints retain the CPUID
        // geometry they originally saw. The shared record versions this policy.
        if self._vm.legacy_topology.load(Ordering::Acquire)
            || leaf > self.cpuid_config.max_basic_leaf
        {
            return Ok(value);
        }
        if count == 0 || self.id >= u32::from(count) {
            return Err(Error::InvalidConfig(
                "invalid Intel HVF CPU geometry".into(),
            ));
        }
        // Intel SDM086 Vol.2A Table3-17, CPUID.1/.4/.0B. CPUID.4 EAX[31:26]
        // bounds cores/package to64. Additional IDs occupy further packages,
        // and a non-power-of-two count leaves unused APIC-ID slots.
        let cores = u32::from(count).min(64);
        let package_shift = u32::BITS - (cores - 1).leading_zeros();
        match leaf {
            1 => {
                value.1 = (value.1 & 0xffff) | (cores << 16) | (self.id << 24);
                value.3 = (value.3 & !(1 << 28)) | (u32::from(cores > 1) << 28);
            }
            4 if value.0 & 31 != 0 => {
                let sharing = if (value.0 >> 5) & 7 <= 2 { 1 } else { cores };
                value.0 = (value.0 & 0x3fff) | ((sharing - 1) << 14) | ((cores - 1) << 26);
            }
            0x0b | 0x1f => {
                value = match subleaf {
                    0 => (0, 1, 0x100, self.id),
                    1 => (package_shift, cores, 0x201, self.id),
                    _ => (0, 0, subleaf & 255, self.id),
                };
            }
            _ => {}
        }
        Ok(value)
    }
}
