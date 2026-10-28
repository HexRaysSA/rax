//! Physical admission for exclusive RAM transactions.

use super::for_each_user_page;
use super::{GICD_SIZE, GuestBridge, UART_BASE, UART_SIZE};
use crate::error::MemoryAccessKind;
use crate::isa::arm::memory::{MemResult, MemoryError};
use crate::machine::arm_virt::AARCH64_GICD_BASE;

impl GuestBridge {
    /// Resolve a complete exclusive access before entering the RAM domain.
    /// Device windows do not implement the exclusive-access protocol.
    pub(super) fn exclusive_physical(
        &self,
        address: u64,
        size: usize,
        access: MemoryAccessKind,
    ) -> MemResult<u64> {
        if !matches!(size, 1 | 2 | 4 | 8 | 16) || address & (size as u64 - 1) != 0 {
            return Err(MemoryError::Alignment {
                addr: address,
                required: size,
            });
        }
        let mut physical = address;
        if let Some(translation) = self.translation.as_deref() {
            for_each_user_page(translation, address, size, access, |target, range| {
                if range.start == 0 {
                    physical = target;
                } else if physical.checked_add(range.start as u64) != Some(target) {
                    return Err(MemoryError::ExclusiveFailed { addr: address });
                }
                Ok(())
            })?;
        }
        if self.devices_enabled {
            let overlaps = |base: u64, length: u64| {
                u128::from(physical) < u128::from(base) + u128::from(length)
                    && u128::from(base) < u128::from(physical) + size as u128
            };
            let redist =
                crate::machine::arm_virt::aarch64_redist_regions(self.gic_cpus, self.gic_high_base);
            if overlaps(UART_BASE, UART_SIZE)
                || overlaps(AARCH64_GICD_BASE, GICD_SIZE)
                || redist.iter().any(|&(base, length)| overlaps(base, length))
            {
                return Err(MemoryError::ExclusiveFailed { addr: address });
            }
        }
        Ok(physical)
    }
}
