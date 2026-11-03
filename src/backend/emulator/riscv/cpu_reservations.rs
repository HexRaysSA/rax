//! Physical reservation admission before the RAM writer lock.
use super::{
    GuestMemoryFault, MemError, MemResult, MemoryAccessKind, UART_BASE, UART_LEN, UserBridge,
};
use vm_memory::{GuestAddress, GuestMemory};

pub(super) fn overlaps_uart(address: u64, size: usize) -> bool {
    u128::from(address) < u128::from(UART_BASE + UART_LEN)
        && u128::from(address) + size as u128 > u128::from(UART_BASE)
}

impl UserBridge {
    pub(super) fn atomic_address(&self, address: u64, size: usize) -> MemResult<u64> {
        let read = self
            .translation
            .translate(address, MemoryAccessKind::Read)
            .map_err(|mut fault| {
                fault.access = MemoryAccessKind::Write;
                fault.size = size.min(u32::MAX as usize) as u32;
                self.fail(fault, size)
            })?;
        let write = self
            .translation
            .translate(address, MemoryAccessKind::Write)
            .map_err(|mut fault| {
                fault.size = size.min(u32::MAX as usize) as u32;
                self.fail(fault, size)
            })?;
        if read != write || !self.mem.check_range(GuestAddress(write), size) {
            return Err(self.fail(
                GuestMemoryFault::unmapped(address, size, MemoryAccessKind::Write),
                size,
            ));
        }
        Ok(write)
    }

    pub(super) fn reserved_address(
        &self,
        address: u64,
        size: usize,
        access: MemoryAccessKind,
    ) -> MemResult<u64> {
        if !matches!(size, 4 | 8) || address & (size as u64 - 1) != 0 {
            return Err(MemError::Misaligned {
                addr: address,
                size,
            });
        }
        let physical = self
            .translation
            .translate(address, access)
            .map_err(|fault| self.fail(fault, size))?;
        if !self.mem.check_range(GuestAddress(physical), size) {
            return Err(self.fail(GuestMemoryFault::unmapped(address, size, access), size));
        }
        Ok(physical)
    }
}
