//! RISC-V RAM RMWs share the same locks as tracked writes and exclusive rights.
use super::{Monitor, preflight_read, preflight_write};
use crate::isa::riscv::memory::{AtomicOp, MemError, MemResult};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

impl Monitor {
    pub(crate) fn atomic(
        &self,
        memory: &GuestMemoryMmap,
        address: u64,
        size: u8,
        operation: AtomicOp,
    ) -> MemResult<u128> {
        operation.validate(address, size)?;
        let length = usize::from(size);
        let fault = |_| MemError::OutOfBounds {
            addr: address,
            size: length,
        };
        // Admission cannot perform a device callback or mutate RAM. Both
        // permissions apply even when a Zacas comparison later misses.
        preflight_read(memory, address, length).map_err(fault)?;
        preflight_write(memory, address, length).map_err(fault)?;
        let mut domain = self.domain.lock();
        let mut bytes = [0; 16];
        memory
            .read_slice(&mut bytes[..length], GuestAddress(address))
            .map_err(fault)?;
        let old = u128::from_le_bytes(bytes);
        if let Some(new) = operation.replacement(old, size) {
            self.domain.invalidate(&mut domain, address, length);
            memory
                .write_slice(&new.to_le_bytes()[..length], GuestAddress(address))
                .map_err(fault)?;
        }
        Ok(old)
    }
}
