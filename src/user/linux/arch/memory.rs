//! Memory facts needed by Linux ABI exception translation, in addition to
//! the storage and admission contract used by the architectural CPU adapters.

use crate::user::cpu::CpuAddressSpace;
use crate::user::mm::AddressSpace;

/// Authoritative Linux exception-frame memory queries. A remote failure must
/// remain an emulator error; it must never fabricate an architectural #PF.
pub trait LinuxAddressSpace: CpuAddressSpace {
    /// Whether an address has a populated page in a VMA with at least one
    /// permission. Does not populate the page or change its permissions.
    fn resident_accessible(&self, address: u64) -> Result<bool, String>;
}

impl LinuxAddressSpace for AddressSpace {
    fn resident_accessible(&self, address: u64) -> Result<bool, String> {
        Ok(self.is_resident(address)
            && self
                .vma_at(address)
                .is_some_and(|vma| !vma.perms.is_empty()))
    }
}

#[cfg(unix)]
impl LinuxAddressSpace for crate::user::mm::process_owner::OwnerMemory {
    fn resident_accessible(&self, address: u64) -> Result<bool, String> {
        self.query_resident_accessible(address)
    }
}

#[cfg(test)]
mod tests;
