//! Linux MM initialization shared by native children and the memory owner.
//!
//! `MmState::clone` preserves the pinned-account identity for existing users
//! of an MM. A private fork instead needs `mm_init` accounting and `dup_mmap`
//! lock removal on its unpublished address-space snapshot.

use super::MmState;
use crate::user::linux::abi::vma_flags;
use crate::user::mm::{AddressSpace, MmError};

mod advice;
mod aio;
mod aio_reap;
mod brk;
mod inheritance;
mod locks;
pub(crate) mod mapping;
mod queries;
mod ranges;
mod remap;
mod resources;
pub(crate) use aio_reap::{AioRead, AioReadResult};
pub(crate) use brk::BrkPolicy;
pub(crate) use inheritance::prepare_fork_inheritance;
pub(crate) use locks::LockPolicy;
pub(crate) use mapping::{MmapArgs, MmapPolicy, PreparedMmap};
pub(crate) use ranges::ProtectPolicy;
pub(crate) use remap::RemapArgs;
pub(crate) use resources::MmResources;
#[cfg(test)]
pub(crate) use resources::pending_fixture;
#[cfg(unix)]
pub(crate) mod remote;

impl MmState {
    /// Derive private-child bookkeeping without changing the parent's MM.
    /// The caller owns an unpublished, quiescent snapshot, not a shared clone.
    /// Inheritance advice selects the child layout and contents. Rings inherited
    /// through open files continue to charge their original account, while new
    /// child rings use a fresh one.
    pub(crate) fn fork_private(&self, snapshot: &AddressSpace) -> Result<Self, MmError> {
        prepare_fork_inheritance(snapshot)?;
        let mut child = self.clone();
        child.pinned_vm = Default::default();
        child.reset_fork_locks(snapshot)?;
        Ok(child)
    }

    /// `mm_init` clears lock accounting and `dup_mmap` clears VM_LOCKED_MASK.
    /// This takes O(V log V) time and O(V) temporary space for V VMAs. It changes no
    /// page contents, permissions, or unrelated mapping flags. Failure leaves
    /// the unpublished child unusable; the owner must not register it.
    pub(crate) fn reset_fork_locks(&mut self, space: &AddressSpace) -> Result<(), MmError> {
        self.def_lock = 0;
        self.locked_vm = 0;
        for vma in space.vma_snapshot() {
            if vma.flags & vma_flags::LOCKED_MASK != 0 {
                space.set_flags(vma.start, vma.len(), vma_flags::LOCKED_MASK, 0)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::initial_state;

#[cfg(test)]
mod inheritance_tests;

#[cfg(test)]
mod aio_tests;
