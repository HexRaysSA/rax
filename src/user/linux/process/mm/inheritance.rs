//! Linux `dup_mmap` policy for an unpublished private child. Generic storage
//! snapshots retain every VMA; this personality step consumes inheritance flags.

use crate::user::linux::abi::vma_flags;
use crate::user::mm::{AddressSpace, Backing, MmError};

/// Apply only to a private child while its address space is quiescent. Shared
/// MM workers must retain their common mappings and contents. The VMA walk uses
/// O(V) temporary storage; unmap/discard also process the affected sparse pages.
/// Failure invalidates the unpublished child, which must not begin execution.
pub(crate) fn prepare_fork_inheritance(space: &AddressSpace) -> Result<(), MmError> {
    if !space.available() {
        return Err(MmError::InvalidArgument(
            "unavailable private fork snapshot",
        ));
    }
    for vma in space.vma_snapshot() {
        if vma.flags & vma_flags::DONTCOPY != 0 {
            space.unmap(vma.start, vma.len())?;
        } else if vma.flags & vma_flags::WIPEONFORK != 0 {
            if vma.shared || !matches!(vma.backing, Backing::Anonymous) {
                return Err(MmError::InvalidArgument(
                    "WIPEONFORK requires private anonymous memory",
                ));
            }
            // Retain WIPEONFORK for nested forks. Discard private pages so the
            // child's next touch sees zero without changing parent storage.
            space.discard(vma.start, vma.len())?;
        }
    }
    Ok(())
}
