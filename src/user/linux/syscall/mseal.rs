//! Memory sealing (`mm/mseal.c`, Linux 6.19): `mseal`, and what a seal
//! refuses.
//!
//! A sealed VMA carries [`vma_flags::SEALED`] (`VM_SEALED`), which nothing
//! removes. The calls that would change it check [`sealed_in`] where the
//! kernel does (`vma_is_sealed`): `munmap` and every unmapping behind
//! `mmap(MAP_FIXED)`, `shmat(SHM_REMAP)`, and `mremap(MREMAP_FIXED)`
//! (`vms_gather_munmap_vmas`: `EPERM`, nothing changed), `mremap` of a
//! sealed VMA (`check_prep_vma`), `mprotect` VMA by VMA
//! (`mprotect_fixup`), and the discarding advice on private anonymous
//! memory that could not be written anyway ([`blocks_discard`],
//! `can_madvise_modify`). A shrinking `brk` over a seal keeps the break,
//! and `shmdt` leaves a sealed attach mapped, as their unmapping fails.

use super::super::abi::vma_flags;
use super::super::process::ProcState;
use super::{Ctx, SysResult};
use crate::user::mm::{AddressSpace, Backing, Perms, Vma};

/// Whether a VMA overlapping `[start, start + len)` is sealed.
pub fn sealed_in(p: &ProcState, start: u64, len: u64) -> bool {
    sealed_in_space(&p.space, start, len)
}

pub(in crate::user::linux) fn sealed_in_space(space: &AddressSpace, start: u64, len: u64) -> bool {
    let end = start.saturating_add(len);
    space
        .vmas_in(start, end)
        .iter()
        .any(|v| v.flags & vma_flags::SEALED != 0)
}

/// `is_discard`: the advice that can throw a page's contents away.
fn is_discard(advice: u32) -> bool {
    // MADV_DONTNEED, MADV_FREE, MADV_REMOVE, MADV_DONTFORK,
    // MADV_WIPEONFORK, MADV_DONTNEED_LOCKED, MADV_GUARD_INSTALL.
    matches!(advice, 4 | 8 | 9 | 10 | 18 | 24 | 102)
}

/// `can_madvise_modify`, negated: discarding advice on a sealed private
/// anonymous VMA its owner cannot write (`EPERM`). File-backed and shared
/// memory, and memory that could be written, are left alone.
pub fn blocks_discard(v: &Vma, advice: u32) -> bool {
    v.flags & vma_flags::SEALED != 0
        && is_discard(advice)
        && matches!(v.backing, Backing::Anonymous)
        && !v.shared
        && !v.perms.contains(Perms::WRITE)
}

/// `mseal`.
pub fn mseal(c: &mut Ctx<'_>, start: u64, len: u64, flags: u64) -> SysResult {
    c.p.mm().seal_range(&c.p.space, start, len, flags)
}
