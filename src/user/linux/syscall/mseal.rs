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

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::vma_flags;
use super::super::process::ProcState;
use super::{Ctx, SysResult};
use crate::user::mm::{Backing, Perms, Vma};

/// `PAGE_SIZE`.
const P: u64 = 4096;

/// Whether a VMA overlapping `[start, start + len)` is sealed.
pub fn sealed_in(p: &ProcState, start: u64, len: u64) -> bool {
    let end = start.saturating_add(len);
    p.space
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

/// `do_mseal`: no flags (`EINVAL`), a page-aligned start (`EINVAL`), the
/// length rounded up without wrapping (`EINVAL`), nothing for an empty
/// range, and no hole anywhere in it (`ENOMEM`); then every VMA of the
/// range is sealed, a second seal changing nothing.
pub fn mseal(c: &mut Ctx<'_>, start: u64, len: u64, flags: u64) -> SysResult {
    if flags != 0 {
        return Err(Errno(EINVAL));
    }
    if start & (P - 1) != 0 {
        return Err(Errno(EINVAL));
    }
    let aligned = len.wrapping_add(P - 1) & !(P - 1);
    if len != 0 && aligned == 0 {
        return Err(Errno(EINVAL));
    }
    let end = start.wrapping_add(aligned);
    if end < start {
        return Err(Errno(EINVAL));
    }
    if end == start {
        return Ok(0);
    }
    // range_contains_unmapped.
    if c.p.space.first_unmapped(start, aligned).is_some() {
        return Err(Errno(ENOMEM));
    }
    c.p.space
        .set_flags(start, aligned, vma_flags::SEALED, vma_flags::SEALED)
        .map_err(|_| Errno(ENOMEM))?;
    Ok(0)
}
