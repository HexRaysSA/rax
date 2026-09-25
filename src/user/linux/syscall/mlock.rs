//! Memory locking (`mm/mlock.c`, `mm/gup.c`, Linux 6.19): `mlock`,
//! `mlock2`, `munlock`, `mlockall`, and `munlockall`, with the lock
//! accounting the other memory calls share.
//!
//! A locked VMA carries [`vma_flags::LOCKED`] (and
//! [`vma_flags::LOCKONFAULT`] when its pages are locked only as they fault
//! in). `mm->locked_vm` ([`MmState::locked_vm`]) is a count the calls keep
//! as the kernel's do ([`mapped`], [`unmapped`], and the lock changes
//! here), which `RLIMIT_MEMLOCK` is checked against and
//! `/proc/<pid>/status` shows as `VmLck`. Nothing is paged
//! out here, so a lock changes what the kernel would refuse (`madvise`
//! discards, growth beyond `RLIMIT_MEMLOCK`) and populates the pages, not
//! residency. `CAP_IPC_LOCK` is being root.
//!
//! [`MmState::locked_vm`]: super::super::process::MmState::locked_vm

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::vma_flags;
use super::super::process::ProcState;
use super::{Ctx, SysResult};
use crate::error::MemoryAccessKind;
use crate::user::mm::{FaultClass, Perms};

/// `PAGE_SIZE`.
const P: u64 = 4096;
/// `RLIMIT_MEMLOCK`.
const RLIMIT_MEMLOCK: usize = 8;
/// `MLOCK_ONFAULT`.
const MLOCK_ONFAULT: u32 = 1;
/// `MCL_CURRENT`, `MCL_FUTURE`, `MCL_ONFAULT` (`asm-generic/mman.h`).
const MCL_CURRENT: u32 = 1;
const MCL_FUTURE: u32 = 2;
const MCL_ONFAULT: u32 = 4;

/// `capable(CAP_IPC_LOCK)`.
fn capable(p: &ProcState) -> bool {
    p.creds.1 == 0
}

/// `RLIMIT_MEMLOCK` in pages.
fn limit_pages(p: &ProcState) -> u64 {
    p.rlimits[RLIMIT_MEMLOCK].0 >> 12
}

/// `mm->locked_vm`, in pages.
pub fn locked_pages(p: &ProcState) -> u64 {
    p.mm.locked_vm
}

/// The pages of `[start, start + len)` in locked VMAs.
fn locked_in(p: &ProcState, start: u64, len: u64) -> u64 {
    let end = start.saturating_add(len);
    p.space
        .vmas_in(start, end)
        .iter()
        .filter(|v| v.flags & vma_flags::LOCKED != 0)
        .map(|v| (v.end.min(end) - v.start.max(start)) / P)
        .sum()
}

/// Before `[start, start + len)` is unmapped or mapped over: its locked
/// pages leave the count (`vms_gather_munmap_vmas`,
/// `vms_complete_munmap_vmas`).
pub fn unmapped(p: &mut ProcState, start: u64, len: u64) {
    let pages = locked_in(p, start, len);
    p.mm.locked_vm = p.mm.locked_vm.wrapping_sub(pages);
}

/// A new mapping of `len` bytes with VMA flags `flags` (`mmap_region`,
/// `do_brk_flags`, `vrm_stat_account`): counted when locked.
pub fn mapped(p: &mut ProcState, flags: u32, len: u64) {
    if flags & vma_flags::LOCKED != 0 {
        p.mm.locked_vm = p.mm.locked_vm.wrapping_add(len / P);
    }
}

/// `can_do_mlock`: a nonzero `RLIMIT_MEMLOCK`, or `CAP_IPC_LOCK`.
pub fn can_do_mlock(p: &ProcState) -> bool {
    p.rlimits[RLIMIT_MEMLOCK].0 != 0 || capable(p)
}

/// `mlock_future_ok`: whether `bytes` more of a mapping with VMA flags
/// `flags` stay within `RLIMIT_MEMLOCK` (always, unlocked or privileged).
pub fn future_ok(p: &ProcState, flags: u32, bytes: u64) -> bool {
    if flags & vma_flags::LOCKED == 0 || capable(p) {
        return true;
    }
    (bytes >> 12).saturating_add(locked_pages(p)) <= limit_pages(p)
}

/// `__mm_populate`: faults in the pages of `[start, end)` VMA by VMA, as
/// `populate_vma_page_range` does: a range locked on fault is left alone,
/// a `PROT_NONE` one is `EFAULT`, a private writable one is written (to
/// break copy-on-write), and anything else is read even without
/// `PROT_READ` (`FOLL_FORCE`). A page that cannot be brought in is
/// `EFAULT` (`ENOMEM` when memory runs out). With `ignore_errors` a failing
/// VMA is passed over (`mm_populate`).
pub fn populate(p: &ProcState, start: u64, end: u64, ignore_errors: bool) -> Result<(), Errno> {
    for v in p.space.vmas_in(start, end) {
        let (lo, hi) = (v.start.max(start), v.end.min(end));
        let r = if v.flags & vma_flags::LOCKONFAULT != 0 {
            Ok(())
        } else if v.perms.is_empty() {
            Err(Errno(EFAULT))
        } else {
            let write = v.perms.contains(Perms::WRITE) && !v.shared;
            let access = if write {
                MemoryAccessKind::Write
            } else {
                MemoryAccessKind::Read
            };
            (lo..hi).step_by(P as usize).try_for_each(|page| {
                let r = if write {
                    p.space.translate(page, access)
                } else {
                    p.space.translate_raw(page, access)
                };
                r.map(|_| ()).map_err(|_| {
                    Errno(match p.space.classify_fault(page, access) {
                        FaultClass::OutOfMemory => ENOMEM,
                        _ => EFAULT,
                    })
                })
            })
        };
        if let Err(e) = r
            && !ignore_errors
        {
            return Err(e);
        }
    }
    Ok(())
}

/// `mlock_fixup` over `[lo, hi)` of one VMA, counting pages newly locked
/// or unlocked: a special mapping is never locked.
fn fixup(p: &mut ProcState, v: &crate::user::mm::Vma, lo: u64, hi: u64, lock: u32) {
    if v.flags & vma_flags::SPECIAL != 0 || v.flags & vma_flags::LOCKED_MASK == lock {
        return;
    }
    let was = v.flags & vma_flags::LOCKED != 0;
    let now = lock & vma_flags::LOCKED != 0;
    let pages = (hi - lo) / P;
    if now && !was {
        p.mm.locked_vm = p.mm.locked_vm.wrapping_add(pages);
    } else if was && !now {
        p.mm.locked_vm = p.mm.locked_vm.wrapping_sub(pages);
    }
    let _ = p.space.set_flags(lo, hi - lo, vma_flags::LOCKED_MASK, lock);
}

/// `apply_vma_lock_flags`: `lock` for every VMA of `[start, start + len)`
/// in turn; a range starting in a hole is `ENOMEM` at once, a later hole
/// `ENOMEM` once the VMAs before it are changed.
fn apply_lock_flags(p: &mut ProcState, start: u64, len: u64, lock: u32) -> Result<(), Errno> {
    let end = start.wrapping_add(len);
    if end < start {
        return Err(Errno(EINVAL));
    }
    if end == start {
        return Ok(());
    }
    if p.space.vma_at(start).is_none() {
        return Err(Errno(ENOMEM));
    }
    let mut cursor = start;
    for v in p.space.vmas_in(start, end) {
        if v.start > cursor {
            return Err(Errno(ENOMEM));
        }
        let hi = v.end.min(end);
        fixup(p, &v, cursor, hi, lock);
        cursor = hi;
    }
    if cursor < end {
        return Err(Errno(ENOMEM));
    }
    Ok(())
}

/// `count_mm_mlocked_page_nr`: the pages of `[start, start + len)` already
/// locked, in the kernel's arithmetic.
fn already_locked(p: &ProcState, start: u64, len: u64) -> u64 {
    let end = start.checked_add(len).unwrap_or(u64::MAX);
    let mut count = 0u64;
    for v in p.space.vmas_in(start, end) {
        if v.flags & vma_flags::LOCKED == 0 {
            continue;
        }
        if start > v.start {
            count = count.wrapping_sub(start - v.start);
        }
        if end < v.end {
            count = count.wrapping_add(end - v.start);
            break;
        }
        count = count.wrapping_add(v.end - v.start);
    }
    count >> 12
}

/// `__mlock_posix_error_return`: a page that could not be brought in is
/// `ENOMEM`, memory running out `EAGAIN`.
fn posix_error(e: Errno) -> Errno {
    match e.0 {
        EFAULT => Errno(ENOMEM),
        ENOMEM => Errno(EAGAIN),
        _ => e,
    }
}

/// `do_mlock`: the right to lock (`EPERM`), the range made whole pages,
/// `RLIMIT_MEMLOCK` less what the range already holds locked (`ENOMEM`),
/// the VMAs, then their pages.
fn do_mlock(c: &mut Ctx<'_>, start: u64, len: u64, lock: u32) -> SysResult {
    let p = &mut *c.p;
    if !can_do_mlock(p) {
        return Err(Errno(EPERM));
    }
    let len = len.wrapping_add(start & (P - 1)).wrapping_add(P - 1) & !(P - 1);
    let start = start & !(P - 1);
    let limit = limit_pages(p);
    let mut locked = (len >> 12).wrapping_add(locked_pages(p));
    if locked > limit && !capable(p) {
        locked = locked.wrapping_sub(already_locked(p, start, len));
    }
    if locked > limit && !capable(p) {
        return Err(Errno(ENOMEM));
    }
    apply_lock_flags(p, start, len, lock)?;
    populate(p, start, start.wrapping_add(len), false).map_err(posix_error)?;
    Ok(0)
}

/// `mlock`.
pub fn mlock(c: &mut Ctx<'_>, start: u64, len: u64) -> SysResult {
    do_mlock(c, start, len, vma_flags::LOCKED)
}

/// `mlock2`: `MLOCK_ONFAULT` locks the pages as they fault in.
pub fn mlock2(c: &mut Ctx<'_>, start: u64, len: u64, flags: u32) -> SysResult {
    if flags & !MLOCK_ONFAULT != 0 {
        return Err(Errno(EINVAL));
    }
    let mut lock = vma_flags::LOCKED;
    if flags & MLOCK_ONFAULT != 0 {
        lock |= vma_flags::LOCKONFAULT;
    }
    do_mlock(c, start, len, lock)
}

/// `munlock`: no limit or right is checked.
pub fn munlock(c: &mut Ctx<'_>, start: u64, len: u64) -> SysResult {
    let len = len.wrapping_add(start & (P - 1)).wrapping_add(P - 1) & !(P - 1);
    apply_lock_flags(c.p, start & !(P - 1), len, 0).map(|()| 0)
}

/// `apply_mlockall_flags`: `MCL_FUTURE` sets the lock new mappings take
/// (and clears it without), `MCL_CURRENT` locks every VMA, and 0
/// (`munlockall`) unlocks them all.
fn apply_mlockall(p: &mut ProcState, flags: u32) {
    let onfault = if flags & MCL_ONFAULT != 0 {
        vma_flags::LOCKONFAULT
    } else {
        0
    };
    p.mm.def_lock = 0;
    if flags & MCL_FUTURE != 0 {
        p.mm.def_lock = vma_flags::LOCKED | onfault;
        if flags & MCL_CURRENT == 0 {
            return;
        }
    }
    let lock = if flags & MCL_CURRENT != 0 {
        vma_flags::LOCKED | onfault
    } else {
        0
    };
    for v in p.space.vma_snapshot() {
        fixup(p, &v, v.start, v.end, lock);
    }
}

/// `mlockall`: the flags (`EINVAL` for none, unknown ones, or
/// `MCL_ONFAULT` alone), the right to lock (`EPERM`), and for
/// `MCL_CURRENT` the whole address space within `RLIMIT_MEMLOCK`
/// (`ENOMEM`); the pages are then brought in, failures passed over.
pub fn mlockall(c: &mut Ctx<'_>, flags: i32) -> SysResult {
    let flags = flags as u32;
    if flags == 0 || flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0 || flags == MCL_ONFAULT
    {
        return Err(Errno(EINVAL));
    }
    if !can_do_mlock(c.p) {
        return Err(Errno(EPERM));
    }
    let total: u64 = c.p.space.vma_snapshot().iter().map(|v| v.len() / P).sum();
    if flags & MCL_CURRENT != 0 && total > limit_pages(c.p) && !capable(c.p) {
        return Err(Errno(ENOMEM));
    }
    apply_mlockall(c.p, flags);
    if flags & MCL_CURRENT != 0 {
        let top = c.p.abi.task_size();
        populate(c.p, 0, top, true)?;
    }
    Ok(0)
}

/// `munlockall`.
pub fn munlockall(c: &mut Ctx<'_>) -> SysResult {
    apply_mlockall(c.p, 0);
    Ok(0)
}

/// In a new process (`dup_mmap`, `mm_init`): no VMA stays locked, nothing
/// is counted, and no lock is kept for new mappings.
pub fn forked(p: &mut ProcState) {
    p.mm.def_lock = 0;
    p.mm.locked_vm = 0;
    for v in p.space.vma_snapshot() {
        if v.flags & vma_flags::LOCKED_MASK != 0 {
            let _ = p
                .space
                .set_flags(v.start, v.len(), vma_flags::LOCKED_MASK, 0);
        }
    }
}
