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
use super::super::process::{MmState, ProcState};
use super::{Ctx, SysResult};
use crate::error::MemoryAccessKind;
use crate::user::mm::{AddressSpace, FaultClass, Perms};

/// `PAGE_SIZE`.
const P: u64 = 4096;
/// `RLIMIT_MEMLOCK`.
const RLIMIT_MEMLOCK: usize = 8;

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
    p.mm().locked_vm
}

/// The pages of `[start, start + len)` in locked VMAs.
fn locked_in(space: &AddressSpace, start: u64, len: u64) -> u64 {
    let end = start.saturating_add(len);
    space
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
    unmapped_mm(&p.space, &mut p.mm(), start, len);
}

pub(in crate::user::linux) fn unmapped_mm(
    space: &AddressSpace,
    mm: &mut MmState,
    start: u64,
    len: u64,
) {
    mm.locked_vm = mm.locked_vm.wrapping_sub(locked_in(space, start, len));
}

/// A new mapping of `len` bytes with VMA flags `flags` (`mmap_region`,
/// `do_brk_flags`, `vrm_stat_account`): counted when locked.
pub fn mapped(p: &mut ProcState, flags: u32, len: u64) {
    mapped_mm(&mut p.mm(), flags, len);
}

pub(in crate::user::linux) fn mapped_mm(mm: &mut MmState, flags: u32, len: u64) {
    if flags & vma_flags::LOCKED != 0 {
        mm.locked_vm = mm.locked_vm.wrapping_add(len / P);
    }
}

/// `can_do_mlock`: a nonzero `RLIMIT_MEMLOCK`, or `CAP_IPC_LOCK`.
pub fn can_do_mlock(p: &ProcState) -> bool {
    super::super::process::mm::LockPolicy::from(p).can_lock()
}

/// `mlock_future_ok`: whether `bytes` more of a mapping with VMA flags
/// `flags` stay within `RLIMIT_MEMLOCK` (always, unlocked or privileged).
pub fn future_ok(p: &ProcState, flags: u32, bytes: u64) -> bool {
    future_ok_mm(&p.mm(), flags, bytes, capable(p), limit_pages(p))
}

pub(in crate::user::linux) fn future_ok_mm(
    mm: &MmState,
    flags: u32,
    bytes: u64,
    privileged: bool,
    limit_pages: u64,
) -> bool {
    if flags & vma_flags::LOCKED == 0 || privileged {
        return true;
    }
    (bytes >> 12).saturating_add(mm.locked_vm) <= limit_pages
}

/// `__mm_populate`: faults in the pages of `[start, end)` VMA by VMA, as
/// `populate_vma_page_range` does: a range locked on fault is left alone,
/// a `PROT_NONE` one is `EFAULT`, a private writable one is written (to
/// break copy-on-write), and anything else is read even without
/// `PROT_READ` (`FOLL_FORCE`). A page that cannot be brought in is
/// `EFAULT` (`ENOMEM` when memory runs out). With `ignore_errors` a failing
/// VMA is passed over (`mm_populate`).
pub fn populate(p: &ProcState, start: u64, end: u64, ignore_errors: bool) -> Result<(), Errno> {
    populate_space(&p.space, start, end, ignore_errors)
}

pub(in crate::user::linux) fn populate_space(
    space: &AddressSpace,
    start: u64,
    end: u64,
    ignore_errors: bool,
) -> Result<(), Errno> {
    for v in space.vmas_in(start, end) {
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
                    space.translate(page, access)
                } else {
                    space.translate_raw(page, access)
                };
                r.map(|_| ()).map_err(|_| {
                    Errno(match space.classify_fault(page, access) {
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

/// `mlock`.
pub fn mlock(c: &mut Ctx<'_>, start: u64, len: u64) -> SysResult {
    let policy = super::super::process::mm::LockPolicy::from(&*c.p);
    c.p.mm().lock_range(&c.p.space, policy, start, len, 0)
}

/// `mlock2`.
pub fn mlock2(c: &mut Ctx<'_>, start: u64, len: u64, flags: u32) -> SysResult {
    let policy = super::super::process::mm::LockPolicy::from(&*c.p);
    c.p.mm().lock_range(&c.p.space, policy, start, len, flags)
}

/// `munlock`.
pub fn munlock(c: &mut Ctx<'_>, start: u64, len: u64) -> SysResult {
    c.p.mm().unlock_range(&c.p.space, start, len)
}

/// `mlockall`.
pub fn mlockall(c: &mut Ctx<'_>, flags: i32) -> SysResult {
    let policy = super::super::process::mm::LockPolicy::from(&*c.p);
    c.p.mm().lock_all(&c.p.space, policy, flags)
}

/// `munlockall`.
pub fn munlockall(c: &mut Ctx<'_>) -> SysResult {
    c.p.mm().unlock_all(&c.p.space)
}

/// In a new process (`dup_mmap`, `mm_init`): no VMA stays locked, nothing
/// is counted, and no lock is kept for new mappings.
pub fn forked(p: &mut ProcState) {
    let _ = p.mm().reset_fork_locks(&p.space);
}
