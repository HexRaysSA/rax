//! Whole-MM Linux memory-lock operations. Caller policy is copied; mapping
//! flags, default lock flags, lock accounting and page population stay with
//! the authoritative MM. Guest errors retain existing partial effects.

use serde::{Deserialize, Serialize};

use super::MmState;
use crate::user::linux::abi::errno::Errno;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, PAGE_SIZE, vma_flags};
use crate::user::linux::process::ProcState;
use crate::user::linux::syscall::SysResult;
use crate::user::linux::syscall::mlock::populate_space;
use crate::user::mm::AddressSpace;

const P: u64 = PAGE_SIZE;
const MLOCK_ONFAULT: u32 = 1;
const MCL_CURRENT: u32 = 1;
const MCL_FUTURE: u32 = 2;
const MCL_ONFAULT: u32 = 4;

/// Calling-process policy. `memlock_limit` is in bytes, not pages.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LockPolicy {
    pub(crate) abi: LinuxAbi,
    pub(crate) privileged: bool,
    pub(crate) memlock_limit: u64,
}

impl From<&ProcState> for LockPolicy {
    fn from(process: &ProcState) -> Self {
        Self {
            abi: process.abi,
            privileged: process.creds.1 == 0,
            memlock_limit: process.rlimits[8].0,
        }
    }
}

impl LockPolicy {
    pub(crate) fn can_lock(self) -> bool {
        self.memlock_limit != 0 || self.privileged
    }
}

impl MmState {
    /// `mlock_fixup` over `[lo, hi)` of one VMA, counting pages newly locked
    /// or unlocked: a special mapping is never locked.
    fn fixup_lock(
        &mut self,
        space: &AddressSpace,
        v: &crate::user::mm::Vma,
        lo: u64,
        hi: u64,
        lock: u32,
    ) {
        if v.flags & vma_flags::SPECIAL != 0 || v.flags & vma_flags::LOCKED_MASK == lock {
            return;
        }
        let was = v.flags & vma_flags::LOCKED != 0;
        let now = lock & vma_flags::LOCKED != 0;
        let pages = (hi - lo) / P;
        if now && !was {
            self.locked_vm = self.locked_vm.wrapping_add(pages);
        } else if was && !now {
            self.locked_vm = self.locked_vm.wrapping_sub(pages);
        }
        let _ = space.set_flags(lo, hi - lo, vma_flags::LOCKED_MASK, lock);
    }

    /// `apply_vma_lock_flags`: `lock` for every VMA of `[start, start + len)`
    /// in turn; a range starting in a hole is `ENOMEM` at once, a later hole
    /// `ENOMEM` once the VMAs before it are changed.
    fn apply_lock_flags(
        &mut self,
        space: &AddressSpace,
        start: u64,
        len: u64,
        lock: u32,
    ) -> Result<(), Errno> {
        let end = start.wrapping_add(len);
        if end < start {
            return Err(Errno(EINVAL));
        }
        if end == start {
            return Ok(());
        }
        if space.vma_at(start).is_none() {
            return Err(Errno(ENOMEM));
        }
        let mut cursor = start;
        for v in space.vmas_in(start, end) {
            if v.start > cursor {
                return Err(Errno(ENOMEM));
            }
            let hi = v.end.min(end);
            self.fixup_lock(space, &v, cursor, hi, lock);
            cursor = hi;
        }
        if cursor < end {
            return Err(Errno(ENOMEM));
        }
        Ok(())
    }

    /// `count_mm_mlocked_page_nr`: the pages of `[start, start + len)` already
    /// locked, in the kernel's arithmetic.
    fn already_locked(space: &AddressSpace, start: u64, len: u64) -> u64 {
        let end = start.checked_add(len).unwrap_or(u64::MAX);
        let mut count = 0u64;
        for v in space.vmas_in(start, end) {
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
    fn do_lock_range(
        &mut self,
        space: &AddressSpace,
        policy: LockPolicy,
        start: u64,
        len: u64,
        lock: u32,
    ) -> SysResult {
        if !policy.can_lock() {
            return Err(Errno(EPERM));
        }
        let len = len.wrapping_add(start & (P - 1)).wrapping_add(P - 1) & !(P - 1);
        let start = start & !(P - 1);
        let limit = policy.memlock_limit >> 12;
        let mut locked = (len >> 12).wrapping_add(self.locked_vm);
        if locked > limit && !policy.privileged {
            locked = locked.wrapping_sub(Self::already_locked(space, start, len));
        }
        if locked > limit && !policy.privileged {
            return Err(Errno(ENOMEM));
        }
        self.apply_lock_flags(space, start, len, lock)?;
        populate_space(space, start, start.wrapping_add(len), false).map_err(Self::posix_error)?;
        Ok(0)
    }

    /// `mlock2`: `MLOCK_ONFAULT` locks the pages as they fault in.
    pub(crate) fn lock_range(
        &mut self,
        space: &AddressSpace,
        policy: LockPolicy,
        start: u64,
        len: u64,
        flags: u32,
    ) -> SysResult {
        if flags & !MLOCK_ONFAULT != 0 {
            return Err(Errno(EINVAL));
        }
        let mut lock = vma_flags::LOCKED;
        if flags & MLOCK_ONFAULT != 0 {
            lock |= vma_flags::LOCKONFAULT;
        }
        self.do_lock_range(space, policy, start, len, lock)
    }

    /// `munlock`: no limit or right is checked.
    pub(crate) fn unlock_range(&mut self, space: &AddressSpace, start: u64, len: u64) -> SysResult {
        let len = len.wrapping_add(start & (P - 1)).wrapping_add(P - 1) & !(P - 1);
        self.apply_lock_flags(space, start & !(P - 1), len, 0)
            .map(|()| 0)
    }

    /// `apply_mlockall_flags`: `MCL_FUTURE` sets the lock new mappings take
    /// (and clears it without), `MCL_CURRENT` locks every VMA, and 0
    /// (`munlockall`) unlocks them all.
    fn apply_lock_all(&mut self, space: &AddressSpace, flags: u32) {
        let onfault = if flags & MCL_ONFAULT != 0 {
            vma_flags::LOCKONFAULT
        } else {
            0
        };
        self.def_lock = 0;
        if flags & MCL_FUTURE != 0 {
            self.def_lock = vma_flags::LOCKED | onfault;
            if flags & MCL_CURRENT == 0 {
                return;
            }
        }
        let lock = if flags & MCL_CURRENT != 0 {
            vma_flags::LOCKED | onfault
        } else {
            0
        };
        for v in space.vma_snapshot() {
            self.fixup_lock(space, &v, v.start, v.end, lock);
        }
    }

    /// `mlockall`: the flags (`EINVAL` for none, unknown ones, or
    /// `MCL_ONFAULT` alone), the right to lock (`EPERM`), and for
    /// `MCL_CURRENT` the whole address space within `RLIMIT_MEMLOCK`
    /// (`ENOMEM`); the pages are then brought in, failures passed over.
    pub(crate) fn lock_all(
        &mut self,
        space: &AddressSpace,
        policy: LockPolicy,
        flags: i32,
    ) -> SysResult {
        let flags = flags as u32;
        if flags == 0
            || flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0
            || flags == MCL_ONFAULT
        {
            return Err(Errno(EINVAL));
        }
        if !policy.can_lock() {
            return Err(Errno(EPERM));
        }
        let total: u64 = space.vma_snapshot().iter().map(|v| v.len() / P).sum();
        if flags & MCL_CURRENT != 0 && total > (policy.memlock_limit >> 12) && !policy.privileged {
            return Err(Errno(ENOMEM));
        }
        self.apply_lock_all(space, flags);
        if flags & MCL_CURRENT != 0 {
            let top = policy.abi.task_size();
            populate_space(space, 0, top, true)?;
        }
        Ok(0)
    }

    /// `munlockall`.
    pub(crate) fn unlock_all(&mut self, space: &AddressSpace) -> SysResult {
        self.apply_lock_all(space, 0);
        Ok(0)
    }
}

#[cfg(test)]
mod tests;
