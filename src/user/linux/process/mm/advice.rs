//! Whole Linux advice operations over the authoritative MM and retained backing.
//! Validation, ascending-VMA partial effects, population, seals and shared-file
//! hole punching all execute in the caller's quiescent owner turn. No resource
//! policy is reconstructed from worker-provided inode or seal bytes.

use super::MmState;
use crate::error::MemoryAccessKind;
use crate::user::linux::abi::errno::Errno;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{PAGE_SIZE, vma_flags};
use crate::user::linux::syscall::SysResult;
use crate::user::linux::syscall::mem::{map_err, page_align, vm_read};
use crate::user::mm::{AddressSpace, Backing, FaultClass, Perms};

const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// `MADV_POPULATE_READ`/`MADV_POPULATE_WRITE` (`madvise_populate`): faults
/// every page in as a read or write would, without changing its contents.
fn madvise_populate(space: &AddressSpace, addr: u64, end: u64, write: bool) -> SysResult {
    let (access, need) = if write {
        (MemoryAccessKind::Write, Perms::WRITE)
    } else {
        (MemoryAccessKind::Read, Perms::READ)
    };
    let mut cursor = addr;
    while cursor < end {
        // No VMA: ENOMEM. Incompatible permissions: EINVAL. A fault that
        // would raise SIGBUS or SIGSEGV: EFAULT.
        let vma = space.vma_at(cursor).ok_or(Errno(ENOMEM))?;
        // check_vma_flags: reading needs VM_READ, not merely readable
        // pages.
        if !vma.perms.contains(need) || (!write && !vm_read(&vma)) {
            return Err(Errno(EINVAL));
        }
        let hi = vma.end.min(end);
        for page in (cursor..hi).step_by(PAGE_SIZE as usize) {
            if space.translate(page, access).is_err() {
                return Err(match space.classify_fault(page, access) {
                    FaultClass::OutOfMemory => Errno(ENOMEM),
                    _ => Errno(EFAULT),
                });
            }
        }
        cursor = hi;
    }
    Ok(0)
}

impl MmState {
    /// `madvise`.
    pub(crate) fn advise_range(
        &self,
        space: &AddressSpace,
        addr: u64,
        len: u64,
        advice: u32,
    ) -> SysResult {
        const MADV_DONTNEED: u32 = 4;
        const MADV_FREE: u32 = 8;
        const MADV_REMOVE: u32 = 9;
        const MADV_DONTFORK: u32 = 10;
        const MADV_DOFORK: u32 = 11;
        const MADV_WIPEONFORK: u32 = 18;
        const MADV_KEEPONFORK: u32 = 19;
        const MADV_COLD: u32 = 20;
        const MADV_PAGEOUT: u32 = 21;
        const MADV_POPULATE_READ: u32 = 22;
        const MADV_POPULATE_WRITE: u32 = 23;
        const MADV_DONTNEED_LOCKED: u32 = 24;
        const MADV_HWPOISON: u32 = 100;
        const MADV_SOFT_OFFLINE: u32 = 101;
        // madvise_behavior_valid(). MADV_GUARD_INSTALL and MADV_GUARD_REMOVE
        // (102, 103; Linux 6.13) are refused as a kernel without guard regions
        // refuses them: accepting them without making the pages fault would
        // silently drop a guard that callers otherwise build from PROT_NONE.
        let valid = matches!(advice, 0..=4 | 8..=25);
        if !valid && !matches!(advice, MADV_HWPOISON | MADV_SOFT_OFFLINE) {
            return Err(Errno(EINVAL));
        }
        if addr & PAGE_MASK != 0 {
            return Err(Errno(EINVAL));
        }
        let len = page_align(len).ok_or(Errno(EINVAL))?;
        let end = addr.checked_add(len).ok_or(Errno(EINVAL))?;
        if end == addr {
            return Ok(0);
        }
        if matches!(advice, MADV_HWPOISON | MADV_SOFT_OFFLINE) {
            return Err(Errno(EPERM));
        }
        if matches!(advice, MADV_POPULATE_READ | MADV_POPULATE_WRITE) {
            return madvise_populate(space, addr, end, advice == MADV_POPULATE_WRITE);
        }
        // madvise_walk_vmas(): the advice applies to each VMA in ascending order
        // and the walk stops at the first VMA that rejects it; unmapped gaps are
        // skipped but make the call fail with ENOMEM once the walk completes.
        let mut hole = false;
        let mut cursor = addr;
        for vma in space.vmas_in(addr, end) {
            hole |= vma.start > cursor;
            let (lo, hi) = (vma.start.max(addr), vma.end.min(end));
            cursor = hi;
            let anonymous = match &vma.backing {
                Backing::Anonymous => true,
                Backing::Shared { object, .. } => object.is_anonymous(),
                Backing::Source { .. } => false,
            };
            // can_madvise_modify: a seal keeps what could not be written.
            if crate::user::linux::syscall::mseal::blocks_discard(&vma, advice) {
                return Err(Errno(EPERM));
            }
            // madvise_update_vma: inheritance policy belongs to the selected
            // VMA subrange. A shmem-backed private mapping still has vm_file,
            // so it cannot use WIPEONFORK either.
            let inheritance = match advice {
                MADV_DONTFORK => Some((vma_flags::DONTCOPY, vma_flags::DONTCOPY)),
                MADV_DOFORK => Some((vma_flags::DONTCOPY, 0)),
                MADV_WIPEONFORK if vma.shared || !matches!(vma.backing, Backing::Anonymous) => {
                    return Err(Errno(EINVAL));
                }
                MADV_WIPEONFORK => Some((vma_flags::WIPEONFORK, vma_flags::WIPEONFORK)),
                MADV_KEEPONFORK => Some((vma_flags::WIPEONFORK, 0)),
                _ => None,
            };
            if let Some((mask, bits)) = inheritance {
                space.set_flags(lo, hi - lo, mask, bits).map_err(map_err)?;
            }
            // A locked VMA keeps its pages: madvise_dontneed_free_valid_vma
            // (MADV_DONTNEED_LOCKED excepted), madvise_remove, and
            // can_madv_lru_vma refuse it.
            if vma.flags & vma_flags::LOCKED != 0
                && matches!(
                    advice,
                    MADV_DONTNEED | MADV_FREE | MADV_REMOVE | MADV_COLD | MADV_PAGEOUT
                )
            {
                return Err(Errno(EINVAL));
            }
            let discard = match advice {
                // Private pages are dropped: the next touch sees zero (anonymous)
                // or the file. Shared pages live on in the page cache or shmem,
                // which the frames themselves model here.
                MADV_DONTNEED | MADV_DONTNEED_LOCKED => !vma.shared,
                // `madvise_free_single_vma`: private anonymous memory only. The
                // kernel may reclaim lazily; reclaiming now is one permitted
                // outcome.
                MADV_FREE if !anonymous || vma.shared => return Err(Errno(EINVAL)),
                MADV_FREE => true,
                // `madvise_remove`: punches a hole in the object behind a
                // shared mapping that may be written (private anonymous memory
                // has no file), so its pages read back as zero; the object's
                // bytes are zeroed, its size kept (FALLOC_FL_KEEP_SIZE).
                MADV_REMOVE if anonymous && !vma.shared => return Err(Errno(EINVAL)),
                MADV_REMOVE if !vma.shared || vma.flags & vma_flags::DENY_WRITE != 0 => {
                    return Err(Errno(EACCES));
                }
                MADV_REMOVE => match &vma.backing {
                    // shmem_fallocate: a write-sealed memfd cannot be punched.
                    Backing::Shared { object, .. }
                        if crate::user::linux::fs::memfd::Memfd::find(object.identity())
                            .is_some_and(|m| m.write_sealed()) =>
                    {
                        return Err(Errno(EPERM));
                    }
                    Backing::Shared { object, offset } => {
                        let at = offset + (lo - vma.start);
                        object.zero_range(at, hi - lo).map_err(Errno::from)?;
                        false
                    }
                    // A shared mapping of a device.
                    _ => return Err(Errno(EOPNOTSUPP)),
                },
                _ => false,
            };
            if discard {
                space.discard(lo, hi - lo).map_err(map_err)?;
            }
        }
        if hole || cursor < end {
            return Err(Errno(ENOMEM));
        }
        Ok(0)
    }
}

#[cfg(test)]
mod tests;
