//! Whole Linux sync and residency-vector operations over the owner MM.
//! The caller keeps the address space quiescent for the complete operation,
//! including the guest vector write. Residency collection does not fault pages
//! in; the output copy can populate pages or fail as any guest write does.

use super::MmState;
use crate::user::linux::abi::LinuxAbi;
use crate::user::linux::abi::errno::Errno;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::syscall::SysResult;
use crate::user::linux::syscall::mem::page_align;
use crate::user::mm::{AddressSpace, PAGE_SIZE};

const PAGE_MASK: u64 = PAGE_SIZE - 1;

impl MmState {
    /// `msync`.
    pub(crate) fn sync_range(
        &self,
        space: &AddressSpace,
        addr: u64,
        len: u64,
        flags: u32,
    ) -> SysResult {
        const MS_ASYNC: u32 = 1;
        const MS_INVALIDATE: u32 = 2;
        const MS_SYNC: u32 = 4;
        if addr & PAGE_MASK != 0
            || flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0
            || flags & (MS_ASYNC | MS_SYNC) == MS_ASYNC | MS_SYNC
        {
            return Err(Errno(EINVAL));
        }
        let len = page_align(len).ok_or(Errno(ENOMEM))?;
        if len != 0 && space.first_unmapped(addr, len).is_some() {
            return Err(Errno(ENOMEM));
        }
        // The pages are the objects' own; MS_SYNC writes them out
        // (vfs_fsync_range), MS_ASYNC and MS_INVALIDATE have nothing to do.
        if flags & MS_SYNC != 0 && len != 0 {
            space.sync(addr, len).map_err(Errno::from)?;
        }
        Ok(0)
    }

    /// `mincore`: one byte per page, bit 0 set for resident pages.
    pub(crate) fn residency_into(
        &self,
        space: &AddressSpace,
        abi: LinuxAbi,
        addr: u64,
        len: u64,
        vec: u64,
    ) -> SysResult {
        if addr & PAGE_MASK != 0 {
            return Err(Errno(EINVAL));
        }
        let len = page_align(len).ok_or(Errno(ENOMEM))?;
        if addr.checked_add(len).is_none_or(|e| e > abi.task_size()) {
            return Err(Errno(ENOMEM));
        }
        if space.first_unmapped(addr, len).is_some() {
            return Err(Errno(ENOMEM));
        }
        let bytes: Vec<u8> = (0..len / PAGE_SIZE)
            .map(|i| u8::from(space.is_resident(addr + i * PAGE_SIZE)))
            .collect();
        space.write(vec, &bytes).map_err(|_| Errno(EFAULT))?;
        Ok(0)
    }
}

#[cfg(test)]
mod tests;
