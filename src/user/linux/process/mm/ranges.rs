//! Whole Linux range operations over the authoritative MM and address space.
//! Guest validation and VMA-by-VMA partial-error ordering are shared with the
//! native syscall adapters. An owner turn serializes the operation; it does
//! not promise rollback for guest errno or an arbitrary underlying MM error.

use serde::{Deserialize, Serialize};

use super::MmState;
use crate::user::linux::abi::errno::Errno;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, PAGE_SIZE, READ_IMPLIES_EXEC, vma_flags};
use crate::user::linux::process::ProcState;
use crate::user::linux::syscall::mem::mman::*;
use crate::user::linux::syscall::mem::{map_err, page_align, perms, read_flag};
use crate::user::linux::syscall::{SysResult, mlock, mseal};
use crate::user::mm::AddressSpace;

const PAGE_MASK: u64 = PAGE_SIZE - 1;
const P: u64 = PAGE_SIZE;

/// Calling-process inputs; mapping state and accounting remain MM-owned.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtectPolicy {
    pub(crate) abi: LinuxAbi,
    pub(crate) persona: u32,
}

impl From<&ProcState> for ProtectPolicy {
    fn from(process: &ProcState) -> Self {
        Self {
            abi: process.abi,
            persona: process.persona,
        }
    }
}

impl MmState {
    /// `munmap`.
    pub(crate) fn unmap_range(
        &mut self,
        space: &AddressSpace,
        abi: LinuxAbi,
        addr: u64,
        len: u64,
    ) -> SysResult {
        let task = abi.task_size();
        if addr & PAGE_MASK != 0 || addr > task || len > task - addr {
            return Err(Errno(EINVAL));
        }
        let len = page_align(len).ok_or(Errno(EINVAL))?;
        if len == 0 {
            return Err(Errno(EINVAL));
        }
        // vms_gather_munmap_vmas: a sealed VMA stops it before anything goes.
        if mseal::sealed_in_space(space, addr, len) {
            return Err(Errno(EPERM));
        }
        mlock::unmapped_mm(space, self, addr, len);
        space.unmap(addr, len).map_err(map_err)?;
        Ok(0)
    }

    /// `mprotect`, in the order of `do_mprotect_pkey`: the request is
    /// validated, then applied VMA by VMA in ascending order until a VMA
    /// refuses it or a hole ends the walk, so earlier VMAs keep the new
    /// protection when a later check fails.
    pub(crate) fn protect_range(
        &mut self,
        space: &AddressSpace,
        policy: ProtectPolicy,
        addr: u64,
        len: u64,
        prot: u32,
    ) -> SysResult {
        let grows = prot & (PROT_GROWSDOWN | PROT_GROWSUP);
        let rier = policy.persona & READ_IMPLIES_EXEC != 0 && prot & PROT_READ != 0;
        let prot = prot & !(PROT_GROWSDOWN | PROT_GROWSUP);
        if grows == PROT_GROWSDOWN | PROT_GROWSUP {
            return Err(Errno(EINVAL));
        }
        if addr & PAGE_MASK != 0 {
            return Err(Errno(EINVAL));
        }
        if len == 0 {
            return Ok(0);
        }
        let len = page_align(len).ok_or(Errno(ENOMEM))?;
        let mut start = addr;
        let end = addr.checked_add(len).ok_or(Errno(ENOMEM))?;
        // arch_validate_prot(): arm64 also accepts PROT_BTI when the CPU
        // supports BTI and PROT_MTE when it supports MTE; the emulated core
        // advertises neither (AT_HWCAP2).
        let mut valid = PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM;
        if policy.abi == LinuxAbi::Aarch64 {
            use crate::user::linux::arch::aarch64;
            if aarch64::caps().hwcap2.unwrap_or(0) & aarch64::hwcap2::BTI != 0 {
                valid |= PROT_BTI;
            }
        }
        if prot & !valid != 0 {
            return Err(Errno(EINVAL));
        }
        let vmas = space.vmas_in(start, end);
        let Some(first) = vmas.first() else {
            return Err(Errno(ENOMEM));
        };
        if grows & PROT_GROWSDOWN != 0 {
            start = first.start;
            if first.flags & vma_flags::GROWSDOWN == 0 {
                return Err(Errno(EINVAL));
            }
        } else {
            if first.start > start {
                return Err(Errno(ENOMEM));
            }
            // No supported architecture has VM_GROWSUP.
            if grows & PROT_GROWSUP != 0 {
                return Err(Errno(EINVAL));
            }
        }
        let mut cursor = start;
        for vma in vmas {
            if vma.start > cursor {
                return Err(Errno(ENOMEM));
            }
            let mut p = prot;
            if rier {
                p |= PROT_EXEC;
            }
            // (newflags & ~(newflags >> 4)) & VM_ACCESS_FLAGS: a permission
            // whose VM_MAY* bit is clear is refused.
            if p & PROT_WRITE != 0 && vma.flags & vma_flags::DENY_WRITE != 0 {
                return Err(Errno(EACCES));
            }
            // mprotect_fixup: a sealed VMA keeps its protection, even the same.
            if vma.flags & vma_flags::SEALED != 0 {
                return Err(Errno(EPERM));
            }
            let hi = vma.end.min(end);
            space
                .protect(cursor, hi - cursor, perms(policy.abi, p))
                .map_err(map_err)?;
            space
                .set_flags(cursor, hi - cursor, vma_flags::NO_READ, read_flag(p))
                .map_err(map_err)?;
            cursor = hi;
        }
        if cursor < end {
            return Err(Errno(ENOMEM));
        }
        Ok(0)
    }

    /// `do_mseal`: no flags (`EINVAL`), a page-aligned start (`EINVAL`), the
    /// length rounded up without wrapping (`EINVAL`), nothing for an empty
    /// range, and no hole anywhere in it (`ENOMEM`); then every VMA of the
    /// range is sealed, a second seal changing nothing.
    pub(crate) fn seal_range(
        &mut self,
        space: &AddressSpace,
        start: u64,
        len: u64,
        flags: u64,
    ) -> SysResult {
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
        if space.first_unmapped(start, aligned).is_some() {
            return Err(Errno(ENOMEM));
        }
        space
            .set_flags(start, aligned, vma_flags::SEALED, vma_flags::SEALED)
            .map_err(|_| Errno(ENOMEM))?;
        Ok(0)
    }
}

#[cfg(test)]
mod tests;
