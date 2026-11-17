//! Complete mmap publication over the authoritative address space and MM.
//! File lookup and resource admission precede it; actual backing/Keep objects
//! remain owned resources, never reconstructed from serialized guest bytes.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::super::{MmState, ProcState};
use super::LockPolicy;
use crate::user::linux::abi::errno::Errno;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, MMAP_MIN_ADDR, PAGE_SIZE, READ_IMPLIES_EXEC, vma_flags};
use crate::user::linux::syscall::mem::mman::*;
use crate::user::linux::syscall::{SysResult, mem, mlock, mseal};
use crate::user::mm::{AddressSpace, Backing, Mapping, SharedObject};

const PAGE_MASK: u64 = PAGE_SIZE - 1;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MmapPolicy {
    pub(crate) lock: LockPolicy,
    pub(crate) persona: u32,
}

impl From<&ProcState> for MmapPolicy {
    fn from(process: &ProcState) -> Self {
        Self {
            lock: LockPolicy::from(process),
            persona: process.persona,
        }
    }
}

/// Raw syscall arguments. Validation is repeated at the owner boundary; a
/// wire record cannot bypass rounding, overflow or mapping-type checks.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MmapArgs {
    pub(crate) address: u64,
    pub(crate) length: u64,
    pub(crate) protection: u32,
    pub(crate) flags: u32,
    pub(crate) offset: u64,
}

impl MmapArgs {
    /// Offset alignment precedes file lookup in the guest adapter. The
    /// remaining checks follow fget and precede backing preparation there.
    pub(crate) fn checked(self) -> Result<Self, Errno> {
        if self.offset & PAGE_MASK != 0 {
            return Err(Errno(EINVAL));
        }
        let Self {
            length: len,
            flags,
            offset: off,
            ..
        } = self;
        if len == 0 {
            return Err(Errno(EINVAL));
        }
        let len = mem::page_align(len).ok_or(Errno(ENOMEM))?;
        if off.checked_add(len).is_none() {
            return Err(Errno(EOVERFLOW));
        }
        let map_type = flags & MAP_TYPE;
        match map_type {
            MAP_SHARED | MAP_PRIVATE => {}
            MAP_SHARED_VALIDATE => {
                if flags & !LEGACY_MAP_MASK != 0 {
                    return Err(Errno(EOPNOTSUPP));
                }
            }
            _ => return Err(Errno(EINVAL)),
        }
        Ok(Self {
            length: len,
            ..self
        })
    }

    pub(crate) fn shared(self) -> bool {
        self.flags & MAP_TYPE != MAP_PRIVATE
    }
}

/// A real admitted resource, including its opaque close/lifetime retention.
/// Constructed by the native file adapter or resolved from the endpoint's
/// owner-side catalog. Its offset is already the mapping's byte offset.
pub(crate) struct PreparedMmap {
    pub(crate) backing: Backing,
    pub(crate) name: Option<Arc<str>>,
    pub(crate) flags: u32,
}

impl PreparedMmap {
    pub(crate) fn anonymous(arguments: MmapArgs) -> Result<Self, Errno> {
        let arguments = arguments.checked()?;
        if arguments.flags & MAP_HUGETLB != 0 {
            return Err(Errno(ENOMEM));
        }
        let (backing, name) = if arguments.shared() {
            shared_anonymous(arguments.length)?
        } else {
            (Backing::Anonymous, None)
        };
        Ok(Self {
            backing,
            name,
            flags: 0,
        })
    }
}

pub(crate) fn shared_anonymous(len: u64) -> Result<(Backing, Option<Arc<str>>), Errno> {
    let object = SharedObject::anonymous(len).map_err(|_| Errno(ENOMEM))?;
    Ok((
        Backing::Shared {
            object: Arc::new(object),
            offset: 0,
        },
        Some("/dev/zero (deleted)".into()),
    ))
}

impl MmState {
    /// Existing non-fixed area search; the mmap base is shared MM state,
    /// while task size and MAP_32BIT semantics belong to the calling ABI.
    pub(crate) fn unmapped_area(
        &self,
        space: &AddressSpace,
        abi: LinuxAbi,
        hint: u64,
        len: u64,
        flags: u32,
    ) -> Result<u64, Errno> {
        let task = abi.task_size();
        if len > task {
            return Err(Errno(ENOMEM));
        }
        if abi == LinuxAbi::X86_64 && flags & MAP_32BIT != 0 {
            // x86 find_start_end(): bottom-up within [1 GiB, 2 GiB).
            return space
                .find_free_bottom_up(len, PAGE_SIZE, 0x4000_0000, 0x8000_0000)
                .ok_or(Errno(ENOMEM));
        }
        // round_hint_to_min().
        let mut hint = hint & !PAGE_MASK;
        if hint != 0 && hint < MMAP_MIN_ADDR {
            hint = MMAP_MIN_ADDR;
        }
        if hint != 0 && hint <= task - len && space.is_free(hint, len) {
            return Ok(hint);
        }
        let low = MMAP_MIN_ADDR.max(PAGE_SIZE);
        space
            .find_free_top_down(len, PAGE_SIZE, low, self.mmap_base)
            // Top-down failure falls back to a bottom-up search of the whole
            // address space (arch_get_unmapped_area).
            .or_else(|| space.find_free_bottom_up(len, PAGE_SIZE, low, task))
            .ok_or(Errno(ENOMEM))
    }

    /// Mapping, lock accounting, replacement and population stay inside one
    /// owner turn. This preserves existing partial effects on underlying MM
    /// errors; a lost reply is never a reason to replay publication.
    pub(crate) fn map_prepared(
        &mut self,
        space: &AddressSpace,
        policy: MmapPolicy,
        arguments: MmapArgs,
        prepared: PreparedMmap,
    ) -> SysResult {
        let arguments = arguments.checked()?;
        let MmapArgs {
            address: addr,
            length: len,
            protection: mut prot,
            flags,
            ..
        } = arguments;
        if prot & PROT_READ != 0 && policy.persona & READ_IMPLIES_EXEC != 0 {
            prot |= PROT_EXEC;
        }
        let shared = arguments.shared();
        let PreparedMmap {
            backing,
            name,
            flags: vm_flags,
        } = prepared;
        let task = policy.lock.abi.task_size();
        let start = if flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0 {
            if addr & PAGE_MASK != 0 {
                return Err(Errno(EINVAL));
            }
            if len > task || addr > task - len {
                return Err(Errno(ENOMEM));
            }
            if addr < MMAP_MIN_ADDR {
                return Err(Errno(EPERM));
            }
            if flags & MAP_FIXED == 0 && !space.is_free(addr, len) {
                return Err(Errno(EEXIST));
            }
            addr
        } else {
            self.unmapped_area(space, policy.lock.abi, addr, len, flags)?
        };
        // do_mmap: MAP_LOCKED needs the right to lock, and a locked mapping
        // (MAP_LOCKED or mlockall's MCL_FUTURE) must fit RLIMIT_MEMLOCK.
        let lock = if flags & MAP_LOCKED != 0 {
            vma_flags::LOCKED
        } else {
            0
        } | self.def_lock;
        if flags & MAP_LOCKED != 0 && !policy.lock.can_lock() {
            return Err(Errno(EPERM));
        }
        if !mlock::future_ok_mm(
            self,
            lock,
            len,
            policy.lock.privileged,
            policy.lock.memlock_limit >> 12,
        ) {
            return Err(Errno(EAGAIN));
        }
        // __mmap_region: a sealed range cannot be mapped over.
        if mseal::sealed_in_space(space, start, len) {
            return Err(Errno(EPERM));
        }
        mlock::unmapped_mm(space, self, start, len);
        space
            .map(
                start,
                len,
                Mapping {
                    perms: mem::perms(policy.lock.abi, prot),
                    backing,
                    shared,
                    name,
                    flags: vm_flags | mem::read_flag(prot) | lock,
                },
            )
            .map_err(mem::map_err)?;
        mlock::mapped_mm(self, lock, len);
        // A locked mapping, or MAP_POPULATE without MAP_NONBLOCK, is brought
        // in at once, failures passed over (mm_populate).
        if lock & vma_flags::LOCKED != 0 || flags & (MAP_POPULATE | MAP_NONBLOCK) == MAP_POPULATE {
            let _ = mlock::populate_space(space, start, start + len, true);
        }
        Ok(start)
    }
}

#[cfg(test)]
mod tests;
