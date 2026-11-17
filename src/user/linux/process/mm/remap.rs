//! Complete Linux remap transaction over the authoritative MM and actual AIO
//! table. Destination unmap, ring identity/relocation, lock accounts, backing
//! movement and optional population keep their existing validation/effect order.

use super::{LockPolicy, MmState};
use crate::user::linux::abi::errno::Errno;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{MMAP_MIN_ADDR, PAGE_SIZE, vma_flags};
use crate::user::linux::aio::Table;
use crate::user::linux::syscall::SysResult;
use crate::user::linux::syscall::mem::{map_err, page_align};
use crate::user::linux::syscall::mlock::{future_ok_mm, mapped_mm, populate_space, unmapped_mm};
use crate::user::linux::syscall::mseal::sealed_in_space;
use crate::user::mm::{AddressSpace, Backing, Mapping};
use serde::{Deserialize, Serialize};

const PAGE_MASK: u64 = PAGE_SIZE - 1;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemapArgs {
    pub(crate) old_address: u64,
    pub(crate) old_length: u64,
    pub(crate) new_length: u64,
    pub(crate) flags: u32,
    pub(crate) new_address: u64,
}

impl MmState {
    /// `mremap`.
    pub(crate) fn remap_range(
        &mut self,
        space: &AddressSpace,
        aio: &mut Table,
        policy: LockPolicy,
        arguments: RemapArgs,
    ) -> SysResult {
        let RemapArgs {
            old_address: old,
            old_length: old_len,
            new_length: new_len,
            flags,
            new_address: new_addr,
        } = arguments;
        const MREMAP_MAYMOVE: u32 = 1;
        const MREMAP_FIXED: u32 = 2;
        const MREMAP_DONTUNMAP: u32 = 4;
        if flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0 {
            return Err(Errno(EINVAL));
        }
        if flags & (MREMAP_FIXED | MREMAP_DONTUNMAP) != 0 && flags & MREMAP_MAYMOVE == 0 {
            return Err(Errno(EINVAL));
        }
        if old & PAGE_MASK != 0 {
            return Err(Errno(EINVAL));
        }
        let old_len = page_align(old_len).ok_or(Errno(EINVAL))?;
        let new_len = page_align(new_len).ok_or(Errno(EINVAL))?;
        if new_len == 0 {
            return Err(Errno(EINVAL));
        }
        if flags & MREMAP_DONTUNMAP != 0 && old_len != new_len {
            return Err(Errno(EINVAL));
        }
        let task = policy.abi.task_size();
        let vma = space.vma_at(old).ok_or(Errno(EFAULT))?;
        // check_prep_vma: a sealed VMA is not remapped.
        if vma.flags & vma_flags::SEALED != 0 {
            return Err(Errno(EPERM));
        }
        // Duplicating a mapping (old_len == 0): only a shared one, whose pages
        // the new mapping shares (mremap_to or a new area).
        if old_len == 0 {
            if !vma.shared {
                return Err(Errno(EINVAL));
            }
            // It grows from nothing: a special mapping cannot.
            if vma.flags & vma_flags::SPECIAL != 0 {
                return Err(Errno(EFAULT));
            }
            return duplicate(self, space, policy, old, new_len, flags, new_addr, &vma);
        }
        // check_prep_vma, for a call that maps a new range (growing or
        // moving): a special mapping is never kept by MREMAP_DONTUNMAP, nor
        // resized; a locked one's change must fit RLIMIT_MEMLOCK.
        let will_map_new = new_len > old_len || flags & (MREMAP_FIXED | MREMAP_DONTUNMAP) != 0;
        if will_map_new && flags & MREMAP_DONTUNMAP != 0 && vma.flags & vma_flags::SPECIAL != 0 {
            return Err(Errno(EINVAL));
        }
        if old.checked_add(old_len).is_none_or(|end| end > vma.end) {
            return Err(Errno(EFAULT));
        }
        if will_map_new && new_len != old_len {
            if vma.flags & vma_flags::SPECIAL != 0 {
                return Err(Errno(EFAULT));
            }
            if !future_ok_mm(
                self,
                vma.flags,
                new_len.abs_diff(old_len),
                policy.privileged,
                policy.memlock_limit >> 12,
            ) {
                return Err(Errno(EAGAIN));
            }
        }
        // A locked VMA's new pages are brought in (populate_expand).
        let locked = vma.flags & vma_flags::LOCKED != 0;
        let populate_new = |base: u64| {
            if locked && new_len > old_len {
                let _ = populate_space(space, base + old_len, base + new_len, true);
            }
        };
        let extension = |base: u64| Mapping {
            perms: vma.perms,
            backing: vma.backing.advanced(old - vma.start + old_len),
            shared: vma.shared,
            name: vma.name.clone(),
            flags: vma.flags,
        };

        if flags & MREMAP_FIXED != 0 {
            if new_addr & PAGE_MASK != 0 || new_len > task || new_addr > task - new_len {
                return Err(Errno(EINVAL));
            }
            if new_addr < old + old_len && old < new_addr + new_len {
                return Err(Errno(EINVAL));
            }
            if new_addr < MMAP_MIN_ADDR {
                return Err(Errno(EPERM));
            }
            // mremap_to's do_munmap of the destination.
            if sealed_in_space(space, new_addr, new_len) {
                return Err(Errno(EPERM));
            }
            unmapped_mm(space, self, new_addr, new_len);
            space.unmap(new_addr, new_len).map_err(map_err)?;
            let moved = old_len.min(new_len);
            if old_len > new_len {
                unmapped_mm(space, self, old + new_len, old_len - new_len);
                space
                    .unmap(old + new_len, old_len - new_len)
                    .map_err(map_err)?;
            }
            let ring = aio.ring_owner(&vma)?;
            moved_account(self, &vma, moved, new_len, flags & MREMAP_DONTUNMAP != 0);
            move_range(
                space,
                old,
                moved,
                new_addr,
                flags & MREMAP_DONTUNMAP != 0,
                &vma,
            )?;
            aio.ring_moved(ring, new_addr);
            if new_len > old_len {
                space
                    .map(new_addr + old_len, new_len - old_len, extension(new_addr))
                    .map_err(map_err)?;
            }
            populate_new(new_addr);
            return Ok(new_addr);
        }

        if new_len <= old_len && flags & MREMAP_DONTUNMAP == 0 {
            if new_len < old_len {
                unmapped_mm(space, self, old + new_len, old_len - new_len);
                space
                    .unmap(old + new_len, old_len - new_len)
                    .map_err(map_err)?;
            }
            return Ok(old);
        }

        // Grow in place when the VMA ends at the old range and the space after
        // it is free.
        let grow = new_len - old_len;
        if flags & MREMAP_DONTUNMAP == 0
            && vma.end == old + old_len
            && old + new_len <= task
            && space.is_free(old + old_len, grow)
        {
            space
                .map(old + old_len, grow, extension(old))
                .map_err(map_err)?;
            // vrm_stat_account of the growth.
            mapped_mm(self, vma.flags, grow);
            populate_new(old);
            return Ok(old);
        }
        if flags & MREMAP_MAYMOVE == 0 {
            return Err(Errno(ENOMEM));
        }
        let dest = self.unmapped_area(space, policy.abi, 0, new_len, 0)?;
        let ring = aio.ring_owner(&vma)?;
        moved_account(self, &vma, old_len, new_len, flags & MREMAP_DONTUNMAP != 0);
        move_range(
            space,
            old,
            old_len,
            dest,
            flags & MREMAP_DONTUNMAP != 0,
            &vma,
        )?;
        aio.ring_moved(ring, dest);
        if new_len > old_len {
            space
                .map(dest + old_len, new_len - old_len, extension(dest))
                .map_err(map_err)?;
        }
        populate_new(dest);
        Ok(dest)
    }
}

/// `move_vma`'s count of locked pages: the new VMA's `new_len` bytes are
/// counted (`vrm_stat_account`), then the `old_len` bytes of the source
/// leave with its unmapping, which `MREMAP_DONTUNMAP` never does (the old
/// range is unlocked with its pages still counted).
fn moved_account(
    mm: &mut MmState,
    vma: &crate::user::mm::Vma,
    old_len: u64,
    new_len: u64,
    dontunmap: bool,
) {
    mapped_mm(mm, vma.flags, new_len);
    if !dontunmap {
        if vma.flags & vma_flags::LOCKED != 0 {
            mm.locked_vm = mm.locked_vm.wrapping_sub(old_len / PAGE_SIZE);
        }
    }
}

/// `mremap` of zero bytes of a shared mapping: a second mapping of the
/// same pages from `old`, at `new_addr` (`MREMAP_FIXED`) or a free area
/// (`MREMAP_MAYMOVE`); without either it cannot grow in place (`ENOMEM`).
fn duplicate(
    mm: &mut MmState,
    space: &AddressSpace,
    policy: LockPolicy,
    old: u64,
    new_len: u64,
    flags: u32,
    new_addr: u64,
    vma: &crate::user::mm::Vma,
) -> SysResult {
    const MREMAP_MAYMOVE: u32 = 1;
    const MREMAP_FIXED: u32 = 2;
    const MREMAP_DONTUNMAP: u32 = 4;
    if flags & MREMAP_DONTUNMAP != 0 {
        return Err(Errno(EINVAL));
    }
    if flags & MREMAP_MAYMOVE == 0 {
        return Err(Errno(ENOMEM));
    }
    let task = policy.abi.task_size();
    let dest = if flags & MREMAP_FIXED != 0 {
        if new_addr & PAGE_MASK != 0 || new_len > task || new_addr > task - new_len {
            return Err(Errno(EINVAL));
        }
        if new_addr < MMAP_MIN_ADDR {
            return Err(Errno(EPERM));
        }
        new_addr
    } else {
        mm.unmapped_area(space, policy.abi, 0, new_len, 0)?
    };
    // mremap_to unmaps the destination; move_vma counts the new VMA.
    if sealed_in_space(space, dest, new_len) {
        return Err(Errno(EPERM));
    }
    unmapped_mm(space, mm, dest, new_len);
    space
        .map(
            dest,
            new_len,
            Mapping {
                perms: vma.perms,
                backing: vma.backing.advanced(old - vma.start),
                shared: true,
                name: vma.name.clone(),
                flags: vma.flags,
            },
        )
        .map_err(map_err)?;
    mapped_mm(mm, vma.flags, new_len);
    Ok(dest)
}

/// Moves pages, optionally leaving an empty mapping behind
/// (`MREMAP_DONTUNMAP`).
fn move_range(
    space: &AddressSpace,
    old: u64,
    len: u64,
    dest: u64,
    dontunmap: bool,
    vma: &crate::user::mm::Vma,
) -> Result<(), Errno> {
    space.remap(old, len, dest).map_err(map_err)?;
    if dontunmap {
        // The range stays mapped, emptied and unlocked: private memory
        // reads as zero, a shared mapping faults the object's pages in
        // again.
        let backing = if vma.shared {
            vma.backing.advanced(old - vma.start)
        } else {
            Backing::Anonymous
        };
        space
            .map(
                old,
                len,
                Mapping {
                    perms: vma.perms,
                    backing,
                    shared: vma.shared,
                    name: vma.name.clone(),
                    flags: vma.flags & !vma_flags::LOCKED_MASK,
                },
            )
            .map_err(map_err)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
