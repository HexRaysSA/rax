//! Memory-management system calls.
//!
//! Argument validation follows Linux 6.19 in order (`mm/mmap.c`,
//! `mm/mprotect.c`, `mm/mremap.c`, `mm/madvise.c`, `mm/msync.c`), so the
//! first failing check determines the error just as on a real kernel.

use std::sync::Arc;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::{
    LinuxAbi, MMAP_MIN_ADDR, PAGE_SIZE, READ_IMPLIES_EXEC, STACK_GUARD_GAP, vma_flags,
};
use super::super::fs::fd::{FileObject, FileType};
use super::super::loader::prot_to_perms;
use super::{Ctx, SysResult};
use crate::error::MemoryAccessKind;
use crate::user::mm::{Backing, FaultClass, HostFileSource, Mapping, MmError, PageSource, Perms};

/// `mmap`/`mprotect` constants (`asm-generic/mman-common.h`, `mman.h`).
pub mod mman {
    /// `PROT_READ`.
    pub const PROT_READ: u32 = 0x1;
    /// `PROT_WRITE`.
    pub const PROT_WRITE: u32 = 0x2;
    /// `PROT_EXEC`.
    pub const PROT_EXEC: u32 = 0x4;
    /// `PROT_SEM`.
    pub const PROT_SEM: u32 = 0x8;
    /// arm64 `PROT_BTI`.
    pub const PROT_BTI: u32 = 0x10;
    /// `PROT_GROWSDOWN`.
    pub const PROT_GROWSDOWN: u32 = 0x0100_0000;
    /// `PROT_GROWSUP`.
    pub const PROT_GROWSUP: u32 = 0x0200_0000;
    /// `MAP_SHARED`.
    pub const MAP_SHARED: u32 = 0x01;
    /// `MAP_PRIVATE`.
    pub const MAP_PRIVATE: u32 = 0x02;
    /// `MAP_SHARED_VALIDATE`.
    pub const MAP_SHARED_VALIDATE: u32 = 0x03;
    /// `MAP_TYPE`.
    pub const MAP_TYPE: u32 = 0x0f;
    /// `MAP_FIXED`.
    pub const MAP_FIXED: u32 = 0x10;
    /// `MAP_ANONYMOUS`.
    pub const MAP_ANONYMOUS: u32 = 0x20;
    /// x86 `MAP_32BIT`.
    pub const MAP_32BIT: u32 = 0x40;
    /// `MAP_GROWSDOWN`.
    pub const MAP_GROWSDOWN: u32 = 0x0100;
    /// `MAP_DENYWRITE`.
    pub const MAP_DENYWRITE: u32 = 0x0800;
    /// `MAP_EXECUTABLE`.
    pub const MAP_EXECUTABLE: u32 = 0x1000;
    /// `MAP_LOCKED`.
    pub const MAP_LOCKED: u32 = 0x2000;
    /// `MAP_NORESERVE`.
    pub const MAP_NORESERVE: u32 = 0x4000;
    /// `MAP_POPULATE`.
    pub const MAP_POPULATE: u32 = 0x8000;
    /// `MAP_NONBLOCK`.
    pub const MAP_NONBLOCK: u32 = 0x10000;
    /// `MAP_STACK`.
    pub const MAP_STACK: u32 = 0x20000;
    /// `MAP_HUGETLB`.
    pub const MAP_HUGETLB: u32 = 0x40000;
    /// `MAP_SYNC`.
    pub const MAP_SYNC: u32 = 0x80000;
    /// `MAP_FIXED_NOREPLACE`.
    pub const MAP_FIXED_NOREPLACE: u32 = 0x100000;
    /// `LEGACY_MAP_MASK`: flags `MAP_SHARED_VALIDATE` accepts.
    pub const LEGACY_MAP_MASK: u32 = MAP_SHARED
        | MAP_PRIVATE
        | MAP_FIXED
        | MAP_ANONYMOUS
        | MAP_DENYWRITE
        | MAP_EXECUTABLE
        | MAP_UNINITIALIZED
        | MAP_GROWSDOWN
        | MAP_LOCKED
        | MAP_NORESERVE
        | MAP_POPULATE
        | MAP_NONBLOCK
        | MAP_STACK
        | MAP_HUGETLB
        | MAP_32BIT
        | MAP_FIXED_NOREPLACE;
    /// `MAP_UNINITIALIZED`.
    pub const MAP_UNINITIALIZED: u32 = 0x4000000;
}
use mman::*;

const PAGE_MASK: u64 = PAGE_SIZE - 1;

fn page_align(x: u64) -> Option<u64> {
    x.checked_add(PAGE_MASK).map(|v| v & !PAGE_MASK)
}

fn map_err(e: MmError) -> Errno {
    match e {
        MmError::InvalidArgument(_) => Errno(EINVAL),
        MmError::OutOfRange | MmError::OutOfMemory | MmError::NotMapped { .. } => Errno(ENOMEM),
    }
}

fn perms(abi: LinuxAbi, prot: u32) -> Perms {
    prot_to_perms(
        abi,
        prot & PROT_READ != 0,
        prot & PROT_WRITE != 0,
        prot & PROT_EXEC != 0,
    )
}

/// `brk`.
pub fn brk(c: &mut Ctx<'_>, addr: u64) -> SysResult {
    let mm = &c.p.mm;
    let (start_brk, cur) = (mm.start_brk, mm.brk);
    if addr < start_brk {
        return Ok(cur);
    }
    let (Some(new_end), Some(old_end)) = (page_align(addr), page_align(cur)) else {
        return Ok(cur);
    };
    if new_end == old_end {
        c.p.mm.brk = addr;
        return Ok(addr);
    }
    if addr <= cur {
        // Shrinking always succeeds.
        c.p.space
            .unmap(new_end, old_end - new_end)
            .map_err(map_err)?;
        c.p.mm.brk = addr;
        return Ok(addr);
    }
    // The new break must leave a page before the next mapping (and the
    // stack guard gap before a stack).
    let probe_end = new_end.saturating_add(PAGE_SIZE);
    if probe_end > c.p.abi.task_size() || !c.p.space.is_free(old_end, probe_end - old_end) {
        return Ok(cur);
    }
    if let Some(next) = c.p.space.vmas_in(probe_end, c.p.abi.task_size()).first() {
        // vm_start_gap(): a VM_GROWSDOWN VMA reserves the guard gap below.
        if next.flags & vma_flags::GROWSDOWN != 0 && next.start < probe_end + STACK_GUARD_GAP {
            return Ok(cur);
        }
    }
    let rw = Perms::READ | Perms::WRITE;
    if c.p
        .space
        .map(
            old_end,
            new_end - old_end,
            Mapping::anonymous(rw).named("[heap]"),
        )
        .is_err()
    {
        return Ok(cur);
    }
    c.p.mm.brk = addr;
    Ok(addr)
}

/// `get_unmapped_area` for a non-fixed request.
fn unmapped_area(c: &Ctx<'_>, hint: u64, len: u64, flags: u32) -> Result<u64, Errno> {
    let task = c.p.abi.task_size();
    if len > task {
        return Err(Errno(ENOMEM));
    }
    if c.p.abi == LinuxAbi::X86_64 && flags & MAP_32BIT != 0 {
        // x86 find_start_end(): bottom-up within [1 GiB, 2 GiB).
        return c
            .p
            .space
            .find_free_bottom_up(len, PAGE_SIZE, 0x4000_0000, 0x8000_0000)
            .ok_or(Errno(ENOMEM));
    }
    // round_hint_to_min().
    let mut hint = hint & !PAGE_MASK;
    if hint != 0 && hint < MMAP_MIN_ADDR {
        hint = MMAP_MIN_ADDR;
    }
    if hint != 0 && hint <= task - len && c.p.space.is_free(hint, len) {
        return Ok(hint);
    }
    let low = MMAP_MIN_ADDR.max(PAGE_SIZE);
    c.p.space
        .find_free_top_down(len, PAGE_SIZE, low, c.p.mm.mmap_base)
        // Top-down failure falls back to a bottom-up search of the whole
        // address space (arch_get_unmapped_area).
        .or_else(|| c.p.space.find_free_bottom_up(len, PAGE_SIZE, low, task))
        .ok_or(Errno(ENOMEM))
}

/// `mmap`.
pub fn mmap(
    c: &mut Ctx<'_>,
    addr: u64,
    len: u64,
    prot: u32,
    flags: u32,
    fd: i32,
    off: u64,
) -> SysResult {
    if off & PAGE_MASK != 0 {
        return Err(Errno(EINVAL));
    }
    if len == 0 {
        return Err(Errno(EINVAL));
    }
    let len = page_align(len).ok_or(Errno(ENOMEM))?;
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
    let shared = map_type != MAP_PRIVATE;
    let anonymous = flags & MAP_ANONYMOUS != 0;
    let mut prot = prot;
    if prot & PROT_READ != 0 && c.p.persona & READ_IMPLIES_EXEC != 0 {
        prot |= PROT_EXEC;
    }

    let mut backing = Backing::Anonymous;
    let mut name: Option<Arc<str>> = None;
    let mut vm_flags = 0;
    if !anonymous {
        let file = c.p.fds.file(fd)?;
        match (&file.object, file.ftype) {
            (FileObject::Host(f), FileType::Regular | FileType::BlockDevice) => {
                if !file.readable() {
                    return Err(Errno(EACCES));
                }
                if shared && !file.writable() {
                    if prot & PROT_WRITE != 0 {
                        return Err(Errno(EACCES));
                    }
                    vm_flags |= vma_flags::DENY_WRITE;
                }
                let source: Arc<dyn PageSource> =
                    Arc::new(HostFileSource::new(f.try_clone()?).map_err(Errno::from)?);
                backing = Backing::Source {
                    source,
                    offset: off,
                };
                name = Some(match &file.host_path {
                    Some(h) => c.p.vfs.guest_path_of(h).into(),
                    None => file.path.as_str().into(),
                });
            }
            // /dev/zero maps anonymous memory.
            (FileObject::Host(_), FileType::CharDevice) if file.path.ends_with("/dev/zero") => {}
            (FileObject::Synthetic(d), FileType::Regular) => {
                backing = Backing::Source {
                    source: Arc::new(crate::user::mm::BytesSource::new(d.clone())),
                    offset: off,
                };
                name = Some(file.path.as_str().into());
            }
            _ => return Err(Errno(ENODEV)),
        }
    } else if flags & MAP_HUGETLB != 0 {
        // No huge pages are reserved (vm.nr_hugepages = 0).
        return Err(Errno(ENOMEM));
    }

    let task = c.p.abi.task_size();
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
        if flags & MAP_FIXED == 0 && !c.p.space.is_free(addr, len) {
            return Err(Errno(EEXIST));
        }
        addr
    } else {
        unmapped_area(c, addr, len, flags)?
    };
    c.p.space
        .map(
            start,
            len,
            Mapping {
                perms: perms(c.p.abi, prot),
                backing,
                shared,
                name,
                flags: vm_flags,
            },
        )
        .map_err(map_err)?;
    Ok(start)
}

/// `munmap`.
pub fn munmap(c: &mut Ctx<'_>, addr: u64, len: u64) -> SysResult {
    let task = c.p.abi.task_size();
    if addr & PAGE_MASK != 0 || addr > task || len > task - addr {
        return Err(Errno(EINVAL));
    }
    let len = page_align(len).ok_or(Errno(EINVAL))?;
    if len == 0 {
        return Err(Errno(EINVAL));
    }
    c.p.space.unmap(addr, len).map_err(map_err)?;
    Ok(0)
}

/// `mprotect`, in the order of `do_mprotect_pkey`: the request is
/// validated, then applied VMA by VMA in ascending order until a VMA
/// refuses it or a hole ends the walk, so earlier VMAs keep the new
/// protection when a later check fails.
pub fn mprotect(c: &mut Ctx<'_>, addr: u64, len: u64, prot: u32) -> SysResult {
    let grows = prot & (PROT_GROWSDOWN | PROT_GROWSUP);
    let rier = c.p.persona & READ_IMPLIES_EXEC != 0 && prot & PROT_READ != 0;
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
    // arch_validate_prot(): arm64 also accepts PROT_BTI (PROT_MTE needs
    // MTE, which is not advertised).
    let mut valid = PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM;
    if c.p.abi == LinuxAbi::Aarch64 {
        valid |= PROT_BTI;
    }
    if prot & !valid != 0 {
        return Err(Errno(EINVAL));
    }
    let vmas = c.p.space.vmas_in(start, end);
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
        let hi = vma.end.min(end);
        c.p.space
            .protect(cursor, hi - cursor, perms(c.p.abi, p))
            .map_err(map_err)?;
        cursor = hi;
    }
    if cursor < end {
        return Err(Errno(ENOMEM));
    }
    Ok(0)
}

/// `mremap`.
pub fn mremap(
    c: &mut Ctx<'_>,
    old: u64,
    old_len: u64,
    new_len: u64,
    flags: u32,
    new_addr: u64,
) -> SysResult {
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
    // Duplicating a mapping (old_len == 0) requires a shared mapping whose
    // pages two addresses can share; the frame model keeps one address per
    // frame.
    if old_len == 0 {
        return Err(Errno(EINVAL));
    }
    let task = c.p.abi.task_size();
    let vma = c.p.space.vma_at(old).ok_or(Errno(EFAULT))?;
    if old.checked_add(old_len).is_none_or(|end| end > vma.end) {
        return Err(Errno(EFAULT));
    }
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
        c.p.space.unmap(new_addr, new_len).map_err(map_err)?;
        let moved = old_len.min(new_len);
        if old_len > new_len {
            c.p.space
                .unmap(old + new_len, old_len - new_len)
                .map_err(map_err)?;
        }
        move_range(c, old, moved, new_addr, flags & MREMAP_DONTUNMAP != 0, &vma)?;
        if new_len > old_len {
            c.p.space
                .map(new_addr + old_len, new_len - old_len, extension(new_addr))
                .map_err(map_err)?;
        }
        return Ok(new_addr);
    }

    if new_len <= old_len && flags & MREMAP_DONTUNMAP == 0 {
        if new_len < old_len {
            c.p.space
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
        && c.p.space.is_free(old + old_len, grow)
    {
        c.p.space
            .map(old + old_len, grow, extension(old))
            .map_err(map_err)?;
        return Ok(old);
    }
    if flags & MREMAP_MAYMOVE == 0 {
        return Err(Errno(ENOMEM));
    }
    let dest = unmapped_area(c, 0, new_len, 0)?;
    move_range(c, old, old_len, dest, flags & MREMAP_DONTUNMAP != 0, &vma)?;
    if new_len > old_len {
        c.p.space
            .map(dest + old_len, new_len - old_len, extension(dest))
            .map_err(map_err)?;
    }
    Ok(dest)
}

/// Moves pages, optionally leaving an empty mapping behind
/// (`MREMAP_DONTUNMAP`).
fn move_range(
    c: &mut Ctx<'_>,
    old: u64,
    len: u64,
    dest: u64,
    dontunmap: bool,
    vma: &crate::user::mm::Vma,
) -> Result<(), Errno> {
    c.p.space.remap(old, len, dest).map_err(map_err)?;
    if dontunmap {
        c.p.space
            .map(
                old,
                len,
                Mapping {
                    perms: vma.perms,
                    backing: Backing::Anonymous,
                    shared: vma.shared,
                    name: vma.name.clone(),
                    flags: vma.flags,
                },
            )
            .map_err(map_err)?;
    }
    Ok(())
}

/// `MADV_POPULATE_READ`/`MADV_POPULATE_WRITE` (`madvise_populate`): faults
/// every page in as a read or write would, without changing its contents.
fn madvise_populate(c: &Ctx<'_>, addr: u64, end: u64, write: bool) -> SysResult {
    let (access, need) = if write {
        (MemoryAccessKind::Write, Perms::WRITE)
    } else {
        (MemoryAccessKind::Read, Perms::READ)
    };
    let mut cursor = addr;
    while cursor < end {
        // No VMA: ENOMEM. Incompatible permissions: EINVAL. A fault that
        // would raise SIGBUS or SIGSEGV: EFAULT.
        let vma = c.p.space.vma_at(cursor).ok_or(Errno(ENOMEM))?;
        if !vma.perms.contains(need) {
            return Err(Errno(EINVAL));
        }
        let hi = vma.end.min(end);
        for page in (cursor..hi).step_by(PAGE_SIZE as usize) {
            if c.p.space.translate(page, access).is_err() {
                return Err(match c.p.space.classify_fault(page, access) {
                    FaultClass::OutOfMemory => Errno(ENOMEM),
                    _ => Errno(EFAULT),
                });
            }
        }
        cursor = hi;
    }
    Ok(0)
}

/// `madvise`.
pub fn madvise(c: &mut Ctx<'_>, addr: u64, len: u64, advice: u32) -> SysResult {
    const MADV_DONTNEED: u32 = 4;
    const MADV_FREE: u32 = 8;
    const MADV_REMOVE: u32 = 9;
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
        return madvise_populate(c, addr, end, advice == MADV_POPULATE_WRITE);
    }
    // madvise_walk_vmas(): the advice applies to each VMA in ascending order
    // and the walk stops at the first VMA that rejects it; unmapped gaps are
    // skipped but make the call fail with ENOMEM once the walk completes.
    let mut hole = false;
    let mut cursor = addr;
    for vma in c.p.space.vmas_in(addr, end) {
        hole |= vma.start > cursor;
        let (lo, hi) = (vma.start.max(addr), vma.end.min(end));
        cursor = hi;
        let anonymous = matches!(vma.backing, Backing::Anonymous);
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
            // `madvise_remove`: punches a hole in the file behind a shared
            // mapping that may be written (private anonymous memory has no
            // file). Shared anonymous memory is shmem, so its pages read
            // back as zero; host files would need `fallocate(PUNCH_HOLE)`,
            // which is not portable, so they report the filesystem-level
            // EOPNOTSUPP.
            MADV_REMOVE if anonymous && !vma.shared => return Err(Errno(EINVAL)),
            MADV_REMOVE if !vma.shared || vma.flags & vma_flags::DENY_WRITE != 0 => {
                return Err(Errno(EACCES));
            }
            MADV_REMOVE if !anonymous => return Err(Errno(EOPNOTSUPP)),
            MADV_REMOVE => true,
            _ => false,
        };
        if discard {
            c.p.space.discard(lo, hi - lo).map_err(map_err)?;
        }
    }
    if hole || cursor < end {
        return Err(Errno(ENOMEM));
    }
    Ok(0)
}

/// `msync`.
pub fn msync(c: &mut Ctx<'_>, addr: u64, len: u64, flags: u32) -> SysResult {
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
    if len != 0 && c.p.space.first_unmapped(addr, len).is_some() {
        return Err(Errno(ENOMEM));
    }
    Ok(0)
}

/// `mlock`/`munlock`/`mlock2`: memory is never paged out, so locking only
/// validates the range.
pub fn mlock(c: &mut Ctx<'_>, addr: u64, len: u64) -> SysResult {
    let start = addr & !PAGE_MASK;
    let end = page_align(addr.saturating_add(len)).ok_or(Errno(ENOMEM))?;
    if end > start && c.p.space.first_unmapped(start, end - start).is_some() {
        return Err(Errno(ENOMEM));
    }
    Ok(0)
}

/// `mincore`: one byte per page, bit 0 set for resident pages.
pub fn mincore(c: &mut Ctx<'_>, addr: u64, len: u64, vec: u64) -> SysResult {
    if addr & PAGE_MASK != 0 {
        return Err(Errno(EINVAL));
    }
    let len = page_align(len).ok_or(Errno(ENOMEM))?;
    if addr
        .checked_add(len)
        .is_none_or(|e| e > c.p.abi.task_size())
    {
        return Err(Errno(ENOMEM));
    }
    if c.p.space.first_unmapped(addr, len).is_some() {
        return Err(Errno(ENOMEM));
    }
    let bytes: Vec<u8> = (0..len / PAGE_SIZE)
        .map(|i| u8::from(c.p.space.is_resident(addr + i * PAGE_SIZE)))
        .collect();
    c.write_mem(vec, &bytes)?;
    Ok(0)
}
