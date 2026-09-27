//! Memory-management calls: `mmap`, `munmap`, `mprotect`, `madvise`,
//! `minherit`, `msync`, `mincore`, and the `mlock` family, as
//! `bsd/kern/kern_mman.c` implements them over the Mach VM map.

use std::sync::Arc;

use super::Ctx;
use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::io::{O_ACCMODE, O_RDWR, O_WRONLY};
use crate::user::darwin::vm::{self, VmFlags};
use crate::user::mm::{Backing, HostFileSource, Mapping, MmError, SharedObject};

/// `MAP_SHARED`.
pub const MAP_SHARED: u32 = 0x0001;
/// `MAP_PRIVATE`.
pub const MAP_PRIVATE: u32 = 0x0002;
/// `MAP_COPY` (obsolete, accepted).
pub const MAP_COPY: u32 = 0x0002;
/// `MAP_FIXED`.
pub const MAP_FIXED: u32 = 0x0010;
/// `MAP_RENAME`.
pub const MAP_RENAME: u32 = 0x0020;
/// `MAP_NORESERVE`.
pub const MAP_NORESERVE: u32 = 0x0040;
/// `MAP_RESERVED0080`.
pub const MAP_RESERVED0080: u32 = 0x0080;
/// `MAP_NOEXTEND`.
pub const MAP_NOEXTEND: u32 = 0x0100;
/// `MAP_HASSEMAPHORE`.
pub const MAP_HASSEMAPHORE: u32 = 0x0200;
/// `MAP_NOCACHE`.
pub const MAP_NOCACHE: u32 = 0x0400;
/// `MAP_JIT`.
pub const MAP_JIT: u32 = 0x0800;
/// `MAP_FILE`.
pub const MAP_FILE: u32 = 0x0000;
/// `MAP_ANON`.
pub const MAP_ANON: u32 = 0x1000;
/// `MAP_RESILIENT_CODESIGN`.
pub const MAP_RESILIENT_CODESIGN: u32 = 0x2000;
/// `MAP_RESILIENT_MEDIA`.
pub const MAP_RESILIENT_MEDIA: u32 = 0x4000;
/// `MAP_32BIT`.
pub const MAP_32BIT: u32 = 0x8000;
/// `MAP_TRANSLATED_ALLOW_EXECUTE`.
pub const MAP_TRANSLATED_ALLOW_EXECUTE: u32 = 0x2_0000;
/// `MAP_UNIX03`.
pub const MAP_UNIX03: u32 = 0x4_0000;
/// `MAP_TPRO`.
pub const MAP_TPRO: u32 = 0x8_0000;

/// `VM_FLAGS_ALIAS_MASK`: the user tag an anonymous `mmap` passes in `fd`.
const VM_FLAGS_ALIAS_MASK: u32 = 0xFF00_0000;
/// `VM_FLAGS_SUPERPAGE_MASK`.
const VM_FLAGS_SUPERPAGE_MASK: u32 = 0x7_0000;
/// `VM_FLAGS_PURGABLE`.
const VM_FLAGS_PURGABLE: u32 = 0x2;
/// `VM_FLAGS_4GB_CHUNK`.
const VM_FLAGS_4GB_CHUNK: u32 = 0x4;

const KNOWN_FLAGS: u32 = MAP_SHARED
    | MAP_PRIVATE
    | MAP_COPY
    | MAP_FIXED
    | MAP_RENAME
    | MAP_NORESERVE
    | MAP_RESERVED0080
    | MAP_NOEXTEND
    | MAP_HASSEMAPHORE
    | MAP_NOCACHE
    | MAP_JIT
    | MAP_TPRO
    | MAP_FILE
    | MAP_ANON
    | MAP_RESILIENT_CODESIGN
    | MAP_RESILIENT_MEDIA
    | MAP_32BIT
    | MAP_TRANSLATED_ALLOW_EXECUTE
    | MAP_UNIX03;

fn mm_errno(e: MmError) -> Errno {
    match e {
        MmError::OutOfMemory | MmError::OutOfRange | MmError::NotMapped { .. } => Errno::ENOMEM,
        MmError::InvalidArgument(_) => Errno::EINVAL,
    }
}

/// Maps `mapping` at a free range of `len` bytes at or above `hint`
/// (anywhere when zero), or at exactly `addr` replacing what is there.
pub fn map_at(
    ctx: &mut Ctx<'_>,
    fixed: Option<u64>,
    hint: u64,
    len: u64,
    mapping: Mapping,
) -> Result<u64, Errno> {
    let vmx = ctx.proc.vm;
    let addr = match fixed {
        Some(a) => {
            if !vmx.contains(a, len) {
                return Err(Errno::ENOMEM);
            }
            a
        }
        None => {
            let from_hint = (hint != 0)
                .then(|| {
                    let h = vmx.round(hint)?;
                    let l = crate::user::darwin::vm::VmLayout {
                        hint: h.max(vmx.min),
                        ..vmx
                    };
                    ctx.proc
                        .space
                        .find_free_bottom_up(len, vmx.page, l.hint, vmx.max)
                })
                .flatten();
            match from_hint.or_else(|| vmx.find_space(&ctx.proc.space, len, vmx.page)) {
                Some(a) => a,
                None => return Err(Errno::ENOMEM),
            }
        }
    };
    ctx.proc.space.map(addr, len, mapping).map_err(mm_errno)?;
    Ok(addr)
}

/// `mmap(addr, len, prot, flags, fd, pos)`.
pub fn mmap(
    ctx: &mut Ctx<'_>,
    addr: u64,
    len: u64,
    prot: u32,
    flags: u32,
    fd: i32,
    pos: u64,
) -> SysResult {
    let page = ctx.proc.vm.page;
    let mask = page - 1;
    let mut prot = prot & vm::VM_PROT_ALL;
    // mmap_sanitize: the file range must not overflow.
    if pos.checked_add(len).is_none()
        || (pos & !mask)
            .checked_add(len + (pos & mask) + mask)
            .is_none()
    {
        return Err(Errno::EINVAL);
    }
    if flags & MAP_UNIX03 != 0 && (len == 0 || pos & mask != 0) {
        return Err(Errno::EINVAL);
    }
    let size = ((pos & mask) + len + mask) & !mask;
    let fixed = if flags & MAP_FIXED != 0 {
        // The address must have the file offset's in-page remainder.
        if addr & mask != pos & mask {
            return Err(Errno::EINVAL);
        }
        Some(addr & !mask)
    } else {
        None
    };
    if prot & (vm::VM_PROT_EXECUTE | vm::VM_PROT_WRITE) != 0 {
        prot |= vm::VM_PROT_READ;
    }
    if flags & !KNOWN_FLAGS != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & MAP_UNIX03 != 0 && flags & (MAP_PRIVATE | MAP_SHARED) == 0 {
        return Err(Errno::EINVAL);
    }
    if flags & MAP_JIT != 0
        && (flags & MAP_SHARED != 0
            || flags & MAP_ANON == 0
            || flags & (MAP_RESILIENT_CODESIGN | MAP_RESILIENT_MEDIA | MAP_TPRO) != 0
            || (flags & MAP_FIXED != 0 && page != 4096))
    {
        return Err(Errno::EINVAL);
    }
    if flags & (MAP_RESILIENT_CODESIGN | MAP_RESILIENT_MEDIA) != 0
        && flags & (MAP_ANON | MAP_JIT | MAP_TPRO) != 0
    {
        return Err(Errno::EINVAL);
    }
    if flags & MAP_RESILIENT_CODESIGN != 0 {
        let reject = if flags & MAP_PRIVATE != 0 {
            vm::VM_PROT_EXECUTE
        } else {
            vm::VM_PROT_WRITE | vm::VM_PROT_EXECUTE
        };
        if prot & reject != 0 {
            return Err(Errno::EPERM);
        }
    }
    let flags = if flags & MAP_SHARED != 0 {
        flags & !MAP_RESILIENT_MEDIA
    } else {
        flags
    };
    if flags & MAP_TPRO != 0 && (prot & vm::VM_PROT_EXECUTE != 0 || prot & vm::VM_PROT_WRITE == 0) {
        return Err(Errno::EPERM);
    }
    let inherit = if flags & MAP_SHARED != 0 {
        vm::VM_INHERIT_SHARE
    } else {
        vm::VM_INHERIT_COPY
    };

    if flags & MAP_ANON != 0 {
        let mut tag = 0;
        if fd != -1 {
            let f = fd as u32;
            if f & (VM_FLAGS_ALIAS_MASK
                | VM_FLAGS_SUPERPAGE_MASK
                | VM_FLAGS_PURGABLE
                | VM_FLAGS_4GB_CHUNK)
                != f
            {
                return Err(Errno::EINVAL);
            }
            tag = f >> 24;
        }
        if size == 0 {
            return Ok(Rv::one(0));
        }
        let mapping = if flags & MAP_SHARED != 0 {
            let obj = SharedObject::anonymous(size).map_err(Errno::from)?;
            Mapping {
                perms: vm::perms(prot),
                backing: Backing::Shared {
                    object: Arc::new(obj),
                    offset: 0,
                },
                shared: true,
                name: None,
                flags: VmFlags::new(vm::VM_PROT_ALL, inherit, tag).bits(),
            }
        } else {
            Mapping {
                flags: VmFlags::new(vm::VM_PROT_ALL, inherit, tag).bits(),
                ..Mapping::anonymous(vm::perms(prot))
            }
        };
        let a = match map_at(ctx, fixed, addr, size, mapping.clone()) {
            // A non-binding hint that failed is retried from the bottom.
            Err(Errno::ENOMEM) if fixed.is_none() && addr != 0 => {
                map_at(ctx, None, 0, size, mapping)?
            }
            r => r?,
        };
        return Ok(Rv::one(a));
    }

    // A file.
    if flags & MAP_JIT != 0 {
        return Err(Errno::EINVAL);
    }
    let file = ctx.proc.fds.file(fd)?;
    let host = file.host_fd().ok_or(Errno::EINVAL)?;
    let meta = host_fstat(host)?;
    let kind = meta.st_mode as u32 & 0o170000;
    if kind == 0o020000 {
        // A character device (the /dev/zero hack is refused).
        return Err(Errno::ENODEV);
    }
    if kind != 0o100000 {
        return Err(Errno::EINVAL);
    }
    let acc = *file.flags.lock().unwrap() & O_ACCMODE;
    let readable = acc != O_WRONLY;
    let writable = acc == O_WRONLY || acc == O_RDWR;
    let mut maxprot = vm::VM_PROT_EXECUTE;
    if readable {
        maxprot |= vm::VM_PROT_READ;
    } else if prot & vm::VM_PROT_READ != 0 {
        return Err(Errno::EACCES);
    }
    if flags & MAP_SHARED != 0 {
        if writable {
            maxprot |= vm::VM_PROT_WRITE;
        } else if prot & vm::VM_PROT_WRITE != 0 {
            return Err(Errno::EACCES);
        }
    } else {
        maxprot |= vm::VM_PROT_WRITE;
    }
    if size == 0 {
        return Ok(Rv::one(0));
    }
    if maxprot & (vm::VM_PROT_EXECUTE | vm::VM_PROT_WRITE) != 0 {
        maxprot |= vm::VM_PROT_READ;
    }
    if flags & MAP_RESILIENT_CODESIGN != 0 {
        maxprot &= prot;
    }
    // A duplicate of the descriptor keeps the file for the mapping's life.
    // SAFETY: fcntl(F_DUPFD_CLOEXEC) on a live descriptor takes no pointers.
    let dup = unsafe { libc::fcntl(host, libc::F_DUPFD_CLOEXEC, 3) };
    if dup < 0 {
        return Err(Errno::last());
    }
    // SAFETY: `dup` is a new descriptor this process owns exclusively.
    let owned = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(dup) };
    let file_start = pos & !mask;
    let name: Option<Arc<str>> = file
        .path
        .as_ref()
        .map(|p| Arc::from(String::from_utf8_lossy(p).as_ref()));
    let backing = if flags & MAP_SHARED != 0 {
        let obj = SharedObject::file(owned, writable).map_err(Errno::from)?;
        Backing::Shared {
            object: Arc::new(obj),
            offset: file_start,
        }
    } else {
        let src = HostFileSource::new(owned).map_err(Errno::from)?;
        Backing::Source {
            source: Arc::new(src),
            offset: file_start,
        }
    };
    let mapping = Mapping {
        perms: vm::perms(prot),
        backing,
        shared: flags & MAP_SHARED != 0,
        name,
        flags: VmFlags::new(maxprot, inherit, 0).bits(),
    };
    let a = match map_at(ctx, fixed, addr, size, mapping.clone()) {
        Err(Errno::ENOMEM) if fixed.is_none() && addr != 0 => map_at(ctx, None, 0, size, mapping)?,
        r => r?,
    };
    Ok(Rv::one(a + (pos & mask)))
}

fn host_fstat(fd: i32) -> Result<libc::stat, Errno> {
    // SAFETY: `st` is written in full by fstat on success; the descriptor
    // is live.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 {
            return Err(Errno::last());
        }
        Ok(st)
    }
}

/// Validates a user range for `munmap`/`mprotect`/`madvise`-style calls:
/// the address must be page-aligned; the length is rounded up to pages.
fn range(ctx: &Ctx<'_>, addr: u64, len: u64) -> Result<(u64, u64), Errno> {
    let vmx = ctx.proc.vm;
    if !vmx.aligned(addr) {
        return Err(Errno::EINVAL);
    }
    let len = match vmx.round(len) {
        Some(l) => l,
        None if len == 0 => return Ok((addr, 0)),
        None => return Err(Errno::EINVAL),
    };
    let end = addr.checked_add(len).ok_or(Errno::EINVAL)?;
    Ok((addr, end - addr))
}

/// `munmap(addr, len)`.
pub fn munmap(ctx: &mut Ctx<'_>, addr: u64, len: u64) -> SysResult {
    let (addr, len) = range(ctx, addr, len)?;
    if len == 0 {
        return Err(Errno::EINVAL);
    }
    if addr.checked_add(len).is_none_or(|e| e > ctx.proc.vm.max) {
        return Err(Errno::EINVAL);
    }
    ctx.proc.space.unmap(addr, len).map_err(mm_errno)?;
    Ok(Rv::one(0))
}

/// Changes the protection of `[addr, addr + len)` to `prot`, checking each
/// entry's maximum protection (`vm_map_protect`).
pub fn protect(ctx: &mut Ctx<'_>, addr: u64, len: u64, prot: u32) -> Result<(), Errno> {
    let end = addr + len;
    if ctx.proc.space.first_unmapped(addr, len).is_some() {
        return Err(Errno::ENOMEM);
    }
    for v in ctx.proc.space.vmas_in(addr, end) {
        if prot & !VmFlags::from_bits(v.flags).max_prot() != 0 {
            return Err(Errno::EACCES);
        }
    }
    ctx.proc
        .space
        .protect(addr, len, vm::perms(prot))
        .map_err(mm_errno)
}

/// `mprotect(addr, len, prot)`.
pub fn mprotect(ctx: &mut Ctx<'_>, addr: u64, len: u64, prot: u32) -> SysResult {
    // VM_PROT_* beyond read/write/execute: VM_PROT_COPY and the trusted and
    // strip bits are not accepted from mprotect.
    if prot & !vm::VM_PROT_ALL != 0 {
        return Err(Errno::EINVAL);
    }
    let (addr, len) = range(ctx, addr, len)?;
    if len == 0 {
        return Ok(Rv::one(0));
    }
    let mut prot = prot;
    if prot & (vm::VM_PROT_EXECUTE | vm::VM_PROT_WRITE) != 0 {
        prot |= vm::VM_PROT_READ;
    }
    protect(ctx, addr, len, prot)?;
    Ok(Rv::one(0))
}

/// `MADV_*`.
pub mod madv {
    pub const NORMAL: i32 = 0;
    pub const RANDOM: i32 = 1;
    pub const SEQUENTIAL: i32 = 2;
    pub const WILLNEED: i32 = 3;
    pub const DONTNEED: i32 = 4;
    pub const FREE: i32 = 5;
    pub const ZERO_WIRED_PAGES: i32 = 6;
    pub const FREE_REUSABLE: i32 = 7;
    pub const FREE_REUSE: i32 = 8;
    pub const CAN_REUSE: i32 = 9;
    pub const PAGEOUT: i32 = 10;
    pub const ZERO: i32 = 11;
}

/// `madvise(addr, len, advice)`.
pub fn madvise(ctx: &mut Ctx<'_>, addr: u64, len: u64, advice: i32) -> SysResult {
    // madvise truncates the start and rounds the end (vm_map_trunc_page /
    // vm_map_round_page), unlike munmap.
    let page = ctx.proc.vm.page;
    let start = addr & !(page - 1);
    let end = addr
        .checked_add(len)
        .and_then(|e| e.checked_add(page - 1))
        .ok_or(Errno::EINVAL)?
        & !(page - 1);
    let len = end - start;
    if !(madv::NORMAL..=madv::ZERO).contains(&advice) {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Ok(Rv::one(0));
    }
    if ctx.proc.space.first_unmapped(start, len).is_some() {
        return Err(Errno::ENOMEM);
    }
    match advice {
        // Discard private anonymous pages: they read back as zero. Shared
        // and file-backed pages keep their contents.
        madv::FREE | madv::FREE_REUSABLE | madv::ZERO => {
            for v in ctx.proc.space.vmas_in(start, end) {
                if !v.shared && matches!(v.backing, Backing::Anonymous) {
                    let lo = v.start.max(start);
                    let hi = v.end.min(end);
                    ctx.proc.space.discard(lo, hi - lo).map_err(mm_errno)?;
                }
            }
        }
        _ => {}
    }
    Ok(Rv::one(0))
}

/// `minherit(addr, len, inherit)`.
pub fn minherit(ctx: &mut Ctx<'_>, addr: u64, len: u64, inherit: i32) -> SysResult {
    let (addr, len) = range(ctx, addr, len)?;
    if !(0..=2).contains(&inherit) {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Ok(Rv::one(0));
    }
    if ctx.proc.space.first_unmapped(addr, len).is_some() {
        return Err(Errno::ENOMEM);
    }
    ctx.proc
        .space
        .set_flags(addr, len, 3 << 4, (inherit as u32) << 4)
        .map_err(mm_errno)?;
    Ok(Rv::one(0))
}

/// `msync(addr, len, flags)`.
pub fn msync(ctx: &mut Ctx<'_>, addr: u64, len: u64, flags: i32) -> SysResult {
    const MS_ASYNC: i32 = 1;
    const MS_INVALIDATE: i32 = 2;
    const MS_SYNC: i32 = 0x10;
    const MS_KILLPAGES: i32 = 4;
    const MS_DEACTIVATE: i32 = 8;
    let page = ctx.proc.vm.page;
    if addr & (page - 1) != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC | MS_KILLPAGES | MS_DEACTIVATE) != 0
        || (flags & MS_ASYNC != 0 && flags & MS_SYNC != 0)
    {
        return Err(Errno::EINVAL);
    }
    let len = (len + page - 1) & !(page - 1);
    if len == 0 {
        return Ok(Rv::one(0));
    }
    if ctx.proc.space.first_unmapped(addr, len).is_some() {
        return Err(Errno::ENOMEM);
    }
    ctx.proc.space.sync(addr, len).map_err(Errno::from)?;
    Ok(Rv::one(0))
}

/// `mincore(addr, len, vec)`: one byte per page, `MINCORE_INCORE` for a
/// resident page.
pub fn mincore(ctx: &mut Ctx<'_>, addr: u64, len: u64, vec: u64) -> SysResult {
    const MINCORE_INCORE: u8 = 0x1;
    const MINCORE_REFERENCED: u8 = 0x2;
    let page = ctx.proc.vm.page;
    let start = addr & !(page - 1);
    let end = addr.checked_add(len).ok_or(Errno::ENOMEM)?;
    let end = (end + page - 1) & !(page - 1);
    if ctx.proc.space.first_unmapped(start, end - start).is_some() {
        return Err(Errno::ENOMEM);
    }
    let mut out = Vec::with_capacity(((end - start) / page) as usize);
    let mut a = start;
    while a < end {
        let resident = (a..a + page)
            .step_by(4096)
            .any(|p| ctx.proc.space.is_resident(p));
        out.push(if resident {
            MINCORE_INCORE | MINCORE_REFERENCED
        } else {
            0
        });
        a += page;
    }
    ctx.write(vec, &out)?;
    Ok(Rv::one(0))
}

/// `mlock`/`munlock`: residency is not modelled; the range must be mapped.
pub fn mlock(ctx: &mut Ctx<'_>, addr: u64, len: u64) -> SysResult {
    let page = ctx.proc.vm.page;
    let start = addr & !(page - 1);
    let end = addr.checked_add(len).ok_or(Errno::EINVAL)?;
    let end = (end + page - 1) & !(page - 1);
    if end > start && ctx.proc.space.first_unmapped(start, end - start).is_some() {
        return Err(Errno::ENOMEM);
    }
    Ok(Rv::one(0))
}
