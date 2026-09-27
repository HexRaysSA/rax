//! Attribute lists, cloning, and access checks the host answers
//! (`bsd/vfs/vfs_attrlist.c`, `bsd/vfs/vfs_syscalls.c`): `getattrlistbulk`,
//! `setattrlist`, `fsetattrlist`, `setattrlistat`, `clonefileat`,
//! `fclonefileat`, `exchangedata`, and `access_extended`.
//!
//! The host checks the arguments in XNU's order and does the work; the
//! emulator gives it copies of the guest's memory. Where the guest's
//! memory cannot be read (or a path is too long) the host is given what
//! fails the same way (an address it cannot read, a string past
//! `MAXPATHLEN`), so the error comes at the point XNU reports it: after a
//! path lookup that fails first, before one that succeeds.

use std::ffi::{CString, c_char, c_void};

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::host::{self, check};
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::syscall::util::MAXPATHLEN;

/// An address the host cannot read or write: its copies fault as the
/// guest's would.
const FAULT: usize = 1;

/// `ATTR_MAX_BUFFER_LONGPATHS`: the largest attribute buffer `setattrlist`
/// reads (a larger one is refused before it is read).
const ATTR_MAX_BUFFER: u64 = 32 * 1024;
/// The most of a `getattrlistbulk` buffer the host fills at once.
const BULK_MAX: u64 = 1 << 24;
/// `sizeof(struct attrlist)`.
const ATTRLIST: usize = 24;
/// `ACCESSX_MAX_TABLESIZE`.
const ACCESSX_MAX_TABLESIZE: u64 = 16 * 1024;
/// `sizeof(struct accessx_descriptor)`.
const ACCESSX_DESC: usize = 16;

/// The guest's syscall numbers the host takes through `syscall`.
const SYS_EXCHANGEDATA: libc::c_int = 223;
const SYS_ACCESS_EXTENDED: libc::c_int = 284;

/// Guest memory for the host to read: a copy, or (when unreadable) the
/// fault address.
struct In(Option<Vec<u8>>);

impl In {
    fn read(ctx: &Ctx<'_>, addr: u64, len: usize) -> Self {
        In(ctx.read(addr, len).ok())
    }
    fn ptr(&self) -> *mut c_void {
        match &self.0 {
            Some(b) => b.as_ptr() as *mut c_void,
            None => FAULT as *mut c_void,
        }
    }
}

/// A path argument for the host: the host path, a string too long for
/// `MAXPATHLEN`, or the fault address.
enum PathArg {
    Host(CString),
    Long(CString),
    Fault,
}

impl PathArg {
    fn read(ctx: &Ctx<'_>, addr: u64) -> Result<Self, Errno> {
        match ctx.path(addr) {
            Ok(p) => Ok(PathArg::Host(host::path(&ctx.proc.vfs, &p)?)),
            Err(Errno::ENAMETOOLONG) => Ok(PathArg::Long(
                CString::new(vec![b'x'; MAXPATHLEN + 1]).expect("no NUL"),
            )),
            Err(_) => Ok(PathArg::Fault),
        }
    }
    fn ptr(&self) -> *const c_char {
        match self {
            PathArg::Host(c) | PathArg::Long(c) => c.as_ptr(),
            PathArg::Fault => FAULT as *const c_char,
        }
    }
}

/// A host descriptor for a directory argument (`AT_FDCWD` included).
fn dirfd(ctx: &Ctx<'_>, fd: i32) -> Result<i32, Errno> {
    host::dirfd(&ctx.proc.fds, fd)
}

/// A descriptor's host descriptor (`EBADF` for none).
fn fd_host(ctx: &Ctx<'_>, fd: i32) -> Result<i32, Errno> {
    ctx.proc.fds.file(fd)?.host_fd().ok_or(Errno::EBADF)
}

/// Whether the guest can take `len` bytes at `addr`: every byte mapped
/// writable.
fn writable(ctx: &Ctx<'_>, addr: u64, len: u64) -> bool {
    use crate::user::mm::Perms;
    let Some(end) = addr.checked_add(len) else {
        return false;
    };
    let mut at = addr;
    for v in ctx.proc.space.vmas_in(addr, end) {
        if v.start > at || !v.perms.contains(Perms::WRITE) {
            return false;
        }
        at = v.end;
    }
    at >= end || len == 0
}

/// `getattrlistbulk(dirfd, alist, attributeBuffer, bufferSize, options)`:
/// the host reads the directory at the guest descriptor's offset and
/// fills the buffer with one record per entry (each led by its length);
/// the records are copied out, and the result is their count.
pub fn getattrlistbulk(
    ctx: &mut Ctx<'_>,
    dirfd: i32,
    alist: u64,
    buf: u64,
    size: u64,
    options: u64,
) -> SysResult {
    let h = fd_host(ctx, dirfd)?;
    let al = In::read(ctx, alist, ATTRLIST);
    let len = size.min(BULK_MAX) as usize;
    let mut out = vec![0u8; len];
    let ptr = if writable(ctx, buf, len as u64) {
        out.as_mut_ptr().cast()
    } else {
        FAULT as *mut c_void
    };
    // SAFETY: the attribute list and buffer are live copies of the sizes
    // given, or FAULT.
    let n = check(unsafe { libc::getattrlistbulk(h, al.ptr(), ptr, len, options) })?;
    let mut used = 0usize;
    for _ in 0..n {
        let Some(rec) = out.get(used..used + 4) else {
            break;
        };
        let l = u32::from_le_bytes(rec.try_into().expect("4 bytes")) as usize;
        if l == 0 {
            break;
        }
        used = (used + l).min(len);
    }
    ctx.write(buf, &out[..used])?;
    Ok(Rv::one(n as u64))
}

/// The attribute buffer a set call gives the host: the guest's, or (when
/// too large to be read, or unreadable) the fault address.
fn attr_buffer(ctx: &Ctx<'_>, buf: u64, size: u64) -> In {
    if size > ATTR_MAX_BUFFER {
        return In(None);
    }
    In::read(ctx, buf, size as usize)
}

/// `setattrlist(path, alist, attributeBuffer, bufferSize, options)`.
pub fn setattrlist(
    ctx: &mut Ctx<'_>,
    path: u64,
    alist: u64,
    buf: u64,
    size: u64,
    options: u64,
) -> SysResult {
    let p = PathArg::read(ctx, path)?;
    let al = In::read(ctx, alist, ATTRLIST);
    let ab = attr_buffer(ctx, buf, size);
    // SAFETY: the path is NUL-terminated or FAULT; the list and buffer
    // are live copies of the sizes given, or FAULT.
    check(unsafe {
        libc::setattrlist(p.ptr(), al.ptr(), ab.ptr(), size as usize, options as u32)
    })?;
    Ok(Rv::one(0))
}

/// `setattrlistat(dirfd, path, alist, attributeBuffer, bufferSize,
/// options)`.
pub fn setattrlistat(
    ctx: &mut Ctx<'_>,
    fd: i32,
    path: u64,
    alist: u64,
    buf: u64,
    size: u64,
    options: u32,
) -> SysResult {
    let hd = dirfd(ctx, fd)?;
    let p = PathArg::read(ctx, path)?;
    let al = In::read(ctx, alist, ATTRLIST);
    let ab = attr_buffer(ctx, buf, size);
    // SAFETY: as for setattrlist, with a live directory descriptor.
    check(unsafe { libc::setattrlistat(hd, p.ptr(), al.ptr(), ab.ptr(), size as usize, options) })?;
    Ok(Rv::one(0))
}

/// `fsetattrlist(fd, alist, attributeBuffer, bufferSize, options)`.
pub fn fsetattrlist(
    ctx: &mut Ctx<'_>,
    fd: i32,
    alist: u64,
    buf: u64,
    size: u64,
    options: u64,
) -> SysResult {
    let h = fd_host(ctx, fd)?;
    let al = In::read(ctx, alist, ATTRLIST);
    let ab = attr_buffer(ctx, buf, size);
    // SAFETY: the list and buffer are live copies of the sizes given, or
    // FAULT; the descriptor is live.
    check(unsafe { libc::fsetattrlist(h, al.ptr(), ab.ptr(), size as usize, options as u32) })?;
    Ok(Rv::one(0))
}

/// `clonefileat(src_dirfd, src, dst_dirfd, dst, flags)`: a copy-on-write
/// clone of a file (or directory tree).
pub fn clonefileat(
    ctx: &mut Ctx<'_>,
    src_dirfd: i32,
    src: u64,
    dst_dirfd: i32,
    dst: u64,
    flags: u32,
) -> SysResult {
    let sd = dirfd(ctx, src_dirfd)?;
    let dd = dirfd(ctx, dst_dirfd)?;
    let s = PathArg::read(ctx, src)?;
    let d = PathArg::read(ctx, dst)?;
    // SAFETY: the paths are NUL-terminated or FAULT; the descriptors live.
    check(unsafe { libc::clonefileat(sd, s.ptr(), dd, d.ptr(), flags) })?;
    Ok(Rv::one(0))
}

/// `fclonefileat(src_fd, dst_dirfd, dst, flags)`.
pub fn fclonefileat(
    ctx: &mut Ctx<'_>,
    src_fd: i32,
    dst_dirfd: i32,
    dst: u64,
    flags: u32,
) -> SysResult {
    let h = fd_host(ctx, src_fd)?;
    let dd = dirfd(ctx, dst_dirfd)?;
    let d = PathArg::read(ctx, dst)?;
    // SAFETY: the path is NUL-terminated or FAULT; the descriptors live.
    check(unsafe { libc::fclonefileat(h, dd, d.ptr(), flags) })?;
    Ok(Rv::one(0))
}

/// `exchangedata(path1, path2, options)`: two files swap contents.
pub fn exchangedata(ctx: &mut Ctx<'_>, path1: u64, path2: u64, options: u32) -> SysResult {
    let a = PathArg::read(ctx, path1)?;
    let b = PathArg::read(ctx, path2)?;
    // SAFETY: the paths are NUL-terminated or FAULT.
    check(unsafe { libc::syscall(SYS_EXCHANGEDATA, a.ptr(), b.ptr(), options) })?;
    Ok(Rv::one(0))
}

/// `access_extended(entries, size, results, uid)`: access checks for a
/// table of descriptors and the names after them (at most
/// `ACCESSX_MAX_TABLESIZE` bytes, `ENOMEM` beyond; `EINVAL` for less than
/// one descriptor); one result per descriptor the table holds (the first
/// name's offset ends the table), written after the checks.
pub fn access_extended(
    ctx: &mut Ctx<'_>,
    entries: u64,
    size: u64,
    results: u64,
    uid: u32,
) -> SysResult {
    let table = if size <= ACCESSX_MAX_TABLESIZE {
        In::read(ctx, entries, size as usize)
    } else {
        In(None)
    };
    let max = (size.saturating_sub(2) as usize / ACCESSX_DESC).min(ACCESSX_MAX_TABLESIZE as usize);
    let mut count = max;
    if let Some(t) = &table.0 {
        for i in 0..max {
            if i >= count {
                break;
            }
            let off = u32::from_le_bytes(
                t[i * ACCESSX_DESC..i * ACCESSX_DESC + 4]
                    .try_into()
                    .expect("4 bytes"),
            );
            let j = off as usize / ACCESSX_DESC;
            if j != 0 && j < count {
                count = j;
            }
        }
    }
    let mut out = vec![0i32; max.max(1)];
    let ptr = if writable(ctx, results, (count * 4) as u64) {
        out.as_mut_ptr() as usize
    } else {
        FAULT
    };
    // SAFETY: the table is a live copy of `size` bytes or FAULT; the
    // results have room for every descriptor the table can hold.
    check(unsafe { libc::syscall(SYS_ACCESS_EXTENDED, table.ptr(), size as usize, ptr, uid) })?;
    let bytes: Vec<u8> = out[..count.min(out.len())]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    ctx.write(results, &bytes)?;
    Ok(Rv::one(0))
}
