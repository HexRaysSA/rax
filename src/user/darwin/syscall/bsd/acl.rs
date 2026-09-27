//! Extended security (access control lists): the `*_extended` calls of
//! `bsd/vfs/vfs_syscalls.c` and `bsd/kern/kern_descrip.c`, which libSystem's
//! `statx_np`, `chmodx_np`, `openx_np`, `mkdirx_np`, and `mkfifox_np` make.
//!
//! The lists are the host file system's, so each call is the host's with
//! the guest's memory copied in XNU's order: a list to set is copied in
//! (`kauth_copyinfilesec`: its header, `EINVAL` for a bad magic number or
//! more than 128 entries, then its entries) before the file is looked up;
//! a list asked for is copied out after the status, its size written back
//! whether or not the caller's buffer holds it.

use std::ffi::CString;

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::fd::{FileKind, OpenFile};
use crate::user::darwin::host;
use crate::user::darwin::io::O_CLOEXEC;
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::syscall::bsd::path::put_stat;

/// `KAUTH_FILESEC_MAGIC`.
const FILESEC_MAGIC: u32 = 0x012c_c16d;
/// `KAUTH_FILESEC_NOACL`: a filesec without a list.
const FILESEC_NOACL: u32 = u32::MAX;
/// `KAUTH_ACL_MAX_ENTRIES`.
const ACL_MAX_ENTRIES: u32 = 128;
/// `KAUTH_FILESEC_SIZE(0)`: magic, owner and group GUIDs, entry count,
/// flags.
const FILESEC_HEADER: usize = 44;
/// `sizeof(struct kauth_ace)`.
const ACE_SIZE: usize = 24;
/// The largest filesec (`KAUTH_FILESEC_SIZE(KAUTH_ACL_MAX_ENTRIES)`).
const FILESEC_MAX: usize = FILESEC_HEADER + ACE_SIZE * ACL_MAX_ENTRIES as usize;

/// Host system-call numbers (the guest's).
mod sys {
    pub const OPEN_EXTENDED: i32 = 277;
    pub const CHMOD_EXTENDED: i32 = 282;
    pub const FCHMOD_EXTENDED: i32 = 283;
    pub const MKFIFO_EXTENDED: i32 = 291;
    pub const MKDIR_EXTENDED: i32 = 292;
    pub const STAT64_EXTENDED: i32 = 341;
    pub const LSTAT64_EXTENDED: i32 = 342;
    pub const FSTAT64_EXTENDED: i32 = 343;
}

/// What an `xsecurity` argument asks for.
enum Filesec {
    /// `USER_ADDR_NULL`: no change.
    Unchanged,
    /// `_FILESEC_REMOVE_ACL` (1): remove the list.
    Remove,
    /// A filesec to set.
    Set(Vec<u8>),
}

impl Filesec {
    /// The host argument (a pointer into `self`, or the special value).
    fn host_ptr(&self) -> usize {
        match self {
            Filesec::Unchanged => 0,
            Filesec::Remove => 1,
            Filesec::Set(b) => b.as_ptr() as usize,
        }
    }
}

/// `kauth_copyinfilesec` (with `chmod_extended_init`'s special values).
fn copyin_filesec(ctx: &Ctx<'_>, addr: u64) -> Result<Filesec, Errno> {
    match addr {
        0 => return Ok(Filesec::Unchanged),
        1 => return Ok(Filesec::Remove),
        _ => {}
    }
    let mut buf = ctx.read(addr, FILESEC_HEADER)?;
    let word = |o: usize| u32::from_le_bytes(buf[o..o + 4].try_into().expect("4 bytes"));
    if word(0) != FILESEC_MAGIC {
        return Err(Errno::EINVAL);
    }
    let count = match word(36) {
        FILESEC_NOACL => 0,
        n if n > ACL_MAX_ENTRIES => return Err(Errno::EINVAL),
        n => n as usize,
    };
    if count > 0 {
        let aces = ctx.read(addr + FILESEC_HEADER as u64, count * ACE_SIZE)?;
        buf.extend_from_slice(&aces);
    }
    Ok(Filesec::Set(buf))
}

/// A path argument's host path.
fn path_arg(ctx: &Ctx<'_>, addr: u64) -> Result<(Vec<u8>, CString), Errno> {
    let p = ctx.path(addr)?;
    let c = host::path(&ctx.proc.vfs, &p)?;
    Ok((p, c))
}

/// A host call's result.
fn host_result(r: libc::c_int) -> Result<libc::c_int, Errno> {
    if r < 0 { Err(Errno::last()) } else { Ok(r) }
}

/// `stat64_extended`, `lstat64_extended`, `fstat64_extended`: the
/// status, then (when `xsecurity` is given) the list's size at
/// `xsecurity_size` and the list itself if the buffer there holds it.
fn stat_extended(
    ctx: &mut Ctx<'_>,
    call: i32,
    target: usize,
    ub: u64,
    xsecurity: u64,
    xsecurity_size: u64,
) -> SysResult {
    // SAFETY: an all-zero stat is valid to overwrite.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut sec = vec![0u8; FILESEC_MAX];
    // The caller's buffer size decides whether the host copies the list;
    // an unreadable size is found only after the status, as XNU does.
    let bufsize = if xsecurity != 0 {
        ctx.read_u64(xsecurity_size).unwrap_or(0)
    } else {
        0
    };
    let mut size: u64 = bufsize.min(FILESEC_MAX as u64);
    let (xs, xss) = if xsecurity != 0 {
        (sec.as_mut_ptr() as usize, &raw mut size as usize)
    } else {
        (0, 0)
    };
    // SAFETY: `target` is a NUL-terminated path or a descriptor as the
    // call takes; `st`, `sec` (FILESEC_MAX bytes, `size` of them offered)
    // and `size` are valid for the host to write.
    host_result(unsafe { libc::syscall(call, target, &raw mut st, xs, xss) })?;
    put_stat(ctx, ub, &st)?;
    if xsecurity != 0 {
        ctx.write_u64(xsecurity_size, size)?;
        if bufsize >= size && size > 0 {
            ctx.write(xsecurity, &sec[..size as usize])?;
        }
    }
    Ok(Rv::one(0))
}

/// `stat64_extended(path, ub, xsecurity, xsecurity_size)` (`lstat` when
/// `follow` is false).
pub fn stat64_extended(
    ctx: &mut Ctx<'_>,
    follow: bool,
    path: u64,
    ub: u64,
    xsecurity: u64,
    xsecurity_size: u64,
) -> SysResult {
    let (_, cpath) = path_arg(ctx, path)?;
    let call = if follow {
        sys::STAT64_EXTENDED
    } else {
        sys::LSTAT64_EXTENDED
    };
    stat_extended(
        ctx,
        call,
        cpath.as_ptr() as usize,
        ub,
        xsecurity,
        xsecurity_size,
    )
}

/// `fstat64_extended(fd, ub, xsecurity, xsecurity_size)`.
pub fn fstat64_extended(
    ctx: &mut Ctx<'_>,
    fd: i32,
    ub: u64,
    xsecurity: u64,
    xsecurity_size: u64,
) -> SysResult {
    let h = ctx.proc.fds.file(fd)?.host_fd().ok_or(Errno::EBADF)?;
    stat_extended(
        ctx,
        sys::FSTAT64_EXTENDED,
        h as usize,
        ub,
        xsecurity,
        xsecurity_size,
    )
}

/// `chmod_extended(path, uid, gid, mode, xsecurity)`.
pub fn chmod_extended(
    ctx: &mut Ctx<'_>,
    path: u64,
    uid: u32,
    gid: u32,
    mode: i32,
    xsecurity: u64,
) -> SysResult {
    let sec = copyin_filesec(ctx, xsecurity)?;
    let (_, cpath) = path_arg(ctx, path)?;
    // SAFETY: `cpath` is NUL-terminated; the filesec is valid for its
    // size or a special value.
    host_result(unsafe {
        libc::syscall(
            sys::CHMOD_EXTENDED,
            cpath.as_ptr(),
            uid,
            gid,
            mode,
            sec.host_ptr(),
        )
    })?;
    Ok(Rv::one(0))
}

/// `fchmod_extended(fd, uid, gid, mode, xsecurity)`.
pub fn fchmod_extended(
    ctx: &mut Ctx<'_>,
    fd: i32,
    uid: u32,
    gid: u32,
    mode: i32,
    xsecurity: u64,
) -> SysResult {
    let sec = copyin_filesec(ctx, xsecurity)?;
    let h = ctx.proc.fds.file(fd)?.host_fd().ok_or(Errno::EINVAL)?;
    // SAFETY: the filesec is valid for its size or a special value.
    host_result(unsafe { libc::syscall(sys::FCHMOD_EXTENDED, h, uid, gid, mode, sec.host_ptr()) })?;
    Ok(Rv::one(0))
}

/// `mkdir_extended` and `mkfifo_extended(path, uid, gid, mode,
/// xsecurity)`.
pub fn mknode_extended(
    ctx: &mut Ctx<'_>,
    fifo: bool,
    path: u64,
    uid: u32,
    gid: u32,
    mode: i32,
    xsecurity: u64,
) -> SysResult {
    let sec = copyin_filesec(ctx, xsecurity)?;
    let (_, cpath) = path_arg(ctx, path)?;
    let call = if fifo {
        sys::MKFIFO_EXTENDED
    } else {
        sys::MKDIR_EXTENDED
    };
    // SAFETY: `cpath` is NUL-terminated; the filesec is valid for its
    // size or a special value.
    host_result(unsafe { libc::syscall(call, cpath.as_ptr(), uid, gid, mode, sec.host_ptr()) })?;
    Ok(Rv::one(0))
}

/// `open_extended(path, flags, uid, gid, mode, xsecurity)`: `open` with
/// an owner and list for a file it creates.
pub fn open_extended(
    ctx: &mut Ctx<'_>,
    path: u64,
    flags: u32,
    uid: u32,
    gid: u32,
    mode: i32,
    xsecurity: u64,
) -> SysResult {
    let sec = copyin_filesec(ctx, xsecurity)?;
    let (guest, cpath) = path_arg(ctx, path)?;
    let hflags = host::open_flags(flags) | libc::O_CLOEXEC;
    // SAFETY: `cpath` is NUL-terminated; the filesec is valid for its
    // size or a special value.
    let fd = host_result(unsafe {
        libc::syscall(
            sys::OPEN_EXTENDED,
            cpath.as_ptr(),
            hflags,
            uid,
            gid,
            mode,
            sec.host_ptr(),
        )
    })? as i32;
    // SAFETY: `fd` was just returned by the host and is owned here.
    let owned = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    let full = if guest.first() == Some(&b'/') {
        guest
    } else {
        let mut p = ctx.proc.cwd.clone();
        p.push(b'/');
        p.extend_from_slice(&guest);
        p
    };
    let file = std::sync::Arc::new(OpenFile {
        kind: FileKind::Host(owned),
        path: Some(super::path::normalize(&full)),
        flags: std::sync::Mutex::new(flags & !O_CLOEXEC),
    });
    let limit = ctx.proc.rlimits[8].0;
    let n = ctx
        .proc
        .fds
        .install(file, flags & O_CLOEXEC != 0, 0, limit)?;
    Ok(Rv::one(n as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filesec_sizes() {
        assert_eq!(FILESEC_HEADER + ACE_SIZE, 68);
        assert_eq!(FILESEC_MAX, 44 + 24 * 128);
        assert_eq!(Filesec::Unchanged.host_ptr(), 0);
        assert_eq!(Filesec::Remove.host_ptr(), 1);
    }
}
