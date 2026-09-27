//! Calls that take paths: opening, metadata, links, directories, and the
//! working directory.
//!
//! Each call reads its path arguments from the guest (`copyinstr`, so a
//! path of `MAXPATHLEN` bytes or more is `ENAMETOOLONG` and an unreadable
//! one `EFAULT`), resolves them through the root overlay, and performs the
//! host's own call.

use std::ffi::CString;
use std::sync::Arc;

use crate::user::darwin::abi::Errno;
use crate::user::darwin::abi::types::Stat;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::fd::OpenFile;
use crate::user::darwin::host::{self, AT_FDCWD, AT_SYMLINK_NOFOLLOW, check};
use crate::user::darwin::io::O_CLOEXEC;
#[cfg(not(target_os = "macos"))]
use crate::user::darwin::io::{O_EXLOCK, O_SHLOCK};
use crate::user::darwin::syscall::Ctx;

fn guest_path(ctx: &Ctx<'_>, addr: u64) -> Result<(Vec<u8>, CString), Errno> {
    let p = ctx.path(addr)?;
    let c = host::path(&ctx.proc.vfs, &p)?;
    Ok((p, c))
}

fn nofile(ctx: &Ctx<'_>) -> u64 {
    ctx.proc.rlimits[8].0
}

/// `openat(fd, path, flags, mode)` (`open` with `AT_FDCWD`).
pub fn openat(ctx: &mut Ctx<'_>, dirfd: i32, path: u64, flags: u32, mode: u32) -> SysResult {
    let (guest, cpath) = guest_path(ctx, path)?;
    let hdir = host::dirfd(&ctx.proc.fds, dirfd)?;
    // Descriptors are opened close-on-exec on the host: a guest exec never
    // executes a host program, and the guest's own flag is kept per slot.
    let hflags = host::open_flags(flags) | libc::O_CLOEXEC;
    // SAFETY: `cpath` is NUL-terminated for the call's duration.
    let fd = check(unsafe { libc::openat(hdir, cpath.as_ptr(), hflags, mode as libc::c_uint) })?;
    // SAFETY: `fd` was just returned by the host and is owned here.
    let owned = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    #[cfg(not(target_os = "macos"))]
    if flags & (O_SHLOCK | O_EXLOCK) != 0 {
        let op = if flags & O_EXLOCK != 0 {
            libc::LOCK_EX
        } else {
            libc::LOCK_SH
        } | if flags & crate::user::darwin::io::O_NONBLOCK != 0 {
            libc::LOCK_NB
        } else {
            0
        };
        // SAFETY: flock on the descriptor just opened.
        check(unsafe { libc::flock(fd, op) })?;
    }
    let full = absolute(ctx, dirfd, &guest);
    let file = Arc::new(OpenFile::host(owned, flags & !O_CLOEXEC, Some(full)));
    let limit = nofile(ctx);
    let n = ctx
        .proc
        .fds
        .install(file, flags & O_CLOEXEC != 0, 0, limit)?;
    Ok(Rv::one(n as u64))
}

/// The absolute guest path of `path` relative to `dirfd`, for `F_GETPATH`.
fn absolute(ctx: &Ctx<'_>, dirfd: i32, path: &[u8]) -> Vec<u8> {
    if path.first() == Some(&b'/') {
        return path.to_vec();
    }
    let base = if dirfd == AT_FDCWD {
        ctx.proc.cwd.clone()
    } else {
        ctx.proc
            .fds
            .file(dirfd)
            .ok()
            .and_then(|f| f.path.clone())
            .unwrap_or_else(|| ctx.proc.cwd.clone())
    };
    let mut p = base;
    if p.last() != Some(&b'/') {
        p.push(b'/');
    }
    p.extend_from_slice(path);
    p
}

/// Writes a host `stat` to the guest as `struct stat64`.
pub fn put_stat(ctx: &Ctx<'_>, buf: u64, st: &libc::stat) -> SysResult {
    ctx.write(buf, &Stat::from_host(st).bytes())?;
    Ok(Rv::one(0))
}

/// `fstatat64(fd, path, buf, flag)` (`stat64`/`lstat64` with `AT_FDCWD`).
pub fn fstatat64(ctx: &mut Ctx<'_>, dirfd: i32, path: u64, buf: u64, flag: u32) -> SysResult {
    let (_, cpath) = guest_path(ctx, path)?;
    let hdir = host::dirfd(&ctx.proc.fds, dirfd)?;
    let st = host::fstatat(hdir, &cpath, host::at_flags(flag)?)?;
    put_stat(ctx, buf, &st)
}

/// `stat64(path, buf)`.
pub fn stat64(ctx: &mut Ctx<'_>, path: u64, buf: u64) -> SysResult {
    fstatat64(ctx, AT_FDCWD, path, buf, 0)
}

/// `lstat64(path, buf)`.
pub fn lstat64(ctx: &mut Ctx<'_>, path: u64, buf: u64) -> SysResult {
    fstatat64(ctx, AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW)
}

/// `faccessat(fd, path, amode, flag)` (`access` with `AT_FDCWD`).
pub fn faccessat(ctx: &mut Ctx<'_>, dirfd: i32, path: u64, amode: i32, flag: u32) -> SysResult {
    let (_, cpath) = guest_path(ctx, path)?;
    let hdir = host::dirfd(&ctx.proc.fds, dirfd)?;
    // SAFETY: `cpath` is NUL-terminated.
    check(unsafe { libc::faccessat(hdir, cpath.as_ptr(), amode, host::at_flags(flag)?) })?;
    Ok(Rv::one(0))
}

/// `readlinkat(fd, path, buf, bufsize)` (`readlink` with `AT_FDCWD`).
pub fn readlinkat(ctx: &mut Ctx<'_>, dirfd: i32, path: u64, buf: u64, size: u64) -> SysResult {
    let (_, cpath) = guest_path(ctx, path)?;
    let hdir = host::dirfd(&ctx.proc.fds, dirfd)?;
    let mut out = vec![0u8; (size as usize).min(1 << 20)];
    // SAFETY: `out` has `out.len()` writable bytes; `cpath` is terminated.
    let n = host::check_size(unsafe {
        libc::readlinkat(hdir, cpath.as_ptr(), out.as_mut_ptr().cast(), out.len())
    })?;
    ctx.write(buf, &out[..n])?;
    Ok(Rv::one(n as u64))
}

/// `unlinkat(fd, path, flag)` (`unlink` with `AT_FDCWD`, `rmdir` with
/// `AT_REMOVEDIR`).
pub fn unlinkat(ctx: &mut Ctx<'_>, dirfd: i32, path: u64, flag: u32) -> SysResult {
    let (_, cpath) = guest_path(ctx, path)?;
    let hdir = host::dirfd(&ctx.proc.fds, dirfd)?;
    // SAFETY: `cpath` is NUL-terminated.
    check(unsafe { libc::unlinkat(hdir, cpath.as_ptr(), host::at_flags(flag)?) })?;
    Ok(Rv::one(0))
}

/// `rmdir(path)`: `unlinkat(AT_FDCWD, path, AT_REMOVEDIR)`.
pub fn rmdir(ctx: &mut Ctx<'_>, path: u64) -> SysResult {
    let (_, cpath) = guest_path(ctx, path)?;
    // SAFETY: `cpath` is NUL-terminated.
    check(unsafe { libc::rmdir(cpath.as_ptr()) })?;
    Ok(Rv::one(0))
}

/// `mkdirat(fd, path, mode)` (`mkdir` with `AT_FDCWD`).
pub fn mkdirat(ctx: &mut Ctx<'_>, dirfd: i32, path: u64, mode: u32) -> SysResult {
    let (_, cpath) = guest_path(ctx, path)?;
    let hdir = host::dirfd(&ctx.proc.fds, dirfd)?;
    // SAFETY: `cpath` is NUL-terminated.
    check(unsafe { libc::mkdirat(hdir, cpath.as_ptr(), mode as libc::mode_t) })?;
    Ok(Rv::one(0))
}

/// `renameat(fromfd, from, tofd, to)` (`rename` with `AT_FDCWD`).
pub fn renameat(ctx: &mut Ctx<'_>, fromfd: i32, from: u64, tofd: i32, to: u64) -> SysResult {
    let (_, cfrom) = guest_path(ctx, from)?;
    let (_, cto) = guest_path(ctx, to)?;
    let hf = host::dirfd(&ctx.proc.fds, fromfd)?;
    let ht = host::dirfd(&ctx.proc.fds, tofd)?;
    // SAFETY: both paths are NUL-terminated.
    check(unsafe { libc::renameat(hf, cfrom.as_ptr(), ht, cto.as_ptr()) })?;
    Ok(Rv::one(0))
}

/// `renameatx_np(fromfd, from, tofd, to, flags)`.
pub fn renameatx_np(
    ctx: &mut Ctx<'_>,
    fromfd: i32,
    from: u64,
    tofd: i32,
    to: u64,
    flags: u32,
) -> SysResult {
    if flags == 0 {
        return renameat(ctx, fromfd, from, tofd, to);
    }
    #[cfg(target_os = "macos")]
    {
        let (_, cfrom) = guest_path(ctx, from)?;
        let (_, cto) = guest_path(ctx, to)?;
        let hf = host::dirfd(&ctx.proc.fds, fromfd)?;
        let ht = host::dirfd(&ctx.proc.fds, tofd)?;
        // SAFETY: both paths are NUL-terminated.
        check(unsafe { libc::renameatx_np(hf, cfrom.as_ptr(), ht, cto.as_ptr(), flags) })?;
        Ok(Rv::one(0))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(Errno::ENOTSUP)
    }
}

/// `linkat(fd1, path1, fd2, path2, flag)` (`link` with `AT_FDCWD`).
pub fn linkat(
    ctx: &mut Ctx<'_>,
    fd1: i32,
    path1: u64,
    fd2: i32,
    path2: u64,
    flag: u32,
) -> SysResult {
    let (_, c1) = guest_path(ctx, path1)?;
    let (_, c2) = guest_path(ctx, path2)?;
    let h1 = host::dirfd(&ctx.proc.fds, fd1)?;
    let h2 = host::dirfd(&ctx.proc.fds, fd2)?;
    // SAFETY: both paths are NUL-terminated.
    check(unsafe { libc::linkat(h1, c1.as_ptr(), h2, c2.as_ptr(), host::at_flags(flag)?) })?;
    Ok(Rv::one(0))
}

/// `symlinkat(target, fd, path)` (`symlink` with `AT_FDCWD`).
pub fn symlinkat(ctx: &mut Ctx<'_>, target: u64, dirfd: i32, path: u64) -> SysResult {
    // The link's contents are not resolved: copy them as given.
    let t = ctx.path(target)?;
    let ct = CString::new(t).map_err(|_| Errno::EINVAL)?;
    let (_, cpath) = guest_path(ctx, path)?;
    let hdir = host::dirfd(&ctx.proc.fds, dirfd)?;
    // SAFETY: both strings are NUL-terminated.
    check(unsafe { libc::symlinkat(ct.as_ptr(), hdir, cpath.as_ptr()) })?;
    Ok(Rv::one(0))
}

/// `fchmodat(fd, path, mode, flag)` (`chmod` with `AT_FDCWD`).
pub fn fchmodat(ctx: &mut Ctx<'_>, dirfd: i32, path: u64, mode: u32, flag: u32) -> SysResult {
    let (_, cpath) = guest_path(ctx, path)?;
    let hdir = host::dirfd(&ctx.proc.fds, dirfd)?;
    // SAFETY: `cpath` is NUL-terminated.
    check(unsafe {
        libc::fchmodat(
            hdir,
            cpath.as_ptr(),
            mode as libc::mode_t,
            host::at_flags(flag)?,
        )
    })?;
    Ok(Rv::one(0))
}

/// `fchownat(fd, path, uid, gid, flag)` (`chown`/`lchown` with
/// `AT_FDCWD`).
pub fn fchownat(
    ctx: &mut Ctx<'_>,
    dirfd: i32,
    path: u64,
    uid: u32,
    gid: u32,
    flag: u32,
) -> SysResult {
    let (_, cpath) = guest_path(ctx, path)?;
    let hdir = host::dirfd(&ctx.proc.fds, dirfd)?;
    // SAFETY: `cpath` is NUL-terminated.
    check(unsafe { libc::fchownat(hdir, cpath.as_ptr(), uid, gid, host::at_flags(flag)?) })?;
    Ok(Rv::one(0))
}

/// `chdir(path)`: the host's working directory follows the guest's.
pub fn chdir(ctx: &mut Ctx<'_>, path: u64) -> SysResult {
    let (guest, cpath) = guest_path(ctx, path)?;
    // SAFETY: `cpath` is NUL-terminated.
    check(unsafe { libc::chdir(cpath.as_ptr()) })?;
    ctx.proc.cwd = normalize(&absolute(ctx, AT_FDCWD, &guest));
    Ok(Rv::one(0))
}

/// `fchdir(fd)`.
pub fn fchdir(ctx: &mut Ctx<'_>, fd: i32) -> SysResult {
    let file = ctx.proc.fds.file(fd)?;
    // A kqueue is not a vnode (file_vnode).
    let h = file.host_fd().ok_or(Errno::EINVAL)?;
    // SAFETY: fchdir on a live host descriptor.
    check(unsafe { libc::fchdir(h) })?;
    ctx.proc.cwd = match file.path.clone() {
        Some(p) => normalize(&p),
        None => host_cwd().unwrap_or_else(|| ctx.proc.cwd.clone()),
    };
    Ok(Rv::one(0))
}

/// The host's working directory.
pub fn host_cwd() -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStringExt;
    std::env::current_dir()
        .ok()
        .map(|p| p.into_os_string().into_vec())
}

/// Removes `.` and `..` components and duplicate slashes.
pub fn normalize(p: &[u8]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::new();
    for c in p.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    let mut out = Vec::new();
    for c in parts {
        out.push(b'/');
        out.extend_from_slice(c);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    out
}

/// `truncate(path, length)`.
pub fn truncate(ctx: &mut Ctx<'_>, path: u64, length: i64) -> SysResult {
    let (_, cpath) = guest_path(ctx, path)?;
    // SAFETY: `cpath` is NUL-terminated.
    check(unsafe { libc::truncate(cpath.as_ptr(), length as libc::off_t) })?;
    Ok(Rv::one(0))
}

/// `mkfifoat(fd, path, mode)` (`mkfifo` with `AT_FDCWD`).
pub fn mkfifoat(ctx: &mut Ctx<'_>, dirfd: i32, path: u64, mode: u32) -> SysResult {
    let (_, cpath) = guest_path(ctx, path)?;
    let hdir = host::dirfd(&ctx.proc.fds, dirfd)?;
    // SAFETY: `cpath` is NUL-terminated.
    check(unsafe { libc::mkfifoat(hdir, cpath.as_ptr(), mode as libc::mode_t) })?;
    Ok(Rv::one(0))
}

/// `utimes(path, times)`.
pub fn utimes(ctx: &mut Ctx<'_>, path: u64, times: u64) -> SysResult {
    let (_, cpath) = guest_path(ctx, path)?;
    let tv = read_timevals(ctx, times)?;
    let ptr = tv.as_ref().map_or(std::ptr::null(), |t| t.as_ptr());
    // SAFETY: `cpath` is NUL-terminated; `ptr` is null or two timevals.
    check(unsafe { libc::utimes(cpath.as_ptr(), ptr) })?;
    Ok(Rv::one(0))
}

/// Reads an optional pair of `struct timeval`s.
pub fn read_timevals(ctx: &Ctx<'_>, addr: u64) -> Result<Option<[libc::timeval; 2]>, Errno> {
    if addr == 0 {
        return Ok(None);
    }
    let b = ctx.read(addr, 32)?;
    let tv = |o: usize| {
        let t = crate::user::darwin::abi::types::Timeval::from_bytes(
            b[o..o + 16].try_into().expect("16 bytes"),
        );
        libc::timeval {
            tv_sec: t.sec as libc::time_t,
            tv_usec: t.usec as libc::suseconds_t,
        }
    };
    Ok(Some([tv(0), tv(16)]))
}

/// `pathconf(path, name)`.
pub fn pathconf(ctx: &mut Ctx<'_>, path: u64, name: i32) -> SysResult {
    let (_, cpath) = guest_path(ctx, path)?;
    host::set_errno(0);
    // SAFETY: `cpath` is NUL-terminated.
    let r = unsafe { libc::pathconf(cpath.as_ptr(), name) };
    if r < 0 {
        let e = Errno::last();
        if e.0 != 0 {
            return Err(e);
        }
    }
    Ok(Rv::one(r as u64))
}

/// `getattrlistat(fd, path, alist, buf, size, options)` and its path-only
/// and descriptor forms. The attribute buffer is self-relative, so the
/// host's answer is the guest's byte for byte.
#[cfg(target_os = "macos")]
pub fn getattrlistat(
    ctx: &mut Ctx<'_>,
    dirfd: Option<i32>,
    path: Option<u64>,
    alist: u64,
    buf: u64,
    size: u64,
    options: u64,
) -> SysResult {
    let attrs = ctx.read(alist, 24)?;
    let mut out = vec![0u8; (size as usize).min(1 << 24)];
    let r = match (dirfd, path) {
        (fd, Some(p)) => {
            let (_, cpath) = guest_path(ctx, p)?;
            let hdir = host::dirfd(&ctx.proc.fds, fd.unwrap_or(AT_FDCWD))?;
            // SAFETY: `attrs` is a 24-byte attrlist, `out` has `out.len()`
            // bytes, and `cpath` is NUL-terminated.
            unsafe {
                libc::getattrlistat(
                    hdir,
                    cpath.as_ptr(),
                    attrs.as_ptr() as *mut libc::c_void,
                    out.as_mut_ptr().cast(),
                    out.len(),
                    options as libc::c_ulong,
                )
            }
        }
        (Some(fd), None) => {
            let h = ctx.proc.fds.file(fd)?.host_fd().ok_or(Errno::EBADF)?;
            // SAFETY: as above, on a live descriptor.
            unsafe {
                libc::fgetattrlist(
                    h,
                    attrs.as_ptr() as *mut libc::c_void,
                    out.as_mut_ptr().cast(),
                    out.len(),
                    options as u32,
                )
            }
        }
        (None, None) => return Err(Errno::EINVAL),
    };
    check(r)?;
    ctx.write(buf, &out)?;
    Ok(Rv::one(0))
}

/// `fsgetpath` options (`FSOPT_NOFIRMLINKPATH`, `FSOPT_ISREALFSID`).
const FSGETPATH_OPTIONS: u32 = 0x0080 | 0x0200;

/// `MAXLONGPATHLEN`.
const MAXLONGPATHLEN: u64 = 8192;

/// `fsgetpath_ext(buf, bufsize, fsid, objid, options)` (`fsgetpath` with
/// no options): the path of the file system object `objid` on the volume
/// `fsid`, which the host names; a root overlay's prefix is removed. The
/// result is the path's length with its NUL.
pub fn fsgetpath(
    ctx: &mut Ctx<'_>,
    buf: u64,
    bufsize: u64,
    fsid: u64,
    objid: u64,
    options: u32,
) -> SysResult {
    if options & !FSGETPATH_OPTIONS != 0 {
        return Err(Errno::EINVAL);
    }
    let fsid: [u8; 8] = ctx.read(fsid, 8)?.try_into().expect("8 bytes");
    if bufsize == 0 || bufsize > MAXLONGPATHLEN {
        return Err(Errno::EINVAL);
    }
    let path = host_fsgetpath(fsid, objid, bufsize as usize, options)?;
    let path = match &ctx.proc.vfs.root {
        Some(root) => {
            use std::os::unix::ffi::OsStrExt;
            let root = root.as_os_str().as_bytes();
            match path.strip_prefix(root) {
                Some(rest) if rest.first() == Some(&b'/') => rest.to_vec(),
                _ => path,
            }
        }
        None => path,
    };
    let mut out = path;
    out.push(0);
    if out.len() as u64 > bufsize {
        return Err(Errno::ENOSPC);
    }
    ctx.write(buf, &out)?;
    Ok(Rv::one(out.len() as u64))
}

/// The host's `fsgetpath_ext`: the path without its NUL.
#[cfg(target_os = "macos")]
fn host_fsgetpath(fsid: [u8; 8], objid: u64, size: usize, options: u32) -> Result<Vec<u8>, Errno> {
    /// `SYS_fsgetpath_ext`.
    const SYS_FSGETPATH_EXT: libc::c_int = 217;
    let mut out = vec![0u8; size];
    // SAFETY: `out` has `size` writable bytes and `fsid` is the 8-byte
    // fsid_t the call reads.
    let n = unsafe {
        libc::syscall(
            SYS_FSGETPATH_EXT,
            out.as_mut_ptr(),
            size,
            fsid.as_ptr(),
            objid,
            options,
        )
    };
    if n < 0 {
        return Err(Errno::last());
    }
    let n = (n as usize).min(size);
    let end = out[..n].iter().position(|&b| b == 0).unwrap_or(n);
    out.truncate(end);
    Ok(out)
}

/// Other hosts have no volume-and-object lookup.
#[cfg(not(target_os = "macos"))]
fn host_fsgetpath(_: [u8; 8], _: u64, _: usize, _: u32) -> Result<Vec<u8>, Errno> {
    Err(Errno::ENOTSUP)
}

/// `statfs64(path, buf)`: the host's statistics of the volume holding
/// `path` (following symbolic links).
pub fn statfs64(ctx: &mut Ctx<'_>, path: u64, buf: u64) -> SysResult {
    let (_, cpath) = guest_path(ctx, path)?;
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `cpath` is NUL-terminated; statfs writes a complete
        // struct on success.
        let s = unsafe {
            let mut s: libc::statfs = std::mem::zeroed();
            check(libc::statfs(cpath.as_ptr(), &mut s))?;
            s
        };
        ctx.write(
            buf,
            &crate::user::darwin::abi::types::Statfs::from_host(&s).bytes(),
        )?;
        Ok(Rv::one(0))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (cpath, buf);
        Err(Errno::ENOSYS)
    }
}
