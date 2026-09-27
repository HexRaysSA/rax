//! Extended attributes (`getxattr`, `setxattr`, `removexattr`,
//! `listxattr` and their descriptor forms in `bsd/vfs/vfs_syscalls.c`).
//!
//! The attributes are the host file system's: the host checks the names,
//! the flags, the protected `com.apple.system.` names, and the file. What
//! is the guest's is its memory, so each call copies its path, name, and
//! value in XNU's order around the host's work: an option the call does
//! not take fails first (`EINVAL`), a path is looked up before
//! `getxattr`'s and `listxattr`'s name or buffer is touched, and
//! `setxattr` and `removexattr` read the name (and check its protection
//! and the value's size) before the path.

use std::ffi::CString;

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::host::{self, check_size};
use crate::user::darwin::syscall::Ctx;

/// `XATTR_*` options (`bsd/sys/xattr.h`).
pub mod opt {
    pub const NOFOLLOW: u32 = 0x0001;
    pub const NOSECURITY: u32 = 0x0008;
    pub const NODEFAULT: u32 = 0x0010;
    pub const NOFOLLOW_ANY: u32 = 0x0040;
    pub const RESOLVE_BENEATH: u32 = 0x0080;
}

/// `XATTR_MAXNAMELEN`.
const XATTR_MAXNAMELEN: usize = 127;

/// `XATTR_MAXSIZE` (`INT32_MAX`).
const XATTR_MAXSIZE: u64 = i32::MAX as u64;

/// Options no path call takes.
const PATH_REFUSED: u32 = opt::NOSECURITY | opt::NODEFAULT;

/// Options no descriptor call takes (they name path lookups).
const FD_REFUSED: u32 =
    opt::NOFOLLOW | opt::NOSECURITY | opt::NODEFAULT | opt::NOFOLLOW_ANY | opt::RESOLVE_BENEATH;

/// `xattr_protected`.
fn protected(name: &[u8]) -> bool {
    name.starts_with(b"com.apple.system.")
}

/// An attribute name (`copyinstr` of `XATTR_MAXNAMELEN + 1` bytes).
fn attr_name(ctx: &Ctx<'_>, addr: u64) -> Result<CString, Errno> {
    let name = ctx.cstr(addr, XATTR_MAXNAMELEN + 1)?;
    CString::new(name).map_err(|_| Errno::EINVAL)
}

/// A path argument, with the host path.
fn path_arg(ctx: &Ctx<'_>, addr: u64) -> Result<CString, Errno> {
    let p = ctx.path(addr)?;
    host::path(&ctx.proc.vfs, &p)
}

/// `namei`'s result for `path`, for an error that must follow the lookup.
fn lookup(path: &CString, options: u32) -> Result<(), Errno> {
    let flags = if options & opt::NOFOLLOW != 0 {
        libc::AT_SYMLINK_NOFOLLOW
    } else {
        0
    };
    host::fstatat(libc::AT_FDCWD, path, flags).map(|_| ())
}

/// The host descriptor for `fd` (`file_vnode`: `EBADF`, and `EINVAL`
/// for what the host does not hold).
fn host_fd(ctx: &Ctx<'_>, fd: i32) -> Result<i32, Errno> {
    ctx.proc.fds.file(fd)?.host_fd().ok_or(Errno::EINVAL)
}

/// The attribute's target on the host.
#[derive(Clone, Copy)]
enum Target<'a> {
    Path(&'a CString),
    Fd(i32),
}

/// The host's `getxattr`/`fgetxattr` into `buf` (a size query when `None`).
#[cfg(target_os = "macos")]
fn host_get(
    t: Target<'_>,
    name: &CString,
    buf: Option<&mut [u8]>,
    position: u32,
    options: u32,
) -> Result<usize, Errno> {
    let (ptr, len) = match buf {
        Some(b) => (b.as_mut_ptr().cast(), b.len()),
        None => (std::ptr::null_mut(), 0),
    };
    let opts = options as libc::c_int;
    // SAFETY: `ptr` is NULL or valid for `len` writable bytes; `name`
    // and the path are NUL-terminated.
    check_size(unsafe {
        match t {
            Target::Path(p) => libc::getxattr(p.as_ptr(), name.as_ptr(), ptr, len, position, opts),
            Target::Fd(fd) => libc::fgetxattr(fd, name.as_ptr(), ptr, len, position, opts),
        }
    })
}

/// The host's `listxattr`/`flistxattr` into `buf` (a size query when
/// `None`).
#[cfg(target_os = "macos")]
fn host_list(t: Target<'_>, buf: Option<&mut [u8]>, options: u32) -> Result<usize, Errno> {
    let (ptr, len) = match buf {
        Some(b) => (b.as_mut_ptr().cast(), b.len()),
        None => (std::ptr::null_mut(), 0),
    };
    let opts = options as libc::c_int;
    // SAFETY: `ptr` is NULL or valid for `len` writable bytes; the path
    // is NUL-terminated.
    check_size(unsafe {
        match t {
            Target::Path(p) => libc::listxattr(p.as_ptr(), ptr, len, opts),
            Target::Fd(fd) => libc::flistxattr(fd, ptr, len, opts),
        }
    })
}

/// Reads an attribute (or the list of names, `name` being `None`) into
/// the guest's `value`, at most `size` bytes of it, returning the bytes
/// copied; or, for a `query`, the length. The host buffer is no larger
/// than what there is to read (and empty, but not absent, for a size of
/// 0: too small for a non-empty attribute).
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
fn read_into(
    ctx: &Ctx<'_>,
    t: Target<'_>,
    name: Option<&CString>,
    query: bool,
    value: u64,
    size: u64,
    position: u32,
    options: u32,
) -> SysResult {
    let read = |buf: Option<&mut [u8]>| match name {
        Some(n) => host_get(t, n, buf, position, options),
        None => host_list(t, buf, options),
    };
    let whole = read(None)?;
    if query {
        return Ok(Rv::one(whole as u64));
    }
    let size = size.min(XATTR_MAXSIZE) as usize;
    let mut buf = vec![0u8; size.min(whole)];
    let n = read(Some(&mut buf))?;
    ctx.write(value, &buf[..n])?;
    Ok(Rv::one(n as u64))
}

/// `getxattr(path, name, value, size, position, options)`.
#[cfg(target_os = "macos")]
pub fn getxattr(
    ctx: &mut Ctx<'_>,
    path: u64,
    name: u64,
    value: u64,
    size: u64,
    position: u32,
    options: u32,
) -> SysResult {
    if options & PATH_REFUSED != 0 {
        return Err(Errno::EINVAL);
    }
    let path = path_arg(ctx, path)?;
    let name = match attr_name(ctx, name) {
        Ok(n) => n,
        Err(e) => return Err(lookup(&path, options).err().unwrap_or(e)),
    };
    let query = value == 0 || size == u64::MAX || size == u64::from(u32::MAX);
    read_into(
        ctx,
        Target::Path(&path),
        Some(&name),
        query,
        value,
        size,
        position,
        options,
    )
}

/// `fgetxattr(fd, name, value, size, position, options)`.
#[cfg(target_os = "macos")]
pub fn fgetxattr(
    ctx: &mut Ctx<'_>,
    fd: i32,
    name: u64,
    value: u64,
    size: u64,
    position: u32,
    options: u32,
) -> SysResult {
    if options & FD_REFUSED != 0 {
        return Err(Errno::EINVAL);
    }
    let h = host_fd(ctx, fd)?;
    let name = attr_name(ctx, name)?;
    // A NULL value or a size of 0 asks for the length.
    let query = value == 0 || size == 0;
    read_into(
        ctx,
        Target::Fd(h),
        Some(&name),
        query,
        value,
        size,
        position,
        options,
    )
}

/// The checks `setxattr` and `fsetxattr` make of the name and value
/// before the file: protection (`EPERM`), a value without a buffer
/// (`EINVAL`), and a size over `INT_MAX` (`E2BIG`).
fn set_checks(name: &CString, value: u64, size: u64) -> Result<(), Errno> {
    if protected(name.as_bytes()) {
        return Err(Errno::EPERM);
    }
    if size != 0 && value == 0 {
        return Err(Errno::EINVAL);
    }
    if size > i32::MAX as u64 {
        return Err(Errno::E2BIG);
    }
    Ok(())
}

/// The host's `setxattr`/`fsetxattr`.
#[cfg(target_os = "macos")]
fn host_set(t: Target<'_>, name: &CString, data: &[u8], position: u32, options: u32) -> SysResult {
    let opts = options as libc::c_int;
    // SAFETY: `data` is valid for its length; `name` and the path are
    // NUL-terminated.
    let r = unsafe {
        match t {
            Target::Path(p) => libc::setxattr(
                p.as_ptr(),
                name.as_ptr(),
                data.as_ptr().cast(),
                data.len(),
                position,
                opts,
            ),
            Target::Fd(fd) => libc::fsetxattr(
                fd,
                name.as_ptr(),
                data.as_ptr().cast(),
                data.len(),
                position,
                opts,
            ),
        }
    };
    host::check(r)?;
    Ok(Rv::one(0))
}

/// `setxattr(path, name, value, size, position, options)`.
#[cfg(target_os = "macos")]
pub fn setxattr(
    ctx: &mut Ctx<'_>,
    path: u64,
    name: u64,
    value: u64,
    size: u64,
    position: u32,
    options: u32,
) -> SysResult {
    if options & PATH_REFUSED != 0 {
        return Err(Errno::EINVAL);
    }
    let name = attr_name(ctx, name)?;
    set_checks(&name, value, size)?;
    let path = path_arg(ctx, path)?;
    let data = match ctx.read(value, size as usize) {
        Ok(d) => d,
        Err(e) => return Err(lookup(&path, options).err().unwrap_or(e)),
    };
    host_set(Target::Path(&path), &name, &data, position, options)
}

/// `fsetxattr(fd, name, value, size, position, options)`.
#[cfg(target_os = "macos")]
pub fn fsetxattr(
    ctx: &mut Ctx<'_>,
    fd: i32,
    name: u64,
    value: u64,
    size: u64,
    position: u32,
    options: u32,
) -> SysResult {
    if options & FD_REFUSED != 0 {
        return Err(Errno::EINVAL);
    }
    let name = attr_name(ctx, name)?;
    set_checks(&name, value, size)?;
    let h = host_fd(ctx, fd)?;
    let data = ctx.read(value, size as usize)?;
    host_set(Target::Fd(h), &name, &data, position, options)
}

/// `removexattr(path, name, options)`.
#[cfg(target_os = "macos")]
pub fn removexattr(ctx: &mut Ctx<'_>, path: u64, name: u64, options: u32) -> SysResult {
    if options & PATH_REFUSED != 0 {
        return Err(Errno::EINVAL);
    }
    let name = attr_name(ctx, name)?;
    if protected(name.as_bytes()) {
        return Err(Errno::EPERM);
    }
    let path = path_arg(ctx, path)?;
    // SAFETY: both strings are NUL-terminated.
    host::check(unsafe {
        libc::removexattr(path.as_ptr(), name.as_ptr(), options as libc::c_int)
    })?;
    Ok(Rv::one(0))
}

/// `fremovexattr(fd, name, options)`.
#[cfg(target_os = "macos")]
pub fn fremovexattr(ctx: &mut Ctx<'_>, fd: i32, name: u64, options: u32) -> SysResult {
    if options & FD_REFUSED != 0 {
        return Err(Errno::EINVAL);
    }
    let name = attr_name(ctx, name)?;
    if protected(name.as_bytes()) {
        return Err(Errno::EPERM);
    }
    let h = host_fd(ctx, fd)?;
    // SAFETY: `name` is NUL-terminated.
    host::check(unsafe { libc::fremovexattr(h, name.as_ptr(), options as libc::c_int) })?;
    Ok(Rv::one(0))
}

/// `listxattr(path, namebuf, size, options)`.
#[cfg(target_os = "macos")]
pub fn listxattr(ctx: &mut Ctx<'_>, path: u64, buf: u64, size: u64, options: u32) -> SysResult {
    if options & PATH_REFUSED != 0 {
        return Err(Errno::EINVAL);
    }
    let path = path_arg(ctx, path)?;
    let query = buf == 0 || size == 0;
    read_into(ctx, Target::Path(&path), None, query, buf, size, 0, options)
}

/// `flistxattr(fd, namebuf, size, options)`.
#[cfg(target_os = "macos")]
pub fn flistxattr(ctx: &mut Ctx<'_>, fd: i32, buf: u64, size: u64, options: u32) -> SysResult {
    if options & FD_REFUSED != 0 {
        return Err(Errno::EINVAL);
    }
    let h = host_fd(ctx, fd)?;
    let query = buf == 0 || size == 0;
    read_into(ctx, Target::Fd(h), None, query, buf, size, 0, options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_checks_follow_xnu_order() {
        let name = |s: &str| CString::new(s).unwrap();
        assert_eq!(
            set_checks(&name("com.apple.system.x"), 0, 4),
            Err(Errno::EPERM)
        );
        assert_eq!(set_checks(&name("user.x"), 0, 4), Err(Errno::EINVAL));
        assert_eq!(
            set_checks(&name("user.x"), 0x1000, 1 << 31),
            Err(Errno::E2BIG)
        );
        assert_eq!(set_checks(&name("user.x"), 0, 0), Ok(()));
        assert!(protected(b"com.apple.system.Security"));
        assert!(!protected(b"com.apple.FinderInfo"));
    }
}
