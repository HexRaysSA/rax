//! Unix implementation of host-backed Darwin descriptor operations.

use super::*;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

use crate::user::darwin::abi::Errno;
use crate::user::darwin::fd::FdTable;
use crate::user::darwin::vfs::Vfs;

/// A host call's result: `Err` with the translated `errno` when negative.
pub fn check(r: libc::c_int) -> Result<libc::c_int, Errno> {
    if r < 0 { Err(Errno::last()) } else { Ok(r) }
}

/// A host call's `ssize_t` result.
pub fn check_size(r: isize) -> Result<usize, Errno> {
    if r < 0 {
        Err(Errno::last())
    } else {
        Ok(r as usize)
    }
}

/// The host path for a guest path, NUL-terminated.
pub fn path(vfs: &Vfs, guest: &[u8]) -> Result<CString, Errno> {
    if vfs.is_closed() {
        return Err(Errno::EPERM);
    }
    let p = match &vfs.root {
        None => guest.to_vec(),
        Some(_) if guest.first() == Some(&b'/') => {
            vfs.host_path(guest, b"/")?.as_os_str().as_bytes().to_vec()
        }
        Some(_) => guest.to_vec(),
    };
    CString::new(p).map_err(|_| Errno::EINVAL)
}

/// The host descriptor a guest `*at` directory argument names.
pub fn dirfd(fds: &FdTable, fd: i32) -> Result<i32, Errno> {
    if fd == AT_FDCWD {
        return Ok(libc::AT_FDCWD);
    }
    fds.file(fd)?.host_fd().ok_or(Errno::ENOTDIR)
}

/// Host `AT_*` flags for Darwin `flags`; `EINVAL` for flags the host cannot
/// express.
pub fn at_flags(flags: u32) -> Result<i32, Errno> {
    #[cfg(target_os = "macos")]
    {
        Ok(flags as i32)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut h = 0;
        for (g, hf) in [
            (AT_EACCESS, libc::AT_EACCESS),
            (AT_SYMLINK_NOFOLLOW, libc::AT_SYMLINK_NOFOLLOW),
            (AT_SYMLINK_FOLLOW, libc::AT_SYMLINK_FOLLOW),
            (AT_REMOVEDIR, libc::AT_REMOVEDIR),
        ] {
            if flags & g != 0 {
                h |= hf;
            }
        }
        if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_SYMLINK_FOLLOW | AT_REMOVEDIR) != 0 {
            return Err(Errno::EINVAL);
        }
        Ok(h)
    }
}

/// The path of a host descriptor's vnode (`F_GETPATH`: symbolic links
/// resolved, as `vn_getpath` names it), where the host can say.
pub fn fd_path(fd: i32) -> Option<Vec<u8>> {
    #[cfg(target_vendor = "apple")]
    {
        let mut buf = [0u8; 1024];
        // SAFETY: F_GETPATH writes at most MAXPATHLEN (1024) bytes into
        // `buf`.
        if unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) } == 0 {
            let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            return Some(buf[..n].to_vec());
        }
    }
    let _ = fd;
    None
}

/// `fstat` on a host descriptor.
pub fn fstat(fd: i32) -> Result<libc::stat, Errno> {
    // SAFETY: fstat writes a complete struct on success; `fd` is live.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        check(libc::fstat(fd, &mut st))?;
        Ok(st)
    }
}

/// Whether this descriptor is a kernel anonymous pipe. A named FIFO remains a
/// vnode after unlink; `S_IFIFO` and path availability do not identify its type.
pub fn anonymous_pipe(fd: i32) -> bool {
    if !fstat(fd).is_ok_and(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFIFO) {
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        // PROC_PIDFDPIPEINFO (6) accepts DTYPE_PIPE and returns pipe_fdinfo
        // (184 bytes). Query only this process's already-owned descriptor.
        let mut info = [0u64; 23];
        // SAFETY: the aligned initialized buffer holds all 184 writable bytes.
        unsafe { libc::proc_pidfdinfo(libc::getpid(), fd, 6, info.as_mut_ptr().cast(), 184) == 184 }
    }
    #[cfg(target_os = "linux")]
    {
        // Anonymous Linux pipes live on PIPEFS_MAGIC; a named FIFO lives on
        // its containing filesystem, including after its pathname is removed.
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: live descriptor and a complete writable statfs output.
        if unsafe { libc::fstatfs(fd, filesystem.as_mut_ptr()) } != 0 {
            return false;
        }
        // SAFETY: successful fstatfs initialized the complete structure.
        let filesystem = unsafe { filesystem.assume_init() };
        u32::try_from(filesystem.f_type).ok() == Some(0x5049_5045)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

#[cfg(test)]
#[path = "pipe_tests.rs"]
mod pipe_tests;

/// `fstatat` on the host.
pub fn fstatat(dirfd: i32, path: &CString, flags: i32) -> Result<libc::stat, Errno> {
    // SAFETY: `path` is NUL-terminated; fstatat writes a complete struct
    // on success.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        check(libc::fstatat(dirfd, path.as_ptr(), &mut st, flags))?;
        Ok(st)
    }
}

/// Host `open` flags for the guest's, with the Darwin-only locking flags
/// applied by the caller.
pub fn open_flags(flags: u32) -> i32 {
    crate::user::darwin::io::guest_to_host_oflags(flags)
}

/// Sets the host thread's `errno` (to tell a `-1` result from an error).
pub fn set_errno(v: i32) {
    // SAFETY: the errno location is the calling thread's own int.
    unsafe {
        #[cfg(target_os = "macos")]
        {
            *libc::__error() = v;
        }
        #[cfg(target_os = "linux")]
        {
            *libc::__errno_location() = v;
        }
    }
}
