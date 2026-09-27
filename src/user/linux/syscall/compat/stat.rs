//! File status in a compatibility task's layouts: `struct compat_stat`
//! (`stat`, `lstat`, `fstat`: `cp_compat_stat`, `fs/stat.c`), `struct
//! stat64` (`stat64`, `lstat64`, `fstat64`, `fstatat64`: i386's through
//! `cp_stat64`, `arch/x86/kernel/sys_ia32.c`, ARM EABI's through
//! `cp_new_stat64`, `fs/stat.c`), `struct __old_kernel_stat` (`oldstat`,
//! `oldlstat`, `oldfstat`: `cp_old_stat`), and `struct compat_statfs` and
//! `struct compat_statfs64` (`fs/statfs.c`). Each looks the file up as the
//! native call does, then converts; a value the layout cannot hold is
//! `EOVERFLOW`.

use super::super::super::abi::LinuxAbi;
use super::super::super::abi::compat::{
    COMPAT_STATFS64_SIZE, STAT64_PADS, encode_compat_statfs, encode_compat_statfs64,
    encode_old_stat, encode_stat64, encode_stat64_eabi,
};
use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::abi::types::{Kstatfs, Stat};
use super::super::path::{self, AT_FDCWD, AT_SYMLINK_NOFOLLOW};
use super::super::{Ctx, SysResult};

/// Where a status call finds its file.
#[derive(Clone, Copy, Debug)]
pub enum Of {
    /// A path, followed to its end unless it is a link (`AT_SYMLINK_NOFOLLOW`
    /// in the flags), relative to a directory descriptor.
    Path { dirfd: i32, path: u64, flags: u32 },
    /// A descriptor.
    Fd(i32),
}

impl Of {
    /// `stat` and `stat64`'s file (`vfs_stat`).
    pub fn followed(path: u64) -> Self {
        Of::Path {
            dirfd: AT_FDCWD,
            path,
            flags: 0,
        }
    }

    /// `lstat` and `lstat64`'s file (`vfs_lstat`).
    pub fn link(path: u64) -> Self {
        Of::Path {
            dirfd: AT_FDCWD,
            path,
            flags: AT_SYMLINK_NOFOLLOW,
        }
    }

    fn stat(self, c: &mut Ctx<'_>) -> Result<Stat, Errno> {
        match self {
            Of::Path { dirfd, path, flags } => path::stat_at(c, dirfd, path, flags),
            Of::Fd(fd) => path::stat_fd(c, fd),
        }
    }
}

/// `compat_sys_newstat`, `compat_sys_newlstat`, `compat_sys_newfstat`.
pub fn stat(c: &mut Ctx<'_>, of: Of, buf: u64) -> SysResult {
    let st = of.stat(c)?;
    if st.compat_overflow() {
        return Err(Errno(EOVERFLOW));
    }
    c.write_mem(buf, &st.encode(c.p.abi))?;
    Ok(0)
}

/// `stat64`, `lstat64`, `fstat64`, and `fstatat64`. i386's `cp_stat64`
/// stores the fields one by one, so the pads keep what the buffer held;
/// ARM's `cp_new_stat64` writes the whole structure.
pub fn stat64(c: &mut Ctx<'_>, of: Of, buf: u64) -> SysResult {
    let st = of.stat(c)?;
    if c.p.abi == LinuxAbi::Arm {
        c.write_mem(buf, &encode_stat64_eabi(&st))?;
        return Ok(0);
    }
    let mut image = encode_stat64(&st);
    let old = c.read_mem(buf, image.len())?;
    for pad in STAT64_PADS {
        image[pad.clone()].copy_from_slice(&old[pad]);
    }
    c.write_mem(buf, &image)?;
    Ok(0)
}

/// `oldstat`, `oldlstat`, and `oldfstat` (`sys_stat`, `sys_lstat`,
/// `sys_fstat` with `struct __old_kernel_stat`).
pub fn old_stat(c: &mut Ctx<'_>, of: Of, buf: u64) -> SysResult {
    let st = of.stat(c)?;
    let image = encode_old_stat(&st).ok_or(Errno(EOVERFLOW))?;
    c.write_mem(buf, &image)?;
    Ok(0)
}

/// Where a file-system statistics call finds its file system.
#[derive(Clone, Copy, Debug)]
pub enum FsOf {
    /// The one holding a path (`user_statfs`).
    Path(u64),
    /// The one holding a descriptor's file (`fd_statfs`).
    Fd(i32),
}

impl FsOf {
    fn statfs(self, c: &mut Ctx<'_>) -> Result<Kstatfs, Errno> {
        match self {
            FsOf::Path(p) => path::statfs_path(c, p),
            FsOf::Fd(fd) => path::statfs_fd(c, fd),
        }
    }
}

/// `compat_sys_statfs` and `compat_sys_fstatfs`.
pub fn statfs(c: &mut Ctx<'_>, of: FsOf, buf: u64) -> SysResult {
    let k = of.statfs(c)?;
    let image = encode_compat_statfs(&k).ok_or(Errno(EOVERFLOW))?;
    c.write_mem(buf, &image)?;
    Ok(0)
}

/// `compat_sys_statfs64` and `compat_sys_fstatfs64`: the size argument
/// must be `sizeof(struct compat_statfs64)` (`EINVAL`, before the lookup).
pub fn statfs64(c: &mut Ctx<'_>, of: FsOf, size: u64, buf: u64) -> SysResult {
    if size != COMPAT_STATFS64_SIZE {
        return Err(Errno(EINVAL));
    }
    let k = of.statfs(c)?;
    let image = encode_compat_statfs64(&k).ok_or(Errno(EOVERFLOW))?;
    c.write_mem(buf, &image)?;
    Ok(0)
}
