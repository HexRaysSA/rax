//! Mounts (Linux 6.19 `fs/namespace.c`, `fs/fsopen.c`): `mount`,
//! `umount2`, `pivot_root`, `open_tree`, `open_tree_attr`,
//! `mount_setattr`, `move_mount`, and the file-system context calls
//! `fsopen`, `fspick`, `fsconfig`, and `fsmount`.
//!
//! The guest sees the host's mounts and cannot change them. Each change
//! needs `CAP_SYS_ADMIN` over the mount namespace (`may_mount`): an
//! unprivileged caller fails there with `EPERM`; root passes it, the
//! argument checks that follow still apply, and the change is refused with
//! `EOPNOTSUPP`. Since no file-system context is ever opened, `fsconfig`
//! and `fsmount` find none (`EINVAL`) once their own checks pass.
//!
//! | Call | Before `may_mount` | Root, after it |
//! |---|---|---|
//! | `mount` | the type and device strings (`EFAULT`; `PATH_MAX` or longer: `EINVAL`), the options (`EFAULT` when none can be read), the mount point's lookup, `MS_NOUSER` (`EINVAL`, after the `0xC0ED` magic is dropped) | refused |
//! | `umount2` | unknown flags (`EINVAL`), the lookup (`UMOUNT_NOFOLLOW`) | refused |
//! | `pivot_root` | — | refused |
//! | `move_mount` | — | unknown or conflicting flags (`EINVAL`); refused |
//! | `fsopen` | — | unknown flags (`EINVAL`), the name (`EFAULT`, `EINVAL`); refused |
//! | `fspick` | — | unknown flags (`EINVAL`), the lookup; refused |
//! | `fsmount` | — | unknown flags or attributes (`EINVAL`), the descriptor (`EBADF`); not a context (`EINVAL`) |
//! | `open_tree` | a free descriptor (`EMFILE`), unknown flags or `AT_RECURSIVE` without `OPEN_TREE_CLONE` (`EINVAL`); only a clone needs the capability | the lookup; refused |
//! | `open_tree_attr` | an attribute size without attributes (`EINVAL`), `open_tree`'s checks and lookup, then with attributes their size (`E2BIG`, `EINVAL`) | the attributes (below); none to change: the descriptor; else refused |
//! | `mount_setattr` | unknown flags (`EINVAL`), the attribute size (`E2BIG`, `EINVAL`) | the attributes (below); none to change: 0; else the lookup, then refused |
//! | `fsconfig` | (no capability) the command's arguments (`EINVAL`, unknown commands `EOPNOTSUPP`), the descriptor (`EBADF`); not a context (`EINVAL`) | — |
//!
//! Attributes (`struct mount_attr`, `copy_struct_from_user`): a nonzero
//! byte past the known 32 is `E2BIG`; then `build_mount_kattr`'s checks
//! (`EINVAL`), and for `MOUNT_ATTR_IDMAP` the user-namespace descriptor
//! (`EBADF`), which is never a namespace file here (`EINVAL`).
//!
//! `open_tree` without `OPEN_TREE_CLONE` needs no privilege: it opens the
//! path as `dentry_open` with `O_PATH` does (`f_flags` exactly `O_PATH`).
//! For a descriptor without a host file (a pipe, socket, or anonymous
//! file) named by `AT_EMPTY_PATH`, the new descriptor shares its
//! description.

use std::sync::Arc;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::{O_CLOEXEC, O_PATH};
use super::super::fs::fd::{FileObject, OpenFile};
use super::super::fs::{self, PATH_MAX};
use super::super::procfs::ProcEntry;
use super::admin::{capability, refused};
use super::path::{self, AT_EMPTY_PATH, AT_FDCWD, AT_NO_AUTOMOUNT, AT_SYMLINK_NOFOLLOW, Target};
use super::{Ctx, SysResult};

/// `AT_RECURSIVE`.
const AT_RECURSIVE: u32 = 0x8000;
/// `OPEN_TREE_CLONE`.
const OPEN_TREE_CLONE: u32 = 1;
/// `PAGE_SIZE`.
const PAGE_SIZE: u64 = 4096;

/// `MS_*` mount flags (`linux/mount.h`).
mod ms {
    pub const MGC_VAL: u64 = 0xc0ed_0000;
    pub const MGC_MSK: u64 = 0xffff_0000;
    pub const NOUSER: u64 = 1 << 31;
    /// `MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED`.
    pub const PROPAGATION: u64 = (1 << 17) | (1 << 18) | (1 << 19) | (1 << 20);
}

/// `MOUNT_ATTR_*` (`linux/mount.h`).
mod attr {
    pub const ATIME: u64 = 0x70;
    pub const RELATIME: u64 = 0x00;
    pub const NOATIME: u64 = 0x10;
    pub const STRICTATIME: u64 = 0x20;
    pub const IDMAP: u64 = 0x10_0000;
    /// `FSMOUNT_VALID_FLAGS`: `RDONLY`, `NOSUID`, `NODEV`, `NOEXEC`, the
    /// atime field, `NODIRATIME`, and `NOSYMFOLLOW`.
    pub const FSMOUNT_VALID: u64 = 0x1 | 0x2 | 0x4 | 0x8 | ATIME | 0x80 | 0x20_0000;
    /// `MOUNT_SETATTR_VALID_FLAGS`.
    pub const SETATTR_VALID: u64 = FSMOUNT_VALID | IDMAP;
    /// `MOUNT_ATTR_SIZE_VER0`: `struct mount_attr`.
    pub const SIZE_VER0: u64 = 32;
}

/// `strndup_user` of a mount string (`copy_mount_string`): `EFAULT`, or
/// `EINVAL` without a NUL in `PATH_MAX` bytes. A null pointer is no string.
fn mount_string(c: &Ctx<'_>, addr: u64) -> Result<(), Errno> {
    if addr != 0 {
        c.p.space
            .read_cstr(addr, PATH_MAX - 1)
            .map_err(|_| Errno(EFAULT))?
            .ok_or(Errno(EINVAL))?;
    }
    Ok(())
}

/// `user_path_at`: resolves a path argument to an existing object.
fn lookup(
    c: &Ctx<'_>,
    dirfd: i32,
    path: u64,
    at_flags: u32,
    follow: bool,
) -> Result<Target, Errno> {
    let target = path::resolve(c, dirfd, path, at_flags, follow)?;
    path::stat_target(c, &target, follow)?;
    Ok(target)
}

/// `fdget`: an open descriptor that is not `O_PATH`, else `EBADF`.
fn fdget(c: &Ctx<'_>, fd: i32) -> Result<Arc<OpenFile>, Errno> {
    let file = c.p.fds.file(fd)?;
    if file.flags() & O_PATH != 0 {
        return Err(Errno(EBADF));
    }
    Ok(file)
}

/// `get_unused_fd_flags`, before the call does its work: `EMFILE` when no
/// descriptor is free.
fn reserve(c: &Ctx<'_>) -> Result<(), Errno> {
    c.p.fds.free_fds(1, super::io::nofile(c)).map(|_| ())
}

/// `mount`: the strings, the options, the mount point, the flags, then
/// `may_mount`.
pub fn mount(c: &Ctx<'_>, dev: u64, dir: u64, fstype: u64, flags: u64, data: u64) -> SysResult {
    mount_string(c, fstype)?;
    mount_string(c, dev)?;
    // copy_mount_options: up to a page, EFAULT only if none is readable.
    if data != 0 {
        c.read_mem(data, 1)?;
    }
    lookup(c, AT_FDCWD, dir, 0, true)?;
    let mut flags = flags;
    if flags & ms::MGC_MSK == ms::MGC_VAL {
        flags &= !ms::MGC_MSK;
    }
    if flags & ms::NOUSER != 0 {
        return Err(Errno(EINVAL));
    }
    capability(c)?;
    refused()
}

/// `umount2`: the flags, the lookup, then `may_mount`.
pub fn umount2(c: &Ctx<'_>, target: u64, flags: i32) -> SysResult {
    const MNT_FORCE: u32 = 1;
    const MNT_DETACH: u32 = 2;
    const MNT_EXPIRE: u32 = 4;
    const UMOUNT_NOFOLLOW: u32 = 8;
    let flags = flags as u32;
    if flags & !(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) != 0 {
        return Err(Errno(EINVAL));
    }
    lookup(c, AT_FDCWD, target, 0, flags & UMOUNT_NOFOLLOW == 0)?;
    capability(c)?;
    refused()
}

/// `pivot_root`: `may_mount` first.
pub fn pivot_root(c: &Ctx<'_>) -> SysResult {
    capability(c)?;
    refused()
}

/// `move_mount`: `may_mount`, then the flags.
pub fn move_mount(c: &Ctx<'_>, flags: u32) -> SysResult {
    const MOVE_MOUNT_MASK: u32 = 0x377;
    const MOVE_MOUNT_SET_GROUP: u32 = 0x100;
    const MOVE_MOUNT_BENEATH: u32 = 0x200;
    capability(c)?;
    let both = MOVE_MOUNT_BENEATH | MOVE_MOUNT_SET_GROUP;
    if flags & !MOVE_MOUNT_MASK != 0 || flags & both == both {
        return Err(Errno(EINVAL));
    }
    refused()
}

/// `fsopen`: `may_mount`, the flags, then the file-system name.
pub fn fsopen(c: &Ctx<'_>, name: u64, flags: u32) -> SysResult {
    const FSOPEN_CLOEXEC: u32 = 1;
    capability(c)?;
    if flags & !FSOPEN_CLOEXEC != 0 {
        return Err(Errno(EINVAL));
    }
    c.p.space
        .read_cstr(name, PAGE_SIZE as usize - 1)
        .map_err(|_| Errno(EFAULT))?
        .ok_or(Errno(EINVAL))?;
    refused()
}

/// `fspick`: `may_mount`, the flags, then the lookup.
pub fn fspick(c: &Ctx<'_>, dirfd: i32, path: u64, flags: u32) -> SysResult {
    const FSPICK_CLOEXEC: u32 = 1;
    const FSPICK_SYMLINK_NOFOLLOW: u32 = 2;
    const FSPICK_NO_AUTOMOUNT: u32 = 4;
    const FSPICK_EMPTY_PATH: u32 = 8;
    capability(c)?;
    let valid = FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW | FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH;
    if flags & !valid != 0 {
        return Err(Errno(EINVAL));
    }
    let empty = if flags & FSPICK_EMPTY_PATH != 0 {
        AT_EMPTY_PATH
    } else {
        0
    };
    lookup(c, dirfd, path, empty, flags & FSPICK_SYMLINK_NOFOLLOW == 0)?;
    refused()
}

/// `fsmount`: `may_mount`, the flags and attributes, then the context.
pub fn fsmount(c: &Ctx<'_>, fs_fd: i32, flags: u32, attr_flags: u32) -> SysResult {
    const FSMOUNT_CLOEXEC: u32 = 1;
    capability(c)?;
    let attrs = u64::from(attr_flags);
    if flags & !FSMOUNT_CLOEXEC != 0 || attrs & !attr::FSMOUNT_VALID != 0 {
        return Err(Errno(EINVAL));
    }
    if !matches!(
        attrs & attr::ATIME,
        attr::STRICTATIME | attr::NOATIME | attr::RELATIME
    ) {
        return Err(Errno(EINVAL));
    }
    fdget(c, fs_fd)?;
    Err(Errno(EINVAL))
}

/// `fsconfig`: the descriptor's sign, the command's arguments, then the
/// descriptor, which is never a file-system context.
pub fn fsconfig(c: &Ctx<'_>, fd: i32, cmd: u32, key: u64, value: u64, aux: i32) -> SysResult {
    const AT_FDCWD_AUX: i32 = AT_FDCWD;
    if fd < 0 {
        return Err(Errno(EINVAL));
    }
    let (key, value) = (key != 0, value != 0);
    let bad = match cmd {
        // FSCONFIG_SET_FLAG
        0 => !key || value || aux != 0,
        // FSCONFIG_SET_STRING
        1 => !key || !value || aux != 0,
        // FSCONFIG_SET_BINARY
        2 => !key || !value || aux <= 0 || aux > 1024 * 1024,
        // FSCONFIG_SET_PATH, FSCONFIG_SET_PATH_EMPTY
        3 | 4 => !key || !value || (aux != AT_FDCWD_AUX && aux < 0),
        // FSCONFIG_SET_FD
        5 => !key || value || aux < 0,
        // FSCONFIG_CMD_CREATE, FSCONFIG_CMD_RECONFIGURE,
        // FSCONFIG_CMD_CREATE_EXCL
        6..=8 => key || value || aux != 0,
        _ => return Err(Errno(EOPNOTSUPP)),
    };
    if bad {
        return Err(Errno(EINVAL));
    }
    fdget(c, fd)?;
    Err(Errno(EINVAL))
}

/// `vfs_open_tree`: the flags, `may_mount` for a clone, then the lookup;
/// a clone is refused, anything else opened `O_PATH`.
fn vfs_open_tree(
    c: &mut Ctx<'_>,
    dirfd: i32,
    path: u64,
    flags: u32,
) -> Result<Arc<OpenFile>, Errno> {
    let valid = AT_EMPTY_PATH
        | AT_NO_AUTOMOUNT
        | AT_RECURSIVE
        | AT_SYMLINK_NOFOLLOW
        | OPEN_TREE_CLONE
        | O_CLOEXEC;
    if flags & !valid != 0 || flags & (AT_RECURSIVE | OPEN_TREE_CLONE) == AT_RECURSIVE {
        return Err(Errno(EINVAL));
    }
    let clone = flags & OPEN_TREE_CLONE != 0;
    if clone {
        capability(c)?;
    }
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let target = lookup(c, dirfd, path, flags & AT_EMPTY_PATH, follow)?;
    if clone {
        refused()?;
    }
    path_file(c, target, follow)
}

/// A new `O_PATH` description of `target` (`dentry_open` with `O_PATH`).
fn path_file(c: &mut Ctx<'_>, target: Target, follow: bool) -> Result<Arc<OpenFile>, Errno> {
    match target {
        Target::Host { guest, host } => {
            let m = if follow {
                std::fs::metadata(&host)?
            } else {
                std::fs::symlink_metadata(&host)?
            };
            Ok(OpenFile::new(
                FileObject::PathOnly,
                fs::file_type_of(&m),
                guest,
                Some(host),
                O_PATH,
            ))
        }
        Target::Fd(f) => Ok(match &f.host_path {
            Some(h) => OpenFile::new(
                FileObject::PathOnly,
                f.ftype,
                f.path.clone(),
                Some(h.clone()),
                O_PATH,
            ),
            None => f,
        }),
        Target::Proc(ProcEntry::Link(link), guest) if !follow => {
            let nofollow = c.p.abi.open_flags().nofollow;
            path::open_target(
                c,
                Target::Proc(ProcEntry::Link(link), guest),
                O_PATH | nofollow,
                0,
            )
        }
        other => path::open_target(c, other, O_PATH, 0),
    }
}

/// `open_tree`.
pub fn open_tree(c: &mut Ctx<'_>, dirfd: i32, path: u64, flags: u32) -> SysResult {
    reserve(c)?;
    let file = vfs_open_tree(c, dirfd, path, flags)?;
    super::io::install(c, file, flags & O_CLOEXEC != 0)
}

/// `open_tree_attr`: `open_tree`, then, with attributes, the change they
/// ask for applied to the tree before its descriptor is published.
pub fn open_tree_attr(
    c: &mut Ctx<'_>,
    dirfd: i32,
    path: u64,
    flags: u32,
    uattr: u64,
    usize: u64,
) -> SysResult {
    if uattr == 0 && usize != 0 {
        return Err(Errno(EINVAL));
    }
    reserve(c)?;
    let file = vfs_open_tree(c, dirfd, path, flags)?;
    if uattr != 0 && wants_setattr(c, uattr, usize)? {
        refused()?;
    }
    super::io::install(c, file, flags & O_CLOEXEC != 0)
}

/// `mount_setattr`: the flags, the attributes, then the lookup.
pub fn mount_setattr(
    c: &Ctx<'_>,
    dirfd: i32,
    path: u64,
    flags: u32,
    uattr: u64,
    usize: u64,
) -> SysResult {
    if flags & !(AT_EMPTY_PATH | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT) != 0 {
        return Err(Errno(EINVAL));
    }
    if !wants_setattr(c, uattr, usize)? {
        return Ok(0);
    }
    lookup(
        c,
        dirfd,
        path,
        flags & AT_EMPTY_PATH,
        flags & AT_SYMLINK_NOFOLLOW == 0,
    )?;
    refused()
}

/// `wants_mount_setattr`: the size, `may_mount`, and the attributes;
/// whether they ask for a change.
fn wants_setattr(c: &Ctx<'_>, uattr: u64, usize: u64) -> Result<bool, Errno> {
    if usize > PAGE_SIZE {
        return Err(Errno(E2BIG));
    }
    if usize < attr::SIZE_VER0 {
        return Err(Errno(EINVAL));
    }
    capability(c)?;
    let b = copy_struct(c, uattr, attr::SIZE_VER0, usize)?;
    let word = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    let (set, clr, propagation, userns_fd) = (word(0), word(1), word(2), word(3));
    if set == 0 && clr == 0 && propagation == 0 {
        return Ok(false);
    }
    // build_mount_kattr.
    if propagation & !ms::PROPAGATION != 0 || propagation.count_ones() > 1 {
        return Err(Errno(EINVAL));
    }
    if (set | clr) & !attr::SETATTR_VALID != 0 {
        return Err(Errno(EINVAL));
    }
    if clr & attr::ATIME != 0 {
        if clr & attr::ATIME != attr::ATIME
            || !matches!(
                set & attr::ATIME,
                attr::RELATIME | attr::NOATIME | attr::STRICTATIME
            )
        {
            return Err(Errno(EINVAL));
        }
    } else if set & attr::ATIME != 0 {
        return Err(Errno(EINVAL));
    }
    // build_mount_idmapped: an idmapping cannot be removed from a mount
    // that was ever visible, and the user namespace comes by descriptor.
    if (set | clr) & attr::IDMAP != 0 {
        if clr & attr::IDMAP != 0 || userns_fd > i32::MAX as u64 {
            return Err(Errno(EINVAL));
        }
        fdget(c, userns_fd as i32)?;
        return Err(Errno(EINVAL));
    }
    Ok(true)
}

/// `copy_struct_from_user` of a `ksize`-byte structure given as `usize`
/// bytes at `addr`: past `ksize` only zeros (`E2BIG` at a nonzero byte,
/// `EFAULT` at a fault before one), then the known part.
pub(super) fn copy_struct(
    c: &Ctx<'_>,
    addr: u64,
    ksize: u64,
    usize: u64,
) -> Result<Vec<u8>, Errno> {
    let mut at = addr.checked_add(ksize).ok_or(Errno(EFAULT))?;
    let mut left = usize.saturating_sub(ksize);
    while left > 0 {
        let n = (PAGE_SIZE - at % PAGE_SIZE).min(left);
        if c.read_mem(at, n as usize)?.iter().any(|&b| b != 0) {
            return Err(Errno(E2BIG));
        }
        at += n;
        left -= n;
    }
    let mut b = c.read_mem(addr, ksize.min(usize) as usize)?;
    b.resize(ksize as usize, 0);
    Ok(b)
}
