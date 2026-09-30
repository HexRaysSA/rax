//! Immutable supplied-namespace path operations.

use super::{Ctx, Errno, Rv, SysResult};
use crate::user::darwin::{
    fd::{EmbeddedFile, FileKind, OpenFile},
    host::AT_FDCWD,
    io::*,
};
use crate::user::supplied_fs::Entry;
use std::sync::{Arc, Mutex};

fn lookup(ctx: &Ctx<'_>, dirfd: i32, path: u64) -> Result<(String, Entry), Errno> {
    let path = ctx.path(path)?;
    let base = if path.starts_with(b"/") || dirfd == AT_FDCWD {
        ctx.proc.cwd.clone()
    } else {
        let file = ctx.proc.fds.file(dirfd)?;
        match &file.kind {
            FileKind::Embedded(EmbeddedFile::Supplied { entry, .. }) if entry.is_dir() => {
                file.path.clone().ok_or(Errno::ENOTDIR)?
            }
            _ => return Err(Errno::ENOTDIR),
        }
    };
    ctx.proc.vfs.lookup(&path, &base).map_err(Errno::from)
}

pub(super) fn accessat(ctx: &Ctx<'_>, dirfd: i32, path: u64, mode: i32, flags: u32) -> SysResult {
    use crate::user::darwin::host::{AT_EACCESS, AT_SYMLINK_NOFOLLOW, AT_SYMLINK_NOFOLLOW_ANY};
    if mode & !7 != 0 || flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_SYMLINK_NOFOLLOW_ANY) != 0
    {
        return Err(Errno::EINVAL);
    }
    lookup(ctx, dirfd, path)?;
    // Every supplied node grants read/search/execute to every virtual identity.
    // No identity can make the immutable supplied filesystem writable.
    if mode & 2 != 0 {
        return Err(Errno::EROFS);
    }
    Ok(Rv::one(0))
}

pub(super) fn readlinkat(ctx: &Ctx<'_>, dirfd: i32, path: u64) -> SysResult {
    lookup(ctx, dirfd, path)?;
    // The supplied namespace contains regular files and directories only.
    Err(Errno::EINVAL)
}

pub(super) fn chdir(ctx: &mut Ctx<'_>, path: u64) -> SysResult {
    let (path, entry) = lookup(ctx, AT_FDCWD, path)?;
    if !entry.is_dir() {
        return Err(Errno::ENOTDIR);
    }
    ctx.proc.cwd = path.into_bytes();
    Ok(Rv::one(0))
}

pub(super) fn fchdir(ctx: &mut Ctx<'_>, fd: i32) -> SysResult {
    let file = ctx.proc.fds.file(fd)?;
    match &file.kind {
        FileKind::Embedded(EmbeddedFile::Supplied { entry, .. }) if entry.is_dir() => {
            ctx.proc.cwd = file.path.clone().ok_or(Errno::ENOTDIR)?;
            Ok(Rv::one(0))
        }
        FileKind::Embedded(_) => Err(Errno::ENOTDIR),
        _ => Err(Errno::EPERM),
    }
}

pub(super) fn openat(ctx: &mut Ctx<'_>, dirfd: i32, path: u64, flags: u32) -> SysResult {
    if flags & O_ACCMODE == O_ACCMODE {
        return Err(Errno::EINVAL);
    }
    let supported = O_ACCMODE
        | O_STATUS_FLAGS
        | O_CREAT
        | O_EXCL
        | O_TRUNC
        | O_DIRECTORY
        | O_NOFOLLOW
        | O_NOFOLLOW_ANY
        | O_NOCTTY
        | O_CLOEXEC
        | O_CLOFORK;
    if flags & !supported != 0 {
        return Err(Errno::ENOTSUP);
    }
    let (path, entry) = lookup(ctx, dirfd, path).map_err(|error| {
        if error == Errno::ENOENT && flags & O_CREAT != 0 {
            Errno::EROFS
        } else {
            error
        }
    })?;
    if flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL {
        return Err(Errno::EEXIST);
    }
    if flags & O_ACCMODE != O_RDONLY || flags & O_TRUNC != 0 {
        return Err(Errno::EROFS);
    }
    if flags & O_DIRECTORY != 0 && !entry.is_dir() {
        return Err(Errno::ENOTDIR);
    }
    let file = OpenFile::supplied(path, entry);
    *file.flags.lock().map_err(|_| Errno::EIO)? = flags & (O_STATUS_FLAGS | O_DIRECTORY);
    let fd = ctx.proc.fds.install_with(
        Arc::new(file),
        flags & O_CLOEXEC != 0,
        flags & O_CLOFORK != 0,
        0,
        ctx.proc.rlimits[8].0,
    )?;
    Ok(Rv::one(fd as u64))
}

pub(super) fn statat(ctx: &Ctx<'_>, dirfd: i32, path: u64, buf: u64, flags: u32) -> SysResult {
    use crate::user::darwin::host::{AT_SYMLINK_NOFOLLOW, AT_SYMLINK_NOFOLLOW_ANY};
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_SYMLINK_NOFOLLOW_ANY) != 0 {
        return Err(Errno::EINVAL);
    }
    let (_, entry) = lookup(ctx, dirfd, path)?;
    let file = EmbeddedFile::Supplied {
        entry,
        cursor: Mutex::new(0),
    };
    ctx.write(buf, &file.stat()?.bytes())?;
    Ok(Rv::one(0))
}
