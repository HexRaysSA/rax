//! Immutable supplied-namespace path operations.

use super::{Ctx, Errno, Rv, SysResult};
use crate::user::darwin::{
    fd::{EmbeddedFile, FileKind, OpenFile},
    host::{AT_EACCESS, AT_FDCWD, AT_SYMLINK_NOFOLLOW, AT_SYMLINK_NOFOLLOW_ANY},
    io::*,
};
use crate::user::supplied_fs::{Entry, LinkPolicy};
use std::sync::{Arc, Mutex};

fn lookup(
    ctx: &Ctx<'_>,
    dirfd: i32,
    path: u64,
    policy: LinkPolicy,
) -> Result<(String, Entry), Errno> {
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
    ctx.proc
        .vfs
        .lookup_with_policy(&path, &base, policy)
        .map_err(Errno::from)
}

fn link_policy(flags: u32) -> LinkPolicy {
    if flags & AT_SYMLINK_NOFOLLOW_ANY != 0 {
        // The *at metadata calls allow inspecting a terminal link.
        LinkPolicy::NoFollowAncestors
    } else if flags & AT_SYMLINK_NOFOLLOW != 0 {
        LinkPolicy::NoFollowLast
    } else {
        LinkPolicy::Follow
    }
}

pub(super) fn accessat(ctx: &Ctx<'_>, dirfd: i32, path: u64, mode: i32, flags: u32) -> SysResult {
    if mode & !7 != 0 || flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_SYMLINK_NOFOLLOW_ANY) != 0
    {
        return Err(Errno::EINVAL);
    }
    let (_, entry) = lookup(ctx, dirfd, path, link_policy(flags))?;
    if entry.device().is_some() {
        return if mode & 1 == 0 {
            Ok(Rv::one(0))
        } else {
            Err(Errno::EACCES)
        };
    }
    // Every supplied node grants read/search/execute to every virtual identity.
    // No identity can make the immutable supplied filesystem writable.
    if mode & 2 != 0 {
        return Err(Errno::EROFS);
    }
    Ok(Rv::one(0))
}

pub(super) fn readlinkat(ctx: &Ctx<'_>, dirfd: i32, path: u64, buf: u64, size: u64) -> SysResult {
    if size > i32::MAX as u64 {
        return Err(Errno::EINVAL);
    }
    let (_, entry) = lookup(ctx, dirfd, path, LinkPolicy::NoFollowLast)?;
    let target = entry.link_target().ok_or(Errno::EINVAL)?;
    let count = size.min(target.len() as u64) as usize;
    ctx.write(buf, &target[..count])?;
    Ok(Rv::one(count as u64))
}

pub(super) fn chdir(ctx: &mut Ctx<'_>, path: u64) -> SysResult {
    let (path, entry) = lookup(ctx, AT_FDCWD, path, LinkPolicy::Follow)?;
    if !entry.is_dir() {
        return Err(Errno::ENOTDIR);
    }
    ctx.proc.cwd = path.into_bytes();
    Ok(Rv::one(0))
}

pub(super) fn fchdir(ctx: &mut Ctx<'_>, fd: i32) -> SysResult {
    let file = ctx.proc.fds.file(fd)?;
    ctx.proc.cwd = directory_descriptor(&file)?;
    Ok(Rv::one(0))
}

pub(crate) fn directory_descriptor(file: &OpenFile) -> Result<Vec<u8>, Errno> {
    match &file.kind {
        FileKind::Embedded(EmbeddedFile::Supplied { entry, .. }) if entry.is_dir() => {
            file.path.clone().ok_or(Errno::ENOTDIR)
        }
        FileKind::Embedded(_) => Err(Errno::ENOTDIR),
        _ => Err(Errno::EPERM),
    }
}

pub(super) fn openat(ctx: &mut Ctx<'_>, dirfd: i32, path: u64, flags: u32) -> SysResult {
    let file = open_file(flags, |policy| lookup(ctx, dirfd, path, policy))?;
    let fd = ctx.proc.fds.install_with(
        file,
        flags & O_CLOEXEC != 0,
        flags & O_CLOFORK != 0,
        0,
        ctx.proc.rlimits[8].0,
    )?;
    Ok(Rv::one(fd as u64))
}

pub(crate) fn open_file(
    flags: u32,
    lookup: impl FnOnce(LinkPolicy) -> Result<(String, Entry), Errno>,
) -> Result<Arc<OpenFile>, Errno> {
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
    let exclusive = flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL;
    let policy = if flags & O_NOFOLLOW_ANY != 0 {
        LinkPolicy::NoFollowAny
    } else if flags & O_NOFOLLOW != 0 || exclusive {
        LinkPolicy::NoFollowLast
    } else {
        LinkPolicy::Follow
    };
    let (path, entry) = lookup(policy).map_err(|error| {
        if error == Errno::ENOENT && flags & O_CREAT != 0 {
            Errno::EROFS
        } else {
            error
        }
    })?;
    if exclusive {
        return Err(Errno::EEXIST);
    }
    if entry.link_target().is_some() {
        return Err(Errno::ELOOP);
    }
    let device = entry.device();
    if device.is_none() && (flags & O_ACCMODE != O_RDONLY || flags & O_TRUNC != 0) {
        return Err(Errno::EROFS);
    }
    if flags & O_DIRECTORY != 0 && !entry.is_dir() {
        return Err(Errno::ENOTDIR);
    }
    let status = flags & (O_STATUS_FLAGS | O_DIRECTORY | O_ACCMODE);
    let file = if let Some(device) = device {
        OpenFile::device(path, device, entry.ino, status)
    } else {
        let file = OpenFile::supplied(path, entry);
        *file.flags.lock().map_err(|_| Errno::EIO)? = status;
        file
    };
    Ok(Arc::new(file))
}

pub(super) fn statat(ctx: &Ctx<'_>, dirfd: i32, path: u64, buf: u64, flags: u32) -> SysResult {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_SYMLINK_NOFOLLOW_ANY) != 0 {
        return Err(Errno::EINVAL);
    }
    let (_, entry) = lookup(ctx, dirfd, path, link_policy(flags))?;
    let stat = if let Some(device) = entry.device() {
        EmbeddedFile::device_stat(device, entry.ino)
    } else {
        EmbeddedFile::Supplied {
            entry,
            cursor: Mutex::new(0),
        }
        .stat()?
    };
    ctx.write(buf, &stat.bytes())?;
    Ok(Rv::one(0))
}
