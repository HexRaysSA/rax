//! Path operations in the closed guest namespace.

use super::{Ctx, Errno, Rv, SysResult};
use crate::user::darwin::{
    fd::{EmbeddedFile, FileKind, OpenFile},
    host::{AT_EACCESS, AT_FDCWD, AT_REMOVEDIR, AT_SYMLINK_NOFOLLOW, AT_SYMLINK_NOFOLLOW_ANY},
    io::*,
};
use crate::user::supplied_fs::{
    Entry, LinkPolicy, WorkspaceDirectory, WorkspaceRename, relative_workspace_path,
};
use std::sync::{Arc, Mutex};

type DirectoryBase = (Vec<u8>, Option<Arc<WorkspaceDirectory>>);

fn path_and_base(ctx: &Ctx<'_>, dirfd: i32, path: u64) -> Result<(Vec<u8>, DirectoryBase), Errno> {
    let path = ctx.path(path)?;
    let base = if path.starts_with(b"/") || dirfd == AT_FDCWD {
        (ctx.proc.cwd.clone(), ctx.proc.cwd_directory.clone())
    } else {
        let file = ctx.proc.fds.file(dirfd)?;
        match &file.kind {
            FileKind::Embedded(EmbeddedFile::Supplied { entry, .. }) if entry.is_dir() => (
                file.path.clone().ok_or(Errno::ENOTDIR)?,
                entry.workspace_directory().cloned(),
            ),
            _ => return Err(Errno::ENOTDIR),
        }
    };
    Ok((path, base))
}

fn path_with_workspace_base(
    path: &[u8],
    base: &[u8],
    directory: Option<&Arc<WorkspaceDirectory>>,
    ids: (u32, u32),
) -> Result<(String, Option<Entry>), Errno> {
    if directory.is_none() || path.is_empty() || path.starts_with(b"/") {
        return Ok((
            crate::user::darwin::vfs::Vfs::absolute_guest_path(path, base)?,
            None,
        ));
    }
    let path = std::str::from_utf8(path).map_err(|_| Errno::EINVAL)?;
    let base = std::str::from_utf8(base).map_err(|_| Errno::EINVAL)?;
    Ok(relative_workspace_path(base, directory, path, ids, &[])?)
}

fn lookup(
    ctx: &Ctx<'_>,
    dirfd: i32,
    path: u64,
    policy: LinkPolicy,
) -> Result<(String, Entry), Errno> {
    let (path, (base, directory)) = path_and_base(ctx, dirfd, path)?;
    lookup_as(
        ctx,
        &path,
        &base,
        directory.as_ref(),
        policy,
        (ctx.proc.creds.1, ctx.proc.creds.3),
    )
}

fn lookup_as(
    ctx: &Ctx<'_>,
    path: &[u8],
    base: &[u8],
    directory: Option<&Arc<WorkspaceDirectory>>,
    policy: LinkPolicy,
    ids: (u32, u32),
) -> Result<(String, Entry), Errno> {
    let files = ctx.proc.vfs.files().ok_or(Errno::ENOTSUP)?;
    let (absolute, retained) = path_with_workspace_base(path, base, directory, ids)?;
    if let Some(entry) = retained {
        return Ok((absolute, entry));
    }
    files
        .lookup_for_guest(&absolute, policy, ids, &[])
        .map_err(Errno::from)
}

pub(crate) fn lookup_followed(
    ctx: &Ctx<'_>,
    path: &[u8],
    base: &[u8],
    directory: Option<&Arc<WorkspaceDirectory>>,
) -> Result<(String, Entry), Errno> {
    lookup_as(
        ctx,
        path,
        base,
        directory,
        LinkPolicy::Follow,
        (ctx.proc.creds.1, ctx.proc.creds.3),
    )
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
    let (uid, euid, gid, egid) = ctx.proc.creds;
    let ids = if flags & AT_EACCESS != 0 {
        (euid, egid)
    } else {
        (uid, gid)
    };
    let (path, (base, directory)) = path_and_base(ctx, dirfd, path)?;
    let (_, entry) = lookup_as(
        ctx,
        &path,
        &base,
        directory.as_ref(),
        link_policy(flags),
        ids,
    )?;
    let allowed = entry
        .workspace_file()
        .map(|file| file.permits(mode as u32, ids, &[]))
        .or_else(|| {
            entry
                .workspace_directory()
                .map(|dir| dir.permits(mode as u32, ids, &[]))
        });
    if let Some(allowed) = allowed {
        return if allowed {
            Ok(Rv::one(0))
        } else {
            Err(Errno::EACCES)
        };
    }
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
    check_search(ctx, &entry)?;
    ctx.proc.cwd = path.into_bytes();
    ctx.proc.cwd_directory = entry.workspace_directory().cloned();
    Ok(Rv::one(0))
}

pub(super) fn fchdir(ctx: &mut Ctx<'_>, fd: i32) -> SysResult {
    let file = ctx.proc.fds.file(fd)?;
    (ctx.proc.cwd, ctx.proc.cwd_directory) = directory_descriptor(ctx, &file)?;
    Ok(Rv::one(0))
}

pub(crate) fn check_search(ctx: &Ctx<'_>, entry: &Entry) -> Result<(), Errno> {
    if !entry.is_dir() {
        return Err(Errno::ENOTDIR);
    }
    if let Some(directory) = entry.workspace_directory()
        && !directory.permits(1, (ctx.proc.creds.1, ctx.proc.creds.3), &[])
    {
        return Err(Errno::EACCES);
    }
    Ok(())
}

pub(crate) fn directory_descriptor(ctx: &Ctx<'_>, file: &OpenFile) -> Result<DirectoryBase, Errno> {
    match &file.kind {
        FileKind::Embedded(EmbeddedFile::Supplied { entry, .. }) => {
            check_search(ctx, entry)?;
            Ok((
                file.path.clone().ok_or(Errno::ENOTDIR)?,
                entry.workspace_directory().cloned(),
            ))
        }
        FileKind::Embedded(_) => Err(Errno::ENOTDIR),
        _ => Err(Errno::EPERM),
    }
}

pub(super) fn openat(ctx: &mut Ctx<'_>, dirfd: i32, path: u64, flags: u32, mode: u32) -> SysResult {
    if flags & (O_CREAT | O_TRUNC) != 0 && ctx.proc.vfs.files().is_some_and(|f| f.has_workspace()) {
        ctx.proc.fds.lowest_free(0, ctx.proc.rlimits[8].0)?;
    }
    let (path, (base, directory)) = path_and_base(ctx, dirfd, path)?;
    let file = open_file(ctx, &path, &base, directory.as_ref(), flags, mode)?;
    let fd = ctx.proc.fds.install_with(
        file,
        flags & O_CLOEXEC != 0,
        flags & O_CLOFORK != 0,
        0,
        ctx.proc.rlimits[8].0,
    )?;
    Ok(Rv::one(fd as u64))
}

pub(super) fn unlinkat(ctx: &Ctx<'_>, dirfd: i32, path: u64, flags: u32) -> SysResult {
    if flags & !AT_REMOVEDIR != 0 {
        return Err(Errno::EINVAL);
    }
    let files = ctx.proc.vfs.files().ok_or(Errno::EROFS)?;
    let (path, (base, directory)) = path_and_base(ctx, dirfd, path)?;
    let ids = (ctx.proc.creds.1, ctx.proc.creds.3);
    let (absolute, retained) = path_with_workspace_base(&path, &base, directory.as_ref(), ids)?;
    if retained.is_some() {
        return Err(Errno::ENOENT);
    }
    if flags == AT_REMOVEDIR {
        files.remove_workspace_directory(&absolute, ids, &[])?;
    } else {
        match files.unlink_workspace_file(&absolute, ids, &[]) {
            Err(crate::user::supplied_fs::Error::IsDirectory) => return Err(Errno::EPERM),
            result => result?,
        }
    }
    Ok(Rv::one(0))
}

pub(super) fn mkdirat(ctx: &Ctx<'_>, dirfd: i32, path: u64, mode: u32) -> SysResult {
    let files = ctx.proc.vfs.files().ok_or(Errno::EROFS)?;
    let (path, (base, directory)) = path_and_base(ctx, dirfd, path)?;
    let ids = (ctx.proc.creds.1, ctx.proc.creds.3);
    let (absolute, retained) = path_with_workspace_base(&path, &base, directory.as_ref(), ids)?;
    if retained.is_some() {
        return Err(Errno::ENOENT);
    }
    files.create_workspace_directory(&absolute, mode & !ctx.proc.umask, ids, &[])?;
    Ok(Rv::one(0))
}

pub(super) fn symlinkat(ctx: &Ctx<'_>, target: u64, dirfd: i32, path: u64) -> SysResult {
    let target = ctx.path(target)?;
    let files = ctx.proc.vfs.files().ok_or(Errno::EROFS)?;
    let (path, (base, directory)) = path_and_base(ctx, dirfd, path)?;
    let ids = (ctx.proc.creds.1, ctx.proc.creds.3);
    let (absolute, retained) = path_with_workspace_base(&path, &base, directory.as_ref(), ids)?;
    if retained.is_some() {
        return Err(Errno::ENOENT);
    }
    files.create_workspace_symlink(&absolute, target, ctx.proc.umask, ids, &[])?;
    Ok(Rv::one(0))
}

pub(super) fn renameat(
    ctx: &Ctx<'_>,
    fromfd: i32,
    from: u64,
    tofd: i32,
    to: u64,
    flags: u32,
) -> SysResult {
    const RENAME_SWAP: u32 = 2;
    const RENAME_EXCL: u32 = 4;
    let how = match flags {
        0 => WorkspaceRename::Replace,
        RENAME_SWAP => WorkspaceRename::Exchange,
        RENAME_EXCL => WorkspaceRename::Exclusive,
        _ => return Err(Errno::EINVAL),
    };
    let files = ctx.proc.vfs.files().ok_or(Errno::EROFS)?;
    let ids = (ctx.proc.creds.1, ctx.proc.creds.3);
    let read_path = |fd, address| {
        let (path, (base, directory)) = path_and_base(ctx, fd, address)?;
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        let (absolute, retained) = path_with_workspace_base(&path, &base, directory.as_ref(), ids)?;
        if retained.is_some() {
            return Err(Errno::ENOENT);
        }
        Ok(absolute)
    };
    let from = read_path(fromfd, from)?;
    let to = read_path(tofd, to)?;
    files.rename_workspace_entry(&from, &to, ids, &[], how)?;
    Ok(Rv::one(0))
}

pub(crate) fn open_file(
    ctx: &Ctx<'_>,
    path: &[u8],
    base: &[u8],
    directory: Option<&Arc<WorkspaceDirectory>>,
    flags: u32,
    mode: u32,
) -> Result<Arc<OpenFile>, Errno> {
    let owner = (ctx.proc.creds.1, ctx.proc.creds.3);
    let file = open_or_create(
        flags,
        owner,
        |policy| lookup_as(ctx, path, base, directory, policy, owner),
        |exclusive| {
            let files = ctx.proc.vfs.files().ok_or(Errno::EROFS)?;
            if !files.has_workspace() {
                return Err(Errno::EROFS);
            }
            if flags & O_DIRECTORY != 0 {
                return Err(Errno::ENOTDIR);
            }
            let (absolute, retained) = path_with_workspace_base(path, base, directory, owner)?;
            if retained.is_some() {
                return Err(Errno::ENOENT);
            }
            let mode = mode & !ctx.proc.umask;
            let absolute = if exclusive || flags & (O_NOFOLLOW | O_NOFOLLOW_ANY | O_SYMLINK) != 0 {
                absolute
            } else {
                files.workspace_create_path(&absolute, owner, &[])?
            };
            files
                .create_workspace_file(&absolute, mode, owner, &[], exclusive)
                .map_err(Errno::from)
        },
    )?;
    if flags & O_TRUNC != 0
        && let FileKind::Embedded(object) = &file.kind
        && let Some((workspace, _)) = object.workspace()
    {
        ctx.space()
            .truncated(crate::user::mm::PageSource::identity(workspace), 0);
    }
    Ok(file)
}

fn open_or_create(
    flags: u32,
    owner: (u32, u32),
    lookup: impl FnOnce(LinkPolicy) -> Result<(String, Entry), Errno>,
    create: impl FnOnce(bool) -> Result<(String, Entry), Errno>,
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
        | O_SYMLINK
        | O_NOCTTY
        | O_CLOEXEC
        | O_CLOFORK;
    if flags & !supported != 0 {
        return Err(Errno::ENOTSUP);
    }
    let exclusive = flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL;
    let policy = if flags & O_NOFOLLOW_ANY != 0 {
        LinkPolicy::NoFollowAny
    } else if flags & (O_NOFOLLOW | O_SYMLINK) != 0 || exclusive {
        LinkPolicy::NoFollowLast
    } else {
        LinkPolicy::Follow
    };
    let (path, entry, created) = match lookup(policy) {
        Ok(_) if exclusive => return Err(Errno::EEXIST),
        Ok((path, entry)) => (path, entry, false),
        Err(Errno::ENOENT) if flags & O_CREAT != 0 => {
            let (path, entry) = create(exclusive)?;
            (path, entry, true)
        }
        Err(error) => return Err(error),
    };
    if entry.link_target().is_some() {
        if flags & O_SYMLINK == 0 || flags & (O_NOFOLLOW | O_NOFOLLOW_ANY) != 0 {
            return Err(Errno::ELOOP);
        }
        if flags & O_DIRECTORY != 0 {
            return Err(Errno::ENOTDIR);
        }
        let status = flags & (O_STATUS_FLAGS | O_ACCMODE);
        return Ok(Arc::new(OpenFile::supplied_with_flags(path, entry, status)));
    }
    let device = entry.device();
    let workspace = entry.workspace_file();
    if device.is_none()
        && workspace.is_none()
        && (flags & O_ACCMODE != O_RDONLY || flags & O_TRUNC != 0)
    {
        return Err(Errno::EROFS);
    }
    if flags & O_DIRECTORY != 0 && !entry.is_dir() {
        return Err(Errno::ENOTDIR);
    }
    if let Some(directory) = entry.workspace_directory()
        && !directory.permits(4, owner, &[])
    {
        return Err(Errno::EACCES);
    }
    let status = flags & (O_STATUS_FLAGS | O_DIRECTORY | O_ACCMODE);
    let file = if let Some(device) = device {
        OpenFile::device(path, device, entry.ino, status)
    } else if let Some(file) = workspace {
        let mut need = match flags & O_ACCMODE {
            O_RDONLY => 4,
            O_WRONLY => 2,
            _ => 6,
        };
        if flags & O_TRUNC != 0 {
            need |= 2;
        }
        if !created && !file.permits(need, owner, &[]) {
            return Err(Errno::EACCES);
        }
        if flags & O_TRUNC != 0 {
            file.resize(0)?;
        }
        OpenFile::workspace(path, entry, status)
    } else {
        OpenFile::supplied_with_flags(path, entry, status)
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
            access: O_RDONLY,
        }
        .stat()?
    };
    ctx.write(buf, &stat.bytes())?;
    Ok(Rv::one(0))
}
