//! Path operations in the closed guest namespace.

use super::{Ctx, Errno, Rv, SysResult};
use crate::user::darwin::{
    abi::types::Stat,
    fd::{EmbeddedFile, FileKind, FileRef, OpenFile, RESOURCE_FORK_SUFFIX},
    host::{
        AT_EACCESS, AT_FDCWD, AT_REMOVEDIR, AT_SYMLINK_FOLLOW, AT_SYMLINK_NOFOLLOW,
        AT_SYMLINK_NOFOLLOW_ANY,
    },
    io::*,
    syscall::bsd::file::lifetime,
    workspace_locks,
};
use crate::user::supplied_fs::{
    Entry, LinkPolicy, WorkspaceCloneDestination, WorkspaceDirectory, WorkspaceRename,
    relative_workspace_path,
};
use std::sync::{Arc, Mutex};

type DirectoryBase = (Vec<u8>, Option<Arc<WorkspaceDirectory>>);

fn resource_base(path: &[u8]) -> Option<&[u8]> {
    let mut base = path.strip_suffix(RESOURCE_FORK_SUFFIX.as_bytes())?;
    while base.len() > 1 && base.ends_with(b"/") {
        base = &base[..base.len() - 1];
    }
    Some(if base.is_empty() { b"/" } else { base })
}

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

fn allows_initial_search(ctx: &Ctx<'_>, dirfd: i32, path: &[u8]) -> bool {
    dirfd != AT_FDCWD
        && !path.starts_with(b"/")
        && ctx
            .proc
            .fds
            .file(dirfd)
            .is_ok_and(|file| matches!(&file.kind, FileKind::Embedded(data) if data.search_only()))
}

pub(in crate::user::darwin::syscall::bsd) fn lookup(
    ctx: &Ctx<'_>,
    dirfd: i32,
    path: u64,
    policy: LinkPolicy,
) -> Result<(String, Entry), Errno> {
    let (path, (base, directory)) = path_and_base(ctx, dirfd, path)?;
    let resource = resource_base(&path);
    let result = lookup_as(
        ctx,
        resource.unwrap_or(&path),
        &base,
        directory.as_ref(),
        allows_initial_search(ctx, dirfd, &path),
        policy,
        (ctx.proc.creds.1, ctx.proc.creds.3),
    )?;
    if resource.is_some() {
        return Err(Errno::EPERM);
    }
    Ok(result)
}

pub(super) fn statfs64(ctx: &mut Ctx<'_>, path: u64, buf: u64) -> SysResult {
    let (_, entry) = lookup(ctx, AT_FDCWD, path, LinkPolicy::Follow)?;
    if entry.workspace_mode().is_none() {
        return Err(Errno::ENOTSUP);
    }
    super::write_workspace_statfs(ctx, buf)
}

pub(super) fn pathconf(ctx: &Ctx<'_>, path: u64, name: i32) -> SysResult {
    let (_, entry) = lookup(ctx, AT_FDCWD, path, LinkPolicy::Follow)?;
    if entry.workspace_mode().is_none() {
        return Err(Errno::ENOTSUP);
    }
    super::workspace_pathconf(name)
}

fn lookup_as(
    ctx: &Ctx<'_>,
    path: &[u8],
    base: &[u8],
    directory: Option<&Arc<WorkspaceDirectory>>,
    allow_search: bool,
    policy: LinkPolicy,
    ids: (u32, u32),
) -> Result<(String, Entry), Errno> {
    let files = ctx.proc.vfs.files().ok_or(Errno::ENOTSUP)?;
    let (absolute, retained) = path_with_workspace_base(path, base, directory, ids)?;
    if let Some(entry) = retained {
        return Ok((absolute, entry));
    }
    if allow_search && let Some(directory) = directory.filter(|directory| directory.linked()) {
        let relative = std::str::from_utf8(path).map_err(|_| Errno::EINVAL)?;
        return files
            .lookup_from_workspace_search(&absolute, relative, directory, policy, ids)
            .map_err(Errno::from);
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
        false,
        LinkPolicy::Follow,
        (ctx.proc.creds.1, ctx.proc.creds.3),
    )
}

pub(in crate::user::darwin::syscall::bsd) fn link_policy(flags: u32) -> LinkPolicy {
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
    let resource = resource_base(&path);
    let (_, entry) = lookup_as(
        ctx,
        resource.unwrap_or(&path),
        &base,
        directory.as_ref(),
        allows_initial_search(ctx, dirfd, &path),
        link_policy(flags),
        ids,
    )?;
    if resource.is_some() {
        return Err(Errno::EPERM);
    }
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
    if let Some((fd, file, waiter, entered_flags)) = lifetime::entered_workspace_open(ctx.thread) {
        let result = workspace_locks::resume(ctx, fd, &file, waiter);
        return finish_locked_open(ctx, fd, file, entered_flags, result);
    }

    let workspace = ctx.proc.vfs.files().is_some_and(|f| f.has_workspace());
    let lock_flags = if workspace {
        flags & (O_SHLOCK | O_EXLOCK)
    } else {
        0
    };
    if flags & (O_CREAT | O_TRUNC) != 0 && workspace {
        ctx.proc.fds.lowest_free(0, ctx.proc.rlimits[8].0)?;
    }
    let (path, (base, directory)) = path_and_base(ctx, dirfd, path)?;
    let allow_search = allows_initial_search(ctx, dirfd, &path);
    let descriptor = (lock_flags != 0)
        .then(|| ctx.proc.fds.reserve_open(ctx.proc.rlimits[8].0))
        .transpose()?;
    let target = resolve_open_file(
        ctx,
        &path,
        &base,
        directory.as_ref(),
        allow_search,
        flags & !lock_flags,
        mode,
    );
    let file = match target {
        Ok(file) => file,
        Err(error) => {
            if let Some(fd) = descriptor {
                ctx.proc.fds.release(fd);
            }
            return Err(error);
        }
    };
    if let Some(fd) = descriptor {
        let result = workspace_locks::lock_open(ctx, fd, &file, flags);
        return finish_locked_open(ctx, fd, file, flags, result);
    }

    truncate_opened(ctx, &file, flags)?;
    let fd = ctx.proc.fds.install_with(
        file,
        flags & O_CLOEXEC != 0,
        flags & O_CLOFORK != 0,
        0,
        ctx.proc.rlimits[8].0,
    )?;
    Ok(Rv::one(fd as u64))
}

fn finish_locked_open(
    ctx: &mut Ctx<'_>,
    fd: i32,
    file: FileRef,
    flags: u32,
    result: SysResult,
) -> SysResult {
    if ctx.thread.wait.is_some() {
        return result;
    }
    ctx.proc.fds.release(fd);
    result?;
    truncate_opened(ctx, &file, flags)?;
    ctx.proc
        .fds
        .install_at(fd as usize, file, flags & O_CLOEXEC != 0);
    ctx.proc.fds.get_mut(fd)?.clofork = flags & O_CLOFORK != 0;
    Ok(Rv::one(fd as u64))
}

pub(super) fn unlinkat(ctx: &Ctx<'_>, dirfd: i32, path: u64, flags: u32) -> SysResult {
    if flags & !AT_REMOVEDIR != 0 {
        return Err(Errno::EINVAL);
    }
    let files = ctx.proc.vfs.files().ok_or(Errno::EROFS)?;
    let (path, (base, directory)) = path_and_base(ctx, dirfd, path)?;
    let ids = (ctx.proc.creds.1, ctx.proc.creds.3);
    if flags == 0
        && let Some(resource) = resource_base(&path)
    {
        let (_, entry) = lookup_as(
            ctx,
            resource,
            &base,
            directory.as_ref(),
            allows_initial_search(ctx, dirfd, &path),
            LinkPolicy::Follow,
            ids,
        )?;
        return Err(if entry.workspace_file().is_some() {
            Errno::ENOTSUP
        } else {
            Errno::ENOENT
        });
    }
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

pub(super) fn linkat(
    ctx: &Ctx<'_>,
    fromfd: i32,
    from: u64,
    tofd: i32,
    to: u64,
    flags: u32,
) -> SysResult {
    let policy = match flags {
        0 => LinkPolicy::NoFollowLast,
        AT_SYMLINK_FOLLOW => LinkPolicy::Follow,
        _ => return Err(Errno::EINVAL),
    };
    let files = ctx.proc.vfs.files().ok_or(Errno::EROFS)?;
    let (_, source) = lookup(ctx, fromfd, from, policy)?;
    let (path, (base, directory)) = path_and_base(ctx, tofd, to)?;
    let ids = (ctx.proc.creds.1, ctx.proc.creds.3);
    let (absolute, retained) = path_with_workspace_base(&path, &base, directory.as_ref(), ids)?;
    if retained.is_some() {
        return Err(Errno::ENOENT);
    }
    files.link_workspace_entry(source, &absolute, ids, &[])?;
    Ok(Rv::one(0))
}

const CLONE_NOFOLLOW: u32 = 1;
const CLONE_NOOWNERCOPY: u32 = 2;
const CLONE_ACL: u32 = 4;
const CLONE_NOFOLLOW_ANY: u32 = 8;
const CLONE_RESOLVE_BENEATH: u32 = 16;

fn clone_policy(flags: u32) -> Result<LinkPolicy, Errno> {
    let known =
        CLONE_NOFOLLOW | CLONE_NOOWNERCOPY | CLONE_ACL | CLONE_NOFOLLOW_ANY | CLONE_RESOLVE_BENEATH;
    if flags & !known != 0 {
        return Err(Errno::EINVAL);
    }
    // A confined workspace still cannot satisfy the caller's separate
    // constraint on traversal relative to the selected directory descriptor.
    if flags & CLONE_RESOLVE_BENEATH != 0 {
        return Err(Errno::ENOTSUP);
    }
    Ok(
        match (flags & CLONE_NOFOLLOW != 0, flags & CLONE_NOFOLLOW_ANY != 0) {
            (false, false) => LinkPolicy::Follow,
            (true, false) => LinkPolicy::NoFollowLast,
            (false, true) => LinkPolicy::NoFollowAny,
            (true, true) => LinkPolicy::NoFollowAncestors,
        },
    )
}

pub(in crate::user::darwin::syscall::bsd) fn clonefileat(
    ctx: &Ctx<'_>,
    fromfd: i32,
    from: u64,
    tofd: i32,
    to: u64,
    flags: u32,
) -> SysResult {
    let policy = clone_policy(flags)?;
    let (_, source) = lookup(ctx, fromfd, from, policy)?;
    clone_file(ctx, &source, tofd, to, flags, policy, false)
}

pub(in crate::user::darwin::syscall::bsd) fn fclonefileat(
    ctx: &Ctx<'_>,
    fromfd: i32,
    tofd: i32,
    to: u64,
    flags: u32,
) -> SysResult {
    let policy = clone_policy(flags)?;
    let file = ctx.proc.fds.file(fromfd)?;
    let open_flags = *file.flags.lock().map_err(|_| Errno::EIO)?;
    if open_flags & O_ACCMODE == O_WRONLY || open_flags & (O_EXEC | O_EVTONLY) != 0 {
        return Err(Errno::EBADF);
    }
    let FileKind::Embedded(object) = &file.kind else {
        return Err(Errno::EINVAL);
    };
    if object.resource().is_some() {
        return Err(Errno::ENOTSUP);
    }
    let source = object.entry().ok_or(Errno::EINVAL)?;
    clone_file(ctx, source, tofd, to, flags, policy, true)
}

fn clone_file(
    ctx: &Ctx<'_>,
    source: &Entry,
    tofd: i32,
    to: u64,
    flags: u32,
    policy: LinkPolicy,
    opened_for_read: bool,
) -> SysResult {
    let files = ctx.proc.vfs.files().ok_or(Errno::ENOTSUP)?;
    let (path, (base, directory)) = path_and_base(ctx, tofd, to)?;
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    let ids = (ctx.proc.creds.1, ctx.proc.creds.3);
    let (absolute, retained) = path_with_workspace_base(&path, &base, directory.as_ref(), ids)?;
    if retained.is_some() {
        return Err(Errno::EEXIST);
    }
    let search_from = if allows_initial_search(ctx, tofd, &path)
        && let Some(directory) = directory.as_ref().filter(|directory| directory.linked())
    {
        Some((
            std::str::from_utf8(&path).map_err(|_| Errno::EINVAL)?,
            directory,
        ))
    } else {
        None
    };
    let target = WorkspaceCloneDestination {
        path: &absolute,
        policy,
        search_from,
        ids,
        copy_owner: flags & CLONE_NOOWNERCOPY == 0,
    };
    match files.clone_workspace_leaf(source, target, opened_for_read) {
        Ok(()) => Ok(Rv::one(0)),
        Err(crate::user::supplied_fs::Error::IsDirectory) => Err(Errno::ENOTSUP),
        Err(crate::user::supplied_fs::Error::NotRegular) => Err(Errno::EINVAL),
        Err(error) => Err(error.into()),
    }
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
    allow_search: bool,
    flags: u32,
    mode: u32,
) -> Result<Arc<OpenFile>, Errno> {
    let file = resolve_open_file(ctx, path, base, directory, allow_search, flags, mode)?;
    truncate_opened(ctx, &file, flags)?;
    Ok(file)
}

pub(in crate::user::darwin) fn resolve_open_file(
    ctx: &Ctx<'_>,
    path: &[u8],
    base: &[u8],
    directory: Option<&Arc<WorkspaceDirectory>>,
    allow_search: bool,
    flags: u32,
    mode: u32,
) -> Result<FileRef, Errno> {
    let owner = (ctx.proc.creds.1, ctx.proc.creds.3);
    if let Some(resource) = resource_base(path) {
        let (policy, search, _) = open_policy(flags)?;
        let (path, entry) = lookup_as(ctx, resource, base, directory, allow_search, policy, owner)?;
        if search || flags & O_DIRECTORY != 0 {
            return Err(Errno::ENOTDIR);
        }
        return OpenFile::resource_fork(path, entry, flags, owner).map(Arc::new);
    }
    open_or_create(
        flags,
        owner,
        |policy| lookup_as(ctx, path, base, directory, allow_search, policy, owner),
        |policy, exclusive| {
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
            if allow_search
                && let Some(directory) = directory.filter(|directory| directory.linked())
            {
                let relative = std::str::from_utf8(path).map_err(|_| Errno::EINVAL)?;
                return files
                    .create_from_workspace_search(
                        &absolute,
                        (relative, directory),
                        policy,
                        mode,
                        owner,
                        exclusive,
                    )
                    .map_err(Errno::from);
            }
            let absolute = if policy == LinkPolicy::Follow {
                files.workspace_create_path(&absolute, owner, &[])?
            } else {
                absolute
            };
            files
                .create_workspace_file_with_status(&absolute, mode, owner, &[], exclusive)
                .map_err(Errno::from)
        },
    )
}

// The kernel acquires the advisory lock before shortening the vnode.
pub(in crate::user::darwin) fn truncate_opened(
    ctx: &Ctx<'_>,
    file: &FileRef,
    flags: u32,
) -> Result<(), Errno> {
    use crate::user::mm::PageSource;

    if flags & O_TRUNC != 0
        && let FileKind::Embedded(object) = &file.kind
    {
        if let Some((workspace, _)) = object.workspace() {
            workspace.resize(0)?;
            ctx.space().truncated(PageSource::identity(workspace), 0);
        } else if let Some((fork, _)) = object.resource() {
            fork.resize(0)?;
            ctx.space()
                .truncated(PageSource::identity(fork.as_ref()), 0);
        }
    }
    Ok(())
}

fn open_policy(flags: u32) -> Result<(LinkPolicy, bool, bool), Errno> {
    let search = flags & O_SEARCH == O_SEARCH;
    if flags & O_ACCMODE == O_ACCMODE || (search && flags & (O_ACCMODE | O_CREAT) != 0) {
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
        | O_CLOFORK
        | if search { O_EXEC } else { 0 };
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
    Ok((policy, search, exclusive))
}

fn open_or_create(
    flags: u32,
    owner: (u32, u32),
    lookup: impl FnOnce(LinkPolicy) -> Result<(String, Entry), Errno>,
    create: impl FnOnce(LinkPolicy, bool) -> Result<(String, Entry, bool), Errno>,
) -> Result<Arc<OpenFile>, Errno> {
    let (policy, search, exclusive) = open_policy(flags)?;
    let (path, entry, created) = match lookup(policy) {
        Ok(_) if exclusive => return Err(Errno::EEXIST),
        Ok((path, entry)) => (path, entry, false),
        Err(Errno::ENOENT) if flags & O_CREAT != 0 => create(policy, exclusive)?,
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
    if search {
        if !entry.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        if flags & O_TRUNC != 0 {
            return Err(Errno::EISDIR);
        }
        if let Some(directory) = entry.workspace_directory()
            && !directory.permits(1, owner, &[])
        {
            return Err(Errno::EACCES);
        }
        let status = O_EXEC | (flags & O_STATUS_FLAGS);
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
        OpenFile::device(path, device, entry.ino, status)?
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
    let stat = path_stat(ctx, dirfd, path, link_policy(flags), false)?;
    ctx.write(buf, &stat.bytes())?;
    Ok(Rv::one(0))
}

pub(in crate::user::darwin::syscall::bsd) fn path_stat(
    ctx: &Ctx<'_>,
    dirfd: i32,
    address: u64,
    policy: LinkPolicy,
    workspace_only: bool,
) -> Result<Stat, Errno> {
    let (path, (base, directory)) = path_and_base(ctx, dirfd, address)?;
    let resource = resource_base(&path);
    let owner = (ctx.proc.creds.1, ctx.proc.creds.3);
    let (_, entry) = lookup_as(
        ctx,
        resource.unwrap_or(&path),
        &base,
        directory.as_ref(),
        allows_initial_search(ctx, dirfd, &path),
        policy,
        owner,
    )?;
    if resource.is_some() {
        if entry.workspace_file().is_none() {
            return Err(Errno::ENOENT);
        }
        let info = entry.workspace_xattrs(0, owner, &[])?.resource_stat()?;
        return EmbeddedFile::resource_stat(&entry, info);
    }
    if workspace_only && entry.workspace_mode().is_none() {
        return Err(Errno::EPERM);
    }
    entry_stat(entry)
}

pub(in crate::user::darwin::syscall::bsd) fn entry_stat(entry: Entry) -> Result<Stat, Errno> {
    if let Some(device) = entry.device() {
        Ok(EmbeddedFile::device_stat(device, entry.ino))
    } else {
        EmbeddedFile::Supplied {
            entry,
            cursor: Mutex::new(0),
            access: O_RDONLY,
        }
        .stat()
    }
}
