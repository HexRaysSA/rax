//! Darwin extended attributes on private workspace inodes and installed files.

use super::{Ctx, Errno, Rv, SysResult, path, xattr_common as xattr};
use crate::user::darwin::abi::tables::nr;
use crate::user::darwin::fd::FileKind;
use crate::user::darwin::host::AT_FDCWD;
use crate::user::supplied_fs::{
    Entry, Error, LinkPolicy, MAX_XATTR_VALUE, RESOURCE_FORK, SetXattr,
};
use xattr::opt::{NOFOLLOW, NOFOLLOW_ANY, RESOLVE_BENEATH};

const CREATE: u32 = 0x0002;
const REPLACE: u32 = 0x0004;
const FINDER_INFO: &[u8] = b"com.apple.FinderInfo";

#[derive(Clone, Copy)]
enum Target {
    Path(u64),
    File(i32),
}

impl Target {
    fn check_options(self, options: u32) -> Result<(), Errno> {
        let refused = match self {
            Self::Path(_) => xattr::PATH_REFUSED,
            Self::File(_) => xattr::FD_REFUSED,
        };
        if options & refused != 0 {
            return Err(Errno::EINVAL);
        }
        if options & RESOLVE_BENEATH != 0 {
            return Err(Errno::ENOTSUP);
        }
        Ok(())
    }

    fn resolve(self, ctx: &Ctx<'_>, options: u32) -> Result<Entry, Errno> {
        match self {
            Self::Path(address) => {
                let policy = match (options & NOFOLLOW_ANY != 0, options & NOFOLLOW != 0) {
                    (true, true) => LinkPolicy::NoFollowAncestors,
                    (true, false) => LinkPolicy::NoFollowAny,
                    (false, true) => LinkPolicy::NoFollowLast,
                    (false, false) => LinkPolicy::Follow,
                };
                Ok(path::embedded::lookup(ctx, AT_FDCWD, address, policy)?.1)
            }
            Self::File(fd) => {
                let file = ctx.proc.fds.file(fd)?;
                match &file.kind {
                    FileKind::Embedded(data) if data.resource().is_some() => Err(Errno::EPERM),
                    FileKind::Embedded(data) => data.entry().cloned().ok_or(Errno::EINVAL),
                    _ => Err(Errno::EINVAL),
                }
            }
        }
    }
}

pub(super) fn call(ctx: &Ctx<'_>, number: u32, args: &[u64; 8]) -> SysResult {
    let target = match number {
        nr::FGETXATTR | nr::FSETXATTR | nr::FREMOVEXATTR | nr::FLISTXATTR => {
            Target::File(args[0] as i32)
        }
        _ => Target::Path(args[0]),
    };
    match number {
        nr::GETXATTR | nr::FGETXATTR => get(ctx, target, args),
        nr::SETXATTR | nr::FSETXATTR => set(ctx, target, args),
        nr::REMOVEXATTR | nr::FREMOVEXATTR => remove(ctx, target, args[1], args[2] as u32),
        nr::LISTXATTR | nr::FLISTXATTR => list(ctx, target, args[1], args[2], args[3] as u32),
        _ => unreachable!("not an extended-attribute syscall"),
    }
}

fn owner(ctx: &Ctx<'_>) -> (u32, u32) {
    (ctx.proc.creds.1, ctx.proc.creds.3)
}

fn errno(error: Error) -> Errno {
    match error {
        Error::NotFound => Errno::ENOATTR,
        Error::ReadOnly => Errno::ENOTSUP,
        error => Errno::from(error),
    }
}

fn attr_name(ctx: &Ctx<'_>, address: u64) -> Result<Vec<u8>, Errno> {
    let name = ctx.cstr(address, xattr::XATTR_MAXNAMELEN + 1)?;
    if xattr::protected(&name) {
        return Err(Errno::EPERM);
    }
    if name.is_empty() || std::str::from_utf8(&name).is_err() {
        return Err(Errno::EINVAL);
    }
    Ok(name)
}

fn get(ctx: &Ctx<'_>, target: Target, args: &[u64; 8]) -> SysResult {
    let [_, name, buffer, size, position, options, ..] = *args;
    let options = options as u32;
    target.check_options(options)?;
    let entry = target.resolve(ctx, options)?;
    let name = attr_name(ctx, name)?;
    let query = buffer == 0
        || match target {
            Target::Path(_) => size == u64::MAX || size == u64::from(u32::MAX),
            Target::File(_) => size == 0,
        };
    let position = position as u32 as usize;
    let is_resource = name == RESOURCE_FORK;
    if !query && position != 0 && !is_resource {
        return Err(Errno::EINVAL);
    }
    #[cfg(target_os = "macos")]
    if let Some(file) = entry.darwin_installed_file() {
        return super::xattr::read_installed(
            ctx,
            file,
            Some(&name),
            buffer,
            (!query).then_some(size),
            position as u32,
            options,
        );
    }
    let value = entry
        .workspace_xattrs(4, owner(ctx), &[])
        .and_then(|attrs| attrs.get(&name))
        .map_err(errno)?;
    if query {
        return Ok(Rv::one(value.len() as u64));
    }
    let value = if is_resource {
        let tail = &value[position.min(value.len())..];
        &tail[..size.min(tail.len() as u64) as usize]
    } else {
        &value
    };
    copy(ctx, buffer, size, value)
}

fn set(ctx: &Ctx<'_>, target: Target, args: &[u64; 8]) -> SysResult {
    let [_, name, buffer, size, position, options, ..] = *args;
    let options = options as u32;
    target.check_options(options)?;
    let name = attr_name(ctx, name)?;
    if size != 0 && buffer == 0 {
        return Err(Errno::EINVAL);
    }
    if size > i32::MAX as u64 {
        return Err(Errno::E2BIG);
    }
    let entry = target.resolve(ctx, options)?;
    let attrs = entry.workspace_xattrs(2, owner(ctx), &[]).map_err(errno)?;
    let rule = match options & (CREATE | REPLACE) {
        CREATE => SetXattr::Create,
        REPLACE => SetXattr::Replace,
        0 => SetXattr::Upsert,
        _ => return Err(Errno::EINVAL),
    };
    let position = position as u32 as usize;
    let offset = if name == RESOURCE_FORK {
        if entry.workspace_file().is_none() {
            return Err(Errno::EPERM);
        }
        Some(position)
    } else {
        if position != 0 {
            return Err(Errno::EINVAL);
        }
        if name == FINDER_INFO && size != 32 {
            return Err(Errno::ERANGE);
        }
        None
    };
    if size > MAX_XATTR_VALUE.saturating_sub(position) as u64 {
        return Err(Errno::ENOSPC);
    }
    let data = ctx.read(buffer, size as usize)?;
    // APFS treats all-zero FinderInfo as absent.
    let clear = name == FINDER_INFO && data.iter().all(|&byte| byte == 0);
    attrs
        .set(name, (!clear).then_some(data), offset, rule)
        .map_err(errno)?;
    entry.workspace_xattrs_changed();
    Ok(Rv::one(0))
}

fn remove(ctx: &Ctx<'_>, target: Target, name: u64, options: u32) -> SysResult {
    target.check_options(options)?;
    let name = attr_name(ctx, name)?;
    let entry = target.resolve(ctx, options)?;
    entry
        .workspace_xattrs(2, owner(ctx), &[])
        .and_then(|attrs| attrs.remove(&name))
        .map_err(errno)?;
    entry.workspace_xattrs_changed();
    Ok(Rv::one(0))
}

fn list(ctx: &Ctx<'_>, target: Target, buffer: u64, size: u64, options: u32) -> SysResult {
    target.check_options(options)?;
    let entry = target.resolve(ctx, options)?;
    let query = buffer == 0 || size == 0;
    #[cfg(target_os = "macos")]
    if let Some(file) = entry.darwin_installed_file() {
        return super::xattr::read_installed(
            ctx,
            file,
            None,
            buffer,
            (!query).then_some(size),
            0,
            options,
        );
    }
    let names = entry
        .workspace_xattrs(4, owner(ctx), &[])
        .and_then(|attrs| attrs.list())
        .map_err(errno)?;
    if query {
        return Ok(Rv::one(names.len() as u64));
    }
    copy(ctx, buffer, size, &names)
}

fn copy(ctx: &Ctx<'_>, buffer: u64, size: u64, value: &[u8]) -> SysResult {
    if size < value.len() as u64 {
        return Err(Errno::ERANGE);
    }
    ctx.write(buffer, value)?;
    Ok(Rv::one(value.len() as u64))
}
