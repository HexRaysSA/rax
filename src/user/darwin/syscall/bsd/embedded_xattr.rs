//! Extended-attribute enumeration on private workspace inodes.

use super::{Ctx, Errno, Rv, SysResult, path};
use crate::user::darwin::fd::FileKind;
use crate::user::darwin::host::AT_FDCWD;
use crate::user::supplied_fs::LinkPolicy;

// Darwin options from <sys/xattr.h>.
const NOFOLLOW: u32 = 0x0001;
const NOSECURITY: u32 = 0x0008;
const NODEFAULT: u32 = 0x0010;
const NOFOLLOW_ANY: u32 = 0x0040;
const RESOLVE_BENEATH: u32 = 0x0080;

pub(super) fn list_path(ctx: &Ctx<'_>, addr: u64, options: u32) -> SysResult {
    if options & (NOSECURITY | NODEFAULT) != 0 {
        return Err(Errno::EINVAL);
    }
    if options & RESOLVE_BENEATH != 0 {
        return Err(Errno::ENOTSUP);
    }
    let policy = match (options & NOFOLLOW_ANY != 0, options & NOFOLLOW != 0) {
        (true, true) => LinkPolicy::NoFollowAncestors,
        (true, false) => LinkPolicy::NoFollowAny,
        (false, true) => LinkPolicy::NoFollowLast,
        (false, false) => LinkPolicy::Follow,
    };
    let (_, entry) = path::embedded::lookup(ctx, AT_FDCWD, addr, policy)?;
    if entry.workspace_mode().is_none() {
        return Err(Errno::ENOTSUP);
    }
    // Private inodes currently have no extended-attribute payloads.
    Ok(Rv::one(0))
}

pub(super) fn list_file(ctx: &Ctx<'_>, fd: i32, options: u32) -> SysResult {
    if options & (NOSECURITY | NODEFAULT | NOFOLLOW | NOFOLLOW_ANY | RESOLVE_BENEATH) != 0 {
        return Err(Errno::EINVAL);
    }
    let file = ctx.proc.fds.file(fd)?;
    match &file.kind {
        FileKind::Embedded(data) if data.entry().is_some_and(|e| e.workspace_mode().is_some()) => {
            Ok(Rv::one(0))
        }
        FileKind::Embedded(data) if data.entry().is_some() => Err(Errno::ENOTSUP),
        _ => Err(Errno::EINVAL),
    }
}
