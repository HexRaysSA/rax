//! Mode and timestamp changes on private guest filesystem objects.

use super::{Ctx, Errno, Rv, SysResult, path};
use crate::user::darwin::abi::types::{Timespec, Timeval};
use crate::user::darwin::fd::FileKind;
use crate::user::darwin::host::{AT_FDCWD, AT_SYMLINK_NOFOLLOW, AT_SYMLINK_NOFOLLOW_ANY};
use crate::user::supplied_fs::{
    Entry, WorkspaceFlavor, WorkspaceSetTime as SetTime, WorkspaceTimeUpdate, WorkspaceTimestamp,
};

fn fd_entry(ctx: &Ctx<'_>, fd: i32) -> Result<Entry, Errno> {
    let file = ctx.proc.fds.file(fd)?;
    match &file.kind {
        FileKind::Embedded(data) if data.resource().is_some() => Err(Errno::EPERM),
        FileKind::Embedded(data) => data.entry().cloned().ok_or(Errno::ENOTSUP),
        _ => Err(Errno::ENOTSUP),
    }
}

fn path_entry(ctx: &Ctx<'_>, dirfd: i32, addr: u64, flags: u32) -> Result<Entry, Errno> {
    let policy = path::embedded::link_policy(flags);
    path::embedded::lookup(ctx, dirfd, addr, policy).map(|(_, entry)| entry)
}

fn set_mode(ctx: &Ctx<'_>, entry: &Entry, mode: u32) -> SysResult {
    entry.set_workspace_mode(mode, (ctx.proc.creds.1, ctx.proc.creds.3), &[])?;
    Ok(Rv::one(0))
}

pub(super) fn fchmod(ctx: &Ctx<'_>, fd: i32, mode: u32) -> SysResult {
    set_mode(ctx, &fd_entry(ctx, fd)?, mode)
}

pub(super) fn fchmodat(ctx: &Ctx<'_>, fd: i32, path: u64, mode: u32, flags: u32) -> SysResult {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_SYMLINK_NOFOLLOW_ANY) != 0 {
        return Err(Errno::EINVAL);
    }
    set_mode(ctx, &path_entry(ctx, fd, path, flags)?, mode)
}

fn set_times(ctx: &Ctx<'_>, entry: &Entry, times: [SetTime; 2], allow_write: bool) -> SysResult {
    let update = WorkspaceTimeUpdate {
        times,
        allow_write,
        flavor: WorkspaceFlavor::Darwin,
    };
    entry.set_workspace_times(update, (ctx.proc.creds.1, ctx.proc.creds.3), &[])?;
    Ok(Rv::one(0))
}

fn timestamp(seconds: i64, nanoseconds: i64) -> Result<SetTime, Errno> {
    // Darwin's attribute path normalizes timespecs as APFS stores them.
    const NANOS_PER_SECOND: i64 = 1_000_000_000;
    let seconds = seconds
        .checked_add(nanoseconds.div_euclid(NANOS_PER_SECOND))
        .ok_or(Errno::EOVERFLOW)?;
    Ok(SetTime::At(WorkspaceTimestamp {
        seconds,
        nanoseconds: nanoseconds.rem_euclid(NANOS_PER_SECOND),
    }))
}

pub(super) fn utimes(ctx: &Ctx<'_>, fd: Option<i32>, path: u64, times: u64) -> SysResult {
    let entry = match fd {
        Some(fd) => fd_entry(ctx, fd)?,
        None => path_entry(ctx, AT_FDCWD, path, 0)?,
    };
    if times == 0 {
        return set_times(ctx, &entry, [SetTime::Now; 2], true);
    }
    let bytes = ctx.read(times, 32)?;
    let decode = |bytes: &[u8]| {
        let value = Timeval::from_bytes(bytes.try_into().expect("Darwin timeval"));
        if !(0..1_000_000).contains(&value.usec) {
            return Err(Errno::EINVAL);
        }
        timestamp(value.sec, i64::from(value.usec) * 1000)
    };
    let times = [decode(&bytes[..16])?, decode(&bytes[16..])?];
    set_times(ctx, &entry, times, false)
}

/// The timestamp subset used by the installed futimens and utimensat wrappers.
pub(super) fn setattrlist(
    ctx: &Ctx<'_>,
    dirfd: i32,
    path: Option<u64>,
    alist: u64,
    buf: u64,
    size: u64,
    options: u64,
) -> SysResult {
    const FSOPT_NOFOLLOW: u64 = 0x0001;
    const FSOPT_UTIMES_NULL: u64 = 0x0400;
    const FSOPT_NOFOLLOW_ANY: u64 = 0x0800;
    const MODTIME: u32 = 0x0400;
    const ACCTIME: u32 = 0x1000;
    if options & !(FSOPT_NOFOLLOW | FSOPT_UTIMES_NULL | FSOPT_NOFOLLOW_ANY) != 0 {
        return Err(Errno::ENOTSUP);
    }
    let mut flags = 0;
    if options & FSOPT_NOFOLLOW != 0 {
        flags |= AT_SYMLINK_NOFOLLOW;
    }
    if options & FSOPT_NOFOLLOW_ANY != 0 {
        flags |= AT_SYMLINK_NOFOLLOW_ANY;
    }
    let entry = match path {
        Some(addr) => path_entry(ctx, dirfd, addr, flags)?,
        None => fd_entry(ctx, dirfd)?,
    };
    let attrs = ctx.read(alist, 24)?;
    if u16::from_le_bytes(attrs[..2].try_into().expect("attrlist count")) != 5 {
        return Err(Errno::EINVAL);
    }
    let common = u32::from_le_bytes(attrs[4..8].try_into().expect("attrlist common bitmap"));
    if common & !(MODTIME | ACCTIME) != 0 || attrs[8..].iter().any(|&byte| byte != 0) {
        return Err(Errno::ENOTSUP);
    }
    let required = u64::from(common.count_ones()) * 16;
    if size != required {
        return Err(Errno::EINVAL);
    }
    if required == 0 {
        return set_times(ctx, &entry, [SetTime::Omit; 2], false);
    }
    let bytes = ctx.read(buf, required as usize)?;
    let mut payloads = bytes.chunks_exact(16);
    let mut times = [SetTime::Omit; 2];
    for (flag, index) in [(MODTIME, 1), (ACCTIME, 0)] {
        if common & flag != 0 {
            let payload = payloads.next().expect("validated attrlist size");
            let value = Timespec::from_bytes(payload.try_into().expect("Darwin timespec"));
            times[index] = timestamp(value.sec, value.nsec)?;
        }
    }
    set_times(ctx, &entry, times, options & FSOPT_UTIMES_NULL != 0)
}
