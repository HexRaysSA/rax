//! File times (`fs/utimes.c`): `utimensat` and the older `utimes`,
//! `futimesat`, and `utime` (x86-64), all through `do_utimes`.
//!
//! A path is looked up (following a final symbolic link unless
//! `AT_SYMLINK_NOFOLLOW`) before the times are checked (`vfs_utimes`); a
//! null path with a descriptor other than `AT_FDCWD` sets that file's
//! times and takes no flags. `UTIME_NOW` for both times, or no times,
//! touches the file with the current time. The host sets the times of host
//! objects; pipes, sockets, and synthesized `/proc` files accept them
//! (Linux keeps them on inodes this emulation does not model), and
//! anonymous-inode files refuse them (`anon_inode_setattr`).

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::types::Timespec;
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::host::{self, SetTime};
use super::super::procfs::ProcEntry;
use super::path::{AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, Target, resolve, resolve_str};
use super::{Ctx, SysResult};

/// `UTIME_NOW`.
const UTIME_NOW: i64 = (1 << 30) - 1;
/// `UTIME_OMIT`.
const UTIME_OMIT: i64 = (1 << 30) - 2;

/// `nsec_valid`.
fn nsec_valid(nsec: i64) -> bool {
    nsec == UTIME_OMIT || nsec == UTIME_NOW || (0..=999_999_999).contains(&nsec)
}

/// `vfs_utimes`'s check and the times it sets.
fn times_of(times: Option<[Timespec; 2]>) -> Result<[SetTime; 2], Errno> {
    let Some(t) = times else {
        return Ok([SetTime::Now; 2]);
    };
    if !t.iter().all(|t| nsec_valid(t.nsec)) {
        return Err(Errno(EINVAL));
    }
    Ok(t.map(|t| match t.nsec {
        UTIME_NOW => SetTime::Now,
        UTIME_OMIT => SetTime::Omit,
        n => SetTime::At(t.sec, n),
    }))
}

/// `fsnotify_change`'s mask for times `t`.
fn notify_mask(t: &[SetTime; 2]) -> u32 {
    super::notify::times_mask(t[0] != SetTime::Omit, t[1] != SetTime::Omit)
}

/// Sets the times of an open file (`vfs_utimes` on its path).
fn file_times(c: &Ctx<'_>, file: &OpenFile, t: [SetTime; 2]) -> SysResult {
    match &file.object {
        FileObject::Host(f) => {
            host::set_fd_times(f, t)?;
            super::notify::changed_file(file, notify_mask(&t));
        }
        // An O_PATH description names its object by host path.
        FileObject::PathOnly => {
            let h = file.host_path.as_ref().ok_or(Errno(EBADF))?;
            let follow = file.ftype != FileType::Symlink;
            host::set_times(h, t, follow)?;
            super::notify::changed(c, h, follow, notify_mask(&t));
        }
        FileObject::Anon(_) => return Err(Errno(EOPNOTSUPP)),
        FileObject::PipeRead(_)
        | FileObject::PipeWrite(_)
        | FileObject::Socket(_)
        | FileObject::Synthetic(_) => {}
    }
    Ok(0)
}

/// `do_utimes`: a null `path` with a descriptor sets that file's times
/// (`do_utimes_fd`), anything else looks the path up (`do_utimes_path`).
fn do_utimes(
    c: &mut Ctx<'_>,
    dirfd: i32,
    path: u64,
    times: Option<[Timespec; 2]>,
    flags: u32,
) -> SysResult {
    if path == 0 && dirfd != AT_FDCWD {
        if flags != 0 {
            return Err(Errno(EINVAL));
        }
        let file = c.p.fds.file(dirfd)?;
        if matches!(file.object, FileObject::PathOnly) {
            return Err(Errno(EBADF));
        }
        return file_times(c, &file, times_of(times)?);
    }
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno(EINVAL));
    }
    if path == 0 {
        return Err(Errno(EFAULT));
    }
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let mut target = resolve(c, dirfd, path, flags, follow)?;
    // A /proc/<pid>/fd link leads to its file.
    while let (Target::Proc(ProcEntry::Link(link), _), true) = (&target, follow) {
        target = resolve_str(c, AT_FDCWD, link, true)?;
    }
    // user_path_at: the object must exist before its times are checked.
    if let Target::Host { host, .. } = &target {
        if follow {
            std::fs::metadata(host)?;
        } else {
            std::fs::symlink_metadata(host)?;
        }
    }
    let t = times_of(times)?;
    match target {
        Target::Host { host, .. } => {
            host::set_times(&host, t, follow)?;
            super::notify::changed(c, &host, follow, notify_mask(&t));
            Ok(0)
        }
        Target::Fd(file) => file_times(c, &file, t),
        Target::Proc(..) => Ok(0),
    }
}

/// Two `struct __kernel_timespec`.
fn read_timespecs(c: &Ctx<'_>, addr: u64) -> Result<[Timespec; 2], Errno> {
    let raw = c.read_mem(addr, 32)?;
    Ok([
        Timespec::decode(raw[..16].try_into().unwrap()),
        Timespec::decode(raw[16..].try_into().unwrap()),
    ])
}

/// `utimensat` (a null path with a descriptor is `futimens`): with both
/// times `UTIME_OMIT` there is nothing to do, and the path is not even
/// looked up.
pub fn utimensat(c: &mut Ctx<'_>, dirfd: i32, path: u64, times: u64, flags: u32) -> SysResult {
    let t = if times != 0 {
        let t = read_timespecs(c, times)?;
        if t[0].nsec == UTIME_OMIT && t[1].nsec == UTIME_OMIT {
            return Ok(0);
        }
        Some(t)
    } else {
        None
    };
    do_utimes(c, dirfd, path, t, flags)
}

/// `futimesat` (and `utimes`): two `struct __kernel_old_timeval`, whose
/// microseconds must lie in `[0, 1000000)` (`UTIME_NOW` and `UTIME_OMIT`
/// are not special here).
pub fn futimesat(c: &mut Ctx<'_>, dirfd: i32, path: u64, tv: u64) -> SysResult {
    let t = if tv != 0 {
        let raw = c.read_mem(tv, 32)?;
        let w = |i: usize| i64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
        let (s0, u0, s1, u1) = (w(0), w(1), w(2), w(3));
        if !(0..1_000_000).contains(&u0) || !(0..1_000_000).contains(&u1) {
            return Err(Errno(EINVAL));
        }
        Some([
            Timespec {
                sec: s0,
                nsec: u0 * 1000,
            },
            Timespec {
                sec: s1,
                nsec: u1 * 1000,
            },
        ])
    } else {
        None
    };
    do_utimes(c, dirfd, path, t, 0)
}

/// `utime`: a `struct utimbuf` of whole seconds (`actime`, `modtime`).
pub fn utime(c: &mut Ctx<'_>, path: u64, times: u64) -> SysResult {
    let t = if times != 0 {
        let raw = c.read_mem(times, 16)?;
        let w = |i: usize| i64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
        Some([
            Timespec { sec: w(0), nsec: 0 },
            Timespec { sec: w(1), nsec: 0 },
        ])
    } else {
        None
    };
    do_utimes(c, AT_FDCWD, path, t, 0)
}
