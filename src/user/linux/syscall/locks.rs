//! File-lock calls: `flock` and the record-lock commands of `fcntl`
//! (`fs/locks.c`, `fs/fcntl.c`), on host locks ([`fs::locks`]).
//!
//! Each call checks its arguments in the kernel's order, then tries the
//! host lock without sleeping. A call that must wait (`flock` without
//! `LOCK_NB`, `F_SETLKW`, `F_OFD_SETLKW`) sleeps and tries again every
//! [`RETRY`] until the lock is granted or a signal ends the wait with
//! `-ERESTARTSYS`, as `wait_event_interruptible` does; other guest threads
//! run meanwhile. Waiting this way detects no deadlocks: where Linux fails a
//! POSIX wait that would deadlock with `EDEADLK`, the wait lasts until a
//! signal. Descriptions the host cannot lock (anonymous inodes, synthesized
//! `/proc` files, and on macOS pipes and sockets) are granted every lock.
//!
//! [`fs::locks`]: super::super::fs::locks

use std::time::{Duration, Instant};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::O_PATH;
use super::super::fs::fd::{FileObject, OpenFile};
use super::super::fs::locks::{self, F_RDLCK, F_UNLCK, F_WRLCK, OFFSET_MAX, Owner, Range};
use super::super::signal::deliver::restart::ERESTARTSYS;
use super::super::wait::{Resume, Wait};
use super::{Ctx, SysResult};

/// How long a waiting lock call sleeps between attempts.
pub const RETRY: Duration = Duration::from_millis(2);

/// Sleeps until the next attempt of a waiting lock call, or ends it with
/// `-ERESTARTSYS` if a signal is pending.
fn wait(c: &mut Ctx<'_>) -> Errno {
    if c.signal_pending() {
        return Errno(ERESTARTSYS);
    }
    c.block(Wait::until(Some(Instant::now() + RETRY)), Resume::Retry)
}

/// `flock` (`SYSCALL_DEFINE2(flock)`).
pub fn flock(c: &mut Ctx<'_>, fd: i32, cmd: u32) -> SysResult {
    const LOCK_SH: u32 = 1;
    const LOCK_EX: u32 = 2;
    const LOCK_NB: u32 = 4;
    const LOCK_UN: u32 = 8;
    const LOCK_MAND: u32 = 32;
    // LOCK_MAND requests are ignored, as since Linux 5.15.
    if cmd & LOCK_MAND != 0 {
        return Ok(0);
    }
    let op = match cmd & !LOCK_NB {
        LOCK_SH => libc::LOCK_SH,
        LOCK_EX => libc::LOCK_EX,
        LOCK_UN => libc::LOCK_UN,
        _ => return Err(Errno(EINVAL)),
    };
    // fdget: an O_PATH descriptor is no descriptor here.
    let file = c.p.fds.file(fd)?;
    if file.flags() & O_PATH != 0 {
        return Err(Errno(EBADF));
    }
    if op != libc::LOCK_UN && !file.readable() && !file.writable() {
        return Err(Errno(EBADF));
    }
    let Some(host) = locks::host_fd(&file) else {
        return Ok(0);
    };
    match locks::flock(host, op) {
        Ok(()) => Ok(0),
        Err(Errno(EAGAIN)) if cmd & LOCK_NB == 0 => Err(wait(c)),
        Err(e) => Err(e),
    }
}

/// A guest `struct flock` (the same 32 bytes on every supported ABI:
/// `short l_type, l_whence; off_t l_start, l_len; pid_t l_pid`).
struct Flock {
    kind: i16,
    whence: i16,
    start: i64,
    len: i64,
    pid: i32,
}

impl Flock {
    fn read(c: &Ctx<'_>, addr: u64) -> Result<Self, Errno> {
        let b = c.read_mem(addr, 32)?;
        let i64_at = |at: usize| i64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        Ok(Flock {
            kind: i16::from_le_bytes([b[0], b[1]]),
            whence: i16::from_le_bytes([b[2], b[3]]),
            start: i64_at(8),
            len: i64_at(16),
            pid: i32::from_le_bytes(b[24..28].try_into().unwrap()),
        })
    }

    fn write(&self, c: &Ctx<'_>, addr: u64) -> Result<(), Errno> {
        let mut b = c.read_mem(addr, 32)?;
        b[0..2].copy_from_slice(&self.kind.to_le_bytes());
        b[2..4].copy_from_slice(&self.whence.to_le_bytes());
        b[8..16].copy_from_slice(&self.start.to_le_bytes());
        b[16..24].copy_from_slice(&self.len.to_le_bytes());
        b[24..28].copy_from_slice(&self.pid.to_le_bytes());
        c.write_mem(addr, &b)
    }

    /// `flock64_to_posix_lock`: the absolute range, from the description's
    /// position (`SEEK_CUR`) or size (`SEEK_END`).
    fn range(&self, file: &OpenFile) -> Result<Range, Errno> {
        const SEEK_SET: i16 = 0;
        const SEEK_CUR: i16 = 1;
        const SEEK_END: i16 = 2;
        let base = match self.whence {
            SEEK_SET => 0,
            SEEK_CUR => file.seek(0, 1).map_or(0, |p| p as i64),
            SEEK_END => match &file.object {
                FileObject::Host(f) => f.metadata().map_or(0, |m| m.len() as i64),
                _ => 0,
            },
            _ => return Err(Errno(EINVAL)),
        };
        if self.start > OFFSET_MAX - base {
            return Err(Errno(EOVERFLOW));
        }
        let mut start = base + self.start;
        if start < 0 {
            return Err(Errno(EINVAL));
        }
        let end;
        if self.len > 0 {
            if self.len - 1 > OFFSET_MAX - start {
                return Err(Errno(EOVERFLOW));
            }
            end = start + (self.len - 1);
        } else if self.len < 0 {
            if start + self.len < 0 {
                return Err(Errno(EINVAL));
            }
            end = start - 1;
            start += self.len;
        } else {
            end = OFFSET_MAX;
        }
        Ok(Range { start, end })
    }
}

/// The description behind `fd` for a record-lock command: `EBADF` for a
/// closed or `O_PATH` descriptor (`check_fcntl_cmd`), then the structure.
fn setup(c: &Ctx<'_>, fd: i32, arg: u64) -> Result<(std::sync::Arc<OpenFile>, Flock), Errno> {
    let file = c.p.fds.file(fd)?;
    if file.flags() & O_PATH != 0 {
        return Err(Errno(EBADF));
    }
    let fl = Flock::read(c, arg)?;
    Ok((file, fl))
}

/// `F_GETLK` and `F_OFD_GETLK` (`fcntl_getlk`).
pub fn getlk(c: &mut Ctx<'_>, fd: i32, arg: u64, owner: Owner) -> SysResult {
    #[cfg(not(target_os = "linux"))]
    if owner == Owner::Description {
        return Err(Errno(EINVAL));
    }
    let (file, mut fl) = setup(c, fd, arg)?;
    if owner == Owner::Process && fl.kind != F_RDLCK && fl.kind != F_WRLCK {
        return Err(Errno(EINVAL));
    }
    let range = fl.range(&file)?;
    // assign_type
    if !matches!(fl.kind, F_RDLCK | F_WRLCK | F_UNLCK) {
        return Err(Errno(EINVAL));
    }
    if owner == Owner::Description && fl.pid != 0 {
        return Err(Errno(EINVAL));
    }
    let conflict = match locks::host_fd(&file) {
        // An F_UNLCK request tests for nothing.
        Some(host) if fl.kind != F_UNLCK => locks::test(host, owner, fl.kind, range)?,
        _ => None,
    };
    match conflict {
        Some(k) => {
            fl.kind = k.kind;
            fl.whence = 0;
            fl.start = k.range.start;
            fl.len = if k.range.end == OFFSET_MAX {
                0
            } else {
                k.range.end - k.range.start + 1
            };
            fl.pid = k.pid;
        }
        None => fl.kind = F_UNLCK,
    }
    fl.write(c, arg)?;
    Ok(0)
}

/// `F_SETLK`, `F_SETLKW`, `F_OFD_SETLK`, and `F_OFD_SETLKW`
/// (`fcntl_setlk`).
pub fn setlk(c: &mut Ctx<'_>, fd: i32, arg: u64, owner: Owner, sleep: bool) -> SysResult {
    #[cfg(not(target_os = "linux"))]
    if owner == Owner::Description {
        return Err(Errno(EINVAL));
    }
    let (file, fl) = setup(c, fd, arg)?;
    let range = fl.range(&file)?;
    // assign_type, then check_fmode_for_setlk.
    match fl.kind {
        F_RDLCK if !file.readable() => return Err(Errno(EBADF)),
        F_WRLCK if !file.writable() => return Err(Errno(EBADF)),
        F_RDLCK | F_WRLCK | F_UNLCK => {}
        _ => return Err(Errno(EINVAL)),
    }
    if owner == Owner::Description && fl.pid != 0 {
        return Err(Errno(EINVAL));
    }
    let Some(host) = locks::host_fd(&file) else {
        return Ok(0);
    };
    match locks::set(host, owner, fl.kind, range) {
        Ok(()) => {
            if owner == Owner::Process && fl.kind != F_UNLCK {
                locks::note_posix(host);
            }
            Ok(0)
        }
        Err(Errno(EAGAIN)) if sleep => Err(wait(c)),
        Err(e) => Err(e),
    }
}
