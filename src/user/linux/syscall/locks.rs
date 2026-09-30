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
#[cfg(unix)]
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

/// The `struct flock` layouts of the record-lock commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlockLayout {
    /// `struct flock` of the 64-bit ABIs (32 bytes: `short l_type,
    /// l_whence; off_t l_start, l_len; pid_t l_pid`). A reply keeps the
    /// caller's padding: `fcntl_getlk` returns the structure it read.
    Native,
    /// `struct compat_flock` (16 bytes: 32-bit start, length, and PID),
    /// written whole (`put_compat_flock`).
    Compat,
    /// `struct compat_flock64` (24 bytes, packed on x86: 64-bit start and
    /// length at offsets 4 and 12).
    Compat64,
    /// `struct compat_flock64` without `__ARCH_NEED_COMPAT_FLOCK64_PACKED`
    /// (arm64's for an ARM task: 32 bytes, the native offsets), written
    /// whole (`put_compat_flock64`).
    Compat64Aligned,
}

/// `COMPAT_OFF_T_MAX`.
const COMPAT_OFF_T_MAX: i64 = i32::MAX as i64;

/// A guest `struct flock`.
struct Flock {
    kind: i16,
    whence: i16,
    start: i64,
    len: i64,
    pid: i32,
}

impl Flock {
    fn read(c: &Ctx<'_>, addr: u64, layout: FlockLayout) -> Result<Self, Errno> {
        let size = match layout {
            FlockLayout::Native | FlockLayout::Compat64Aligned => 32,
            FlockLayout::Compat => 16,
            FlockLayout::Compat64 => 24,
        };
        let b = c.read_mem(addr, size)?;
        let i32_at = |at: usize| i32::from_le_bytes(b[at..at + 4].try_into().unwrap());
        let i64_at = |at: usize| i64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        let (start, len, pid) = match layout {
            FlockLayout::Native | FlockLayout::Compat64Aligned => {
                (i64_at(8), i64_at(16), i32_at(24))
            }
            FlockLayout::Compat => (i64::from(i32_at(4)), i64::from(i32_at(8)), i32_at(12)),
            FlockLayout::Compat64 => (i64_at(4), i64_at(12), i32_at(20)),
        };
        Ok(Flock {
            kind: i16::from_le_bytes([b[0], b[1]]),
            whence: i16::from_le_bytes([b[2], b[3]]),
            start,
            len,
            pid,
        })
    }

    fn write(&self, c: &Ctx<'_>, addr: u64, layout: FlockLayout) -> Result<(), Errno> {
        let mut b = match layout {
            FlockLayout::Native => c.read_mem(addr, 32)?,
            FlockLayout::Compat => vec![0; 16],
            FlockLayout::Compat64 => vec![0; 24],
            FlockLayout::Compat64Aligned => vec![0; 32],
        };
        b[0..2].copy_from_slice(&self.kind.to_le_bytes());
        b[2..4].copy_from_slice(&self.whence.to_le_bytes());
        match layout {
            FlockLayout::Native | FlockLayout::Compat64Aligned => {
                b[8..16].copy_from_slice(&self.start.to_le_bytes());
                b[16..24].copy_from_slice(&self.len.to_le_bytes());
                b[24..28].copy_from_slice(&self.pid.to_le_bytes());
            }
            FlockLayout::Compat => {
                b[4..8].copy_from_slice(&(self.start as i32).to_le_bytes());
                b[8..12].copy_from_slice(&(self.len as i32).to_le_bytes());
                b[12..16].copy_from_slice(&self.pid.to_le_bytes());
            }
            FlockLayout::Compat64 => {
                b[4..12].copy_from_slice(&self.start.to_le_bytes());
                b[12..20].copy_from_slice(&self.len.to_le_bytes());
                b[20..24].copy_from_slice(&self.pid.to_le_bytes());
            }
        }
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
fn setup(
    c: &Ctx<'_>,
    fd: i32,
    arg: u64,
    layout: FlockLayout,
) -> Result<(std::sync::Arc<OpenFile>, Flock), Errno> {
    let file = c.p.fds.file(fd)?;
    if file.flags() & O_PATH != 0 {
        return Err(Errno(EBADF));
    }
    let fl = Flock::read(c, arg, layout)?;
    #[cfg(not(unix))]
    if matches!(file.object, FileObject::Host(_)) {
        return Err(Errno(EPERM));
    }
    Ok((file, fl))
}

/// `F_GETLK` and `F_OFD_GETLK` (`fcntl_getlk`), and a compatibility
/// task's `F_GETLK` and `F_GETLK64`. A `struct compat_flock` reply whose
/// start does not fit is `EOVERFLOW`; its length is clamped
/// (`fixup_compat_flock`).
pub fn getlk(c: &mut Ctx<'_>, fd: i32, arg: u64, owner: Owner, layout: FlockLayout) -> SysResult {
    #[cfg(not(target_os = "linux"))]
    if owner == Owner::Description && c.p.config.host_services {
        return Err(Errno(EINVAL));
    }
    let (file, mut fl) = setup(c, fd, arg, layout)?;
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
    #[cfg(unix)]
    let conflict = match locks::host_fd(&file) {
        // An F_UNLCK request tests for nothing.
        Some(host) if fl.kind != F_UNLCK => locks::test(host, owner, fl.kind, range)?,
        _ => None,
    };
    #[cfg(not(unix))]
    let conflict: Option<locks::Conflict> = None;
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
    if layout == FlockLayout::Compat {
        if fl.start > COMPAT_OFF_T_MAX {
            return Err(Errno(EOVERFLOW));
        }
        fl.len = fl.len.min(COMPAT_OFF_T_MAX);
    }
    fl.write(c, arg, layout)?;
    Ok(0)
}

/// `F_SETLK`, `F_SETLKW`, `F_OFD_SETLK`, and `F_OFD_SETLKW`
/// (`fcntl_setlk`), with the structure in `layout`.
pub fn setlk(
    c: &mut Ctx<'_>,
    fd: i32,
    arg: u64,
    owner: Owner,
    sleep: bool,
    layout: FlockLayout,
) -> SysResult {
    #[cfg(not(target_os = "linux"))]
    if owner == Owner::Description && c.p.config.host_services {
        return Err(Errno(EINVAL));
    }
    let (file, fl) = setup(c, fd, arg, layout)?;
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
    #[cfg(unix)]
    {
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
    #[cfg(not(unix))]
    Ok(0)
}
