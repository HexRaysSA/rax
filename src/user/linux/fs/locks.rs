//! File locks (`fs/locks.c`) as host locks.
//!
//! Guest processes are host processes, and each guest open file description
//! owns one host descriptor (shared by `dup` and inherited by `fork`), so
//! the host's locks give the guest Linux's owners exactly: `flock` locks and
//! open-file-description (OFD) record locks belong to the description, and
//! POSIX record locks to the process, whose threads are one host process.
//! They also exclude other host programs.
//!
//! Two host behaviors need help. Closing *any* host descriptor of a file
//! releases the process's POSIX locks on it, including descriptors the
//! emulator keeps for itself (a mapping's): while the process may hold
//! POSIX locks on an inode, the emulator's own descriptors of it are kept
//! open ([`retire`]) and released only with the locks. And a guest `close`
//! must release those locks (`locks_remove_posix`) even when the host
//! descriptor stays open because the description has other guest
//! descriptors ([`filp_close`]).
//!
//! A macOS host has no OFD locks, and no locks on pipes or sockets.

use std::collections::HashMap;
use std::fs::File;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use super::super::abi::errno::{Errno, from_host};
use super::super::abi::errno_table::*;
use super::fd::{FileObject, OpenFile};

/// Linux `struct flock` lock types.
pub const F_RDLCK: i16 = 0;
pub const F_WRLCK: i16 = 1;
pub const F_UNLCK: i16 = 2;

/// A record lock's range, `end` included (`OFFSET_MAX` for "to the end").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub start: i64,
    pub end: i64,
}

/// Linux `OFFSET_MAX`.
pub const OFFSET_MAX: i64 = i64::MAX;

/// Who owns a record lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    /// The process (`F_SETLK`, `F_SETLKW`, `F_GETLK`).
    Process,
    /// The open file description (`F_OFD_*`).
    Description,
}

/// The conflicting lock `F_GETLK` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Conflict {
    /// `F_RDLCK` or `F_WRLCK`.
    pub kind: i16,
    pub range: Range,
    /// The owning process, or -1 for an OFD lock.
    pub pid: i32,
}

/// The host descriptor a lock on `file` is taken through, if the host can
/// lock that kind of object.
pub fn host_fd(file: &OpenFile) -> Option<RawFd> {
    match &file.object {
        FileObject::Host(f) => Some(f.as_raw_fd()),
        #[cfg(target_os = "linux")]
        FileObject::PipeRead(p) => Some(p.as_raw_fd()),
        #[cfg(target_os = "linux")]
        FileObject::PipeWrite(p) => Some(p.as_raw_fd()),
        #[cfg(target_os = "linux")]
        FileObject::Socket(s) => Some(s.as_raw_fd()),
        _ => None,
    }
}

fn host_errno() -> Errno {
    Errno(from_host(
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
    ))
}

/// `flock` on the host without sleeping: `op` is `LOCK_SH`, `LOCK_EX`, or
/// `LOCK_UN`. `EWOULDBLOCK` (`EAGAIN`) when another description holds a
/// conflicting lock; the description then holds no lock, as
/// `flock_lock_inode` removes a lock of the other type before it looks for
/// conflicts (a macOS host keeps it, so it is removed here).
pub fn flock(fd: RawFd, op: i32) -> Result<(), Errno> {
    // SAFETY: flock only reads its integer arguments; the descriptor is
    // the caller's and a stale one fails with EBADF.
    let r = unsafe { libc::flock(fd, op | libc::LOCK_NB) };
    if r == 0 {
        return Ok(());
    }
    let e = host_errno();
    if e == Errno(EAGAIN) {
        // SAFETY: as above.
        unsafe { libc::flock(fd, libc::LOCK_UN) };
    }
    Err(e)
}

fn host_flock(kind: i16, range: Range) -> libc::flock {
    // SAFETY: an all-zero `struct flock` is a valid value on every host.
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = match kind {
        F_RDLCK => libc::F_RDLCK,
        F_WRLCK => libc::F_WRLCK,
        _ => libc::F_UNLCK,
    } as _;
    fl.l_whence = libc::SEEK_SET as _;
    fl.l_start = range.start as _;
    fl.l_len = if range.end == OFFSET_MAX {
        0
    } else {
        (range.end - range.start + 1) as _
    };
    fl
}

#[cfg(target_os = "linux")]
fn command(owner: Owner, test: bool) -> Result<i32, Errno> {
    Ok(match (owner, test) {
        (Owner::Process, false) => libc::F_SETLK,
        (Owner::Process, true) => libc::F_GETLK,
        (Owner::Description, false) => libc::F_OFD_SETLK,
        (Owner::Description, true) => libc::F_OFD_GETLK,
    })
}

#[cfg(not(target_os = "linux"))]
fn command(owner: Owner, test: bool) -> Result<i32, Errno> {
    match (owner, test) {
        (Owner::Process, false) => Ok(libc::F_SETLK),
        (Owner::Process, true) => Ok(libc::F_GETLK),
        (Owner::Description, _) => Err(Errno(EINVAL)),
    }
}

/// Sets or clears a record lock on the host without sleeping. `EAGAIN`
/// when another owner holds a conflicting lock.
pub fn set(fd: RawFd, owner: Owner, kind: i16, range: Range) -> Result<(), Errno> {
    let cmd = command(owner, false)?;
    let fl = host_flock(kind, range);
    // SAFETY: `fl` is a valid `struct flock` that outlives the call.
    let r = unsafe { libc::fcntl(fd, cmd, &fl) };
    if r == 0 {
        return Ok(());
    }
    match host_errno() {
        // POSIX lets a conflict be EACCES; Linux reports EAGAIN.
        Errno(EACCES) => Err(Errno(EAGAIN)),
        e => Err(e),
    }
}

/// The first lock another owner holds that conflicts with a `kind` lock on
/// `range`, if any (`F_GETLK`).
pub fn test(fd: RawFd, owner: Owner, kind: i16, range: Range) -> Result<Option<Conflict>, Errno> {
    let cmd = command(owner, true)?;
    let mut fl = host_flock(kind, range);
    if owner == Owner::Description {
        fl.l_pid = 0;
    }
    // SAFETY: `fl` is a valid `struct flock` the host fills in.
    let r = unsafe { libc::fcntl(fd, cmd, &mut fl) };
    if r != 0 {
        return Err(host_errno());
    }
    let kind = match i32::from(fl.l_type) {
        t if t == libc::F_RDLCK as i32 => F_RDLCK,
        t if t == libc::F_WRLCK as i32 => F_WRLCK,
        _ => return Ok(None),
    };
    // off_t is 64-bit and pid_t 32-bit on every supported host.
    let start: i64 = fl.l_start;
    let len: i64 = fl.l_len;
    let end = if len == 0 {
        OFFSET_MAX
    } else {
        start + len - 1
    };
    Ok(Some(Conflict {
        kind,
        range: Range { start, end },
        pid: fl.l_pid,
    }))
}

/// Inodes (device, inode number) this process may hold POSIX locks on,
/// each with the emulator's own descriptors of it kept open meanwhile.
type Kept = HashMap<(u64, u64), Vec<File>>;

/// The process's [`Kept`] inodes. POSIX locks belong to the host process,
/// so this is per host process.
static POSIX: Mutex<Option<Kept>> = Mutex::new(None);
static ANY_POSIX: AtomicBool = AtomicBool::new(false);

fn identity(fd: RawFd) -> Option<(u64, u64)> {
    // SAFETY: an all-zero `struct stat` is valid and fstat fills it in.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` outlives the call; a bad descriptor fails with EBADF.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    Some((st.st_dev as u64, st.st_ino as u64))
}

/// Records that the process took a POSIX lock through `fd`.
pub fn note_posix(fd: RawFd) {
    let Some(id) = identity(fd) else { return };
    crate::user::mm::set_retire(retire);
    let mut map = POSIX.lock().unwrap();
    map.get_or_insert_with(HashMap::new).entry(id).or_default();
    ANY_POSIX.store(true, Ordering::Release);
}

/// The mm retirement hook: keeps a descriptor of an inode the process may
/// hold POSIX locks on, since closing it would release them.
fn retire(file: File) {
    if ANY_POSIX.load(Ordering::Acquire)
        && let Some(id) = identity(file.as_raw_fd())
    {
        let mut map = POSIX.lock().unwrap();
        if let Some(kept) = map.as_mut().and_then(|m| m.get_mut(&id)) {
            kept.push(file);
            return;
        }
    }
    drop(file);
}

/// `locks_remove_posix` for a guest `close` of `file`: releases every
/// POSIX lock the process holds on its inode, then closes the emulator's
/// descriptors of it kept meanwhile.
pub fn filp_close(file: &OpenFile) {
    if !ANY_POSIX.load(Ordering::Acquire) {
        return;
    }
    let Some(fd) = host_fd(file) else { return };
    let Some(id) = identity(fd) else { return };
    let kept = {
        let mut map = POSIX.lock().unwrap();
        let Some(m) = map.as_mut() else { return };
        let Some(kept) = m.remove(&id) else { return };
        if m.is_empty() {
            ANY_POSIX.store(false, Ordering::Release);
        }
        kept
    };
    let whole = Range {
        start: 0,
        end: OFFSET_MAX,
    };
    let _ = set(fd, Owner::Process, F_UNLCK, whole);
    drop(kept);
}

/// Whether the process may hold POSIX locks on the inode of `fd`, and how
/// many of the emulator's descriptors of it are kept meanwhile.
#[cfg(test)]
pub(crate) fn posix_state(fd: RawFd) -> Option<usize> {
    let id = identity(fd)?;
    let map = POSIX.lock().unwrap();
    map.as_ref()?.get(&id).map(Vec::len)
}

/// In a new process: it holds no POSIX locks, so the descriptors its parent
/// kept may be closed.
pub fn forked() {
    let kept = POSIX.lock().unwrap().take();
    ANY_POSIX.store(false, Ordering::Release);
    drop(kept);
}
