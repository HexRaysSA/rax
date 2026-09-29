//! POSIX named semaphores (`sem_open`, `sem_close`, `sem_unlink`,
//! `sem_wait`, `sem_trywait`, `sem_post` in `bsd/kern/posix_sem.c`).
//!
//! The semaphores are the host's, so a guest shares them by name with every
//! other process on the host, emulated or native, and the host checks the
//! flags, value, and permissions. An open semaphore is a descriptor:
//! `sem_open` returns its number as the `sem_t *`, and the other calls take
//! that number back and refuse a descriptor of another kind (`EBADF`).
//!
//! Every guest thread runs on one host thread, so `sem_wait` never blocks
//! the host: it takes the semaphore when it can and otherwise sleeps,
//! looking again every [`POLL`], until it takes it or a signal ends the
//! wait (`EINTR`, as a Mach semaphore wait aborted by a signal, whatever
//! `SA_RESTART` says).

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::fd::{FileKind, OpenFile};
use crate::user::darwin::io::O_ACCMODE;
use crate::user::darwin::syscall::{Ctx, sleep_no_restart};
use crate::user::darwin::wait::Wait;

/// `PSEMNAMLEN`: the longest name, its NUL included.
const PSEMNAMLEN: usize = 31;
/// `MAXPATHLEN`: `copyinstr`'s limit for the name.
const MAXPATHLEN: usize = 1024;
/// How often a waiting `sem_wait` looks at the semaphore again.
pub const POLL: Duration = Duration::from_millis(1);

/// The host semaphore of guest descriptor `sem` (`fp_get_ftype` with
/// `DTYPE_PSXSEM`): its number, the `sem_t *` the host's calls take.
fn host_sem(ctx: &Ctx<'_>, sem: u64) -> Result<i32, Errno> {
    // CAST_DOWN_EXPLICIT(int, uap->sem)
    let file = ctx.proc.fds.file(sem as i32)?;
    match &file.kind {
        FileKind::Sem(h) => Ok(h.as_raw_fd()),
        _ => Err(Errno::EBADF),
    }
}

fn as_sem(h: i32) -> *mut libc::sem_t {
    h as usize as *mut libc::sem_t
}

/// The host's result of a semaphore call.
fn host_result(r: i32) -> SysResult {
    if r == 0 {
        Ok(Rv::one(0))
    } else {
        Err(Errno::last())
    }
}

/// `sem_open(name, oflag, mode, value)`.
pub fn sem_open(ctx: &mut Ctx<'_>, name: u64, oflag: u32, mode: u32, value: u32) -> SysResult {
    let name = ctx.cstr(name, MAXPATHLEN)?;
    if name.len() + 1 > PSEMNAMLEN {
        return Err(Errno::ENAMETOOLONG);
    }
    let cname = CString::new(name).map_err(|_| Errno::EINVAL)?;
    // falloc precedes the value, existence, and permission checks.
    let limit = ctx.proc.rlimits[8].0;
    ctx.proc.fds.lowest_free(0, limit)?;
    // SAFETY: `cname` is NUL-terminated for the call's duration; the mode
    // and value are passed as the variadic arguments sem_open reads.
    let sem = unsafe {
        libc::sem_open(
            cname.as_ptr(),
            crate::user::darwin::host::open_flags(oflag),
            mode as libc::c_uint,
            value as libc::c_uint,
        )
    };
    if sem == libc::SEM_FAILED {
        return Err(Errno::last());
    }
    let h = sem as usize as i32;
    // SAFETY: the host returned descriptor `h` for the semaphore, owned
    // here; the host descriptor is close-on-exec, as every one the
    // emulator holds, and closing it is `sem_close`.
    let owned = unsafe {
        libc::fcntl(h, libc::F_SETFD, libc::FD_CLOEXEC);
        OwnedFd::from_raw_fd(h)
    };
    let file = Arc::new(OpenFile {
        kind: FileKind::Sem(owned),
        path: None,
        flags: Mutex::new(oflag & O_ACCMODE),
    });
    let n = ctx.proc.fds.install(file, false, 0, limit)?;
    Ok(Rv::one(n as u64))
}

/// `sem_close(sem)`: the descriptor is closed as `close` closes it.
pub fn sem_close(ctx: &mut Ctx<'_>, sem: u64) -> SysResult {
    host_sem(ctx, sem)?;
    super::file::close(ctx, sem as i32)
}

/// `sem_unlink(name)`.
pub fn sem_unlink(ctx: &mut Ctx<'_>, name: u64) -> SysResult {
    let name = ctx.cstr(name, MAXPATHLEN)?;
    if name.len() + 1 > PSEMNAMLEN {
        return Err(Errno::ENAMETOOLONG);
    }
    let cname = CString::new(name).map_err(|_| Errno::EINVAL)?;
    // SAFETY: `cname` is NUL-terminated for the call's duration.
    host_result(unsafe { libc::sem_unlink(cname.as_ptr()) })
}

/// `sem_trywait(sem)`.
pub fn sem_trywait(ctx: &mut Ctx<'_>, sem: u64) -> SysResult {
    let h = host_sem(ctx, sem)?;
    // SAFETY: `h` is an open host semaphore, which sem_trywait takes by
    // its number and does not dereference.
    host_result(unsafe { libc::sem_trywait(as_sem(h)) })
}

/// `sem_post(sem)`.
pub fn sem_post(ctx: &mut Ctx<'_>, sem: u64) -> SysResult {
    let h = host_sem(ctx, sem)?;
    // SAFETY: as in `sem_trywait`.
    host_result(unsafe { libc::sem_post(as_sem(h)) })
}

/// `sem_wait(sem)` and `sem_wait_nocancel(sem)`.
pub fn sem_wait(ctx: &mut Ctx<'_>, sem: u64) -> SysResult {
    let h = host_sem(ctx, sem)?;
    // Restarted before its next look: a signal ended the wait.
    if let Some(r) = ctx.thread.resume
        && r.deadline.is_some_and(|d| d > Instant::now())
    {
        return Err(Errno::EINTR);
    }
    // SAFETY: as in `sem_trywait`.
    match host_result(unsafe { libc::sem_trywait(as_sem(h)) }) {
        Err(Errno::EAGAIN) => sleep_no_restart(ctx, Wait::until(Some(Instant::now() + POLL))),
        // The host was interrupted by one of the emulator's own signals.
        Err(Errno::EINTR) => sleep_no_restart(ctx, Wait::until(Some(Instant::now()))),
        r => r,
    }
}
