//! Waiting for children (`wait4`, `wait4_nocancel` in
//! `bsd/kern/kern_exit.c`).
//!
//! The guest's children are host processes (a guest `fork` forks the
//! host process), so their state changes are the host kernel's: a wait
//! asks the host without blocking, and a caller that must wait sleeps
//! until the host's `SIGCHLD` wakes it (see `signal::host`), its wait
//! interruptible by signals as XNU's `msleep(PCATCH)` is.

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::signal::{self, SIGCHLD};
use crate::user::darwin::syscall::{self, Ctx};
use crate::user::darwin::wait::{Wait, WaitKey};

/// `wait4` options (`bsd/sys/wait.h`).
pub mod opt {
    pub const WNOHANG: i32 = 0x01;
    pub const WUNTRACED: i32 = 0x02;
    pub const WCONTINUED: i32 = 0x10;
}

/// `sizeof(struct user64_rusage)`.
const RUSAGE_SIZE: usize = 144;

/// A child's state change as the host reports it.
struct Reaped {
    pid: i32,
    status: i32,
    rusage: libc::rusage,
}

/// The host's `wait4` without blocking: `Ok(None)` when no child has
/// changed state yet.
fn host_wait4(pid: i32, options: i32) -> Result<Option<Reaped>, Errno> {
    let mut host_opts = libc::WNOHANG;
    if options & opt::WUNTRACED != 0 {
        host_opts |= libc::WUNTRACED;
    }
    if options & opt::WCONTINUED != 0 {
        host_opts |= libc::WCONTINUED;
    }
    let mut status = 0;
    // SAFETY: an all-zero rusage is a valid value to be overwritten.
    let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `status` and `rusage` are valid for the host to write.
    let r = unsafe { libc::wait4(pid, &mut status, host_opts, &mut rusage) };
    match r {
        r if r < 0 => Err(Errno::last()),
        0 => Ok(None),
        pid => Ok(Some(Reaped {
            pid,
            status: guest_status(status),
            rusage,
        })),
    }
}

/// A host wait status in XNU's encoding: an exit code in bits 8-15, a
/// terminating signal (with the core flag 0x80) in bits 0-7, a stop as
/// `W_STOPCODE(signal)`, a continue as `W_STOPCODE(SIGCONT)`.
fn guest_status(host: i32) -> i32 {
    let sig = |s: i32| signal::host::from_host(s).unwrap_or(s);
    if libc::WIFEXITED(host) {
        (libc::WEXITSTATUS(host) & 0xff) << 8
    } else if libc::WIFSIGNALED(host) {
        let core = if libc::WCOREDUMP(host) { 0x80 } else { 0 };
        (sig(libc::WTERMSIG(host)) & 0x7f) | core
    } else if libc::WIFSTOPPED(host) {
        (sig(libc::WSTOPSIG(host)) << 8) | 0x7f
    } else if libc::WIFCONTINUED(host) {
        (signal::SIGCONT << 8) | 0x7f
    } else {
        host & 0xffff
    }
}

/// `struct user64_rusage` from the host's `struct rusage`
/// (`munge_user64_rusage`).
fn rusage_bytes(r: &libc::rusage) -> [u8; RUSAGE_SIZE] {
    let mut b = [0u8; RUSAGE_SIZE];
    let longs = [
        r.ru_utime.tv_sec as i64,
        i64::from(r.ru_utime.tv_usec),
        r.ru_stime.tv_sec as i64,
        i64::from(r.ru_stime.tv_usec),
        r.ru_maxrss as i64,
        r.ru_ixrss as i64,
        r.ru_idrss as i64,
        r.ru_isrss as i64,
        r.ru_minflt as i64,
        r.ru_majflt as i64,
        r.ru_nswap as i64,
        r.ru_inblock as i64,
        r.ru_oublock as i64,
        r.ru_msgsnd as i64,
        r.ru_msgrcv as i64,
        r.ru_nsignals as i64,
        r.ru_nvcsw as i64,
        r.ru_nivcsw as i64,
    ];
    for (i, v) in longs.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    b
}

/// `wait4(pid, status, options, rusage)`.
pub fn wait4(ctx: &mut Ctx<'_>, pid: i32, status: u64, options: i32, rusage: u64) -> SysResult {
    if pid == i32::MIN {
        return Err(Errno::EINVAL);
    }
    // The pid 0 means the caller's process group; the host agrees.
    let Some(r) = host_wait4(pid, options)? else {
        if options & opt::WNOHANG != 0 {
            return Ok(Rv::one(0));
        }
        // msleep0(PWAIT | PCATCH) until a child changes state.
        let wait = if signal::host::forwarding() {
            Wait::key(WaitKey::Child, None)
        } else {
            // Nothing forwards the host's SIGCHLD: look again shortly.
            let again = std::time::Instant::now() + std::time::Duration::from_millis(10);
            Wait {
                keys: vec![WaitKey::Child],
                deadline: Some(again),
                interruptible: true,
                ..Default::default()
            }
        };
        return syscall::sleep(ctx, wait);
    };
    let exited = r.status & 0x7f != 0x7f;
    if status != 0 {
        ctx.write(status, &(r.status & 0xffff).to_le_bytes())?;
    }
    if rusage != 0 {
        ctx.write(rusage, &rusage_bytes(&r.rusage))?;
    }
    if exited {
        ctx.proc.children.remove(&r.pid);
        // With SIGCHLD blocked, reaping the last child clears a pending
        // SIGCHLD (conformance change 6577252).
        if ctx.proc.children.is_empty() && ctx.thread.sig.mask & signal::bit(SIGCHLD) != 0 {
            ctx.thread.sig.pending &= !signal::bit(SIGCHLD);
        }
    }
    Ok(Rv::one(r.pid as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host wait status for an exit, a signal death, a stop.
    #[cfg(target_os = "macos")]
    fn host(exit: Option<i32>, sig: Option<i32>, stop: Option<i32>) -> i32 {
        match (exit, sig, stop) {
            (Some(c), ..) => c << 8,
            (_, Some(s), _) => s,
            (.., Some(s)) => (s << 8) | 0x7f,
            _ => 0,
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn statuses_keep_xnus_encoding() {
        assert_eq!(guest_status(host(Some(7), None, None)), 0x0700);
        assert_eq!(guest_status(host(None, Some(libc::SIGTERM), None)), 0x0f);
        assert_eq!(
            guest_status(host(None, Some(libc::SIGSEGV), None) | 0x80),
            0x8b
        );
        assert_eq!(guest_status(host(None, None, Some(libc::SIGSTOP))), 0x117f);
        // A continue is W_STOPCODE(SIGCONT).
        assert_eq!(guest_status(0x137f), 0x137f);
    }

    #[test]
    fn rusage_layout() {
        // SAFETY: an all-zero rusage is valid.
        let mut r: libc::rusage = unsafe { std::mem::zeroed() };
        r.ru_utime.tv_sec = 3;
        r.ru_utime.tv_usec = 4;
        r.ru_maxrss = 5;
        r.ru_nivcsw = 6;
        let b = rusage_bytes(&r);
        let at = |i: usize| i64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        assert_eq!((at(0), at(1), at(4), at(17)), (3, 4, 5, 6));
    }
}
