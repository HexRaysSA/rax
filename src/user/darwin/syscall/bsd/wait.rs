//! Waiting for children (`wait4`, `waitid`, and their `_nocancel`
//! variants in `bsd/kern/kern_exit.c`).
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

/// `wait4` and `waitid` options (`bsd/sys/wait.h`).
pub mod opt {
    pub const WNOHANG: i32 = 0x01;
    pub const WUNTRACED: i32 = 0x02;
    pub const WEXITED: i32 = 0x04;
    pub const WSTOPPED: i32 = 0x08;
    pub const WCONTINUED: i32 = 0x10;
    pub const WNOWAIT: i32 = 0x20;
}

/// `idtype_t`.
pub mod idtype {
    pub const P_PID: i32 = 1;
    pub const P_PGID: i32 = 2;
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
        return sleep_for_child(ctx);
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

/// Sleeps until a child changes state (`msleep0(PWAIT | PCATCH)`).
fn sleep_for_child(ctx: &mut Ctx<'_>) -> SysResult {
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
    syscall::sleep(ctx, wait)
}

/// The host's `waitid`: the child that matched, if one has changed state.
fn host_waitid(idtype: i32, id: u32, options: i32) -> Result<Option<libc::siginfo_t>, Errno> {
    let (htype, hid) = match idtype {
        idtype::P_PID => (libc::P_PID, id),
        idtype::P_PGID => (libc::P_PGID, id),
        // Any other type selects every child, as P_ALL does.
        _ => (libc::P_ALL, 0),
    };
    let mut hopts = libc::WNOHANG;
    for (guest, host) in [
        (opt::WEXITED, libc::WEXITED),
        (opt::WSTOPPED, libc::WSTOPPED),
        (opt::WCONTINUED, libc::WCONTINUED),
        (opt::WNOWAIT, libc::WNOWAIT),
    ] {
        if options & guest != 0 {
            hopts |= host;
        }
    }
    // SAFETY: an all-zero siginfo_t is a valid value to be overwritten.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is valid for the host to write.
    if unsafe { libc::waitid(htype, hid as libc::id_t, &mut info, hopts) } < 0 {
        return Err(Errno::last());
    }
    // SAFETY: si_pid is set by a successful waitid (zero when no child
    // was ready).
    Ok((unsafe { info.si_pid() } != 0).then_some(info))
}

/// A `user64_siginfo_t` for child `pid`'s state change
/// (`copyoutsiginfo`): `SIGCHLD`, its code, pid, and status (a signal
/// number except for an exit); the user ID is not set.
fn child_siginfo(info: &libc::siginfo_t, pid: i32) -> [u8; 104] {
    // SAFETY: waitid filled the SIGCHLD fields.
    let status = unsafe { info.si_status() };
    let status = match info.si_code {
        libc::CLD_EXITED => status & 0x00ff_ffff,
        // A continue as its default action records it (p_xstat).
        libc::CLD_CONTINUED => signal::SIGCONT,
        _ => signal::host::from_host(status).unwrap_or(status),
    };
    let mut b = [0u8; 104];
    b[0..4].copy_from_slice(&SIGCHLD.to_le_bytes());
    b[8..12].copy_from_slice(&info.si_code.to_le_bytes());
    b[12..16].copy_from_slice(&pid.to_le_bytes());
    b[20..24].copy_from_slice(&status.to_le_bytes());
    b
}

/// The child a host `waitid` result is about. A continue names the
/// process that continued the child (`p_contproc`): the child itself
/// under SIGCONT's default action, which the host cannot report for an
/// emulated child (it catches SIGCONT to forward it), so the child is
/// found by asking about each one.
fn changed_child(ctx: &Ctx<'_>, idtype: i32, id: u32, info: &libc::siginfo_t) -> i32 {
    // SAFETY: waitid filled si_pid.
    let pid = unsafe { info.si_pid() };
    if info.si_code != libc::CLD_CONTINUED {
        return pid;
    }
    if idtype == idtype::P_PID {
        return id as i32;
    }
    let peek = opt::WCONTINUED | opt::WNOWAIT;
    ctx.proc
        .children
        .iter()
        .copied()
        .find(|&c| {
            host_waitid(idtype::P_PID, c as u32, peek)
                .ok()
                .flatten()
                .is_some_and(|i| i.si_code == libc::CLD_CONTINUED)
        })
        .unwrap_or(pid)
}

/// `waitid(idtype, id, infop, options)`.
pub fn waitid(ctx: &mut Ctx<'_>, idtype: i32, id: u32, infop: u64, options: i32) -> SysResult {
    let valid = opt::WNOHANG | opt::WNOWAIT | opt::WCONTINUED | opt::WSTOPPED | opt::WEXITED;
    if options == 0 || options & !valid != 0 {
        return Err(Errno::EINVAL);
    }
    if matches!(idtype, idtype::P_PID | idtype::P_PGID) && (id as i32) < 0 {
        return Err(Errno::EINVAL);
    }
    // Look without consuming, so that a fault writing the siginfo leaves
    // the state change to a later wait.
    let Some(info) = host_waitid(idtype, id, options | opt::WNOWAIT)? else {
        if options & opt::WNOHANG != 0 {
            // The siginfo is left as it was.
            return Ok(Rv::one(0));
        }
        return sleep_for_child(ctx);
    };
    let pid = changed_child(ctx, idtype, id, &info);
    ctx.write(infop, &child_siginfo(&info, pid))?;
    if options & opt::WNOWAIT == 0 {
        host_waitid(idtype::P_PID, pid as u32, options)?;
        if matches!(
            info.si_code,
            libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
        ) {
            ctx.proc.children.remove(&pid);
        }
    }
    Ok(Rv::one(0))
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
