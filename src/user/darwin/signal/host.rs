//! The host side of guest signals: numbering, asynchronous host signals
//! forwarded to the guest, job-control stops, and dying by a signal.
//!
//! The emulated process is the host process, so what the host delivers to
//! it — a terminal interrupt, another process's `kill`, a window change —
//! is for the guest. [`forward`] installs host handlers that record such
//! signals and wake the scheduler through a pipe; the scheduler posts
//! them to the guest process ([`take`]).

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

use super::{Origin, Proc, Signal, nums::*};
use crate::user::darwin::abi::Errno;

/// The host's number for signal `sig` (the same numbers on a macOS host).
pub fn to_host(sig: Signal) -> Option<i32> {
    #[cfg(target_os = "macos")]
    {
        (0..=31).contains(&sig).then_some(sig)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(match sig {
            0 => 0,
            SIGHUP => libc::SIGHUP,
            SIGINT => libc::SIGINT,
            SIGQUIT => libc::SIGQUIT,
            SIGILL => libc::SIGILL,
            SIGTRAP => libc::SIGTRAP,
            SIGABRT => libc::SIGABRT,
            SIGFPE => libc::SIGFPE,
            SIGKILL => libc::SIGKILL,
            SIGBUS => libc::SIGBUS,
            SIGSEGV => libc::SIGSEGV,
            SIGSYS => libc::SIGSYS,
            SIGPIPE => libc::SIGPIPE,
            SIGALRM => libc::SIGALRM,
            SIGTERM => libc::SIGTERM,
            SIGURG => libc::SIGURG,
            SIGSTOP => libc::SIGSTOP,
            SIGTSTP => libc::SIGTSTP,
            SIGCONT => libc::SIGCONT,
            SIGCHLD => libc::SIGCHLD,
            SIGTTIN => libc::SIGTTIN,
            SIGTTOU => libc::SIGTTOU,
            SIGIO => libc::SIGIO,
            SIGXCPU => libc::SIGXCPU,
            SIGXFSZ => libc::SIGXFSZ,
            SIGVTALRM => libc::SIGVTALRM,
            SIGPROF => libc::SIGPROF,
            SIGWINCH => libc::SIGWINCH,
            SIGUSR1 => libc::SIGUSR1,
            SIGUSR2 => libc::SIGUSR2,
            _ => return None,
        })
    }
}

/// The Darwin number of host signal `host`.
pub fn from_host(host: i32) -> Option<Signal> {
    (1..super::NSIG).find(|&s| to_host(s) == Some(host))
}

/// Terminates the calling host process with Darwin signal `sig`'s host
/// counterpart, so that its parent sees the guest's signal death. Returns
/// when the host has no such signal.
pub fn die_by_signal(sig: Signal) {
    let Some(host) = to_host(sig).filter(|&h| h != 0) else {
        return;
    };
    // SAFETY: integer arguments and a fully initialized sigset; the process
    // is about to terminate.
    unsafe {
        libc::signal(host, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, host);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(host);
    }
}

/// Signals whose host actions the emulator's own runtime changes before
/// [`inherited`] can look (Rust's standard library ignores `SIGPIPE` and
/// catches `SIGSEGV` and `SIGBUS` for stack-overflow reports): their
/// inherited state is taken to be the default action without flags.
const RUNTIME_CLAIMED: &[Signal] = &[SIGBUS, SIGSEGV, SIGPIPE];

/// The host process's signal state as the guest inherits it across
/// `exec` (`execsigs` keeps ignored signals, the action flags, and the
/// signal mask). Call it before [`forward`] installs its handlers.
pub fn inherited() -> super::Inherited {
    let mut inh = super::Inherited {
        // The flags of the runtime-claimed signals: none (EINTR).
        intr: RUNTIME_CLAIMED.iter().fold(0, |m, &s| m | super::bit(s)),
        ..Default::default()
    };
    for sig in 1..super::NSIG {
        if sig == SIGKILL || sig == SIGSTOP || RUNTIME_CLAIMED.contains(&sig) {
            continue;
        }
        let Some(host) = to_host(sig) else {
            continue;
        };
        // SAFETY: `oact` is a valid out-pointer; a null new action only
        // queries.
        let oact = unsafe {
            let mut oact: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(host, std::ptr::null(), &mut oact) != 0 {
                continue;
            }
            oact
        };
        let b = super::bit(sig);
        let f = oact.sa_flags;
        if oact.sa_sigaction == libc::SIG_IGN {
            inh.ignore |= b;
        }
        if f & libc::SA_RESTART == 0 {
            inh.intr |= b;
        }
        if f & libc::SA_ONSTACK != 0 {
            inh.onstack |= b;
        }
        if f & libc::SA_SIGINFO != 0 {
            inh.siginfo |= b;
        }
        if f & libc::SA_NODEFER != 0 {
            inh.nodefer |= b;
        }
        if f & libc::SA_RESETHAND != 0 {
            inh.reset |= b;
        }
    }
    // SAFETY: a null new set only queries the calling thread's mask.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        if libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut set) == 0 {
            for sig in 1..super::NSIG {
                if let Some(h) = to_host(sig)
                    && libc::sigismember(&set, h) == 1
                {
                    inh.mask |= super::bit(sig);
                }
            }
        }
    }
    inh.mask &= !super::CANTMASK;
    inh
}

/// The asynchronous signals forwarded to the guest: those a terminal,
/// another process, or the host's timers and resource limits send.
const FORWARDED: &[Signal] = &[
    SIGHUP, SIGINT, SIGQUIT, SIGALRM, SIGTERM, SIGURG, SIGTSTP, SIGCONT, SIGTTIN, SIGTTOU, SIGIO,
    SIGXCPU, SIGXFSZ, SIGVTALRM, SIGPROF, SIGWINCH, SIGINFO, SIGUSR1, SIGUSR2,
];

/// Forwarded signals received and not yet taken, as a Darwin signal set.
static PENDING: AtomicU32 = AtomicU32::new(0);
/// Per signal, the sender as `1 << 63 | pid << 32 | uid` when a process
/// sent it with `kill`, else 0.
static SENDER: [AtomicU64; 32] = [const { AtomicU64::new(0) }; 32];
/// The wake pipe: (read, write), -1 before [`forward`].
static WAKE_READ: AtomicI32 = AtomicI32::new(-1);
static WAKE_WRITE: AtomicI32 = AtomicI32::new(-1);
/// Whether [`forward`] ran.
static FORWARDING: AtomicBool = AtomicBool::new(false);

/// The host `si_code` of a signal a process sent with `kill`: `SI_USER`,
/// which XNU's `kill(2)` delivers as 0.
fn sent_by_kill(code: i32) -> bool {
    code == 0 || code == 0x10001
}

#[cfg(target_vendor = "apple")]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: returns the calling thread's errno slot; always valid.
    unsafe { libc::__error() }
}

#[cfg(not(target_vendor = "apple"))]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: returns the calling thread's errno slot; always valid.
    unsafe { libc::__errno_location() }
}

/// The handler of forwarded host signals. It is async-signal-safe: it
/// touches only lock-free atomics and calls `write(2)`, and it preserves
/// `errno` for the interrupted code.
extern "C" fn on_host_signal(host: libc::c_int, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    let Some(sig) = from_host(host) else {
        return;
    };
    let errno = errno_location();
    // SAFETY: the kernel passes a valid siginfo_t to SA_SIGINFO handlers;
    // errno_location is this thread's errno slot.
    let (saved, code, pid, uid) =
        unsafe { (*errno, (*info).si_code, (*info).si_pid(), (*info).si_uid()) };
    let sender = if sent_by_kill(code) && pid > 0 {
        (1 << 63) | ((pid as u64 & 0x7fff_ffff) << 32) | u64::from(uid)
    } else {
        0
    };
    SENDER[sig as usize].store(sender, Ordering::Relaxed);
    PENDING.fetch_or(super::bit(sig), Ordering::SeqCst);
    let fd = WAKE_WRITE.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = 1u8;
        // SAFETY: write(2) is async-signal-safe and `byte` is valid for
        // one byte; a full pipe already wakes its reader.
        unsafe {
            libc::write(fd, (&raw const byte).cast(), 1);
        }
    }
    // SAFETY: as above.
    unsafe {
        *errno = saved;
    }
}

/// Installs the forwarding handlers (without `SA_RESTART`, so a blocked
/// host call returns and the scheduler sees the signal) and the wake
/// pipe, and ignores the host's `SIGPIPE`: a write to a broken pipe fails
/// with `EPIPE` and the guest gets its own `SIGPIPE`. Calling it again has
/// no effect.
pub fn forward() -> Result<(), Errno> {
    if FORWARDING.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` holds the two descriptors pipe(2) returns; the fcntl
    // commands take integer arguments.
    unsafe {
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return Err(Errno::last());
        }
        for fd in fds {
            libc::fcntl(
                fd,
                libc::F_SETFL,
                libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK,
            );
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    WAKE_READ.store(fds[0], Ordering::SeqCst);
    WAKE_WRITE.store(fds[1], Ordering::SeqCst);
    for &sig in FORWARDED {
        let Some(host) = to_host(sig) else {
            continue;
        };
        // SAFETY: `sa` is fully initialized (zeroed, then the handler, the
        // flags, and an empty mask); the handler has the SA_SIGINFO
        // signature.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_host_signal as usize;
            sa.sa_flags = libc::SA_SIGINFO;
            libc::sigemptyset(&mut sa.sa_mask);
            if libc::sigaction(host, &sa, std::ptr::null_mut()) != 0 {
                return Err(Errno::last());
            }
        }
    }
    // SAFETY: setting a disposition takes no pointers.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    Ok(())
}

/// Whether host signals are forwarded.
pub fn forwarding() -> bool {
    FORWARDING.load(Ordering::SeqCst)
}

/// The read end of the wake pipe, once [`forward`] ran.
pub fn wake_fd() -> Option<i32> {
    let fd = WAKE_READ.load(Ordering::SeqCst);
    (fd >= 0).then_some(fd)
}

/// Empties the wake pipe.
pub fn drain() {
    if let Some(fd) = wake_fd() {
        let mut buf = [0u8; 64];
        // SAFETY: `buf` is writable for its length; the descriptor is the
        // non-blocking wake pipe this module owns.
        while unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
    }
}

/// Takes the forwarded signals received since the last call, lowest
/// number first, with their senders. The scheduler calls it on every
/// pass, so it costs one atomic load when nothing arrived.
pub fn take() -> Vec<(Signal, Origin)> {
    if PENDING.load(Ordering::SeqCst) == 0 {
        return Vec::new();
    }
    drain();
    let pending = PENDING.swap(0, Ordering::SeqCst);
    (1..super::NSIG)
        .filter(|&s| pending & super::bit(s) != 0)
        .map(|s| {
            let packed = SENDER[s as usize].load(Ordering::Relaxed);
            let origin = if packed >> 63 != 0 {
                Origin::process(((packed >> 32) & 0x7fff_ffff) as i32, packed as u32)
            } else {
                Origin::KERNEL
            };
            (s, origin)
        })
        .collect()
}

/// Stops the process for a stop signal's default action. The emulator
/// is the process, so the host stops it (`SIGSTOP` to itself) when host
/// job control is on; the host's `SIGCONT` continues it. Without host
/// job control (a library user's process) the stop is not modelled.
pub fn stop(proc: &mut Proc) {
    if proc.config.host_job_control {
        // SAFETY: kill(2) on the calling process takes no pointers.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGSTOP);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_numbering_round_trips() {
        for s in 1..super::super::NSIG {
            if let Some(h) = to_host(s) {
                assert_eq!(from_host(h), Some(s), "signal {s}");
            }
        }
        assert_eq!(to_host(SIGUSR1), Some(libc::SIGUSR1));
        assert_eq!(to_host(SIGINFO).is_some(), cfg!(target_os = "macos"));
    }
}
