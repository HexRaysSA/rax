//! Sleeping in system calls.
//!
//! Every thread of a process runs on one emulated CPU, so a call that must
//! sleep cannot block the host. Its handler records what it waits for (a
//! [`Wait`]) and its progress (a [`Resume`] record) and returns; the thread
//! is parked in [`Blocked`] and the scheduler runs other threads. When the
//! wait can end — a descriptor is ready, the deadline passed, a signal was
//! sent to the thread (`TIF_SIGPENDING`), or another thread reported the
//! event it waits for ([`Blocked::woken`], as `FUTEX_WAKE` does) — the call
//! is dispatched again with its record, as a kernel task returns from
//! `schedule()` into the same system call, and re-evaluates its condition
//! in the kernel's order: a ready descriptor before a pending signal
//! (`do_poll`, `pipe_read`), a pending signal before the timeout.
//!
//! When every thread sleeps, [`sleep`] waits in the host's `poll` for the
//! earliest event that can wake one: their descriptors, the forwarded
//! host-signal wake pipe
//! ([`forward_host_signals`](super::host::forward_host_signals)), and the
//! nearest deadline of a wait or interval timer.

use std::time::{Duration, Instant};

use super::futex::FutexWait;
use super::host::{self, Readiness};

/// What a sleeping call waits for besides the events other threads report
/// through [`Blocked::woken`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wait {
    /// Host descriptors, each with the readiness it waits for
    /// (`(fd, readable, writable)`).
    pub fds: Vec<(i32, bool, bool)>,
    /// When the call's timeout expires.
    pub deadline: Option<Instant>,
    /// A signal ends the wait (`TASK_INTERRUPTIBLE`); otherwise only the
    /// process's exit does (`TASK_KILLABLE`).
    pub interruptible: bool,
    /// Signals whose queueing, even while blocked, ends the wait: those a
    /// `signalfd` being read or polled reports (`signalfd_wqh`).
    pub signals: u64,
}

impl Wait {
    /// A wait for a signal or another thread's event only.
    pub fn event() -> Self {
        Wait::until(None)
    }

    /// A wait for a signal, an event, or `deadline`.
    pub fn until(deadline: Option<Instant>) -> Self {
        Wait {
            fds: Vec::new(),
            deadline,
            interruptible: true,
            signals: 0,
        }
    }

    /// A wait for readiness of host descriptors, a signal, or `deadline`.
    pub fn fds(fds: Vec<(i32, bool, bool)>, deadline: Option<Instant>) -> Self {
        Wait {
            fds,
            deadline,
            interruptible: true,
            signals: 0,
        }
    }

    /// A wait for readiness of one host descriptor or a signal.
    pub fn fd(fd: i32, read: bool, write: bool) -> Self {
        Wait::fds(vec![(fd, read, write)], None)
    }

    /// A wait only another thread's event (or the process's exit) ends.
    pub fn uninterruptible() -> Self {
        Wait {
            fds: Vec::new(),
            deadline: None,
            interruptible: false,
            signals: 0,
        }
    }
}

/// The progress of a socket call that sleeps: what it transferred and when
/// its waiting ends (`sock_rcvtimeo`, `sock_sndtimeo`, the `recvmmsg`
/// timeout).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SockWait {
    /// Bytes of the current message transferred.
    pub done: u64,
    /// End of the socket timeout of the current wait (never if `None`).
    pub deadline: Option<Instant>,
    /// Messages completed (`sendmmsg`, `recvmmsg`).
    pub count: u32,
    /// End of the `recvmmsg` timeout.
    pub end: Option<Instant>,
}

/// A handler's progress, handed back when its thread wakes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resume {
    /// Nothing beyond the arguments: evaluate the call again.
    Retry,
    /// A sleep, `poll`, or `select` ending at the instant (never if `None`)
    /// whose temporary signal mask, if any, is already installed.
    Until(Option<Instant>),
    /// A write to a pipe or socket that has transferred this many bytes.
    Written(u64),
    /// `io_submit`: the requests before `index` were submitted; the one at
    /// `index` sleeps with `inner` as its own progress.
    Aio {
        /// The context submitted to.
        ctx: super::aio::Handle,
        /// The request that sleeps.
        index: u64,
        /// Its transfer's progress.
        inner: Box<Resume>,
    },
    /// `io_getevents` and `io_pgetevents`: the context, the events already
    /// copied, and the end of the wait.
    AioEvents {
        /// The context read.
        ctx: super::aio::Handle,
        /// Events copied out.
        got: u64,
        /// End of the wait (never if `None`).
        deadline: Option<Instant>,
    },
    /// A socket call's progress.
    Socket(SockWait),
    /// `rt_sigtimedwait`: its deadline and the mask it replaced
    /// (`real_blocked`).
    SigWait {
        /// End of the wait.
        deadline: Option<Instant>,
        /// The mask to restore.
        real_blocked: u64,
    },
    /// A futex wait.
    Futex(FutexWait),
    /// A `CLONE_VFORK` parent waiting for its child thread to exit, then
    /// returning the child's TID.
    Vfork {
        /// The child.
        child: i32,
    },
    /// A `CLONE_VFORK` parent waiting for its child process to `execve` or
    /// end, then returning the child's PID.
    VforkChild {
        /// The child.
        pid: i32,
    },
    /// `wait4`/`waitid` waiting for a child to change state.
    WaitChild,
}

/// A thread asleep in a system call.
#[derive(Clone, Debug)]
pub struct Blocked {
    /// The system-call number.
    pub nr: u64,
    /// The arguments.
    pub args: [u64; 6],
    /// What ends the wait.
    pub wait: Wait,
    /// The call's progress.
    pub resume: Resume,
    /// Another thread reported the event the call waits for.
    pub woken: bool,
    /// A watched descriptor was found ready.
    pub ready: bool,
}

impl Blocked {
    /// Whether the thread may run its call again at `now`, given its
    /// `TIF_SIGPENDING` flag. Descriptor readiness is found by
    /// [`poll_ready`].
    pub fn can_wake(&self, sigpending: bool, now: Instant) -> bool {
        self.woken
            || self.ready
            || (sigpending && self.wait.interruptible)
            || self.wait.deadline.is_some_and(|d| now >= d)
    }
}

/// Marks each sleeping call whose descriptors are ready now (one host
/// `poll` with a zero timeout for all of them).
pub fn poll_ready<'a>(blocked: impl Iterator<Item = &'a mut Blocked>) {
    let mut owners: Vec<&mut Blocked> = blocked.filter(|b| !b.wait.fds.is_empty()).collect();
    if owners.is_empty() {
        return;
    }
    let fds: Vec<(i32, bool, bool)> = owners
        .iter()
        .flat_map(|b| b.wait.fds.iter().copied())
        .collect();
    let Ok(r) = host::poll(&fds, 0) else {
        return;
    };
    let mut at = 0;
    for b in owners.iter_mut() {
        let n = b.wait.fds.len();
        if r[at..at + n].iter().any(Readiness::any) {
            b.ready = true;
        }
        at += n;
    }
}

/// Nothing can end the wait: no descriptor, deadline, timer, or
/// host-signal source exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadlock;

impl Deadlock {
    /// The diagnostic a process ends with.
    pub fn message(self) -> String {
        "every thread sleeps and nothing can wake one (no descriptor, deadline, timer, or \
         forwarded host signal)"
            .into()
    }
}

/// Sub-millisecond waits without descriptors sleep directly: `poll`'s
/// timeout has millisecond resolution.
const PRECISE_SLEEP: Duration = Duration::from_millis(2);

/// Sleeps the host until one of `fds` is ready, `deadline` passes, or a
/// forwarded host signal arrives (its wake-pipe byte is drained). Returns
/// early, without error, when the host `poll` is interrupted.
pub fn sleep(fds: &[(i32, bool, bool)], deadline: Option<Instant>) -> Result<(), Deadlock> {
    let wake = host::wake_fd();
    if fds.is_empty() && wake.is_none() && deadline.is_none() {
        return Err(Deadlock);
    }
    let now = Instant::now();
    let left = deadline.map(|d| d.saturating_duration_since(now));
    if left.is_some_and(|d| d.is_zero()) {
        return Ok(());
    }
    if fds.is_empty() && left.is_some_and(|d| d < PRECISE_SLEEP || wake.is_none()) {
        std::thread::sleep(left.unwrap());
        return Ok(());
    }
    let timeout_ms = left.map_or(-1, |d| {
        i32::try_from(d.as_nanos().div_ceil(1_000_000)).unwrap_or(i32::MAX)
    });
    let mut all = fds.to_vec();
    if let Some(w) = wake {
        all.push((w, true, false));
    }
    if let Ok(r) = host::poll(&all, timeout_ms)
        && wake.is_some()
        && r.last().is_some_and(|x| x.readable)
    {
        host::drain_wake();
    }
    Ok(())
}
