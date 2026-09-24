//! Blocking: a thread sleeps in the host's `poll` until a watched
//! descriptor is ready, a signal it does not block becomes pending, or a
//! deadline passes.
//!
//! Signals come from the process itself, from expiring interval timers, and
//! from host signals when forwarding is installed
//! ([`forward_host_signals`](super::host::forward_host_signals)); the wait
//! watches the host-signal wake pipe and the nearest timer deadline so none
//! of them is missed. As in the kernel (`do_poll`, `pipe_read`), a ready
//! descriptor takes precedence over a pending signal, and a pending signal
//! over the deadline.

use std::time::{Duration, Instant};

use super::host::{self, Readiness};
use super::process::{ProcState, Thread};
use super::signal::deliver::collect_async;

/// How a wait ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Wake {
    /// A watched descriptor is ready; its readiness, in request order.
    Ready(Vec<Readiness>),
    /// A signal outside the wait's mask is pending.
    Signal,
    /// The deadline passed.
    Timeout,
}

/// Nothing can end the wait: no descriptor, deadline, timer, or host-signal
/// source exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadlock;

impl Deadlock {
    /// The diagnostic a process ends with.
    pub fn message(self) -> String {
        "the only thread blocks and nothing can wake it (no descriptor, deadline, timer, or \
         forwarded host signal)"
            .into()
    }
}

/// `signal_pending` with `blocked` as the mask: a signal outside it is
/// pending for the thread or the process.
pub fn signal_pending(p: &ProcState, t: &Thread, blocked: u64) -> bool {
    t.pending.next(blocked).is_some() || p.shared_pending.next(blocked).is_some()
}

/// Sub-millisecond waits without descriptors sleep directly: `poll`'s
/// timeout has millisecond resolution.
const PRECISE_SLEEP: Duration = Duration::from_millis(2);

/// Blocks thread `t` until one of `fds` (`(host fd, read, write)`) is
/// ready, a signal outside `blocked` is pending, or `deadline` passes.
pub fn block(
    p: &mut ProcState,
    t: &mut Thread,
    fds: &[(i32, bool, bool)],
    deadline: Option<Instant>,
    blocked: u64,
) -> Result<Wake, Deadlock> {
    loop {
        collect_async(p, t);
        if !fds.is_empty() {
            let r = host::poll(fds, 0).unwrap_or_default();
            if r.iter().any(Readiness::any) {
                return Ok(Wake::Ready(r));
            }
        }
        if signal_pending(p, t, blocked) {
            return Ok(Wake::Signal);
        }
        let now = Instant::now();
        if deadline.is_some_and(|d| now >= d) {
            return Ok(Wake::Timeout);
        }
        // CPU-time timers cannot expire while the process sleeps.
        let limit = [deadline, p.itimers.next_deadline()]
            .into_iter()
            .flatten()
            .min();
        let wake = host::wake_fd();
        if fds.is_empty() && wake.is_none() && limit.is_none() {
            return Err(Deadlock);
        }
        let left = limit.map(|l| l.saturating_duration_since(now));
        if fds.is_empty() && left.is_some_and(|d| d < PRECISE_SLEEP || wake.is_none()) {
            std::thread::sleep(left.unwrap());
            continue;
        }
        let timeout_ms = left.map_or(-1, |d| {
            i32::try_from(d.as_nanos().div_ceil(1_000_000)).unwrap_or(i32::MAX)
        });
        let mut all = fds.to_vec();
        if let Some(w) = wake {
            all.push((w, true, false));
        }
        if let Ok(r) = host::poll(&all, timeout_ms) {
            if wake.is_some() && r.last().is_some_and(|x| x.readable) {
                host::drain_wake();
            }
            if r[..fds.len()].iter().any(Readiness::any) {
                return Ok(Wake::Ready(r[..fds.len()].to_vec()));
            }
        }
        // EINTR (a host signal arrived) or a timeout: re-evaluate.
    }
}
