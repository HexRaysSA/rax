//! Sleeping in system calls.
//!
//! Every thread of a process runs on one host thread, so a call that must
//! sleep cannot block the host while another guest thread could run. Its
//! handler records what it waits for (a [`Wait`]) and returns
//! `ERESTART`: the thread's PC is backed up over the trap instruction and
//! the thread parks. When the wait can end — a descriptor is ready, the
//! deadline passed, a signal arrived, or another thread posted the event it
//! waits for ([`WaitKey`]) — the thread runs again and executes the same
//! trap, re-evaluating its condition. A deadline survives the re-execution
//! in the thread's [`Resume`] record, so a timed call waits for its whole
//! timeout once.
//!
//! When every thread sleeps, [`sleep`] blocks in the host's `poll` for the
//! earliest event that can wake one: their descriptors and the nearest
//! deadline.

use std::time::{Duration, Instant};

/// An event other threads post to wake sleepers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WaitKey {
    /// A user address (`ulock`, `psynch`, `__semwait_signal`).
    Address(u64),
    /// A Mach port (or port set) gained a message (by identity).
    Port(u64),
    /// A Mach port's queue gained room for a message (by port identity).
    PortSpace(u64),
    /// A semaphore was signaled (by semaphore identity).
    Semaphore(u64),
    /// A child process changed state.
    Child,
    /// A thread exited (by thread ID), for joins.
    ThreadExit(u64),
    /// A kqueue gained an event (by kqueue identity).
    Kqueue(u64),
}

/// What a sleeping call waits for.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Wait {
    /// Host descriptors with the readiness each waits for (`(fd, read,
    /// write)`).
    pub fds: Vec<(i32, bool, bool)>,
    /// When the call's timeout expires.
    pub deadline: Option<Instant>,
    /// Events that wake the thread.
    pub keys: Vec<WaitKey>,
    /// Whether a signal ends the wait.
    pub interruptible: bool,
    /// When the wait began, in wait order (see [`next_seq`]): targeted
    /// wakes serve the oldest waiter first.
    pub seq: u64,
}

static WAIT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// The next wait-order stamp.
pub fn next_seq() -> u64 {
    WAIT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

impl Wait {
    /// A wait for `key`, a signal, or `deadline`.
    pub fn key(key: WaitKey, deadline: Option<Instant>) -> Self {
        Wait {
            keys: vec![key],
            deadline,
            interruptible: true,
            ..Default::default()
        }
    }

    /// A wait for a signal or `deadline`.
    pub fn until(deadline: Option<Instant>) -> Self {
        Wait {
            deadline,
            interruptible: true,
            ..Default::default()
        }
    }

    /// A wait for readiness of host descriptors, a signal, or `deadline`.
    pub fn fds(fds: Vec<(i32, bool, bool)>, deadline: Option<Instant>) -> Self {
        Wait {
            fds,
            deadline,
            interruptible: true,
            ..Default::default()
        }
    }
}

/// Progress a restarted call keeps: the trap it belongs to and the absolute
/// deadline computed on its first execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resume {
    /// PC of the trap instruction.
    pub pc: u64,
    /// The call's number (BSD number, or negative Mach trap).
    pub call: i64,
    /// The deadline, if the call has a timeout.
    pub deadline: Option<Instant>,
    /// How far a multi-stage call got (`mach_msg`: 1 once its send is
    /// done, so the restart only receives).
    pub step: u32,
}

/// Polls host descriptors once without sleeping: which of `fds` are ready.
pub fn ready_now(fds: &[(i32, bool, bool)]) -> Vec<bool> {
    poll(fds, Some(Duration::ZERO))
}

/// Sleeps until one of `fds` is ready or `deadline` passes (forever when
/// neither is given and `fds` is empty: the caller must not do that).
/// Returns each descriptor's readiness.
pub fn sleep(fds: &[(i32, bool, bool)], deadline: Option<Instant>) -> Vec<bool> {
    let timeout = deadline.map(|d| d.saturating_duration_since(Instant::now()));
    poll(fds, timeout)
}

fn poll(fds: &[(i32, bool, bool)], timeout: Option<Duration>) -> Vec<bool> {
    let mut pfds: Vec<libc::pollfd> = fds
        .iter()
        .map(|&(fd, r, w)| libc::pollfd {
            fd,
            events: (if r { libc::POLLIN } else { 0 }) | (if w { libc::POLLOUT } else { 0 }),
            revents: 0,
        })
        .collect();
    let ms = match timeout {
        None => -1,
        Some(d) => {
            d.as_millis().min(i32::MAX as u128) as i32
                + i32::from(d.as_millis() == 0 && !d.is_zero())
        }
    };
    // SAFETY: `pfds` is a live, correctly sized array of pollfd for the
    // duration of the call.
    let n = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, ms) };
    if n <= 0 {
        return vec![false; fds.len()];
    }
    pfds.iter()
        .map(|p| {
            p.revents
                & (libc::POLLIN | libc::POLLOUT | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)
                != 0
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_of_a_pipe() {
        let mut fds = [0i32; 2];
        // SAFETY: `fds` has room for the two descriptors pipe writes.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        assert_eq!(ready_now(&[(fds[0], true, false)]), vec![false]);
        assert_eq!(ready_now(&[(fds[1], false, true)]), vec![true]);
        // SAFETY: writing one byte from a live buffer to our pipe.
        assert_eq!(unsafe { libc::write(fds[1], b"x".as_ptr().cast(), 1) }, 1);
        assert_eq!(sleep(&[(fds[0], true, false)], None), vec![true]);
        let start = Instant::now();
        sleep(&[], Some(start + Duration::from_millis(20)));
        assert!(start.elapsed() >= Duration::from_millis(19));
        // SAFETY: closing the descriptors this test created.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}
