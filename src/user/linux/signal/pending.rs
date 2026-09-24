//! Pending signals (`struct sigpending`): a set of pending signal numbers
//! and the queue of their `siginfo` records.
//!
//! Queueing follows `__send_signal_locked` (a standard signal that is
//! already pending is not queued again; real-time signals queue every
//! instance) and dequeueing follows `next_signal`, `collect_signal`, and
//! `dequeue_synchronous_signal` in `kernel/signal.c`. A POSIX timer's
//! signal is its one preallocated record (`SIGQUEUE_PREALLOC`), tagged
//! with the timer so that dequeueing can re-arm or drop it
//! (`posixtimer_queue_sigqueue`).

use std::collections::VecDeque;

use super::{SIGRTMIN, SYNCHRONOUS_MASK, SigInfo, sigmask};

/// A queued record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Queued {
    info: SigInfo,
    /// The POSIX timer whose preallocated record this is.
    timer: Option<u64>,
}

/// A pending set and its queue.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SigPending {
    set: u64,
    queue: VecDeque<Queued>,
}

impl SigPending {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// The pending signal numbers as a `sigset_t` word.
    pub fn set(&self) -> u64 {
        self.set
    }

    /// Whether `sig` is pending.
    pub fn contains(&self, sig: i32) -> bool {
        self.set & sigmask(sig) != 0
    }

    /// Queues `info`. A standard signal (below `SIGRTMIN`) that is already
    /// pending is not queued again (`legacy_queue`); returns whether the
    /// record was queued.
    pub fn enqueue(&mut self, info: SigInfo) -> bool {
        if info.signo < SIGRTMIN && self.contains(info.signo) {
            return false;
        }
        self.queue.push_back(Queued { info, timer: None });
        self.set |= sigmask(info.signo);
        true
    }

    /// Queues the record of POSIX timer `timer`, whether or not its signal
    /// is already pending (`posixtimer_queue_sigqueue`).
    pub fn enqueue_timer(&mut self, info: SigInfo, timer: u64) {
        self.queue.push_back(Queued {
            info,
            timer: Some(timer),
        });
        self.set |= sigmask(info.signo);
    }

    /// Whether the record of POSIX timer `timer` is queued here.
    pub fn has_timer(&self, timer: u64) -> bool {
        self.queue.iter().any(|q| q.timer == Some(timer))
    }

    /// `next_signal`: the lowest-numbered pending signal outside `blocked`,
    /// preferring synchronous (fault) signals in the first word.
    pub fn next(&self, blocked: u64) -> Option<i32> {
        let mut x = self.set & !blocked;
        if x == 0 {
            return None;
        }
        if x & SYNCHRONOUS_MASK != 0 {
            x &= SYNCHRONOUS_MASK;
        }
        Some(x.trailing_zeros() as i32 + 1)
    }

    /// Removes and returns the first queued record of `sig`
    /// (`collect_signal`), clearing `sig` from the set unless another
    /// instance remains queued.
    fn collect(&mut self, sig: i32) -> Queued {
        let first = self
            .queue
            .iter()
            .position(|q| q.info.signo == sig)
            .expect("a pending signal has a queued record");
        let q = self.queue.remove(first).unwrap();
        if !self.queue.iter().any(|q| q.info.signo == sig) {
            self.set &= !sigmask(sig);
        }
        q
    }

    /// `__dequeue_signal`: the next deliverable signal and its record.
    pub fn dequeue(&mut self, blocked: u64) -> Option<SigInfo> {
        self.dequeue_tagged(blocked).map(|(info, _)| info)
    }

    /// `__dequeue_signal`, with the POSIX timer whose record it was.
    pub fn dequeue_tagged(&mut self, blocked: u64) -> Option<(SigInfo, Option<u64>)> {
        let sig = self.next(blocked)?;
        let q = self.collect(sig);
        Some((q.info, q.timer))
    }

    /// `dequeue_synchronous_signal`: when an unblocked synchronous signal
    /// is pending, the first queued kernel-generated (fault) record of any
    /// synchronous signal, taken ahead of every other signal. As in the
    /// kernel, the record found is not re-checked against `blocked`.
    pub fn dequeue_synchronous(&mut self, blocked: u64) -> Option<SigInfo> {
        if self.set & !blocked & SYNCHRONOUS_MASK == 0 {
            return None;
        }
        let at = self
            .queue
            .iter()
            .position(|q| q.info.from_kernel() && sigmask(q.info.signo) & SYNCHRONOUS_MASK != 0)?;
        let info = self.queue.remove(at).unwrap().info;
        if !self.queue.iter().any(|q| q.info.signo == info.signo) {
            self.set &= !sigmask(info.signo);
        }
        Some(info)
    }

    /// Discards every pending instance of the signals in `mask`
    /// (`flush_sigqueue_mask`), returning the POSIX timers whose records
    /// were discarded (`sigqueue_free_ignored`).
    pub fn flush(&mut self, mask: u64) -> Vec<u64> {
        self.set &= !mask;
        let mut timers = Vec::new();
        self.queue.retain(|q| {
            let keep = sigmask(q.info.signo) & mask == 0;
            if !keep && let Some(t) = q.timer {
                timers.push(t);
            }
            keep
        });
        timers
    }

    /// `__flush_itimer_signals`: discards every `SI_TIMER` record; a
    /// signal stays pending if another record of it remains, or if it had
    /// no `SI_TIMER` record.
    pub fn flush_timer_signals(&mut self) {
        let mut retain = 0u64;
        let mut signal = self.set;
        self.queue.retain(|q| {
            if q.info.code == super::code::SI_TIMER {
                signal &= !sigmask(q.info.signo);
                false
            } else {
                retain |= sigmask(q.info.signo);
                true
            }
        });
        self.set = signal | retain;
    }

    /// Number of queued records of the signals in `mask`.
    pub fn queued_in(&self, mask: u64) -> usize {
        self.queue
            .iter()
            .filter(|q| sigmask(q.info.signo) & mask != 0)
            .count()
    }

    /// Number of queued records.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }
}
