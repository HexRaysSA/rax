//! Pending signals (`struct sigpending`): a set of pending signal numbers
//! and the queue of their `siginfo` records.
//!
//! Queueing follows `__send_signal_locked` (a standard signal that is
//! already pending is not queued again; real-time signals queue every
//! instance) and dequeueing follows `next_signal`, `collect_signal`, and
//! `dequeue_synchronous_signal` in `kernel/signal.c`.

use std::collections::VecDeque;

use super::{SIGRTMIN, SYNCHRONOUS_MASK, SigInfo, sigmask};

/// A pending set and its queue.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SigPending {
    set: u64,
    queue: VecDeque<SigInfo>,
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
        self.queue.push_back(info);
        self.set |= sigmask(info.signo);
        true
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
    fn collect(&mut self, sig: i32) -> SigInfo {
        let first = self
            .queue
            .iter()
            .position(|q| q.signo == sig)
            .expect("a pending signal has a queued record");
        let info = self.queue.remove(first).unwrap();
        if !self.queue.iter().any(|q| q.signo == sig) {
            self.set &= !sigmask(sig);
        }
        info
    }

    /// `__dequeue_signal`: the next deliverable signal and its record.
    pub fn dequeue(&mut self, blocked: u64) -> Option<SigInfo> {
        let sig = self.next(blocked)?;
        Some(self.collect(sig))
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
            .position(|q| q.from_kernel() && sigmask(q.signo) & SYNCHRONOUS_MASK != 0)?;
        let info = self.queue.remove(at).unwrap();
        if !self.queue.iter().any(|q| q.signo == info.signo) {
            self.set &= !sigmask(info.signo);
        }
        Some(info)
    }

    /// Discards every pending instance of the signals in `mask`
    /// (`flush_sigqueue_mask`).
    pub fn flush(&mut self, mask: u64) {
        self.set &= !mask;
        self.queue.retain(|q| sigmask(q.signo) & mask == 0);
    }

    /// Number of queued records.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }
}
