//! POSIX per-process timers (`timer_create`): the state machine of
//! `kernel/time/posix-timers.c` and `kernel/time/posix-cpu-timers.c`.
//!
//! A timer counts on a base clock in nanoseconds (`ktime_t`): host
//! wall-clock time, host monotonic time, or the emulator's CPU time. Expiry
//! is found lazily: whoever looks at a timer (the scheduler between slices,
//! a system call) passes the current time, and an armed timer whose expiry
//! has passed fires then. As in the kernel, a firing timer queues its one
//! preallocated signal and does not re-arm until that signal is dequeued
//! ([`PosixTimers::deliver`]); the periods that pass meanwhile become the
//! signal's overrun count (`hrtimer_forward`). Changing or deleting a timer
//! invalidates its queued signal (`it_signal_seq`), which is then dropped at
//! dequeue.
//!
//! Every operation takes the current time of the timer's base as an
//! argument, so the state machine does not read clocks itself;
//! [`clock_now`] reads them for callers.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::host::{self, HostClock};

/// The current time of `base` in nanoseconds (the emulator's CPU time for
/// the CPU bases, as `clock_gettime` reports it).
pub fn clock_now(base: Base) -> i64 {
    let clock = match base {
        Base::Realtime => HostClock::Realtime,
        Base::Monotonic => HostClock::Monotonic,
        Base::ProcessCpu => HostClock::ProcessCpu,
        Base::ThreadCpu => HostClock::ThreadCpu,
    };
    let (sec, nsec) = host::clock_gettime(clock);
    sec.saturating_mul(1_000_000_000).saturating_add(nsec)
}

/// The instant at which wall-clock or monotonic time `at` of `base`
/// arrives, as far as the clock is known now.
pub fn instant_at(base: Base, at: i64) -> Instant {
    let left = at.saturating_sub(clock_now(base)).max(0);
    Instant::now() + Duration::from_nanos(left as u64)
}

/// `TIMER_ABSTIME`.
pub const TIMER_ABSTIME: u32 = 1;

/// `SIGEV_SIGNAL`.
pub const SIGEV_SIGNAL: i32 = 0;
/// `SIGEV_NONE`.
pub const SIGEV_NONE: i32 = 1;
/// `SIGEV_THREAD` (to the kernel, a signal to the process).
pub const SIGEV_THREAD: i32 = 2;
/// `SIGEV_THREAD_ID`.
pub const SIGEV_THREAD_ID: i32 = 4;

/// The clock a timer's expiry is measured on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base {
    /// Wall-clock time (absolute `CLOCK_REALTIME`, `CLOCK_TAI`, and
    /// `CLOCK_REALTIME_ALARM` timers).
    Realtime,
    /// Monotonic time (`CLOCK_MONOTONIC`, `CLOCK_BOOTTIME`, and relative
    /// `CLOCK_REALTIME` timers, which clock changes do not affect).
    Monotonic,
    /// Process CPU time.
    ProcessCpu,
    /// Thread CPU time.
    ThreadCpu,
}

impl Base {
    /// Whether the base counts CPU time (`clock_posix_cpu`).
    pub fn is_cpu(self) -> bool {
        matches!(self, Base::ProcessCpu | Base::ThreadCpu)
    }
}

/// Where a timer's signal goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notify {
    /// No signal (`SIGEV_NONE`).
    None,
    /// The process (`SIGEV_SIGNAL`, `SIGEV_THREAD`; `PIDTYPE_TGID`).
    Process,
    /// One thread (`SIGEV_THREAD_ID`; `PIDTYPE_PID`).
    Thread(i32),
}

/// `it_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    /// Not running.
    Disarmed,
    /// Running toward `expires`.
    Armed,
    /// Fired with an interval; re-arms when its signal is dequeued.
    RequeuePending,
}

/// A timer (`struct k_itimer`).
#[derive(Clone, Debug)]
pub struct PosixTimer {
    /// Identity of this timer object; its queued signal carries it.
    pub uid: u64,
    /// The clock it was created on (`it_clock`).
    pub clock: i32,
    /// The base of its current setting.
    pub base: Base,
    /// Its notification.
    pub notify: Notify,
    /// The signal it sends.
    pub signo: i32,
    /// `sigev_value`.
    pub value: u64,
    /// Period in nanoseconds (`it_interval`); 0 for a one-shot timer.
    interval: i64,
    /// Expiry on `base` in nanoseconds; 0 when never set (CPU timers).
    expires: i64,
    status: Status,
    /// Periods missed since the signal was queued (`it_overrun`).
    overrun: i64,
    /// The overrun count of the last delivered signal.
    overrun_last: i64,
    /// Changed on every setting and deletion.
    signal_seq: u64,
    /// `signal_seq` when the signal was last queued.
    sigqueue_seq: u64,
    /// The last queued signal came from a periodic expiry.
    sig_periodic: bool,
    /// Its signal is parked because it was ignored (`ignored_list`).
    ignored: bool,
}

impl PosixTimer {
    /// Whether the timer sends no signal.
    fn sig_none(&self) -> bool {
        self.notify == Notify::None
    }

    /// `hrtimer_forward` / `bump_cpu_timer`: moves `expires` past `now` by
    /// whole periods and returns how many.
    fn forward(&mut self, now: i64) -> i64 {
        let delta = now.saturating_sub(self.expires);
        if delta < 0 || self.interval <= 0 {
            return 0;
        }
        let orun = delta / self.interval + 1;
        self.expires = self
            .expires
            .saturating_add(self.interval.saturating_mul(orun));
        orun
    }

    /// `common_timer_get` / `__posix_cpu_timer_get`: the time left, in
    /// nanoseconds; a timer that has fired but whose signal is not yet
    /// delivered shows 1 ns, a `SIGEV_NONE` one 0.
    fn remaining(&mut self, now: i64) -> i64 {
        if self.interval == 0 && self.status == Status::Disarmed && !self.sig_none() {
            return 0;
        }
        if self.base.is_cpu() && self.expires == 0 {
            return 0;
        }
        if self.interval != 0 && self.status != Status::Armed {
            let n = self.forward(now);
            self.overrun = self.overrun.saturating_add(n);
        }
        let left = self.expires.saturating_sub(now);
        if left > 0 {
            left
        } else if self.sig_none() {
            0
        } else {
            1
        }
    }

    /// `timer_overrun_to_int`.
    fn overrun_int(&self) -> i32 {
        self.overrun_last.min(i32::MAX as i64) as i32
    }
}

/// A timer setting in nanoseconds (`struct itimerspec64`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Setting {
    /// Time to the next expiry (`it_value`).
    pub value: i64,
    /// Period (`it_interval`).
    pub interval: i64,
}

/// What a timer's expiry asks the signal code to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Firing {
    /// The timer object.
    pub uid: u64,
    /// Its ID.
    pub id: i32,
    /// Where the signal goes.
    pub notify: Notify,
    /// The signal.
    pub signo: i32,
    /// `sigev_value`.
    pub value: u64,
    /// The expiry was periodic (`it_sig_periodic`).
    pub periodic: bool,
}

/// A process's timers (`signal_struct::posix_timers`).
#[derive(Clone, Debug, Default)]
pub struct PosixTimers {
    /// `next_posix_timer_id`.
    next_id: u32,
    /// Next object identity.
    next_uid: u64,
    timers: BTreeMap<i32, PosixTimer>,
}

impl PosixTimers {
    /// `posix_timer_add`: the next free ID, counting from where the last
    /// allocation stopped; the ID is used up even if creation then fails.
    pub fn alloc_id(&mut self) -> Option<i32> {
        for _ in 0..=i32::MAX as u32 {
            let id = (self.next_id & i32::MAX as u32) as i32;
            self.next_id = self.next_id.wrapping_add(1);
            if !self.timers.contains_key(&id) {
                return Some(id);
            }
        }
        None
    }

    /// Installs a new, disarmed timer under `id`.
    pub fn insert(
        &mut self,
        id: i32,
        clock: i32,
        base: Base,
        notify: Notify,
        signo: i32,
        value: u64,
    ) {
        self.next_uid += 1;
        self.timers.insert(
            id,
            PosixTimer {
                uid: self.next_uid,
                clock,
                base,
                notify,
                signo,
                value,
                interval: 0,
                expires: 0,
                status: Status::Disarmed,
                overrun: -1,
                overrun_last: 0,
                signal_seq: 0,
                sigqueue_seq: 0,
                sig_periodic: false,
                ignored: false,
            },
        );
    }

    /// The timer with `id`.
    pub fn get(&self, id: i32) -> Option<&PosixTimer> {
        self.timers.get(&id)
    }

    /// Number of timers.
    pub fn len(&self) -> usize {
        self.timers.len()
    }

    /// Whether there are no timers.
    pub fn is_empty(&self) -> bool {
        self.timers.is_empty()
    }

    /// `timer_gettime`.
    pub fn gettime(&mut self, id: i32, now: i64) -> Option<Setting> {
        let t = self.timers.get_mut(&id)?;
        Some(Setting {
            value: t.remaining(now),
            interval: t.interval,
        })
    }

    /// `timer_settime` with a relative or absolute (`TIMER_ABSTIME`) value
    /// on `base` (the caller picks the base: relative `CLOCK_REALTIME`
    /// timers count on monotonic time). Returns the old setting and, when
    /// the new expiry of a CPU-time timer has already passed, the firing it
    /// causes at once.
    pub fn settime(
        &mut self,
        id: i32,
        flags: u32,
        new: Setting,
        base: Base,
        now: i64,
        old_now: i64,
    ) -> Option<(Setting, Option<Firing>)> {
        let t = self.timers.get_mut(&id)?;
        let old = Setting {
            interval: t.interval,
            value: t.remaining(old_now),
        };
        // Prevent delivery and re-arming of a queued signal.
        t.signal_seq += 1;
        t.status = Status::Disarmed;
        // posix_timer_set_common.
        t.interval = if new.value != 0 { new.interval } else { 0 };
        t.overrun_last = 0;
        t.overrun = -1;
        t.base = base;
        if new.value == 0 {
            if t.base.is_cpu() {
                t.expires = 0;
            }
            return Some((old, None));
        }
        t.expires = if flags & TIMER_ABSTIME != 0 {
            new.value
        } else {
            now.saturating_add(new.value)
        };
        if t.sig_none() {
            return Some((old, None));
        }
        t.status = Status::Armed;
        // A CPU timer set in the past fires within the call
        // (posix_cpu_timer_set); a high-resolution one fires as soon as it
        // is next looked at.
        let firing = (t.base.is_cpu() && now >= t.expires).then(|| Self::fire(id, t));
        Some((old, firing))
    }

    /// `timer_getoverrun`.
    pub fn getoverrun(&self, id: i32) -> Option<i32> {
        self.timers.get(&id).map(PosixTimer::overrun_int)
    }

    /// `timer_delete`: the timer is gone; a queued signal of it is dropped
    /// when dequeued.
    pub fn delete(&mut self, id: i32) -> bool {
        self.timers.remove(&id).is_some()
    }

    /// `exit_itimers`: deletes every timer (`execve`, exit).
    pub fn clear(&mut self) {
        self.timers.clear();
    }

    /// `posix_timer_fn` / `cpu_timer_fire`: the expiry of an armed timer.
    fn fire(id: i32, t: &mut PosixTimer) -> Firing {
        t.status = if t.interval != 0 {
            Status::RequeuePending
        } else {
            Status::Disarmed
        };
        if t.base.is_cpu() && t.interval == 0 {
            t.expires = 0;
        }
        t.sigqueue_seq = t.signal_seq;
        t.sig_periodic = t.status == Status::RequeuePending;
        Firing {
            uid: t.uid,
            id,
            notify: t.notify,
            signo: t.signo,
            value: t.value,
            periodic: t.sig_periodic,
        }
    }

    /// Fires every armed timer whose expiry has passed, given the current
    /// time of each base; the caller queues their signals
    /// (`posixtimer_send_sigqueue`).
    pub fn expire(&mut self, now: impl Fn(Base) -> i64) -> Vec<Firing> {
        let mut fired = Vec::new();
        for (&id, t) in self.timers.iter_mut() {
            if t.status == Status::Armed && now(t.base) >= t.expires {
                fired.push(Self::fire(id, t));
            }
        }
        fired
    }

    /// The expiries of armed wall-clock and monotonic timers, as
    /// `(base, expires)`; CPU time does not pass while the process sleeps.
    pub fn expiries(&self) -> impl Iterator<Item = (Base, i64)> + '_ {
        self.timers
            .values()
            .filter(|t| t.status == Status::Armed && !t.base.is_cpu())
            .map(|t| (t.base, t.expires))
    }

    /// When the earliest armed wall-clock or monotonic timer expires.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.expiries().map(|(b, at)| instant_at(b, at)).min()
    }

    /// Whether any timer is armed.
    pub fn armed(&self) -> bool {
        self.timers.values().any(|t| t.status == Status::Armed)
    }

    /// Whether a CPU-time timer is armed.
    pub fn cpu_armed(&self) -> bool {
        self.timers
            .values()
            .any(|t| t.status == Status::Armed && t.base.is_cpu())
    }

    /// `posixtimer_deliver_signal` for a dequeued signal of timer `uid`:
    /// `None` drops a signal the timer no longer stands behind (it was
    /// changed or deleted since); otherwise a periodic timer re-arms after
    /// the periods missed meanwhile, which become the overrun count, and
    /// the count to report is returned (0 for a one-shot timer).
    pub fn deliver(&mut self, uid: u64, now: impl Fn(Base) -> i64) -> Option<i32> {
        let t = self.timers.values_mut().find(|t| t.uid == uid)?;
        if t.signal_seq != t.sigqueue_seq {
            return None;
        }
        if t.interval == 0 || t.status != Status::RequeuePending {
            return Some(0);
        }
        let n = t.forward(now(t.base));
        t.overrun = t.overrun.saturating_add(n);
        t.status = Status::Armed;
        t.overrun_last = t.overrun;
        t.overrun = -1;
        t.signal_seq += 1;
        Some(t.overrun_int())
    }

    /// `posixtimer_sig_ignore`: the queued signal of timer `uid` was
    /// discarded because it is ignored. A periodic timer keeps it parked,
    /// to queue again when the signal is no longer ignored; otherwise it
    /// is dropped.
    pub fn sig_ignore(&mut self, uid: u64) {
        if let Some(t) = self.timers.values_mut().find(|t| t.uid == uid)
            && t.sig_periodic
        {
            t.ignored = true;
        }
    }

    /// Parks the signal of timer `uid` at its expiry: it is ignored now
    /// (`posixtimer_send_sigqueue`). A one-shot expiry instead drops a
    /// signal parked by an earlier periodic setting.
    pub fn park_ignored(&mut self, uid: u64) {
        if let Some(t) = self.timers.values_mut().find(|t| t.uid == uid) {
            t.ignored = t.sig_periodic;
        }
    }

    /// Whether timer `uid`'s signal is parked.
    pub fn is_parked(&self, uid: u64) -> bool {
        self.timers.values().any(|t| t.uid == uid && t.ignored)
    }

    /// Unparks timer `uid`'s signal as it is queued.
    pub fn unpark(&mut self, uid: u64) {
        if let Some(t) = self.timers.values_mut().find(|t| t.uid == uid) {
            t.ignored = false;
        }
    }

    /// `posixtimer_sig_unignore`: `sig` is no longer ignored; the parked
    /// signals of it are to be queued again.
    pub fn sig_unignore(&mut self, sig: i32) -> Vec<Firing> {
        let mut out = Vec::new();
        for (&id, t) in self.timers.iter_mut() {
            if t.ignored && t.signo == sig {
                t.ignored = false;
                out.push(Firing {
                    uid: t.uid,
                    id,
                    notify: t.notify,
                    signo: t.signo,
                    value: t.value,
                    periodic: t.sig_periodic,
                });
            }
        }
        out
    }
}
