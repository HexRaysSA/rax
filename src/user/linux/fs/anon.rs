//! Anonymous-inode files: `eventfd` (`fs/eventfd.c`), `timerfd`
//! (`fs/timerfd.c`), and `signalfd` (`fs/signalfd.c`), and the pidfds
//! (`fs/pidfs.c`, [`pidfd`](super::pidfd)) and `epoll` instances that
//! share their shape.
//!
//! Their state lives in memory shared with forked processes
//! ([`SharedWords`]), so that a parent and a child holding the same
//! description see one counter or timer, as with a Linux open file
//! description. A small lock word serializes changes. A readiness a
//! sleeping reader or `poll` waits for is mirrored as a *level*: a
//! connected host socket pair whose one direction holds exactly one byte
//! while the condition is true, which every process holding the object
//! can wait for in the host's `poll` without consuming it.
//!
//! A `signalfd` reports the calling thread's pending signals, so its
//! readiness is evaluated by the reader; only its mask is shared.

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use super::super::abi::errno::Errno;
use super::super::host::{self, SharedWords};
use super::super::posix_timers::{Base, Setting, instant_at};

/// An anonymous-inode object.
#[derive(Debug)]
pub enum Anon {
    /// `eventfd`.
    Event(EventFd),
    /// `timerfd`.
    Timer(TimerFd),
    /// `signalfd`.
    Signal(SignalFd),
    /// `epoll`.
    Epoll(super::epoll::Epoll),
    /// A pidfd.
    Pid(std::sync::Arc<super::pidfd::Target>),
    /// An inotify instance.
    Inotify(super::super::fsnotify::Instance),
}

impl Anon {
    /// The name `/proc/<pid>/fd` shows after `anon_inode:`.
    pub fn name(&self) -> &'static str {
        match self {
            Anon::Event(_) => "[eventfd]",
            Anon::Timer(_) => "[timerfd]",
            Anon::Signal(_) => "[signalfd]",
            Anon::Epoll(_) => "[eventpoll]",
            Anon::Pid(_) => "[pidfd]",
            Anon::Inotify(_) => "inotify",
        }
    }
}

/// The lock word, held while a lock guard lives.
struct Locked<'a> {
    w: &'a [AtomicU64],
}

impl<'a> Locked<'a> {
    /// Takes the lock in word 0. Holders never block or run guest code,
    /// so the wait is short.
    fn new(w: &'a [AtomicU64]) -> Self {
        let mut spins = 0u32;
        while w[0]
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spins += 1;
            if spins < 64 {
                std::hint::spin_loop();
            } else {
                std::thread::yield_now();
            }
        }
        Locked { w }
    }

    fn get(&self, i: usize) -> u64 {
        self.w[i].load(Ordering::Relaxed)
    }

    fn set(&self, i: usize, v: u64) {
        self.w[i].store(v, Ordering::Relaxed)
    }
}

impl Drop for Locked<'_> {
    fn drop(&mut self) {
        self.w[0].store(0, Ordering::Release);
    }
}

/// Two levels in one connected socket pair: level `0` is a byte from the
/// second socket to the first (wait for the first to be readable), level
/// `1` the other way.
#[derive(Debug)]
struct Levels {
    a: OwnedFd,
    b: OwnedFd,
}

impl Levels {
    fn new() -> Result<Self, Errno> {
        let (a, b) = host::level_pair()?;
        Ok(Levels { a, b })
    }

    /// The descriptor that is readable while level `which` is set.
    fn fd(&self, which: usize) -> i32 {
        if which == 0 {
            self.a.as_raw_fd()
        } else {
            self.b.as_raw_fd()
        }
    }

    /// Sets or clears level `which`, whose current state is bit `bit` of
    /// word `flags` (updated), under the object's lock.
    fn update(&self, l: &Locked<'_>, flags: usize, bit: u64, which: usize, on: bool) {
        let bits = l.get(flags);
        let set = bits & bit != 0;
        if on == set {
            return;
        }
        let (write_to, read_from) = if which == 0 {
            (self.b.as_raw_fd(), self.a.as_raw_fd())
        } else {
            (self.a.as_raw_fd(), self.b.as_raw_fd())
        };
        if on {
            host::put_byte(write_to);
        } else {
            host::take_byte(read_from);
        }
        l.set(flags, bits ^ bit);
    }
}

/// `EFD_SEMAPHORE`.
pub const EFD_SEMAPHORE: u32 = 1;

/// An `eventfd` counter.
#[derive(Debug)]
pub struct EventFd {
    /// Words: lock, count, flags.
    words: SharedWords,
    levels: Levels,
    /// Its ID (`eventfd_ida`), shown in `fdinfo`.
    pub id: u32,
}

/// The `eventfd` IDs in use in this process (`eventfd_ida`, which is
/// system-wide in the kernel).
static EVENTFD_IDS: std::sync::Mutex<std::collections::BTreeSet<u32>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

/// `ida_alloc`: takes the smallest ID not in `ids`.
fn take_id(ids: &mut std::collections::BTreeSet<u32>) -> u32 {
    let id = (0..).find(|i| !ids.contains(i)).unwrap_or(0);
    ids.insert(id);
    id
}

/// A new `eventfd`'s ID.
fn eventfd_id() -> u32 {
    take_id(&mut EVENTFD_IDS.lock().unwrap())
}

impl Drop for EventFd {
    /// `eventfd_free_ctx`: the ID is free again.
    fn drop(&mut self) {
        EVENTFD_IDS.lock().unwrap().remove(&self.id);
    }
}

const EV_COUNT: usize = 1;
const EV_FLAGS: usize = 2;
const EV_SEMAPHORE: u64 = 1;
const EV_READABLE: u64 = 2;
const EV_WRITABLE: u64 = 4;

impl EventFd {
    /// `do_eventfd`: a counter starting at `count`.
    pub fn new(count: u32, semaphore: bool) -> Result<Self, Errno> {
        let ev = EventFd {
            words: SharedWords::new(3)?,
            levels: Levels::new()?,
            id: eventfd_id(),
        };
        {
            let l = Locked::new(ev.words.words());
            l.set(EV_COUNT, count as u64);
            l.set(EV_FLAGS, if semaphore { EV_SEMAPHORE } else { 0 });
            ev.levels_for(&l, count as u64);
        }
        Ok(ev)
    }

    fn levels_for(&self, l: &Locked<'_>, count: u64) {
        self.levels.update(l, EV_FLAGS, EV_READABLE, 0, count > 0);
        self.levels
            .update(l, EV_FLAGS, EV_WRITABLE, 1, u64::MAX - 1 > count);
    }

    /// The counter.
    pub fn count(&self) -> u64 {
        Locked::new(self.words.words()).get(EV_COUNT)
    }

    /// Whether it counts as a semaphore.
    pub fn semaphore(&self) -> bool {
        Locked::new(self.words.words()).get(EV_FLAGS) & EV_SEMAPHORE != 0
    }

    /// `eventfd_ctx_do_read`: takes the counter (or 1 from it, as a
    /// semaphore); `None` while it is zero.
    pub fn read(&self) -> Option<u64> {
        let l = Locked::new(self.words.words());
        let count = l.get(EV_COUNT);
        if count == 0 {
            return None;
        }
        let take = if l.get(EV_FLAGS) & EV_SEMAPHORE != 0 {
            1
        } else {
            count
        };
        l.set(EV_COUNT, count - take);
        self.levels_for(&l, count - take);
        Some(take)
    }

    /// `eventfd_write`: adds `v` unless the counter would pass
    /// `UINT64_MAX - 1`, returning whether it did.
    pub fn write(&self, v: u64) -> bool {
        let l = Locked::new(self.words.words());
        let count = l.get(EV_COUNT);
        if u64::MAX - count <= v {
            return false;
        }
        l.set(EV_COUNT, count + v);
        self.levels_for(&l, count + v);
        true
    }

    /// `eventfd_poll`: readable, writable, and error readiness.
    pub fn poll(&self) -> (bool, bool, bool) {
        let count = self.count();
        (count > 0, u64::MAX - 1 > count, count == u64::MAX)
    }

    /// The host descriptor readable while the counter is not zero.
    pub fn readable_fd(&self) -> i32 {
        self.levels.fd(0)
    }

    /// The host descriptor readable while a write of 1 fits.
    pub fn writable_fd(&self) -> i32 {
        self.levels.fd(1)
    }
}

/// `TFD_TIMER_ABSTIME`.
pub const TFD_TIMER_ABSTIME: u32 = 1;
/// `TFD_TIMER_CANCEL_ON_SET`.
pub const TFD_TIMER_CANCEL_ON_SET: u32 = 2;

/// A `timerfd`.
#[derive(Debug)]
pub struct TimerFd {
    /// The clock it was created on.
    pub clockid: i32,
    /// Words: lock, expiry, interval, ticks, flags.
    words: SharedWords,
    levels: Levels,
}

const TF_EXPIRES: usize = 1;
const TF_INTERVAL: usize = 2;
const TF_TICKS: usize = 3;
const TF_FLAGS: usize = 4;
const TF_ARMED: u64 = 1;
const TF_EXPIRED: u64 = 2;
const TF_READABLE: u64 = 4;
const TF_REALTIME: u64 = 8;
/// `settime_flags` live in bits 8 and up.
const TF_SETTIME_SHIFT: u32 = 8;

/// `CLOCK_REALTIME`.
const CLOCK_REALTIME: i32 = 0;
/// `CLOCK_REALTIME_ALARM`.
const CLOCK_REALTIME_ALARM: i32 = 8;

impl TimerFd {
    /// `timerfd_create` on `clockid` (already validated), disarmed.
    pub fn new(clockid: i32) -> Result<Self, Errno> {
        let t = TimerFd {
            clockid,
            words: SharedWords::new(5)?,
            levels: Levels::new()?,
        };
        {
            let l = Locked::new(t.words.words());
            let realtime = matches!(clockid, CLOCK_REALTIME | CLOCK_REALTIME_ALARM);
            l.set(TF_FLAGS, if realtime { TF_REALTIME } else { 0 });
        }
        Ok(t)
    }

    fn base(l: &Locked<'_>) -> Base {
        if l.get(TF_FLAGS) & TF_REALTIME != 0 {
            Base::Realtime
        } else {
            Base::Monotonic
        }
    }

    fn flag(l: &Locked<'_>, bit: u64) -> bool {
        l.get(TF_FLAGS) & bit != 0
    }

    fn set_flag(l: &Locked<'_>, bit: u64, on: bool) {
        let f = l.get(TF_FLAGS);
        l.set(TF_FLAGS, if on { f | bit } else { f & !bit });
    }

    /// `timerfd_tmrproc`, found lazily: an armed timer whose expiry has
    /// passed fires once (one tick) and stops until it is read.
    fn refresh(&self, l: &Locked<'_>, now: &dyn Fn(Base) -> i64) {
        if Self::flag(l, TF_ARMED) && now(Self::base(l)) >= l.get(TF_EXPIRES) as i64 {
            Self::set_flag(l, TF_ARMED, false);
            Self::set_flag(l, TF_EXPIRED, true);
            l.set(TF_TICKS, l.get(TF_TICKS).saturating_add(1));
        }
        self.levels
            .update(l, TF_FLAGS, TF_READABLE, 0, l.get(TF_TICKS) != 0);
    }

    /// `hrtimer_forward_now`: moves the expiry past now by whole periods
    /// and returns how many (at least 1 for a timer that has expired).
    fn forward(l: &Locked<'_>, now: i64) -> u64 {
        let expires = l.get(TF_EXPIRES) as i64;
        let interval = l.get(TF_INTERVAL) as i64;
        let delta = now.saturating_sub(expires);
        if delta < 0 || interval <= 0 {
            return 0;
        }
        let orun = delta / interval + 1;
        l.set(
            TF_EXPIRES,
            expires.saturating_add(interval.saturating_mul(orun)) as u64,
        );
        orun as u64
    }

    /// `timerfd_get_remaining`.
    fn remaining(l: &Locked<'_>, now: i64) -> i64 {
        (l.get(TF_EXPIRES) as i64).saturating_sub(now).max(0)
    }

    /// A periodic timer that fired is re-armed past now, its missed
    /// periods added to the ticks (`timerfd_read_iter`,
    /// `do_timerfd_gettime`).
    fn restart(&self, l: &Locked<'_>, now: &dyn Fn(Base) -> i64) -> u64 {
        if Self::flag(l, TF_EXPIRED) && l.get(TF_INTERVAL) != 0 {
            let n = Self::forward(l, now(Self::base(l)));
            Self::set_flag(l, TF_ARMED, true);
            return n.saturating_sub(1);
        }
        0
    }

    /// `do_timerfd_settime`: returns the previous setting.
    pub fn settime(&self, flags: u32, new: Setting, now: &dyn Fn(Base) -> i64) -> Setting {
        let l = Locked::new(self.words.words());
        self.refresh(&l, now);
        Self::set_flag(&l, TF_ARMED, false);
        if Self::flag(&l, TF_EXPIRED) && l.get(TF_INTERVAL) != 0 {
            Self::forward(&l, now(Self::base(&l)));
        }
        let old = Setting {
            value: Self::remaining(&l, now(Self::base(&l))),
            interval: l.get(TF_INTERVAL) as i64,
        };
        // timerfd_setup. A relative CLOCK_REALTIME timer counts on
        // monotonic time (hrtimer_setup); an alarm timer on its clock.
        let realtime = match self.clockid {
            CLOCK_REALTIME => flags & TFD_TIMER_ABSTIME != 0,
            CLOCK_REALTIME_ALARM => true,
            _ => false,
        };
        Self::set_flag(&l, TF_REALTIME, realtime);
        Self::set_flag(&l, TF_EXPIRED, false);
        l.set(TF_TICKS, 0);
        l.set(TF_INTERVAL, new.interval as u64);
        let expires = if new.value != 0 && flags & TFD_TIMER_ABSTIME == 0 {
            now(Self::base(&l)).saturating_add(new.value)
        } else {
            new.value
        };
        l.set(TF_EXPIRES, expires as u64);
        Self::set_flag(&l, TF_ARMED, new.value != 0);
        let f = l.get(TF_FLAGS) & ((1 << TF_SETTIME_SHIFT) - 1);
        let settime = (flags & (TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET)) as u64;
        l.set(TF_FLAGS, f | settime << TF_SETTIME_SHIFT);
        self.refresh(&l, now);
        old
    }

    /// `do_timerfd_gettime`.
    pub fn gettime(&self, now: &dyn Fn(Base) -> i64) -> Setting {
        let l = Locked::new(self.words.words());
        self.refresh(&l, now);
        if Self::flag(&l, TF_EXPIRED) && l.get(TF_INTERVAL) != 0 {
            let extra = self.restart(&l, now);
            Self::set_flag(&l, TF_EXPIRED, false);
            l.set(TF_TICKS, l.get(TF_TICKS).saturating_add(extra));
        }
        self.refresh(&l, now);
        Setting {
            value: Self::remaining(&l, now(Self::base(&l))),
            interval: l.get(TF_INTERVAL) as i64,
        }
    }

    /// `timerfd_read_iter`: the expirations since the last read, which
    /// re-arms a periodic timer; `None` when there are none.
    pub fn read(&self, now: &dyn Fn(Base) -> i64) -> Option<u64> {
        let l = Locked::new(self.words.words());
        self.refresh(&l, now);
        let ticks = l.get(TF_TICKS);
        if ticks == 0 {
            return None;
        }
        let total = ticks.saturating_add(self.restart(&l, now));
        Self::set_flag(&l, TF_EXPIRED, false);
        l.set(TF_TICKS, 0);
        self.refresh(&l, now);
        Some(total)
    }

    /// `TFD_IOC_SET_TICKS`.
    pub fn set_ticks(&self, n: u64, now: &dyn Fn(Base) -> i64) {
        let l = Locked::new(self.words.words());
        self.refresh(&l, now);
        l.set(TF_TICKS, n);
        self.refresh(&l, now);
    }

    /// `timerfd_poll`: whether a read would not block.
    pub fn readable(&self, now: &dyn Fn(Base) -> i64) -> bool {
        self.pending_ticks(now) != 0
    }

    /// What `timerfd_show` reports: the expirations counted since the last
    /// read, the time to the next expiry (0 once it has passed), and the
    /// period, without re-arming a periodic timer.
    pub fn shown(&self, now: &dyn Fn(Base) -> i64) -> (u64, i64, i64) {
        let l = Locked::new(self.words.words());
        self.refresh(&l, now);
        let value = if Self::flag(&l, TF_ARMED) {
            Self::remaining(&l, now(Self::base(&l)))
        } else {
            0
        };
        (l.get(TF_TICKS), value, l.get(TF_INTERVAL) as i64)
    }

    /// The expirations a read would count now, before the periods a
    /// periodic timer has missed since it fired.
    pub fn pending_ticks(&self, now: &dyn Fn(Base) -> i64) -> u64 {
        let l = Locked::new(self.words.words());
        self.refresh(&l, now);
        l.get(TF_TICKS)
    }

    /// When an armed timer expires.
    pub fn deadline(&self) -> Option<Instant> {
        let l = Locked::new(self.words.words());
        Self::flag(&l, TF_ARMED).then(|| instant_at(Self::base(&l), l.get(TF_EXPIRES) as i64))
    }

    /// The host descriptor readable while ticks are pending.
    pub fn readable_fd(&self) -> i32 {
        self.levels.fd(0)
    }

    /// The `TFD_TIMER_*` flags of the last setting.
    pub fn settime_flags(&self) -> u32 {
        (Locked::new(self.words.words()).get(TF_FLAGS) >> TF_SETTIME_SHIFT) as u32
    }
}

/// A `signalfd`.
#[derive(Debug)]
pub struct SignalFd {
    /// Word 0: the signals it reports.
    words: SharedWords,
}

impl SignalFd {
    /// A `signalfd` for the signals in `mask`.
    pub fn new(mask: u64) -> Result<Self, Errno> {
        let s = SignalFd {
            words: SharedWords::new(1)?,
        };
        s.set_mask(mask);
        Ok(s)
    }

    /// The signals it reports.
    pub fn mask(&self) -> u64 {
        self.words.words()[0].load(Ordering::Acquire)
    }

    /// Replaces the signals it reports.
    pub fn set_mask(&self, mask: u64) {
        self.words.words()[0].store(mask, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eventfd_ids_are_the_smallest_free() {
        let mut ids = std::collections::BTreeSet::new();
        assert_eq!(
            (take_id(&mut ids), take_id(&mut ids), take_id(&mut ids)),
            (0, 1, 2)
        );
        ids.remove(&1);
        assert_eq!(take_id(&mut ids), 1);
        assert_eq!(take_id(&mut ids), 3);
    }
}
