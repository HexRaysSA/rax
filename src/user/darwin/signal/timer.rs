//! Interval timers (`setitimer`, `getitimer`, `realitexpire`,
//! `itimerdecr` in `bsd/kern/kern_time.c`, and the virtual-timer checks
//! of `bsd_ast`).
//!
//! `ITIMER_REAL` counts uptime: its expiry is a deadline the scheduler
//! waits for and then sends `SIGALRM` to the process. `ITIMER_VIRTUAL`
//! counts the process's user CPU time and `ITIMER_PROF` its user and
//! system time; they are charged after each time slice of a thread and
//! send `SIGVTALRM` and `SIGPROF` to that thread when they expire.

use std::time::{Duration, Instant};

use super::{Origin, Proc, SIGALRM, SIGPROF, SIGVTALRM, Thread};

/// `ITIMER_REAL`.
pub const ITIMER_REAL: u32 = 0;
/// `ITIMER_VIRTUAL`.
pub const ITIMER_VIRTUAL: u32 = 1;
/// `ITIMER_PROF`.
pub const ITIMER_PROF: u32 = 2;

/// A `struct timeval`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimeVal {
    /// Seconds.
    pub sec: i64,
    /// Microseconds.
    pub usec: i64,
}

impl TimeVal {
    /// `timerisset`.
    pub fn is_set(&self) -> bool {
        self.sec != 0 || self.usec != 0
    }

    /// `itimerfix`: seconds within 0 ..= 100 000 000, microseconds below
    /// one second.
    pub fn valid(&self) -> bool {
        (0..=100_000_000).contains(&self.sec) && (0..1_000_000).contains(&self.usec)
    }

    fn duration(&self) -> Duration {
        Duration::from_secs(self.sec as u64) + Duration::from_micros(self.usec as u64)
    }

    fn from_duration(d: Duration) -> Self {
        TimeVal {
            sec: d.as_secs() as i64,
            usec: i64::from(d.subsec_micros()),
        }
    }
}

/// A `struct itimerval`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ITimerVal {
    /// The reload value.
    pub interval: TimeVal,
    /// The time to the next expiry.
    pub value: TimeVal,
}

/// A process's interval timers.
#[derive(Clone, Copy, Debug, Default)]
pub struct ITimers {
    /// `ITIMER_REAL`'s interval (`p_realtimer.it_interval`).
    pub real_interval: TimeVal,
    /// When `ITIMER_REAL` next expires (`p_rtime`).
    pub real_at: Option<Instant>,
    /// `ITIMER_VIRTUAL` (`p_vtimer_user`).
    pub virt: ITimerVal,
    /// `ITIMER_PROF` (`p_vtimer_prof`).
    pub prof: ITimerVal,
}

impl ITimers {
    /// `getitimer(which)`; `which` is valid.
    pub fn get(&self, which: u32) -> ITimerVal {
        match which {
            ITIMER_REAL => ITimerVal {
                interval: self.real_interval,
                value: self
                    .real_at
                    .map(|at| TimeVal::from_duration(at.saturating_duration_since(Instant::now())))
                    .unwrap_or_default(),
            },
            ITIMER_VIRTUAL => self.virt,
            _ => self.prof,
        }
    }

    /// `setitimer(which)` with a validated value.
    pub fn set(&mut self, which: u32, v: ITimerVal) {
        match which {
            ITIMER_REAL => {
                self.real_interval = v.interval;
                self.real_at = v
                    .value
                    .is_set()
                    .then(|| Instant::now() + v.value.duration());
            }
            ITIMER_VIRTUAL => self.virt = v,
            _ => self.prof = v,
        }
    }
}

/// Sends `SIGALRM` when `ITIMER_REAL` expired and rearms it
/// (`realitexpire`): the next expiry is a whole number of intervals after
/// the last, skipping those already past, unless the timer fell more
/// than two seconds behind.
pub fn expire_real(proc: &mut Proc) {
    let now = Instant::now();
    let Some(at) = proc.itimers.real_at.filter(|&at| at <= now) else {
        return;
    };
    super::psignal(proc, None, SIGALRM, Origin::KERNEL);
    let t = &mut proc.itimers;
    if !t.real_interval.is_set() {
        t.real_at = None;
        return;
    }
    let interval = t.real_interval.duration();
    let mut next = at + interval;
    if next <= now {
        if now.duration_since(next) <= Duration::from_secs(2) {
            while next <= now {
                next += interval;
            }
        } else {
            next = now + interval;
        }
    }
    t.real_at = Some(next);
}

/// `itimerdecr`: charges `usec` to `itp`; true when it expired (and was
/// reloaded from its interval).
fn itimerdecr(itp: &mut ITimerVal, mut usec: i64) -> bool {
    let v = &mut itp.value;
    if v.usec < usec {
        if v.sec == 0 {
            // Expired, and already into the next interval.
            usec -= v.usec;
            return reload(itp, usec);
        }
        v.usec += 1_000_000;
        v.sec -= 1;
    }
    v.usec -= usec;
    if v.is_set() {
        return false;
    }
    reload(itp, 0)
}

fn reload(itp: &mut ITimerVal, usec: i64) -> bool {
    if itp.interval.is_set() {
        itp.value = itp.interval;
        if itp.value.sec > 0 {
            itp.value.usec -= usec;
            if itp.value.usec < 0 {
                itp.value.usec += 1_000_000;
                itp.value.sec -= 1;
            }
        }
    } else {
        itp.value.usec = 0;
    }
    true
}

/// Charges a slice's CPU time to the virtual timers and signals
/// `thread` for each that expired.
pub fn charge(proc: &mut Proc, thread: &mut Thread, user_ns: u64, system_ns: u64) {
    let tid = thread.tid;
    if proc.itimers.virt.value.is_set()
        && itimerdecr(&mut proc.itimers.virt, (user_ns / 1000) as i64)
    {
        super::psignal_try_thread(proc, Some(thread), tid, SIGVTALRM, Origin::KERNEL);
    }
    if proc.itimers.prof.value.is_set()
        && itimerdecr(
            &mut proc.itimers.prof,
            ((user_ns + system_ns) / 1000) as i64,
        )
    {
        super::psignal_try_thread(proc, Some(thread), tid, SIGPROF, Origin::KERNEL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tv(sec: i64, usec: i64) -> TimeVal {
        TimeVal { sec, usec }
    }

    #[test]
    fn itimerfix_bounds() {
        assert!(tv(0, 0).valid());
        assert!(tv(100_000_000, 999_999).valid());
        assert!(!tv(100_000_001, 0).valid());
        assert!(!tv(0, 1_000_000).valid());
        assert!(!tv(-1, 0).valid());
    }

    #[test]
    fn itimerdecr_counts_down_and_reloads() {
        let mut t = ITimerVal {
            interval: tv(1, 0),
            value: tv(0, 300),
        };
        assert!(!itimerdecr(&mut t, 200));
        assert_eq!(t.value, tv(0, 100));
        // 50 us into the next interval: a one-second interval reloads
        // less the overshoot.
        assert!(itimerdecr(&mut t, 150));
        assert_eq!(t.value, tv(0, 999_950));
        let mut t = ITimerVal {
            interval: tv(0, 500),
            value: tv(1, 0),
        };
        assert!(!itimerdecr(&mut t, 400));
        assert_eq!(t.value, tv(0, 999_600));
        // A sub-second interval reloads whole (the kernel's rule).
        let mut t = ITimerVal {
            interval: tv(0, 500),
            value: tv(0, 10),
        };
        assert!(itimerdecr(&mut t, 20));
        assert_eq!(t.value, tv(0, 500));
        // A one-shot timer stops.
        let mut t = ITimerVal {
            interval: tv(0, 0),
            value: tv(0, 10),
        };
        assert!(itimerdecr(&mut t, 10));
        assert!(!t.value.is_set());
    }

    #[test]
    fn real_timer_reports_the_time_left() {
        let mut t = ITimers::default();
        t.set(
            ITIMER_REAL,
            ITimerVal {
                interval: tv(0, 250_000),
                value: tv(5, 0),
            },
        );
        let got = t.get(ITIMER_REAL);
        assert_eq!(got.interval, tv(0, 250_000));
        assert!(got.value.sec == 4 || got.value == tv(5, 0));
        t.set(ITIMER_REAL, ITimerVal::default());
        assert_eq!(t.get(ITIMER_REAL), ITimerVal::default());
    }
}
