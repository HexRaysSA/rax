//! Interval timers (`kernel/time/itimer.c`): `ITIMER_REAL`, which runs on the
//! monotonic clock and raises `SIGALRM`, and the process CPU-time timers
//! `ITIMER_VIRTUAL` (user time, `SIGVTALRM`) and `ITIMER_PROF` (user and
//! system time, `SIGPROF`).
//!
//! As in the kernel, an expired `ITIMER_REAL` with an interval is re-armed
//! only when its `SIGALRM` is dequeued (`posixtimer_rearm_itimer`), so a
//! blocked `SIGALRM` accumulates no expiries; the CPU timers re-arm at
//! expiry (`check_cpu_itimer`). CPU time is the emulator process's host CPU
//! time, which includes emulation overhead.

use std::time::{Duration, Instant};

/// `TICK_NSEC` at `CONFIG_HZ=250`: 4 ms, added to a new CPU-timer value.
pub const TICK_NSEC: u64 = 4_000_000;

/// `ITIMER_REAL`.
pub const ITIMER_REAL: i32 = 0;
/// `ITIMER_VIRTUAL`.
pub const ITIMER_VIRTUAL: i32 = 1;
/// `ITIMER_PROF`.
pub const ITIMER_PROF: i32 = 2;

/// State of `ITIMER_REAL`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Real {
    /// Not running.
    #[default]
    Disarmed,
    /// Running; expires at the instant.
    Armed(Instant),
    /// Expired at the instant; waits for its `SIGALRM` to be dequeued to
    /// re-arm with the interval.
    Fired(Instant),
}

/// A process CPU-time interval timer, in nanoseconds of the clock it
/// samples (`struct cpu_itimer`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuItimer {
    /// Absolute expiry in CPU nanoseconds; zero when disarmed.
    pub expires: u64,
    /// Interval.
    pub incr: u64,
}

/// A timer value and interval, as `struct itimerspec64`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ItimerSpec {
    /// Time to the next expiry.
    pub value: Duration,
    /// Reload interval.
    pub interval: Duration,
}

impl ItimerSpec {
    /// Decodes `struct itimerval` (`it_interval`, `it_value`; `timeval`
    /// pairs of 64-bit words). Microseconds must be below one million and
    /// seconds non-negative (`timeval_valid`).
    pub fn decode_itimerval(b: &[u8; 32]) -> Option<Self> {
        let w = |i: usize| i64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        let tv = |sec: i64, usec: i64| {
            (sec >= 0 && (0..1_000_000).contains(&usec))
                .then(|| Duration::new(sec as u64, usec as u32 * 1000))
        };
        Some(ItimerSpec {
            interval: tv(w(0), w(1))?,
            value: tv(w(2), w(3))?,
        })
    }

    /// Encodes `struct itimerval`, truncating to microseconds
    /// (`put_itimerval`).
    pub fn encode_itimerval(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, d) in [self.interval, self.value].into_iter().enumerate() {
            b[i * 16..i * 16 + 8].copy_from_slice(&(d.as_secs() as i64).to_le_bytes());
            b[i * 16 + 8..i * 16 + 16]
                .copy_from_slice(&(i64::from(d.subsec_micros())).to_le_bytes());
        }
        b
    }
}

/// A process's interval timers.
#[derive(Clone, Debug, Default)]
pub struct Itimers {
    real: Real,
    real_incr: Duration,
    /// `ITIMER_VIRTUAL` and `ITIMER_PROF`.
    pub cpu: [CpuItimer; 2],
}

/// Process CPU time as `[user, user + system]` nanoseconds, the samples
/// `ITIMER_VIRTUAL` and `ITIMER_PROF` count.
pub fn cpu_samples() -> [u64; 2] {
    let (user_us, system_us, _) = super::host::rusage_self();
    [user_us * 1000, (user_us + system_us) * 1000]
}

impl Itimers {
    /// When `ITIMER_REAL` expires next.
    pub fn next_deadline(&self) -> Option<Instant> {
        match self.real {
            Real::Armed(at) => Some(at),
            _ => None,
        }
    }

    /// Whether a CPU-time timer is running.
    pub fn cpu_armed(&self) -> bool {
        self.cpu.iter().any(|t| t.expires != 0)
    }

    /// Expires the timers due at `now` with CPU samples `cpu` (sampled only
    /// when a CPU timer runs) and returns the signals they raise.
    pub fn expire(&mut self, now: Instant, cpu: impl FnOnce() -> [u64; 2]) -> Vec<i32> {
        use super::signal::{SIGALRM, SIGPROF, SIGVTALRM};
        let mut out = Vec::new();
        if let Real::Armed(at) = self.real
            && now >= at
        {
            self.real = if self.real_incr.is_zero() {
                Real::Disarmed
            } else {
                Real::Fired(at)
            };
            out.push(SIGALRM);
        }
        if self.cpu_armed() {
            let samples = cpu();
            for (i, sig) in [SIGVTALRM, SIGPROF].into_iter().enumerate() {
                let t = &mut self.cpu[i];
                if t.expires != 0 && samples[i] >= t.expires {
                    t.expires = if t.incr != 0 { t.expires + t.incr } else { 0 };
                    out.push(sig);
                }
            }
        }
        out
    }

    /// `posixtimer_rearm_itimer`, when `SIGALRM` is dequeued: a fired timer
    /// with an interval restarts at the first multiple of the interval
    /// after its last expiry that lies in the future (`hrtimer_forward_now`).
    pub fn rearm_real(&mut self, now: Instant) {
        if let Real::Fired(at) = self.real {
            let incr = self.real_incr.as_nanos();
            let behind = now.saturating_duration_since(at).as_nanos();
            let steps = behind / incr + 1;
            let next = at + Duration::from_nanos((steps * incr).min(u64::MAX as u128) as u64);
            self.real = Real::Armed(next);
        }
    }

    /// `do_getitimer`.
    pub fn get(&self, which: i32, now: Instant, cpu: impl FnOnce() -> [u64; 2]) -> ItimerSpec {
        match which {
            ITIMER_REAL => {
                // itimer_get_remtime: at least 1 us while running.
                let value = match self.real {
                    Real::Armed(at) => {
                        (at.saturating_duration_since(now)).max(Duration::from_micros(1))
                    }
                    _ => Duration::ZERO,
                };
                ItimerSpec {
                    value,
                    interval: self.real_incr,
                }
            }
            _ => {
                let i = (which - 1) as usize;
                let t = self.cpu[i];
                let value = if t.expires == 0 {
                    0
                } else {
                    let now = cpu()[i];
                    if t.expires < now {
                        TICK_NSEC
                    } else {
                        t.expires - now
                    }
                };
                ItimerSpec {
                    value: Duration::from_nanos(value),
                    interval: Duration::from_nanos(t.incr),
                }
            }
        }
    }

    /// `do_setitimer`: installs `new` and returns the old setting.
    pub fn set(
        &mut self,
        which: i32,
        new: ItimerSpec,
        now: Instant,
        cpu: impl FnOnce() -> [u64; 2],
    ) -> ItimerSpec {
        match which {
            ITIMER_REAL => {
                let old = self.get(which, now, || [0, 0]);
                if new.value.is_zero() {
                    self.real = Real::Disarmed;
                    self.real_incr = Duration::ZERO;
                } else {
                    self.real_incr = new.interval;
                    self.real = Real::Armed(now + new.value);
                }
                old
            }
            _ => {
                // set_cpu_itimer / set_process_cpu_timer.
                let i = (which - 1) as usize;
                let t = self.cpu[i];
                let (mut oval, mut nval) = (t.expires, new.value.as_nanos() as u64);
                if oval != 0 || nval != 0 {
                    let now = cpu()[i];
                    if nval > 0 {
                        nval += TICK_NSEC;
                    }
                    if oval != 0 {
                        oval = if oval <= now { TICK_NSEC } else { oval - now };
                    }
                    if nval != 0 {
                        nval += now;
                    }
                }
                self.cpu[i] = CpuItimer {
                    expires: nval,
                    incr: new.interval.as_nanos() as u64,
                };
                ItimerSpec {
                    value: Duration::from_nanos(oval),
                    interval: Duration::from_nanos(t.incr),
                }
            }
        }
    }
}
