//! Clock and sleep system calls.

use std::time::{Duration, Instant};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::types::Timespec;
use super::super::host::{self, HostClock};
use super::super::signal::deliver::restart::{ERESTART_RESTARTBLOCK, ERESTARTNOHAND};
use super::super::timers::{ITIMER_PROF, ITIMER_REAL, ITIMER_VIRTUAL, ItimerSpec, cpu_samples};
use super::super::wait;
use super::{Ctx, Outcome, RestartBlock, SysResult};

/// Linux clock IDs (`linux/time.h`).
mod clk {
    pub const REALTIME: i32 = 0;
    pub const MONOTONIC: i32 = 1;
    pub const PROCESS_CPUTIME_ID: i32 = 2;
    pub const THREAD_CPUTIME_ID: i32 = 3;
    pub const MONOTONIC_RAW: i32 = 4;
    pub const REALTIME_COARSE: i32 = 5;
    pub const MONOTONIC_COARSE: i32 = 6;
    pub const BOOTTIME: i32 = 7;
    pub const REALTIME_ALARM: i32 = 8;
    pub const BOOTTIME_ALARM: i32 = 9;
    pub const TAI: i32 = 11;
}

/// Coarse clocks tick at the scheduler rate: 4 ms at `CONFIG_HZ=250`.
const COARSE_RESOLUTION_NS: i64 = 4_000_000;

/// The host clock backing a Linux clock ID, and whether it is coarse.
fn host_clock(c: &Ctx<'_>, id: i32) -> Result<(HostClock, bool), Errno> {
    use clk::*;
    Ok(match id {
        REALTIME | REALTIME_ALARM | TAI => (HostClock::Realtime, false),
        REALTIME_COARSE => (HostClock::Realtime, true),
        MONOTONIC | MONOTONIC_RAW | BOOTTIME | BOOTTIME_ALARM => (HostClock::Monotonic, false),
        MONOTONIC_COARSE => (HostClock::Monotonic, true),
        PROCESS_CPUTIME_ID => (HostClock::ProcessCpu, false),
        THREAD_CPUTIME_ID => (HostClock::ThreadCpu, false),
        id if id < 0 => {
            // CPU-time clocks of a process or thread: ~pid in bits 3..,
            // type in bits 0..1, bit 2 selects a thread.
            let pid = !(id >> 3);
            let thread = id & 4 != 0;
            if id & 3 == 3 || (pid != 0 && pid != c.p.pid && pid != c.t.tid) {
                return Err(Errno(EINVAL));
            }
            (
                if thread {
                    HostClock::ThreadCpu
                } else {
                    HostClock::ProcessCpu
                },
                false,
            )
        }
        _ => return Err(Errno(EINVAL)),
    })
}

fn now(clock: HostClock) -> Timespec {
    let (sec, nsec) = host::clock_gettime(clock);
    Timespec { sec, nsec }
}

/// `clock_gettime`.
pub fn clock_gettime(c: &mut Ctx<'_>, id: i32, tp: u64) -> SysResult {
    let (clock, coarse) = host_clock(c, id)?;
    let mut t = now(clock);
    if coarse {
        t.nsec -= t.nsec % COARSE_RESOLUTION_NS;
    }
    c.write_mem(tp, &t.encode())?;
    Ok(0)
}

/// `clock_getres`.
pub fn clock_getres(c: &mut Ctx<'_>, id: i32, res: u64) -> SysResult {
    let (clock, coarse) = host_clock(c, id)?;
    if res != 0 {
        let ns = if coarse {
            COARSE_RESOLUTION_NS
        } else {
            // hrtimer resolution is 1 ns whenever high-resolution timers
            // are active, whatever the host reports.
            let _ = host::clock_getres(clock);
            1
        };
        c.write_mem(res, &Timespec { sec: 0, nsec: ns }.encode())?;
    }
    Ok(0)
}

/// `gettimeofday`: `struct timeval` and a zero `struct timezone`.
pub fn gettimeofday(c: &mut Ctx<'_>, tv: u64, tz: u64) -> SysResult {
    if tv != 0 {
        let t = now(HostClock::Realtime);
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&t.sec.to_le_bytes());
        b[8..].copy_from_slice(&(t.nsec / 1000).to_le_bytes());
        c.write_mem(tv, &b)?;
    }
    if tz != 0 {
        c.write_mem(tz, &[0u8; 8])?;
    }
    Ok(0)
}

/// `time`.
pub fn time(c: &mut Ctx<'_>, tloc: u64) -> SysResult {
    let t = now(HostClock::Realtime);
    if tloc != 0 {
        c.write_u64(tloc, t.sec as u64)?;
    }
    Ok(t.sec as u64)
}

fn read_timespec(c: &Ctx<'_>, addr: u64) -> Result<Timespec, Errno> {
    let b = c.read_mem(addr, 16)?;
    let t = Timespec::decode(&b.try_into().unwrap());
    if t.sec < 0 || !(0..1_000_000_000).contains(&t.nsec) {
        return Err(Errno(EINVAL));
    }
    Ok(t)
}

fn duration(t: Timespec) -> Duration {
    Duration::new(t.sec as u64, t.nsec as u32)
}

/// `do_nanosleep` until `deadline`: 0 when it ends, or with a signal
/// pending `-ERESTART_RESTARTBLOCK` after writing the remaining time to
/// `rmtp` (when nonzero) and arming `hrtimer_nanosleep_restart`.
fn sleep_until(c: &mut Ctx<'_>, deadline: Instant, rmtp: u64) -> Result<Outcome, Errno> {
    let blocked = c.t.sigmask;
    match wait::block(c.p, c.t, &[], Some(deadline), blocked) {
        Ok(wait::Wake::Signal) => {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(Outcome::Return(0));
            }
            if rmtp != 0 {
                let rem = Timespec {
                    sec: left.as_secs() as i64,
                    nsec: i64::from(left.subsec_nanos()),
                };
                c.write_mem(rmtp, &rem.encode())?;
            }
            c.t.restart = Some(RestartBlock::Nanosleep { deadline, rmtp });
            Err(Errno(ERESTART_RESTARTBLOCK))
        }
        _ => Ok(Outcome::Return(0)),
    }
}

/// `nanosleep` (on `CLOCK_MONOTONIC`).
pub fn nanosleep(c: &mut Ctx<'_>, req: u64, rmtp: u64) -> Result<Outcome, Errno> {
    let t = read_timespec(c, req)?;
    c.t.restart = None;
    sleep_until(c, Instant::now() + duration(t), rmtp)
}

/// `restart_syscall` for an interrupted sleep.
pub fn nanosleep_restart(c: &mut Ctx<'_>, deadline: Instant, rmtp: u64) -> Result<Outcome, Errno> {
    sleep_until(c, deadline, rmtp)
}

/// Waits for a signal: the CPU-time clocks do not advance while the only
/// thread sleeps.
fn sleep_on_cpu_clock(c: &mut Ctx<'_>) -> Result<Outcome, Errno> {
    let blocked = c.t.sigmask;
    match wait::block(c.p, c.t, &[], None, blocked) {
        Err(dead) => Ok(Outcome::Fatal(dead.message())),
        Ok(_) => Err(Errno(ERESTARTNOHAND)),
    }
}

/// `clock_nanosleep`.
pub fn clock_nanosleep(
    c: &mut Ctx<'_>,
    id: i32,
    flags: u32,
    req: u64,
    rmtp: u64,
) -> Result<Outcome, Errno> {
    const TIMER_ABSTIME: u32 = 1;
    // The thread CPU clock has no nsleep (EOPNOTSUPP); per-thread dynamic
    // CPU clocks of this thread are refused with EINVAL.
    let (clock, _) = match id {
        clk::THREAD_CPUTIME_ID => return Err(Errno(EOPNOTSUPP)),
        id if id < 0 && id & 4 != 0 => return Err(Errno(EINVAL)),
        _ => host_clock(c, id)?,
    };
    let t = read_timespec(c, req)?;
    let rmtp = if flags & TIMER_ABSTIME != 0 { 0 } else { rmtp };
    c.t.restart = None;
    if clock == HostClock::ProcessCpu {
        return sleep_on_cpu_clock(c);
    }
    if flags & TIMER_ABSTIME != 0 {
        // An absolute sleep is not restarted through restart_syscall.
        let n = now(clock);
        let target = t.sec as i128 * 1_000_000_000 + t.nsec as i128;
        let cur = n.sec as i128 * 1_000_000_000 + n.nsec as i128;
        let left = Duration::from_nanos((target - cur).clamp(0, u64::MAX as i128) as u64);
        return match sleep_until(c, Instant::now() + left, 0) {
            Err(Errno(ERESTART_RESTARTBLOCK)) => {
                c.t.restart = None;
                Err(Errno(ERESTARTNOHAND))
            }
            other => other,
        };
    }
    sleep_until(c, Instant::now() + duration(t), rmtp)
}

// ---------------------------------------------------------- itimers

fn itimer_which(which: i32) -> Result<i32, Errno> {
    match which {
        ITIMER_REAL | ITIMER_VIRTUAL | ITIMER_PROF => Ok(which),
        _ => Err(Errno(EINVAL)),
    }
}

/// `getitimer`.
pub fn getitimer(c: &mut Ctx<'_>, which: i32, value: u64) -> SysResult {
    let which = itimer_which(which)?;
    let v = c.p.itimers.get(which, Instant::now(), cpu_samples);
    c.write_mem(value, &v.encode_itimerval())?;
    Ok(0)
}

/// `setitimer`. A null new value disarms the timer, as the kernel accepts
/// (with a warning).
pub fn setitimer(c: &mut Ctx<'_>, which: i32, value: u64, ovalue: u64) -> SysResult {
    let new = if value != 0 {
        let b: [u8; 32] = c.read_mem(value, 32)?.try_into().unwrap();
        ItimerSpec::decode_itimerval(&b).ok_or(Errno(EINVAL))?
    } else {
        ItimerSpec::default()
    };
    let which = itimer_which(which)?;
    let old = c.p.itimers.set(which, new, Instant::now(), cpu_samples);
    if ovalue != 0 {
        c.write_mem(ovalue, &old.encode_itimerval())?;
    }
    Ok(0)
}

/// `alarm` (x86-64): `ITIMER_REAL` in whole seconds; the previous
/// remainder is rounded to the nearest second, and a nonzero remainder is
/// at least one.
pub fn alarm(c: &mut Ctx<'_>, seconds: u32) -> SysResult {
    let new = ItimerSpec {
        value: Duration::from_secs(u64::from(seconds)),
        interval: Duration::ZERO,
    };
    let old =
        c.p.itimers
            .set(ITIMER_REAL, new, Instant::now(), cpu_samples);
    let mut secs = old.value.as_secs();
    let nanos = old.value.subsec_nanos();
    if (secs == 0 && nanos != 0) || nanos >= 500_000_000 {
        secs += 1;
    }
    Ok(secs)
}
