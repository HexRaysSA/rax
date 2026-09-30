//! Clock and sleep system calls.

use std::time::{Duration, Instant};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::types::Timespec;
use super::super::host::{self, HostClock};
use super::super::signal::deliver::restart::{ERESTART_RESTARTBLOCK, ERESTARTNOHAND};
use super::super::timers::{ITIMER_PROF, ITIMER_REAL, ITIMER_VIRTUAL, ItimerSpec, cpu_samples};
use super::super::wait::{Resume, Wait};
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
    c.put_timespec(tp, t)?;
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
            1
        };
        c.put_timespec(res, Timespec { sec: 0, nsec: ns })?;
    }
    Ok(0)
}

/// `gettimeofday`: `struct timeval` and a zero `struct timezone`.
pub fn gettimeofday(c: &mut Ctx<'_>, tv: u64, tz: u64) -> SysResult {
    if tv != 0 {
        let t = now(HostClock::Realtime);
        c.write_mem(tv, &c.timeval_bytes(t.sec, t.nsec / 1000))?;
    }
    if tz != 0 {
        c.write_mem(tz, &[0u8; 8])?;
    }
    Ok(0)
}

/// `time` (and `time32`, which stores and returns an `old_time32_t`).
pub fn time(c: &mut Ctx<'_>, tloc: u64) -> SysResult {
    let t = now(HostClock::Realtime);
    if tloc != 0 {
        c.put_time(tloc, t.sec)?;
    }
    Ok(if c.time32 {
        i64::from(t.sec as i32) as u64
    } else {
        t.sec as u64
    })
}

fn read_timespec(c: &Ctx<'_>, addr: u64) -> Result<Timespec, Errno> {
    let t = c.get_timespec(addr)?;
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
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Ok(Outcome::Return(0));
    }
    if !c.signal_pending() {
        return Err(c.block(Wait::until(Some(deadline)), Resume::Until(Some(deadline))));
    }
    if rmtp != 0 {
        let rem = Timespec {
            sec: left.as_secs() as i64,
            nsec: i64::from(left.subsec_nanos()),
        };
        c.put_timespec(rmtp, rem)?;
    }
    c.t.restart = Some(RestartBlock::Nanosleep {
        deadline,
        rmtp,
        time32: c.time32,
    });
    Err(Errno(ERESTART_RESTARTBLOCK))
}

/// The deadline a sleep computed when it started, if it is running again
/// after sleeping.
fn resumed(c: &mut Ctx<'_>) -> Option<Instant> {
    match c.resume.take() {
        Some(Resume::Until(d)) => d,
        _ => None,
    }
}

/// `nanosleep` (on `CLOCK_MONOTONIC`).
pub fn nanosleep(c: &mut Ctx<'_>, req: u64, rmtp: u64) -> Result<Outcome, Errno> {
    if let Some(deadline) = resumed(c) {
        return sleep_until(c, deadline, rmtp);
    }
    let t = read_timespec(c, req)?;
    c.t.restart = None;
    sleep_until(c, Instant::now() + duration(t), rmtp)
}

/// `restart_syscall` for an interrupted sleep.
pub fn nanosleep_restart(c: &mut Ctx<'_>, deadline: Instant, rmtp: u64) -> Result<Outcome, Errno> {
    let deadline = resumed(c).unwrap_or(deadline);
    sleep_until(c, deadline, rmtp)
}

/// Waits for a signal: the process CPU-time clock does not advance while
/// every thread sleeps (`-ERESTARTNOHAND`).
fn sleep_on_cpu_clock(c: &mut Ctx<'_>) -> Result<Outcome, Errno> {
    if c.signal_pending() {
        return Err(Errno(ERESTARTNOHAND));
    }
    Err(c.block(Wait::event(), Resume::Retry))
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
    let rmtp = if flags & TIMER_ABSTIME != 0 { 0 } else { rmtp };
    if clock == HostClock::ProcessCpu {
        if c.resume.take().is_none() {
            read_timespec(c, req)?;
            c.t.restart = None;
        }
        return sleep_on_cpu_clock(c);
    }
    let deadline = match resumed(c) {
        Some(d) => d,
        None => {
            let t = read_timespec(c, req)?;
            c.t.restart = None;
            if flags & TIMER_ABSTIME != 0 {
                let n = now(clock);
                let target = t.sec as i128 * 1_000_000_000 + t.nsec as i128;
                let cur = n.sec as i128 * 1_000_000_000 + n.nsec as i128;
                Instant::now()
                    + Duration::from_nanos((target - cur).clamp(0, u64::MAX as i128) as u64)
            } else {
                Instant::now() + duration(t)
            }
        }
    };
    if flags & TIMER_ABSTIME != 0 {
        // An absolute sleep is not restarted through restart_syscall.
        return match sleep_until(c, deadline, 0) {
            Err(Errno(ERESTART_RESTARTBLOCK)) => {
                c.t.restart = None;
                Err(Errno(ERESTARTNOHAND))
            }
            other => other,
        };
    }
    sleep_until(c, deadline, rmtp)
}

// ------------------------------------------------- setting the clocks
//
// Only CLOCK_REALTIME can be set or adjusted, and changing it needs
// CAP_SYS_TIME (`cap_settime`, `timekeeping_validate_timex`). Root passes
// that check and is refused (EOPNOTSUPP): the host's clock is not the
// guest's to change. Reading the NTP state needs nothing, and shows the
// kernel's state at boot, which nothing here changes: an unsynchronized
// clock (`TIME_ERROR`).

/// `TIME_SETTOD_SEC_MAX` (`linux/time64.h`): `KTIME_SEC_MAX` less 30 years
/// of uptime.
const TIME_SETTOD_SEC_MAX: u64 = (i64::MAX / 1_000_000_000) as u64 - 30 * 365 * 24 * 3600;

/// `timespec64_valid_settod`.
fn valid_settod(t: Timespec) -> bool {
    t.sec >= 0 && (0..1_000_000_000).contains(&t.nsec) && (t.sec as u64) < TIME_SETTOD_SEC_MAX
}

/// `do_sys_settimeofday64`: the time, then `CAP_SYS_TIME`, then the time
/// zone (at most 15 hours west or east).
fn settod(c: &Ctx<'_>, t: Option<Timespec>, minuteswest: Option<i32>) -> SysResult {
    if t.is_some_and(|t| !valid_settod(t)) {
        return Err(Errno(EINVAL));
    }
    super::admin::capability(c)?;
    if minuteswest.is_some_and(|m| !(-15 * 60..=15 * 60).contains(&m)) {
        return Err(Errno(EINVAL));
    }
    super::admin::refused()
}

/// `settimeofday`: the time (microseconds past 1000000 or negative are
/// `EINVAL`), the time zone, then `do_sys_settimeofday64`.
pub fn settimeofday(c: &mut Ctx<'_>, tv: u64, tz: u64) -> SysResult {
    let t = if tv != 0 {
        let (sec, usec) = c.get_timeval(tv)?;
        if !(0..=1_000_000).contains(&usec) {
            return Err(Errno(EINVAL));
        }
        Some(Timespec {
            sec,
            nsec: usec * 1000,
        })
    } else {
        None
    };
    let minuteswest = if tz != 0 {
        let b = c.read_mem(tz, 8)?;
        Some(i32::from_le_bytes(b[..4].try_into().unwrap()))
    } else {
        None
    };
    settod(c, t, minuteswest)
}

/// `stime` (`sys_stime32`): whole seconds from an `old_time32_t`, then
/// `CAP_SYS_TIME` (`security_settime64`), then `do_settimeofday64`'s
/// check.
pub fn stime(c: &mut Ctx<'_>, tptr: u64) -> SysResult {
    let sec = i64::from(c.read_u32(tptr)? as i32);
    super::admin::capability(c)?;
    if !valid_settod(Timespec { sec, nsec: 0 }) {
        return Err(Errno(EINVAL));
    }
    super::admin::refused()
}

/// `pid_for_clock` for setting a clock: whether the CPU-time clock `id`
/// names the calling process (by its ID) or one of its threads; `EINVAL`
/// if not. Other processes' clocks are refused.
fn cpu_clock_found(c: &Ctx<'_>, id: i32) -> Result<(), Errno> {
    let pid = !(id >> 3);
    let found = if id & 3 == 3 {
        false
    } else if pid == 0 {
        true
    } else if id & 4 != 0 {
        c.is_own_tid(pid)
    } else {
        pid == c.p.pid
    };
    if found { Ok(()) } else { Err(Errno(EINVAL)) }
}

/// `clock_settime`: a clock with a setter (`EINVAL` for any other), the
/// time, then the setter: `CLOCK_REALTIME` through
/// `do_sys_settimeofday64`; a CPU-time clock, once found, never
/// (`EPERM`); a clock device (`CLOCKFD`) is not found (`EINVAL`).
pub fn clock_settime(c: &mut Ctx<'_>, id: i32, tp: u64) -> SysResult {
    let dynamic = id < 0 && id & 7 == 3;
    if id != clk::REALTIME && id >= 0 {
        return Err(Errno(EINVAL));
    }
    let t = c.get_timespec(tp)?;
    if dynamic {
        Err(Errno(EINVAL))
    } else if id < 0 {
        cpu_clock_found(c, id)?;
        Err(Errno(EPERM))
    } else {
        settod(c, Some(t), None)
    }
}

/// `struct __kernel_timex` (`linux/timex.h`): its size and field offsets.
mod timex {
    pub const SIZE: usize = 208;
    pub const MODES: usize = 0;
    pub const OFFSET: usize = 8;
    pub const FREQ: usize = 16;
    pub const MAXERROR: usize = 24;
    pub const ESTERROR: usize = 32;
    pub const STATUS: usize = 40;
    pub const CONSTANT: usize = 48;
    pub const PRECISION: usize = 56;
    pub const TOLERANCE: usize = 64;
    pub const TIME_SEC: usize = 72;
    pub const TIME_USEC: usize = 80;
    pub const TICK: usize = 88;
    /// `ppsfreq` and `jitter`.
    pub const PPS_WORDS: [usize; 2] = [96, 104];
    pub const SHIFT: usize = 112;
    /// `stabil`, `jitcnt`, `calcnt`, `errcnt`, and `stbcnt`.
    pub const PPS_COUNTS: [usize; 5] = [120, 128, 136, 144, 152];
    pub const TAI: usize = 160;

    /// `modes` bits (`ADJ_ADJTIME`, `ADJ_OFFSET_SINGLESHOT`, and
    /// `ADJ_OFFSET_READONLY` as the kernel splits them).
    pub const ADJ_OFFSET_SINGLESHOT: u32 = 0x0001;
    pub const ADJ_FREQUENCY: u32 = 0x0002;
    pub const ADJ_SETOFFSET: u32 = 0x0100;
    pub const ADJ_NANO: u32 = 0x2000;
    pub const ADJ_OFFSET_READONLY: u32 = 0x2000;
    pub const ADJ_TICK: u32 = 0x4000;
    pub const ADJ_ADJTIME: u32 = 0x8000;

    /// `STA_UNSYNC`.
    pub const STA_UNSYNC: i32 = 0x40;
    /// `TIME_ERROR`: the clock is not synchronized.
    pub const TIME_ERROR: u64 = 5;
    /// `NTP_PHASE_LIMIT`: `MAXPHASE` in microseconds, shifted by 5.
    pub const NTP_PHASE_LIMIT: i64 = (500_000_000 / 1000) << 5;
    /// `USER_TICK_USEC` at `USER_HZ` 100.
    pub const USER_TICK_USEC: i64 = 10_000;
    /// `PPM_SCALE`: `NSEC_PER_USEC << (NTP_SCALE_SHIFT - SHIFT_USEC)`.
    pub const PPM_SCALE: i64 = 1000 << (32 - 16);
    /// `MAXFREQ_SCALED / PPM_SCALE`: 500 ppm, scaled by 2^16.
    pub const TOLERANCE_PPM: i64 = (500_000 << 32) / PPM_SCALE;
}

/// `do_adjtimex` on `CLOCK_REALTIME` with the structure's bytes `b`:
/// `timekeeping_validate_timex`'s checks, a refused change, or the NTP
/// state (`ntp_adjtimex` reading an unsynchronized clock) with the clock
/// state as the result.
fn adjust(c: &Ctx<'_>, b: &mut [u8]) -> SysResult {
    use timex::*;
    let word = |b: &[u8], at: usize| i64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    let modes = u32::from_le_bytes(b[MODES..MODES + 4].try_into().unwrap());
    let changes = if modes & ADJ_ADJTIME != 0 {
        // Single-shot adjtime must not come with other mode bits.
        if modes & ADJ_OFFSET_SINGLESHOT == 0 {
            return Err(Errno(EINVAL));
        }
        modes & ADJ_OFFSET_READONLY == 0
    } else {
        modes != 0
    };
    if changes {
        super::admin::capability(c)?;
    }
    if modes & ADJ_ADJTIME == 0 && modes & ADJ_TICK != 0 && !(9000..=11000).contains(&word(b, TICK))
    {
        return Err(Errno(EINVAL));
    }
    if modes & ADJ_SETOFFSET != 0 {
        super::admin::capability(c)?;
        let limit = if modes & ADJ_NANO != 0 {
            1_000_000_000
        } else {
            1_000_000
        };
        if !(0..limit).contains(&word(b, TIME_USEC)) {
            return Err(Errno(EINVAL));
        }
    }
    if modes & ADJ_FREQUENCY != 0 {
        let freq = word(b, FREQ);
        if freq < i64::MIN / PPM_SCALE || freq > i64::MAX / PPM_SCALE {
            return Err(Errno(EINVAL));
        }
    }
    if changes || modes & ADJ_SETOFFSET != 0 {
        return super::admin::refused();
    }
    let t = now(HostClock::Realtime);
    let mut put = |at: usize, v: i64| b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    put(OFFSET, 0);
    put(FREQ, 0);
    put(MAXERROR, NTP_PHASE_LIMIT);
    put(ESTERROR, NTP_PHASE_LIMIT);
    put(CONSTANT, 2);
    put(PRECISION, 1);
    put(TOLERANCE, TOLERANCE_PPM);
    // Microseconds: STA_NANO is clear.
    put(TIME_SEC, t.sec);
    put(TIME_USEC, t.nsec / 1000);
    put(TICK, USER_TICK_USEC);
    // pps_fill_timex without CONFIG_NTP_PPS: zeros.
    for at in PPS_WORDS.into_iter().chain(PPS_COUNTS) {
        put(at, 0);
    }
    b[STATUS..STATUS + 4].copy_from_slice(&STA_UNSYNC.to_le_bytes());
    b[SHIFT..SHIFT + 4].copy_from_slice(&0i32.to_le_bytes());
    b[TAI..TAI + 4].copy_from_slice(&0i32.to_le_bytes());
    Ok(TIME_ERROR)
}

/// `struct old_timex32` (`linux/time32.h`): every field a 32-bit one,
/// the time an `old_timeval32`, then padding to 128 bytes.
mod timex32 {
    pub const SIZE: usize = 128;
    /// Each field's offset here and in `struct __kernel_timex`, in the
    /// order `get_old_timex32` copies them.
    pub const FIELDS: [(usize, usize); 19] = [
        (4, super::timex::OFFSET),
        (8, super::timex::FREQ),
        (12, super::timex::MAXERROR),
        (16, super::timex::ESTERROR),
        (20, super::timex::STATUS),
        (24, super::timex::CONSTANT),
        (28, super::timex::PRECISION),
        (32, super::timex::TOLERANCE),
        (36, super::timex::TIME_SEC),
        (40, super::timex::TIME_USEC),
        (44, super::timex::TICK),
        (48, super::timex::PPS_WORDS[0]),
        (52, super::timex::PPS_WORDS[1]),
        (56, super::timex::SHIFT),
        (60, super::timex::PPS_COUNTS[0]),
        (64, super::timex::PPS_COUNTS[1]),
        (68, super::timex::PPS_COUNTS[2]),
        (72, super::timex::PPS_COUNTS[3]),
        (76, super::timex::PPS_COUNTS[4]),
    ];
    /// `tai`, which `put_old_timex32` alone copies.
    pub const TAI: usize = 80;
}

/// `struct __kernel_timex` from a `struct old_timex32` (`get_old_timex32`:
/// the fields sign-extended, `tai` and the rest zero).
fn timex_from_old32(old: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; timex::SIZE];
    b[timex::MODES..timex::MODES + 4].copy_from_slice(&old[..4]);
    for (from, to) in timex32::FIELDS {
        let v = i32::from_le_bytes(old[from..from + 4].try_into().unwrap());
        // status and shift are ints in both; the rest long longs.
        if to == timex::STATUS || to == timex::SHIFT {
            b[to..to + 4].copy_from_slice(&v.to_le_bytes());
        } else {
            b[to..to + 8].copy_from_slice(&i64::from(v).to_le_bytes());
        }
    }
    b
}

/// `struct old_timex32` from a `struct __kernel_timex` (`put_old_timex32`:
/// each field truncated, `tai` included, the padding zero).
fn timex_to_old32(b: &[u8]) -> Vec<u8> {
    let mut old = vec![0u8; timex32::SIZE];
    old[..4].copy_from_slice(&b[timex::MODES..timex::MODES + 4]);
    for (to, from) in timex32::FIELDS {
        old[to..to + 4].copy_from_slice(&b[from..from + 4]);
    }
    old[timex32::TAI..timex32::TAI + 4].copy_from_slice(&b[timex::TAI..timex::TAI + 4]);
    old
}

/// The `struct __kernel_timex` at `tx`: for a `*_time32` call a converted
/// `struct old_timex32`.
fn read_timex(c: &Ctx<'_>, tx: u64) -> Result<Vec<u8>, Errno> {
    if c.time32 {
        Ok(timex_from_old32(&c.read_mem(tx, timex32::SIZE)?))
    } else {
        c.read_mem(tx, timex::SIZE)
    }
}

/// Writes `b` back as the call's structure.
fn write_timex(c: &Ctx<'_>, tx: u64, b: &[u8]) -> Result<(), Errno> {
    if c.time32 {
        c.write_mem(tx, &timex_to_old32(b))
    } else {
        c.write_mem(tx, b)
    }
}

/// `adjtimex` (and `adjtimex_time32`): the structure, `do_adjtimex`, and
/// the structure written back whatever the result (`EFAULT` if it cannot
/// be).
pub fn adjtimex(c: &mut Ctx<'_>, tx: u64) -> SysResult {
    let mut b = read_timex(c, tx)?;
    let r = adjust(c, &mut b);
    write_timex(c, tx, &b)?;
    r
}

/// `clock_adjtime` (and `clock_adjtime32`): the structure, the clock
/// (`EINVAL` for none, a clock device included; `EOPNOTSUPP` for one
/// without an adjuster: all but `CLOCK_REALTIME`), `do_adjtimex`, and on
/// success the structure written back.
pub fn clock_adjtime(c: &mut Ctx<'_>, id: i32, tx: u64) -> SysResult {
    let mut b = read_timex(c, tx)?;
    let r = match id {
        clk::REALTIME => adjust(c, &mut b),
        id if id < 0 && id & 7 == 3 => Err(Errno(EINVAL)),
        id if id < 0 || ((0..=clk::TAI).contains(&id) && id != 10) => Err(Errno(EOPNOTSUPP)),
        _ => Err(Errno(EINVAL)),
    };
    if r.is_ok() {
        write_timex(c, tx, &b)?;
    }
    r
}

// ---------------------------------------------------------- itimers

fn itimer_which(which: i32) -> Result<i32, Errno> {
    match which {
        ITIMER_REAL | ITIMER_VIRTUAL | ITIMER_PROF => Ok(which),
        _ => Err(Errno(EINVAL)),
    }
}

/// Writes `v` as a `struct itimerval` (`struct old_itimerval32` for a
/// 32-bit call), truncated to microseconds (`put_itimerval`).
fn put_itimerval(c: &Ctx<'_>, addr: u64, v: ItimerSpec) -> Result<(), Errno> {
    let tv = |d: Duration| c.timeval_bytes(d.as_secs() as i64, i64::from(d.subsec_micros()));
    c.write_mem(addr, &[tv(v.interval), tv(v.value)].concat())
}

/// Reads a `struct itimerval` (`get_itimerval`): whole, then both
/// `timeval`s checked (`timeval_valid`: `EINVAL`).
fn get_itimerval(c: &Ctx<'_>, addr: u64) -> Result<ItimerSpec, Errno> {
    let n = c.timeval_size();
    c.read_mem(addr, 2 * n as usize)?;
    let interval = c.get_timeval(addr)?;
    let value = c.get_timeval(addr + n)?;
    ItimerSpec::from_timevals(interval, value).ok_or(Errno(EINVAL))
}

/// `getitimer`.
pub fn getitimer(c: &mut Ctx<'_>, which: i32, value: u64) -> SysResult {
    let which = itimer_which(which)?;
    let v = c.p.itimers.get(which, Instant::now(), cpu_samples);
    put_itimerval(c, value, v)?;
    Ok(0)
}

/// `setitimer`. A null new value disarms the timer, as the kernel accepts
/// (with a warning).
pub fn setitimer(c: &mut Ctx<'_>, which: i32, value: u64, ovalue: u64) -> SysResult {
    let new = if value != 0 {
        get_itimerval(c, value)?
    } else {
        ItimerSpec::default()
    };
    let which = itimer_which(which)?;
    let old = c.p.itimers.set(which, new, Instant::now(), cpu_samples);
    if ovalue != 0 {
        put_itimerval(c, ovalue, old)?;
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
