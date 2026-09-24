//! POSIX timer system calls: `timer_create`, `timer_settime`,
//! `timer_gettime`, `timer_getoverrun`, and `timer_delete`
//! (`kernel/time/posix-timers.c`, `kernel/time/posix-cpu-timers.c`,
//! `kernel/time/alarmtimer.c`). The timers themselves are
//! [`PosixTimers`](crate::user::linux::posix_timers::PosixTimers).

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::types::Timespec;
use super::super::posix_timers::{
    Base, Notify, SIGEV_NONE, SIGEV_SIGNAL, SIGEV_THREAD, SIGEV_THREAD_ID, Setting, TIMER_ABSTIME,
    clock_now,
};
use super::super::signal::deliver;
use super::super::signal::{NSIG, SIGALRM};
use super::{Ctx, SysResult};

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

/// `sizeof(struct sigevent)`.
const SIGEVENT_SIZE: usize = 64;

/// The kind of clock a timer is created on (`clockid_to_kclock`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TimerClock {
    /// A high-resolution clock (`common_timer_create`).
    Common,
    /// An alarm clock (`alarm_timer_create`).
    Alarm,
    /// A CPU-time clock (`posix_cpu_timer_create`), checked once the timer
    /// has an ID.
    Cpu,
}

/// `clockid_to_kclock` and its `timer_create` operation: `EINVAL` for an
/// unknown clock, `EOPNOTSUPP` for one without timers.
fn timer_clock(id: i32) -> Result<TimerClock, Errno> {
    use clk::*;
    match id {
        REALTIME | MONOTONIC | BOOTTIME | TAI => Ok(TimerClock::Common),
        PROCESS_CPUTIME_ID | THREAD_CPUTIME_ID => Ok(TimerClock::Cpu),
        MONOTONIC_RAW | REALTIME_COARSE | MONOTONIC_COARSE => Err(Errno(EOPNOTSUPP)),
        REALTIME_ALARM | BOOTTIME_ALARM => Ok(TimerClock::Alarm),
        // A descriptor clock (CLOCKFD) has no timers.
        id if id < 0 && id & 7 == 3 => Err(Errno(EOPNOTSUPP)),
        id if id < 0 => Ok(TimerClock::Cpu),
        _ => Err(Errno(EINVAL)),
    }
}

/// `pid_for_clock` for a CPU-time timer: the calling process's or one of
/// its threads' CPU clock. Other processes' CPU time is not measured, so
/// their clocks are refused as unknown ones are (`EINVAL`).
fn cpu_base(c: &Ctx<'_>, id: i32) -> Result<Base, Errno> {
    match id {
        clk::PROCESS_CPUTIME_ID => return Ok(Base::ProcessCpu),
        clk::THREAD_CPUTIME_ID => return Ok(Base::ThreadCpu),
        _ => {}
    }
    // ~pid in bits 3 and up, the clock type in bits 0-1, bit 2 for a
    // thread (CPUCLOCK_PID, CPUCLOCK_WHICH, CPUCLOCK_PERTHREAD).
    let pid = !(id >> 3);
    let thread = id & 4 != 0;
    if id & 3 == 3 {
        return Err(Errno(EINVAL));
    }
    if thread {
        if pid == 0 || c.is_own_tid(pid) {
            return Ok(Base::ThreadCpu);
        }
    } else if pid == 0 || pid == c.p.pid {
        return Ok(Base::ProcessCpu);
    }
    Err(Errno(EINVAL))
}

/// The base a setting of a timer on `clock` counts on: relative
/// `CLOCK_REALTIME` timers are unaffected by clock changes and so count on
/// monotonic time (`common_hrtimer_arm`); alarm timers count on their
/// clock either way (`alarm_timer_arm`).
fn setting_base(clock: i32, base: Base, flags: u32) -> Base {
    if clock == clk::REALTIME {
        if flags & TIMER_ABSTIME != 0 {
            Base::Realtime
        } else {
            Base::Monotonic
        }
    } else {
        base
    }
}

/// The initial base of a timer on `clock`.
fn clock_base(c: &Ctx<'_>, clock: i32) -> Result<Base, Errno> {
    use clk::*;
    Ok(match clock {
        REALTIME | TAI | REALTIME_ALARM => Base::Realtime,
        MONOTONIC | BOOTTIME | BOOTTIME_ALARM => Base::Monotonic,
        _ => cpu_base(c, clock)?,
    })
}

/// `timer_create`: the `sigevent` is read before the clock is looked up.
pub fn timer_create(c: &mut Ctx<'_>, clock: i32, sevp: u64, idp: u64) -> SysResult {
    let event = if sevp != 0 {
        Some(c.read_mem(sevp, SIGEVENT_SIZE)?)
    } else {
        None
    };
    let kind = timer_clock(clock)?;
    // posix_timer_add: the ID is used up from here on, even on failure.
    let id = c.p.timers.alloc_id().ok_or(Errno(EAGAIN))?;
    // good_sigevent.
    let (notify, signo, value) = match &event {
        None => (Notify::Process, SIGALRM, id as u32 as u64),
        Some(ev) => {
            let value = u64::from_le_bytes(ev[0..8].try_into().unwrap());
            let signo = i32::from_le_bytes(ev[8..12].try_into().unwrap());
            let how = i32::from_le_bytes(ev[12..16].try_into().unwrap());
            let tid = i32::from_le_bytes(ev[16..20].try_into().unwrap());
            let valid_signo = signo > 0 && signo <= NSIG;
            let notify = match how {
                x if x == SIGEV_SIGNAL | SIGEV_THREAD_ID => {
                    let own = c.is_own_tid(tid) || (tid == c.p.pid && c.p.leader_exit.is_some());
                    if !own || !valid_signo {
                        return Err(Errno(EINVAL));
                    }
                    Notify::Thread(tid)
                }
                SIGEV_SIGNAL | SIGEV_THREAD if valid_signo => Notify::Process,
                SIGEV_NONE => Notify::None,
                _ => return Err(Errno(EINVAL)),
            };
            (notify, signo, value)
        }
    };
    c.write_u32(idp, id as u32)?;
    let base = clock_base(c, clock)?;
    // alarm_timer_create: an RTC is assumed; waking the system needs
    // CAP_WAKE_ALARM.
    if kind == TimerClock::Alarm && c.p.creds.1 != 0 {
        return Err(Errno(EPERM));
    }
    c.p.timers.insert(id, clock, base, notify, signo, value);
    Ok(0)
}

/// Reads a `struct __kernel_itimerspec` (`get_itimerspec64`): the
/// interval, then the value.
pub fn read_itimerspec(c: &Ctx<'_>, addr: u64) -> Result<(Timespec, Timespec), Errno> {
    let b = c.read_mem(addr, 32)?;
    let interval = Timespec::decode(&b[..16].try_into().unwrap());
    let value = Timespec::decode(&b[16..].try_into().unwrap());
    Ok((interval, value))
}

/// Writes a setting as a `struct __kernel_itimerspec` (`put_itimerspec64`).
pub fn write_itimerspec(c: &Ctx<'_>, addr: u64, s: Setting) -> Result<(), Errno> {
    let mut b = [0u8; 32];
    b[..16].copy_from_slice(&ns_timespec(s.interval).encode());
    b[16..].copy_from_slice(&ns_timespec(s.value).encode());
    c.write_mem(addr, &b)
}

/// `timespec64_valid`.
pub fn timespec_valid(t: Timespec) -> bool {
    t.sec >= 0 && (0..1_000_000_000).contains(&t.nsec)
}

/// `timespec64_to_ktime`: nanoseconds, saturating at `KTIME_MAX`.
pub fn timespec_ns(t: Timespec) -> i64 {
    t.sec
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(t.nsec))
        .unwrap_or(i64::MAX)
}

/// `ktime_to_timespec64`.
pub fn ns_timespec(ns: i64) -> Timespec {
    Timespec {
        sec: ns.div_euclid(1_000_000_000),
        nsec: ns.rem_euclid(1_000_000_000),
    }
}

/// `__lock_timer`: IDs outside `0..=INT_MAX` name no timer.
fn timer_id(raw: u64) -> Result<i32, Errno> {
    let id = raw as i32;
    if id < 0 {
        return Err(Errno(EINVAL));
    }
    Ok(id)
}

/// `timer_settime`.
pub fn timer_settime(c: &mut Ctx<'_>, raw_id: u64, flags: u32, new: u64, old: u64) -> SysResult {
    if new == 0 {
        return Err(Errno(EINVAL));
    }
    let (interval, value) = read_itimerspec(c, new)?;
    if !timespec_valid(interval) || !timespec_valid(value) {
        return Err(Errno(EINVAL));
    }
    let id = timer_id(raw_id)?;
    let t = c.p.timers.get(id).ok_or(Errno(EINVAL))?;
    let (clock, old_base) = (t.clock, t.base);
    let base = setting_base(clock, t.base, flags);
    let setting = Setting {
        value: timespec_ns(value),
        interval: timespec_ns(interval),
    };
    let (prev, firing) =
        c.p.timers
            .settime(
                id,
                flags,
                setting,
                base,
                clock_now(base),
                clock_now(old_base),
            )
            .ok_or(Errno(EINVAL))?;
    if let Some(f) = firing {
        let (p, mut th) = c.split();
        deliver::send_timer_signal(p, &mut th, f);
    }
    if old != 0 {
        write_itimerspec(c, old, prev)?;
    }
    Ok(0)
}

/// `timer_gettime`.
pub fn timer_gettime(c: &mut Ctx<'_>, raw_id: u64, setting: u64) -> SysResult {
    let id = timer_id(raw_id)?;
    let base = c.p.timers.get(id).ok_or(Errno(EINVAL))?.base;
    let cur =
        c.p.timers
            .gettime(id, clock_now(base))
            .ok_or(Errno(EINVAL))?;
    write_itimerspec(c, setting, cur)?;
    Ok(0)
}

/// `timer_getoverrun`.
pub fn timer_getoverrun(c: &mut Ctx<'_>, raw_id: u64) -> SysResult {
    let id = timer_id(raw_id)?;
    let n = c.p.timers.getoverrun(id).ok_or(Errno(EINVAL))?;
    Ok(n as u64)
}

/// `timer_delete`.
pub fn timer_delete(c: &mut Ctx<'_>, raw_id: u64) -> SysResult {
    let id = timer_id(raw_id)?;
    if !c.p.timers.delete(id) {
        return Err(Errno(EINVAL));
    }
    Ok(0)
}
