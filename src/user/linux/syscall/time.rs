//! Clock and sleep system calls.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::types::Timespec;
use super::super::host::{self, HostClock};
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

fn sleep_for(t: Timespec) {
    std::thread::sleep(std::time::Duration::new(t.sec as u64, t.nsec as u32));
}

/// `nanosleep`.
pub fn nanosleep(c: &mut Ctx<'_>, req: u64, _rem: u64) -> SysResult {
    let t = read_timespec(c, req)?;
    sleep_for(t);
    Ok(0)
}

/// `clock_nanosleep`.
pub fn clock_nanosleep(c: &mut Ctx<'_>, id: i32, flags: u32, req: u64, _rem: u64) -> SysResult {
    const TIMER_ABSTIME: u32 = 1;
    let (clock, _) = match id {
        clk::THREAD_CPUTIME_ID => return Err(Errno(EINVAL)),
        _ => host_clock(c, id)?,
    };
    let t = read_timespec(c, req)?;
    if flags & TIMER_ABSTIME != 0 {
        let n = now(clock);
        let target = t.sec as i128 * 1_000_000_000 + t.nsec as i128;
        let cur = n.sec as i128 * 1_000_000_000 + n.nsec as i128;
        if target > cur {
            std::thread::sleep(std::time::Duration::from_nanos((target - cur) as u64));
        }
    } else {
        sleep_for(t);
    }
    Ok(0)
}
