//! Host clock sampling for guest personalities.
//!
//! CPU clocks measure emulator CPU use, including emulation overhead. They do
//! not count guest cycles. Wall time is Unix-epoch time; monotonic time has a
//! host-defined origin. Samples are normalized `(seconds, nanoseconds)` with
//! `0 <= nanoseconds < 1_000_000_000`. Native errors remain errors.

use std::io;

/// Host clock domain, independent of any guest's numeric clock IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostClock {
    /// UTC wall time since 1970-01-01T00:00:00Z, excluding leap seconds.
    Realtime,
    /// Monotonic time with a host-defined origin.
    Monotonic,
    /// User and kernel CPU time consumed by the emulator process.
    ProcessCpu,
    /// User and kernel CPU time consumed by the calling host thread.
    ThreadCpu,
}

/// Read a host clock. The representation's nanosecond unit is not a promise of
/// nanosecond precision; precision and accounting granularity are host-defined.
pub fn read(clock: HostClock) -> io::Result<(i64, i64)> {
    platform::read(clock)
}

#[cfg(unix)]
mod platform {
    use super::*;

    pub fn read(clock: HostClock) -> io::Result<(i64, i64)> {
        let id = match clock {
            HostClock::Realtime => libc::CLOCK_REALTIME,
            HostClock::Monotonic => libc::CLOCK_MONOTONIC,
            HostClock::ProcessCpu => libc::CLOCK_PROCESS_CPUTIME_ID,
            HostClock::ThreadCpu => libc::CLOCK_THREAD_CPUTIME_ID,
        };
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: known clock ID and an initialized, writable timespec.
        if unsafe { libc::clock_gettime(id, &mut ts) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((ts.tv_sec as i64, ts.tv_nsec as i64))
    }
}

// Keep conversion code testable on every host; only the Windows adapter uses
// these representations in production.
#[cfg(any(windows, test))]
mod conversion {
    use super::*;
    pub const NS_PER_SECOND: i128 = 1_000_000_000;
    // 369 Gregorian years, including 89 leap days:
    // (369 * 365 + 89) d * 86400 s/d * 10_000_000 ticks/s.
    const WINDOWS_UNIX_EPOCH_TICKS: i128 = 116_444_736_000_000_000;

    fn normalized(ns: i128) -> (i64, i64) {
        // All callers' input domains are bounded below i64::MAX seconds:
        // FILETIME totals <= 2*u64::MAX*100 ns; QPC uses i64 ticks / positive Hz.
        (
            ns.div_euclid(NS_PER_SECOND) as i64,
            ns.rem_euclid(NS_PER_SECOND) as i64,
        )
    }

    pub fn realtime(ticks: u64) -> (i64, i64) {
        normalized((i128::from(ticks) - WINDOWS_UNIX_EPOCH_TICKS) * 100)
    }

    pub fn cpu(user: u64, kernel: u64) -> (i64, i64) {
        normalized((i128::from(user) + i128::from(kernel)) * 100)
    }

    pub fn counter(ticks: i64, frequency: i64) -> io::Result<(i64, i64)> {
        if frequency <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "host performance-counter frequency must be positive",
            ));
        }
        // Widen before multiplication; dividing the full numerator avoids an
        // intermediate overflow for a long uptime or high counter frequency.
        // Floor conversion error is strictly less than 1 ns for either sign.
        Ok(normalized(
            (i128::from(ticks) * NS_PER_SECOND).div_euclid(i128::from(frequency)),
        ))
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use std::sync::OnceLock;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    impl FileTime {
        fn ticks(self) -> u64 {
            (u64::from(self.high) << 32) | u64::from(self.low)
        }
    }
    type Handle = *mut c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemTimePreciseAsFileTime(time: *mut FileTime);
        fn QueryPerformanceCounter(counter: *mut i64) -> i32;
        fn QueryPerformanceFrequency(frequency: *mut i64) -> i32;
        fn GetCurrentProcess() -> Handle;
        fn GetCurrentThread() -> Handle;
        fn GetProcessTimes(
            process: Handle,
            created: *mut FileTime,
            exited: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn GetThreadTimes(
            thread: Handle,
            created: *mut FileTime,
            exited: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
    }

    fn frequency() -> io::Result<i64> {
        static FREQUENCY: OnceLock<i64> = OnceLock::new();
        if let Some(&frequency) = FREQUENCY.get() {
            return Ok(frequency);
        }
        let mut frequency = 0;
        // SAFETY: writable LARGE_INTEGER storage. Frequency is fixed at boot
        // and identical on all CPUs (Microsoft profileapi contract).
        if unsafe { QueryPerformanceFrequency(&mut frequency) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if frequency <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "host performance-counter frequency must be positive",
            ));
        }
        let _ = FREQUENCY.set(frequency);
        Ok(frequency)
    }

    pub fn read(clock: HostClock) -> io::Result<(i64, i64)> {
        match clock {
            HostClock::Realtime => {
                let mut time = FileTime::default();
                // SAFETY: one initialized, writable FILETIME. This API has no
                // failure return, and is available since Windows 8.
                unsafe {
                    GetSystemTimePreciseAsFileTime(&mut time);
                }
                Ok(conversion::realtime(time.ticks()))
            }
            HostClock::Monotonic => {
                let frequency = frequency()?;
                let mut ticks = 0;
                // SAFETY: one writable LARGE_INTEGER.
                if unsafe { QueryPerformanceCounter(&mut ticks) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                conversion::counter(ticks, frequency)
            }
            HostClock::ProcessCpu | HostClock::ThreadCpu => {
                let mut created = FileTime::default();
                let mut exited = FileTime::default();
                let mut kernel = FileTime::default();
                let mut user = FileTime::default();
                // SAFETY: current process/thread pseudo-handle and four distinct,
                // initialized writable FILETIMEs. Pseudo-handles are not closed.
                let ok = unsafe {
                    if clock == HostClock::ProcessCpu {
                        GetProcessTimes(
                            GetCurrentProcess(),
                            &mut created,
                            &mut exited,
                            &mut kernel,
                            &mut user,
                        )
                    } else {
                        GetThreadTimes(
                            GetCurrentThread(),
                            &mut created,
                            &mut exited,
                            &mut kernel,
                            &mut user,
                        )
                    }
                };
                if ok == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(conversion::cpu(user.ticks(), kernel.ticks()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_epoch_and_extreme_counts() {
        assert_eq!(conversion::realtime(0), (-11_644_473_600, 0));
        assert_eq!(conversion::realtime(116_444_736_000_000_000), (0, 0));
        assert_eq!(
            conversion::realtime(116_444_735_999_999_999),
            (-1, 999_999_900)
        );
        assert_eq!(conversion::realtime(116_444_736_000_000_001), (0, 100));
        assert_eq!(conversion::cpu(10_000_000, 5_000_000), (1, 500_000_000));
        assert_eq!(
            conversion::cpu(u64::MAX, u64::MAX),
            (3_689_348_814_741, 910_323_000)
        );
        assert_eq!(
            conversion::realtime(u64::MAX),
            (1_833_029_933_770, 955_161_500)
        );
    }

    #[test]
    fn performance_counter_scaling_does_not_overflow_or_round_up() {
        assert_eq!(conversion::counter(1, 3).unwrap(), (0, 333_333_333));
        assert_eq!(conversion::counter(-1, 3).unwrap(), (-1, 666_666_666));
        assert_eq!(conversion::counter(i64::MAX, 1).unwrap(), (i64::MAX, 0));
        assert_eq!(conversion::counter(i64::MIN, 1).unwrap(), (i64::MIN, 0));
        assert_eq!(conversion::counter(i64::MAX, i64::MAX).unwrap(), (1, 0));
        for hz in [0, -1, i64::MIN] {
            assert_eq!(
                conversion::counter(1, hz).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn native_thread_clock_excludes_another_threads_work() {
        use std::time::{Duration, Instant};
        let ns = |clock| {
            let (s, n) = read(clock).unwrap();
            i128::from(s) * 1_000_000_000 + i128::from(n)
        };
        let thread_before = ns(HostClock::ThreadCpu);
        let process_before = ns(HostClock::ProcessCpu);
        let worker_cpu = std::thread::spawn(move || {
            let start = ns(HostClock::ThreadCpu);
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                for n in 0u64..100_000 {
                    std::hint::black_box(n.wrapping_mul(n));
                }
                let elapsed = ns(HostClock::ThreadCpu) - start;
                if elapsed >= 50_000_000 {
                    return elapsed;
                }
                assert!(
                    Instant::now() < deadline,
                    "worker CPU clock did not advance"
                );
            }
        })
        .join()
        .unwrap();
        let process_cpu = ns(HostClock::ProcessCpu) - process_before;
        let joining_thread_cpu = ns(HostClock::ThreadCpu) - thread_before;
        // The caller is blocked in join while the worker burns >= 50 ms. This
        // catches accidentally implementing both domains using GetProcessTimes.
        assert!(
            joining_thread_cpu * 4 < worker_cpu,
            "joining thread charged worker CPU: {joining_thread_cpu} vs {worker_cpu} ns"
        );
        // Per-process and per-thread samples can have different accounting
        // quantization. Allow one 20 ms tick when comparing these two domains.
        assert!(process_cpu + 20_000_000 >= worker_cpu);
    }

    #[test]
    fn native_clocks_are_normalized_and_cpu_time_advances() {
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
        let wall = read(HostClock::Realtime).unwrap();
        let system = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert!((i128::from(wall.0) - i128::from(system.as_secs())).abs() <= 5);
        for clock in [
            HostClock::Realtime,
            HostClock::Monotonic,
            HostClock::ProcessCpu,
            HostClock::ThreadCpu,
        ] {
            let (_, ns) = read(clock).unwrap();
            assert!((0..1_000_000_000).contains(&ns));
        }
        let monotonic = read(HostClock::Monotonic).unwrap();
        let thread = read(HostClock::ThreadCpu).unwrap();
        let process = read(HostClock::ProcessCpu).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        // Burn CPU on this thread until accounting advances. Accommodate native
        // accounting granularity without assuming a CPU frequency or tick size.
        loop {
            for n in 0u64..100_000 {
                std::hint::black_box(n.wrapping_mul(n));
            }
            if read(HostClock::ThreadCpu).unwrap() > thread {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "native thread CPU accounting did not advance"
            );
        }
        assert!(read(HostClock::ProcessCpu).unwrap() >= process);
        assert!(read(HostClock::Monotonic).unwrap() >= monotonic);
    }
}
