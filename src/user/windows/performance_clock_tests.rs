use super::PerformanceClock;
use crate::host::time::{Duration, Instant};

#[test]
fn builtin_performance_clock_preserves_elapsed_nanoseconds_and_frequency() {
    let clock = PerformanceClock::select(false).unwrap();
    let started = Instant::now() - Duration::from_secs(2);
    let before = started.elapsed().as_nanos() as u64;
    let counter = clock.counter(started).unwrap();
    let after = started.elapsed().as_nanos() as u64;
    assert_eq!(clock.frequency(), 1_000_000_000);
    assert!((before..=after).contains(&counter));
    assert!(clock.counter(started).unwrap() >= counter);
}

#[cfg(not(windows))]
#[test]
fn installed_windows_performance_clock_requires_its_native_host() {
    assert_eq!(
        PerformanceClock::select(true).unwrap_err().kind(),
        std::io::ErrorKind::Unsupported
    );
}

#[cfg(windows)]
#[test]
fn native_performance_clock_uses_host_frequency_and_epoch() {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn QueryPerformanceCounter(output: *mut i64) -> i32;
        fn QueryPerformanceFrequency(output: *mut i64) -> i32;
    }
    let mut expected_frequency = 0;
    let mut before = 0;
    let mut after = 0;
    // SAFETY: exclusive initialized host outputs, exact native ABI.
    assert_ne!(
        unsafe { QueryPerformanceFrequency(&mut expected_frequency) },
        0
    );
    let clock = PerformanceClock::select(true).unwrap();
    assert_eq!(clock.frequency(), expected_frequency as u64);
    // SAFETY: exclusive initialized host counter outputs.
    assert_ne!(unsafe { QueryPerformanceCounter(&mut before) }, 0);
    let counter = clock
        .counter(Instant::now() - Duration::from_secs(100))
        .unwrap();
    // SAFETY: exclusive initialized host counter output.
    assert_ne!(unsafe { QueryPerformanceCounter(&mut after) }, 0);
    assert!((before as u64..=after as u64).contains(&counter));
}
