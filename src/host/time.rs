//! Host time that does not panic on wasm hosts without a clock.
//!
//! wasm32/wasm64 `unknown` and `none` targets have no clock, and their
//! `std::time::Instant::now` and `SystemTime::now` panic. Every other host uses
//! `std::time` unchanged: [`Instant`] is `std::time::Instant` and
//! [`system_now`] is `SystemTime::now`.
//!
//! On a clockless host, [`Instant`] is a logical monotonic clock that advances
//! by [`LOGICAL_TICK`] at each [`Instant::now`] call, so a deadline loop that
//! samples the clock still observes its deadline pass instead of spinning
//! forever. [`system_now`] is `UNIX_EPOCH` plus the same count. There, a
//! measured duration counts clock samples, not elapsed time.

#[cfg(not(all(target_family = "wasm", any(target_os = "unknown", target_os = "none"))))]
pub use std::time::Instant;

#[cfg(all(target_family = "wasm", any(target_os = "unknown", target_os = "none")))]
pub use logical::Instant;

pub use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LOGICAL_TICK_NANOS: u64 = 1_000;

/// Logical time added by each clock sample on a clockless host.
pub const LOGICAL_TICK: Duration = Duration::from_nanos(LOGICAL_TICK_NANOS);

/// The current wall-clock time (`UNIX_EPOCH` plus the logical count on a
/// clockless host).
#[cfg(not(all(target_family = "wasm", any(target_os = "unknown", target_os = "none"))))]
pub fn system_now() -> SystemTime {
    SystemTime::now()
}

/// The current wall-clock time (`UNIX_EPOCH` plus the logical count on a
/// clockless host).
#[cfg(all(target_family = "wasm", any(target_os = "unknown", target_os = "none")))]
pub fn system_now() -> SystemTime {
    UNIX_EPOCH + logical::sample()
}

#[cfg(all(target_family = "wasm", any(target_os = "unknown", target_os = "none")))]
mod logical {
    use super::{Duration, LOGICAL_TICK_NANOS};
    use core::ops::{Add, AddAssign, Sub, SubAssign};
    use std::sync::atomic::{AtomicU64, Ordering};

    static SAMPLES: AtomicU64 = AtomicU64::new(0);

    /// Advance the shared logical clock by one tick and return its new value.
    /// The nanosecond count saturates after about 584 years of logical time.
    pub(super) fn sample() -> Duration {
        let samples = SAMPLES.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        Duration::from_nanos(samples.saturating_mul(LOGICAL_TICK_NANOS))
    }

    /// A logical monotonic instant with the `std::time::Instant` API.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Instant(Duration);

    impl Instant {
        pub fn now() -> Self {
            Instant(sample())
        }

        /// Saturates to zero when `earlier` is later, as `std` does.
        pub fn duration_since(&self, earlier: Instant) -> Duration {
            self.saturating_duration_since(earlier)
        }

        pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
            self.0.checked_sub(earlier.0)
        }

        pub fn saturating_duration_since(&self, earlier: Instant) -> Duration {
            self.0.saturating_sub(earlier.0)
        }

        pub fn elapsed(&self) -> Duration {
            Instant::now().duration_since(*self)
        }

        pub fn checked_add(&self, duration: Duration) -> Option<Instant> {
            self.0.checked_add(duration).map(Instant)
        }

        pub fn checked_sub(&self, duration: Duration) -> Option<Instant> {
            self.0.checked_sub(duration).map(Instant)
        }
    }

    impl Add<Duration> for Instant {
        type Output = Instant;

        /// Panics on overflow, as `std` does.
        fn add(self, duration: Duration) -> Instant {
            self.checked_add(duration)
                .expect("overflow when adding duration to instant")
        }
    }

    impl AddAssign<Duration> for Instant {
        fn add_assign(&mut self, duration: Duration) {
            *self = *self + duration;
        }
    }

    impl Sub<Duration> for Instant {
        type Output = Instant;

        /// Panics on underflow, as `std` does.
        fn sub(self, duration: Duration) -> Instant {
            self.checked_sub(duration)
                .expect("overflow when subtracting duration from instant")
        }
    }

    impl SubAssign<Duration> for Instant {
        fn sub_assign(&mut self, duration: Duration) {
            *self = *self - duration;
        }
    }

    impl Sub<Instant> for Instant {
        type Output = Duration;

        fn sub(self, earlier: Instant) -> Duration {
            self.duration_since(earlier)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instants_are_monotonic_and_deadlines_pass() {
        let start = Instant::now();
        let deadline = start + 3 * LOGICAL_TICK;
        let mut samples = 0;
        while Instant::now() < deadline {
            samples += 1;
            assert!(samples < 10_000_000, "deadline never observed");
        }
        assert!(start.elapsed() >= 3 * LOGICAL_TICK);
        assert_eq!(start.duration_since(start + LOGICAL_TICK), Duration::ZERO);
        assert_eq!((start + LOGICAL_TICK) - start, LOGICAL_TICK);
    }

    #[test]
    fn wall_clock_is_after_the_epoch() {
        assert!(system_now().duration_since(UNIX_EPOCH).is_ok());
    }
}
