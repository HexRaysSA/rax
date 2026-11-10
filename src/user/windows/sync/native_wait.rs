//! Native deadlines retain their clock domain and never narrow a LARGE_INTEGER.
mod clock;

use super::*;
use crate::user::clock::{HostClock, read};
use crate::user::windows::process::Thread;
use std::io;
use std::time::Duration;

/// A finite native deadline. Relative deadlines exclude host suspend time;
/// absolute deadlines remain NT UTC targets and follow realtime adjustments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeDeadline(Deadline);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Deadline {
    Relative(u128),
    Absolute(u64),
}

impl NativeDeadline {
    pub(crate) fn new(ticks: i64) -> io::Result<Self> {
        Ok(Self(if ticks < 0 {
            // abs(i64::MIN) *100 ns fits u128. Each adapter's u64 counter or
            // normalized i64-second sample also fits after nanosecond scaling.
            Deadline::Relative(clock::awake_nanoseconds()? + u128::from(ticks.unsigned_abs()) * 100)
        } else {
            Deadline::Absolute(ticks as u64)
        }))
    }

    fn remaining_at(&self, awake_ns: u128, utc_ticks: u64) -> u128 {
        match self.0 {
            Deadline::Relative(target) => target.saturating_sub(awake_ns),
            Deadline::Absolute(target) => u128::from(target.saturating_sub(utc_ticks)) * 100,
        }
    }

    pub(crate) fn remaining(&self) -> io::Result<u128> {
        match self.0 {
            Deadline::Relative(_) => Ok(self.remaining_at(clock::awake_nanoseconds()?, 0)),
            Deadline::Absolute(_) => {
                let (seconds, nanos) = read(HostClock::Realtime)?;
                let ticks = super::super::nt::time::file_time(seconds, nanos).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "host clock is outside NT system-time range",
                    )
                })?;
                Ok(self.remaining_at(0, ticks))
            }
        }
    }

    pub(crate) fn expired(&self) -> Result<bool, SyncError> {
        self.remaining()
            .map(|left| left == 0)
            .map_err(|_| SyncError::Invalid("native wait clock sampling failed"))
    }

    /// Coalesce missed periodic expirations in constant time. After the first
    /// absolute expiration, subsequent periods use the suspend-excluding clock.
    pub(crate) fn advance_periodic(&mut self, period_ns: u128) -> io::Result<()> {
        self.advance_at(clock::awake_nanoseconds()?, period_ns);
        Ok(())
    }

    fn advance_at(&mut self, awake_ns: u128, period_ns: u128) {
        assert!(period_ns > 0);
        let target = match self.0 {
            Deadline::Relative(target) => target,
            Deadline::Absolute(_) => awake_ns,
        };
        // Inputs are bounded by normalized i64 seconds and i64 timer ticks.
        // Their widened nanoseconds and one additional period fit u128.
        let periods = awake_ns.saturating_sub(target) / period_ns + 1;
        self.0 = Deadline::Relative(target + periods * period_ns);
    }

    pub(crate) fn hint(&self) -> Instant {
        // The scheduler needs a bounded recheck time, not an overflowing
        // Instant for a 2^63-tick interval or a stale UTC-to-monotonic mapping.
        // Expiration itself is checked against the original clock target.
        let left = self.remaining().unwrap_or(0).min(10_000_000);
        let now = Instant::now();
        now.checked_add(Duration::from_nanos(left as u64))
            .unwrap_or(now)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitTargetError {
    InvalidHandle,
    AccessDenied,
    Unsupported,
}

pub(crate) fn wait_object(p: &Proc, t: &Thread, handle: u64) -> Result<ObjId, WaitTargetError> {
    let id = if handle == p.arch.ptr(u64::MAX - 1) {
        t.obj
    } else if handle == p.arch.ptr(u64::MAX) {
        p.objects
            .iter()
            .find_map(|(id, object)| match object {
                Object::Process { pid, .. } if *pid == p.pid => Some(id),
                _ => None,
            })
            .ok_or(WaitTargetError::InvalidHandle)?
    } else {
        let id = p.objects.id(handle).ok_or(WaitTargetError::InvalidHandle)?;
        let access = p
            .objects
            .access(handle)
            .ok_or(WaitTargetError::InvalidHandle)?;
        if access & 0x0010_0000 == 0 {
            return Err(WaitTargetError::AccessDenied);
        }
        id
    };
    match p.objects.obj(id) {
        Some(
            Object::Event { .. }
            | Object::Mutex { .. }
            | Object::Semaphore { .. }
            | Object::Thread { .. }
            | Object::Process { .. }
            | Object::Timer { .. }
            | Object::IrTimer { .. }
            | Object::WaitCompletionPacket { .. }
            | Object::SecurityFile(_),
        ) => Ok(id),
        Some(_) => Err(WaitTargetError::Unsupported),
        None => Err(WaitTargetError::InvalidHandle),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_timer2_arm_periodic_deadlines_skip_missed_periods_without_drift_or_overflow() {
        let mut relative = NativeDeadline(Deadline::Relative(1_000_000));
        relative.advance_at(4_500_000, 1_000_000);
        assert_eq!(relative.remaining_at(4_500_000, u64::MAX), 500_000);
        relative.advance_at(10_500_000, 1_000_000);
        assert_eq!(relative.remaining_at(10_500_000, 0), 500_000);
        let max = u128::from(i64::MAX as u64) * 100;
        relative.advance_at(10_500_000, max);
        assert_eq!(relative.remaining_at(10_500_000, 0), max + 500_000);
        let mut absolute = NativeDeadline(Deadline::Absolute(0));
        absolute.advance_at(1_000_000, max);
        assert_eq!(absolute.remaining_at(1_000_000, u64::MAX), max);
        let mut fast = NativeDeadline(Deadline::Relative(0));
        fast.advance_at(1_000_000_000_000, 100);
        assert_eq!(fast.remaining_at(1_000_000_000_000, 0), 100);
    }

    #[test]
    fn native_single_wait_absolute_clock_changes_and_relative_clock_domains() {
        let absolute = NativeDeadline(Deadline::Absolute(1000));
        assert_eq!(absolute.remaining_at(u128::MAX, 999), 100);
        assert_eq!(absolute.remaining_at(0, 1000), 0);
        assert_eq!(absolute.remaining_at(0, 1001), 0);
        assert_eq!(absolute.remaining_at(0, 990), 1000);
        let relative = NativeDeadline(Deadline::Relative(1000));
        assert_eq!(relative.remaining_at(999, u64::MAX), 1);
        assert_eq!(relative.remaining_at(1000, 0), 0);
        assert_eq!(relative.remaining_at(1001, u64::MAX), 0);
    }

    #[test]
    fn native_single_wait_maximum_intervals_do_not_overflow_or_become_infinite() {
        let max = u128::from(i64::MIN.unsigned_abs()) * 100;
        assert_eq!(max, 922_337_203_685_477_580_800);
        let deadline = NativeDeadline::new(i64::MIN).unwrap();
        let Deadline::Relative(target) = deadline.0 else {
            unreachable!()
        };
        assert!(target >= max);
        assert!(deadline.remaining().unwrap() > 0);
        assert!(NativeDeadline::new(i64::MAX).unwrap().remaining().unwrap() > 0);
    }
}
