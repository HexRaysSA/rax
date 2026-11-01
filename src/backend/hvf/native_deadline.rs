//! Finite host deadlines and SDK-owned timer-state projection.
//! Apple SDK 27.2 hv.h and mach_time.h define the native deadline units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeadlineError {
    ZeroInterval,
    InvalidTimebase,
    OutOfRange,
}

/// Convert positive ns to mach ticks by rounding upward. O(1) work/storage.
/// The numerator/denominator express ns per tick. u128 covers u64*u32.
/// u64::MAX is reserved for the SDK's unbounded deadline and never returned.
pub(crate) fn finite_deadline(
    now: u64,
    nanoseconds: u64,
    numerator: u32,
    denominator: u32,
) -> Result<u64, DeadlineError> {
    if nanoseconds == 0 {
        return Err(DeadlineError::ZeroInterval);
    }
    if numerator == 0 || denominator == 0 {
        return Err(DeadlineError::InvalidTimebase);
    }
    let ticks = (u128::from(nanoseconds) * u128::from(denominator)).div_ceil(u128::from(numerator));
    let absolute = u64::try_from(u128::from(now) + ticks).map_err(|_| DeadlineError::OutOfRange)?;
    if absolute == u64::MAX {
        return Err(DeadlineError::OutOfRange);
    }
    Ok(absolute)
}

#[cfg(target_os = "macos")]
pub(crate) mod mach {
    use super::finite_deadline;
    use crate::error::{Error, Result};
    use std::time::Duration;

    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }

    unsafe extern "C" {
        fn mach_absolute_time() -> u64;
        fn mach_timebase_info(info: *mut Timebase) -> i32;
    }

    pub(crate) fn now() -> u64 {
        // SAFETY: the retained Mach SDK declares a parameterless scalar clock
        // query. It retains no reference and does not unwind across the C ABI.
        unsafe { mach_absolute_time() }
    }

    /// SDK entry uses absolute mach ticks, not nanoseconds or guest time.
    pub(crate) fn after(limit: Duration) -> Result<u64> {
        let nanos = u64::try_from(limit.as_nanos())
            .map_err(|_| Error::InvalidConfig("native host interval exceeds u64 ns".into()))?;
        if nanos == 0 {
            return Err(Error::InvalidConfig(
                "native host interval must be positive".into(),
            ));
        }
        let mut base = Timebase { numer: 0, denom: 0 };
        // SAFETY: repr(C) matches the retained two-u32 SDK struct. The pointer
        // is aligned, initialized, exclusive and live for the synchronous call;
        // the SDK retains no pointer or Rust reference.
        let status = unsafe { mach_timebase_info(&mut base) };
        if status != 0 {
            return Err(Error::Emulator(format!(
                "mach_timebase_info failed: {status}"
            )));
        }
        finite_deadline(now(), nanos, base.numer, base.denom).map_err(|error| {
            Error::InvalidConfig(format!("invalid native host deadline: {error:?}"))
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn live_mach_abi_produces_finite_deadlines_and_rejects_invalid_intervals() {
            assert_eq!(std::mem::size_of::<Timebase>(), 8);
            assert_eq!(std::mem::align_of::<Timebase>(), 4);
            assert!(after(Duration::ZERO).is_err());
            assert!(after(Duration::MAX).is_err());
            let before = now();
            let deadline = after(Duration::from_millis(10)).unwrap();
            assert!(deadline > before && deadline != u64::MAX);
        }
    }
}

#[cfg(test)]
mod time_tests {
    use super::*;
    #[test]
    fn ten_ms_converts_exactly_at_integral_and_fractional_timebases() {
        assert_eq!(finite_deadline(100, 10_000_000, 1, 1), Ok(10_000_100));
        assert_eq!(finite_deadline(100, 10_000_000, 125, 3), Ok(240_100));
    }
    #[test]
    fn conversion_rounds_up_with_error_strictly_below_one_tick() {
        for (numerator, denominator) in [(1, 1), (125, 3), (1, 3), (u32::MAX, 1), (1, u32::MAX)] {
            for ns in 1..=1024 {
                let end = finite_deadline(17, ns, numerator, denominator).unwrap();
                let ticks = u128::from(end - 17);
                let requested = u128::from(ns) * u128::from(denominator);
                assert!(ticks >= 1);
                assert!(ticks * u128::from(numerator) >= requested);
                assert!((ticks - 1) * u128::from(numerator) < requested);
            }
        }
    }
    #[test]
    fn invalid_intervals_timebases_and_unbounded_or_overflow_deadlines_reject() {
        assert_eq!(
            finite_deadline(0, 0, 1, 1),
            Err(DeadlineError::ZeroInterval)
        );
        for (n, d) in [(0, 1), (1, 0), (0, 0)] {
            assert_eq!(
                finite_deadline(0, 1, n, d),
                Err(DeadlineError::InvalidTimebase)
            );
        }
        for (now, ns, n, d) in [
            (u64::MAX - 1, 1, 1, 1),
            (u64::MAX, 1, 1, 1),
            (0, u64::MAX, 1, 2),
        ] {
            assert_eq!(
                finite_deadline(now, ns, n, d),
                Err(DeadlineError::OutOfRange)
            );
        }
        assert_eq!(finite_deadline(u64::MAX - 2, 1, 1, 1), Ok(u64::MAX - 1));
    }
}

pub(crate) const SDK_TIMER_PIN: u64 = 1 << 6;
pub(crate) const FAIL_ENTRY: u32 = 1 << 31;
const EVENT_VALID: u32 = 1 << 31;
const TIMER_EXIT: u32 = 52;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EntryPolicyError {
    TimerInProducerPolicy,
    UnexpectedControlMutation,
    InterruptedDelivery,
}

pub(crate) struct TimerPolicy {
    original: u64,
}

impl TimerPolicy {
    pub(crate) fn new(policy: u64, current: u64) -> Result<Self, EntryPolicyError> {
        if policy & SDK_TIMER_PIN != 0 {
            return Err(EntryPolicyError::TimerInProducerPolicy);
        }
        if (policy ^ current) & !SDK_TIMER_PIN != 0 {
            return Err(EntryPolicyError::UnexpectedControlMutation);
        }
        Ok(Self { original: policy })
    }

    pub(crate) fn record_value(&self, current: u64) -> Result<u64, EntryPolicyError> {
        if (current ^ self.original) & !SDK_TIMER_PIN != 0 {
            return Err(EntryPolicyError::UnexpectedControlMutation);
        }
        Ok(self.original)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Exit {
    HostYield,
    Dispatch(u32),
}

pub(crate) fn classify(reason: u32, vectoring: u32) -> Result<Exit, EntryPolicyError> {
    // Vectoring information can be stale/undefined on failed entry.
    if reason & FAIL_ENTRY != 0 {
        return Ok(Exit::Dispatch(reason));
    }
    // No general interrupted-event reinjection contract is implemented here.
    if vectoring & EVENT_VALID != 0 {
        return Err(EntryPolicyError::InterruptedDelivery);
    }
    // Extra reason flags are not silently collapsed into a scheduling yield.
    Ok(if reason == TIMER_EXIT {
        Exit::HostYield
    } else {
        Exit::Dispatch(reason)
    })
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn sdk_timer_bit_is_excluded_from_the_record_without_overwriting_other_controls() {
        for original in [
            0,
            9,
            1 << 5,
            u32::MAX as u64 & !SDK_TIMER_PIN,
            u64::MAX & !SDK_TIMER_PIN,
        ] {
            let policy = TimerPolicy::new(original, original).unwrap();
            for current in [original, original | SDK_TIMER_PIN] {
                assert_eq!(policy.record_value(current), Ok(original));
            }
            for bit in 0..64 {
                if bit != 6 {
                    assert_eq!(
                        policy.record_value(original ^ (1 << bit)),
                        Err(EntryPolicyError::UnexpectedControlMutation)
                    );
                }
            }
        }
    }

    #[test]
    fn producer_timer_ownership_and_non_timer_changes_reject_before_entry() {
        assert!(matches!(
            TimerPolicy::new(9 | SDK_TIMER_PIN, 9 | SDK_TIMER_PIN),
            Err(EntryPolicyError::TimerInProducerPolicy)
        ));
        assert!(TimerPolicy::new(9, 9 | SDK_TIMER_PIN).is_ok());
        for bit in 0..64 {
            if bit != 6 {
                assert!(matches!(
                    TimerPolicy::new(9, 9 ^ (1 << bit)),
                    Err(EntryPolicyError::UnexpectedControlMutation)
                ));
            }
        }
    }

    #[test]
    fn only_a_plain_timer_reason_can_become_a_host_yield() {
        for basic in 0..=u16::MAX as u32 {
            assert_eq!(
                classify(basic, 0),
                Ok(if basic == TIMER_EXIT {
                    Exit::HostYield
                } else {
                    Exit::Dispatch(basic)
                })
            );
            for flag in [1 << 16, 1 << 27, 1 << 28, 1 << 29, 1 << 30, FAIL_ENTRY] {
                assert_eq!(classify(basic | flag, 0), Ok(Exit::Dispatch(basic | flag)));
            }
        }
    }

    #[test]
    fn failed_entry_has_priority_over_undefined_vectoring_data() {
        for basic in 0..=u16::MAX as u32 {
            for vectoring in [0, EVENT_VALID, u32::MAX] {
                assert_eq!(
                    classify(basic | FAIL_ENTRY, vectoring),
                    Ok(Exit::Dispatch(basic | FAIL_ENTRY))
                );
            }
        }
    }

    #[test]
    fn unsupported_interrupted_delivery_never_becomes_a_silent_yield_or_dispatch() {
        for basic in 0..=u16::MAX as u32 {
            assert_eq!(
                classify(basic, EVENT_VALID),
                Err(EntryPolicyError::InterruptedDelivery)
            );
        }
    }
}
