//! Host scheduling policy for the existing ARM64 periodic cancellation worker.
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

pub(super) const KICK_PERIOD: Duration = Duration::from_millis(5);

/// The worker's nominal resolution is 5 ms; shorter intervals cannot be
/// admitted. Scheduling/kernel latency is outside this interval guarantee.
pub(super) fn validate_interval(limit: Duration) -> Result<(), &'static str> {
    if limit < KICK_PERIOD {
        return Err("ARM64 native host interval must be at least 5 ms");
    }
    if limit.as_nanos() > u128::from(u64::MAX) {
        return Err("ARM64 native host interval exceeds u64 ns");
    }
    Ok(())
}

/// SDK cancellation is host control state. A failed request makes subsequent
/// entry/capture unavailable; it is never exported as healthy guest state.
#[derive(Default)]
pub(super) struct Cancellation {
    failure: AtomicI32,
}

impl Cancellation {
    pub(super) fn record(&self, result: i32) {
        if result != 0 {
            let _ = self
                .failure
                .compare_exchange(0, result, Ordering::AcqRel, Ordering::Acquire);
        }
    }

    pub(super) fn ready(&self) -> Result<(), i32> {
        match self.failure.load(Ordering::Acquire) {
            0 => Ok(()),
            error => Err(error),
        }
    }
}
