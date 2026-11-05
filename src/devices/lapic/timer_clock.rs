//! Runtime-only timer domain; complete snapshots transport relative timer age.
use crate::host::time::Instant;
use crate::vm::timing::TimingContext;
use std::sync::Arc;

#[derive(Clone, Default)]
pub(super) struct TimerClock {
    owner: Option<Arc<TimingContext>>,
    origin_nanos: u64,
}

impl std::fmt::Debug for TimerClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimerClock")
            .field("owned", &self.owner.is_some())
            .field("origin_nanos", &self.origin_nanos)
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct TimerSample {
    pub elapsed_nanos: u128,
    logical_now: Option<u64>,
}

impl TimerClock {
    pub fn selected(owner: Option<Arc<TimingContext>>) -> Self {
        let origin_nanos = owner.as_ref().map_or(0, |clock| clock.elapsed_nanos());
        Self {
            owner,
            origin_nanos,
        }
    }

    /// The incoming epoch is used before the VM commits its new clock state.
    /// This avoids rebasing a device against the target's old time domain.
    pub fn prepared(clock: Arc<TimingContext>, incoming_nanos: u64) -> Self {
        Self {
            owner: Some(clock),
            origin_nanos: incoming_nanos,
        }
    }

    pub fn restart(&mut self) {
        if let Some(clock) = &self.owner {
            self.origin_nanos = clock.elapsed_nanos();
        }
    }

    /// Virtual timestamp subtraction follows the VM clock's u64 wrap contract;
    /// observation gaps must remain below one complete nanosecond-clock cycle.
    /// The VMM's finite retirement quanta provide this bound during execution.
    pub fn sample(&self, wall_origin: Instant, wall_now: Instant) -> TimerSample {
        if let Some(clock) = &self.owner {
            let now = clock.elapsed_nanos();
            TimerSample {
                elapsed_nanos: u128::from(now.wrapping_sub(self.origin_nanos)),
                logical_now: Some(now),
            }
        } else {
            TimerSample {
                elapsed_nanos: wall_now.saturating_duration_since(wall_origin).as_nanos(),
                logical_now: None,
            }
        }
    }

    /// Periodic phase consumption and rebasing use the same sampled instant.
    pub fn rebase_to(&mut self, sample: TimerSample) {
        if let Some(now) = sample.logical_now {
            self.origin_nanos = now;
        }
    }

    /// Controller replacement retains the target VM's live clock identity.
    /// The incoming origin already belongs to its prepared checkpoint epoch.
    pub fn retain_target_binding(&mut self, target: &Self) {
        self.owner = target.owner.clone();
    }
}

#[cfg(test)]
#[path = "timer_clock_tests.rs"]
mod tests;
