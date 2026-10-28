//! Extended timers use the same native clock domains as native object waits.
use crate::host::time::Instant;
use crate::user::windows::sync::NativeDeadline;
use std::io;

/// A pending Timer2 operation. Signal state and object lifetime belong to the
/// containing kernel object; cancellation removes only this operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timer2Schedule {
    deadline: NativeDeadline,
    period: i64,
}

impl Timer2Schedule {
    pub(crate) fn new(due: i64, period: i64) -> io::Result<Self> {
        Ok(Self {
            deadline: NativeDeadline::new(due)?,
            period,
        })
    }

    pub(crate) fn periodic(&self) -> bool {
        self.period != 0
    }

    pub(crate) fn hint(&self) -> Instant {
        self.deadline.hint()
    }

    pub(crate) fn tick(&mut self) -> io::Result<bool> {
        if self.deadline.remaining()? != 0 {
            return Ok(false);
        }
        if self.periodic() {
            // Native29683 accepts negative periods; they repeat at the next
            // dispatcher opportunity, rather than becoming unsigned/absolute
            // long intervals. Each scheduler turn delivers at most one expiry.
            let ticks = self.period.max(1) as u128;
            self.deadline.advance_periodic(ticks * 100)?;
        }
        Ok(true)
    }
}
