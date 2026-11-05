//! Runtime-only samples in one retained VM or host clock domain.
use super::{ClockMode, ClockState, TimingContext};
use crate::error::{Error, Result};
use crate::host::time::{Duration, Instant};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) enum ClockEpoch {
    Wall(Instant),
    Owned {
        owner: Arc<TimingContext>,
        nanos: u64,
    },
}
impl PartialEq for ClockEpoch {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Wall(a), Self::Wall(b)) => a == b,
            (Self::Owned { owner: a, nanos: x }, Self::Owned { owner: b, nanos: y }) => {
                Arc::ptr_eq(a, b) && x == y
            }
            _ => false,
        }
    }
}
impl Eq for ClockEpoch {}

impl std::fmt::Debug for ClockEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wall(now) => f.debug_tuple("Wall").field(now).finish(),
            Self::Owned { nanos, .. } => f.debug_struct("Owned").field("nanos", nanos).finish(),
        }
    }
}
impl From<Instant> for ClockEpoch {
    fn from(now: Instant) -> Self {
        Self::Wall(now)
    }
}
impl ClockEpoch {
    /// Bind once to the selected VM clock, or preserve unbound host time.
    pub(crate) fn selected_at(wall: Instant) -> Self {
        match TimingContext::current() {
            Some(owner) => Self::Owned {
                nanos: owner.elapsed_nanos(),
                owner,
            },
            None => Self::Wall(wall),
        }
    }
    /// Observe this sample's owner; unrelated ambient scopes cannot replace it.
    pub(crate) fn sample(&self) -> Self {
        match self {
            Self::Wall(_) => Self::Wall(Instant::now()),
            Self::Owned { owner, .. } => Self::Owned {
                nanos: owner.elapsed_nanos(),
                owner: owner.clone(),
            },
        }
    }
    pub(crate) fn same_domain(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Wall(_), Self::Wall(_)) => true,
            (Self::Owned { owner: a, .. }, Self::Owned { owner: b, .. }) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
    /// Virtual subtraction wraps at u64 nanoseconds. Relevant observation gaps
    /// must remain shorter than one complete nanosecond-counter cycle.
    pub(crate) fn duration_since(&self, earlier: &Self) -> Result<Duration> {
        match (self, earlier) {
            (Self::Wall(now), Self::Wall(start)) => Ok(now.saturating_duration_since(*start)),
            (
                Self::Owned { owner, nanos },
                Self::Owned {
                    owner: previous,
                    nanos: start,
                },
            ) if Arc::ptr_eq(owner, previous) => {
                Ok(Duration::from_nanos(nanos.wrapping_sub(*start)))
            }
            _ => Err(Error::InvalidConfig("elapsed clock domain differs".into())),
        }
    }
    /// Virtual publication precedes clock.commit, so prepare the incoming epoch
    /// instead of reading the target's old counter during the CPU commit.
    pub(crate) fn for_restore(&self, incoming: Option<&ClockState>) -> Result<Self> {
        let Some(incoming) = incoming else {
            return Ok(self.clone());
        };
        incoming.validate()?;
        match (self, incoming.mode) {
            (Self::Wall(_), ClockMode::Wall) => Ok(self.clone()),
            (Self::Owned { owner, .. }, mode) if owner.mode() == mode => Ok(Self::Owned {
                owner: owner.clone(),
                nanos: incoming.elapsed_nanos,
            }),
            _ => Err(Error::InvalidConfig(
                "publication clock mode differs from target".into(),
            )),
        }
    }
    /// Importing a VM clock copies the admitted incoming epoch. Publication
    /// without a clock import samples the live domain at its own boundary.
    /// Clock writers are quiescent through this stopped-VM publication scope.
    pub(crate) fn at_publication(&self, importing_clock: bool) -> Self {
        match self {
            Self::Wall(_) => Self::Wall(Instant::now()),
            Self::Owned { .. } if importing_clock => self.clone(),
            Self::Owned { .. } => self.sample(),
        }
    }
}

#[cfg(test)]
#[path = "epoch_tests.rs"]
mod tests;
