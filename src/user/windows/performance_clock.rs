//! One counter unit and epoch for native, public and shared Windows timing.
use crate::host::time::Instant;
use std::io;

const ELAPSED_FREQUENCY: u64 = 1_000_000_000;

#[derive(Debug, Default)]
pub(crate) enum PerformanceClock {
    #[default]
    Elapsed,
    #[cfg(windows)]
    Native { frequency: u64 },
    #[cfg(test)]
    Captured { counter: u64, frequency: u64 },
}

impl PerformanceClock {
    pub(crate) fn select(installed: bool) -> io::Result<Self> {
        if !installed {
            return Ok(Self::Elapsed);
        }
        #[cfg(windows)]
        {
            crate::user::clock::windows_performance_frequency().map(|frequency| Self::Native {
                frequency: frequency as u64,
            })
        }
        #[cfg(not(windows))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "installed Windows performance clock requires a Windows host",
            ))
        }
    }

    pub(crate) fn frequency(&self) -> u64 {
        match self {
            Self::Elapsed => ELAPSED_FREQUENCY,
            #[cfg(windows)]
            Self::Native { frequency } => *frequency,
            #[cfg(test)]
            Self::Captured { frequency, .. } => *frequency,
        }
    }

    pub(crate) fn counter(&self, started: Instant) -> io::Result<u64> {
        match self {
            // Preserve the existing built-in elapsed-nanosecond profile and
            // its modulo-2^64 conversion. This is a unit, not an accuracy claim.
            Self::Elapsed => Ok(started.elapsed().as_nanos() as u64),
            #[cfg(windows)]
            Self::Native { .. } => {
                crate::user::clock::windows_performance_counter().map(|ticks| ticks as u64)
            }
            #[cfg(test)]
            Self::Captured { counter, .. } => Ok(*counter),
        }
    }
}

#[cfg(test)]
#[path = "performance_clock_tests.rs"]
mod tests;
