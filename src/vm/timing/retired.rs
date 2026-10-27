//! Fixed-rate retirement time with a retained sub-nanosecond phase.
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
/// Retired instructions (Hexagon packets) per SI second.
pub const RETIREMENT_FREQUENCY_HZ: u64 = 3_000_000_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClockMode {
    Wall,
    Retired,
}
/// Explicit clock checkpoint state. Callers must quiesce independent writers.
/// Nanoseconds and retired totals use wrapping u64 representations; the phase
/// retains exact thirds of a nanosecond independently of those wraps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockState {
    pub mode: ClockMode,
    pub elapsed_nanos: u64,
    pub retired_units: u64,
    pub subnanosecond_quanta: u8,
    pub diagnostic_ticks: u64,
    pub timer_pending: bool,
}
impl ClockState {
    pub fn validate(&self) -> Result<()> {
        if self.subnanosecond_quanta >= 3 {
            return Err(Error::InvalidConfig(
                "clock phase must be less than three retirement quanta".into(),
            ));
        }
        if self.mode == ClockMode::Wall
            && (self.retired_units != 0 || self.subnanosecond_quanta != 0)
        {
            return Err(Error::InvalidConfig(
                "wall clock cannot contain retirement phase or units".into(),
            ));
        }
        Ok(())
    }
}

/// floor((nanos + phase/3) * frequency_hz / 1e9), modulo 2^64.
/// Internal phase is validated to be 0..=2. Splitting the product avoids the
/// up-to-130-bit intermediate in (3*nanos + phase) * frequency_hz.
pub(super) fn counter_ticks(nanos: u64, phase: u8, frequency_hz: u64) -> u64 {
    const NANOS_PER_SECOND: u128 = 1_000_000_000;
    let product = u128::from(nanos) * u128::from(frequency_hz);
    let whole = product / NANOS_PER_SECOND;
    let remainder = (product % NANOS_PER_SECOND) * 3 + u128::from(phase) * u128::from(frequency_hz);
    (whole + remainder / (NANOS_PER_SECOND * 3)) as u64
}
