//! Fixed-size required clock state, independent of Rust layout/serde defaults.
use super::Snapshot;
use crate::error::{Error, Result};
use crate::vm::timing::{ClockMode, ClockState, RETIREMENT_FREQUENCY_HZ};
use std::io::Read;
pub(super) const SIZE: u64 = 44;
const TAG: &[u8; 8] = b"RAXCLK01";
fn invalid(message: &str) -> Error {
    Error::Emulator(format!("clock checkpoint: {message}"))
}
pub(super) fn validate(state: &ClockState, base: &Snapshot) -> Result<()> {
    state.validate()?;
    if state.elapsed_nanos != base.elapsed_nanos {
        return Err(invalid("clock nanoseconds disagree with base metadata"));
    }
    Ok(())
}
pub(super) fn encode(state: &ClockState) -> Result<[u8; 44]> {
    state.validate()?;
    let mut raw = [0; 44];
    raw[..8].copy_from_slice(TAG);
    raw[8..16].copy_from_slice(&RETIREMENT_FREQUENCY_HZ.to_le_bytes());
    raw[16] = match state.mode {
        ClockMode::Wall => 0,
        ClockMode::Retired => 1,
    };
    raw[17] = state.subnanosecond_quanta;
    raw[18] = u8::from(state.timer_pending);
    for (at, value) in [
        (20, state.elapsed_nanos),
        (28, state.retired_units),
        (36, state.diagnostic_ticks),
    ] {
        raw[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    Ok(raw)
}
pub(super) fn read(reader: &mut impl Read, length: u64, elapsed: u64) -> Result<ClockState> {
    if length != SIZE {
        return Err(invalid("clock record length must be exactly 44 bytes"));
    }
    let mut raw = [0; 44];
    reader
        .read_exact(&mut raw)
        .map_err(|e| Error::Emulator(format!("clock checkpoint: {e}")))?;
    if &raw[..8] != TAG {
        return Err(invalid("bad clock tag"));
    }
    let word = |at: usize| u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
    if word(8) != RETIREMENT_FREQUENCY_HZ {
        return Err(invalid("unsupported retirement frequency"));
    }
    if raw[18] > 1 || raw[19] != 0 {
        return Err(invalid("invalid clock flags or reserved byte"));
    }
    let mode = match raw[16] {
        0 => ClockMode::Wall,
        1 => ClockMode::Retired,
        _ => return Err(invalid("unknown clock mode")),
    };
    let state = ClockState {
        mode,
        subnanosecond_quanta: raw[17],
        timer_pending: raw[18] != 0,
        elapsed_nanos: word(20),
        retired_units: word(28),
        diagnostic_ticks: word(36),
    };
    state.validate()?;
    if state.elapsed_nanos != elapsed {
        return Err(invalid("clock nanoseconds disagree with base metadata"));
    }
    Ok(state)
}
