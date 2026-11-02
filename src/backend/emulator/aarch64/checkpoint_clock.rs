//! Additional counter-domain header for VM-clock-bound RAXA6404 records.
use super::{Result, invalid};
use crate::isa::arm::aarch64::cpu::SystemCounterState;
use crate::vm::timing::ClockMode;

pub(super) const TAG: &[u8; 8] = b"RAXA6404";
pub(super) const OWNED_TAG: &[u8; 8] = b"RAXA6406";
pub(super) const SIZE: usize = 9;

pub(super) fn is_tag(raw: &[u8]) -> bool {
    raw.starts_with(TAG) || raw.starts_with(OWNED_TAG)
}

pub(super) fn encode(state: SystemCounterState) -> Result<[u8; SIZE]> {
    validate(state)?;
    let mut raw = [0; SIZE];
    raw[0] = match state.mode {
        ClockMode::Wall => 0,
        ClockMode::Retired => 1,
    };
    raw[1..].copy_from_slice(&state.frequency_hz.to_le_bytes());
    Ok(raw)
}

pub(super) fn decode(raw: &[u8]) -> Result<SystemCounterState> {
    if raw.len() != SIZE {
        return Err(invalid("truncated system counter header"));
    }
    let mode = match raw[0] {
        0 => ClockMode::Wall,
        1 => ClockMode::Retired,
        _ => return Err(invalid("unknown system counter clock")),
    };
    let state = SystemCounterState {
        mode,
        frequency_hz: u64::from_le_bytes(raw[1..].try_into().unwrap()),
    };
    validate(state)?;
    Ok(state)
}

fn validate(state: SystemCounterState) -> Result<()> {
    if state.frequency_hz == 0 || state.frequency_hz > u64::from(u32::MAX) {
        return Err(invalid("invalid system counter platform frequency"));
    }
    Ok(())
}
