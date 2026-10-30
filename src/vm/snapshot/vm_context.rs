//! Bounded shared backend state, distinct from per-CPU backend records.

use super::BackendContext;
use crate::error::{Error, Result};
use std::io::Read;

const TAG: &[u8; 8] = b"RAXVMC01";
pub(super) const MAX_SECTION: u64 = 64 * 1024 * 1024 + 64 * 1024;

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("shared backend checkpoint context: {message}"))
}

pub(super) fn validate(context: &BackendContext) -> Result<()> {
    if context.kind == 0 || context.data.is_empty() || context.data.len() as u64 > MAX_SECTION - 20
    {
        return Err(invalid("invalid producer or shared record length"));
    }
    Ok(())
}

pub(super) fn encode(context: &BackendContext) -> Result<Vec<u8>> {
    validate(context)?;
    let mut raw = Vec::new();
    raw.try_reserve_exact(20 + context.data.len())
        .map_err(invalid)?;
    raw.extend_from_slice(TAG);
    raw.extend_from_slice(&context.kind.to_le_bytes());
    raw.extend_from_slice(&(context.data.len() as u64).to_le_bytes());
    raw.extend_from_slice(&context.data);
    Ok(raw)
}

pub(super) fn read_from(reader: &mut impl Read, length: u64) -> Result<BackendContext> {
    if !(21..=MAX_SECTION).contains(&length) {
        return Err(invalid("shared record outside framing limits"));
    }
    let mut reader = reader.take(length);
    let mut header = [0; 20];
    reader.read_exact(&mut header).map_err(invalid)?;
    if &header[..8] != TAG {
        return Err(invalid("unknown shared context framing tag"));
    }
    let kind = u32::from_le_bytes(header[8..12].try_into().unwrap());
    let size = u64::from_le_bytes(header[12..].try_into().unwrap());
    if size != length - 20 || kind == 0 {
        return Err(invalid("shared context table differs from framing"));
    }
    let size = usize::try_from(size).map_err(invalid)?;
    let mut data = Vec::new();
    data.try_reserve_exact(size).map_err(invalid)?;
    data.resize(size, 0);
    reader.read_exact(&mut data).map_err(invalid)?;
    let context = BackendContext { kind, data };
    validate(&context)?;
    Ok(context)
}
