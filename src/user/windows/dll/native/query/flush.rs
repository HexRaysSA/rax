//! Immutable process-owned cache-flush metadata and measured WoW64 copy order.

use super::*;
use crate::user::windows::nt::status::STATUS_SUCCESS;

const BYTES: u32 = 32;

fn record(c: &Ctx) -> Result<[u8; 32], ApiErr> {
    c.p.flush_information
        .as_ref()
        .copied()
        .map_err(|reason| c.unsupported(format!("SystemFlushInformation unavailable: {reason}")))
}

pub(super) fn query(c: &mut Ctx, output: u64, length: u32, returned: u64) -> ApiResult {
    // The common native64 entry already probed the whole declared output span
    // and optional ReturnLength. The handler writes only its fixed record.
    if length < BYTES {
        return_length(c, returned, BYTES)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    c.mem().wr(output, &record(c)?)?;
    return_length(c, returned, BYTES)?;
    Flow::ret(STATUS_SUCCESS.into())
}

pub(super) fn wow64(c: &mut Ctx, output: u64, length: u32, returned: u64) -> ApiResult {
    let result = wow64_copy(c, output, length, returned);
    // User-mode copies reject readonly guards without consuming the guard;
    // a reached writable guard is consumed once and returned as a warning.
    super::write_guard_result(c, result)
}

fn wow64_copy(c: &mut Ctx, output: u64, length: u32, returned: u64) -> ApiResult {
    if output == 0 && length != 0 {
        return_length(c, returned, 0)?;
        return Flow::ret(STATUS_ACCESS_VIOLATION.into());
    }
    // The converted call owns a temporary buffer of the declared length.
    // Bound that workspace by the configured emulation budget and x86 VA
    // ceiling; no host allocation proportional to a guest length is attempted.
    if u64::from(length) > c.p.cfg.arena_bytes.min(c.p.vm.high()) {
        return Flow::ret(STATUS_NO_MEMORY.into());
    }
    if length < BYTES {
        return_length(c, returned, BYTES)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    // Byte-copy destinations need no ULONG alignment. ReturnLength is visited
    // after the record, so a late fault retains the already copied data.
    c.mem().wr(output, &record(c)?)?;
    return_length(c, returned, BYTES)?;
    Flow::ret(STATUS_SUCCESS.into())
}
