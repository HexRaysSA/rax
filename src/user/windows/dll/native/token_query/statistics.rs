//! Native and WoW64 publication of the selected token's fixed statistics.
use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::hle::ApiErr;
use crate::user::windows::security::Subject;
use crate::user::windows::security::token::statistics::BYTES;

pub(super) fn preflight(
    c: &mut Ctx,
    output: u64,
    length: u32,
    returned: u64,
) -> Result<Option<u32>, ApiErr> {
    if output != 0 {
        // Same fixed-width native and WoW64 layout: no widening delta.
        // Model private workspace against the configured guest budget while
        // avoiding any host allocation proportional to this untrusted length.
        let capture = ((u64::from(length) + 15) & !15) + 16;
        let charge = (capture + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if charge > c.p.vm.commit_limit() - c.p.vm.committed_bytes()
            || charge > c.p.vm.high() - c.p.vm.low()
        {
            c.set_last_error(8)?;
            return Ok(Some(STATUS_NO_MEMORY));
        }
    } else if length != 0 {
        if returned != 0 {
            c.mem().w32(returned, 0)?;
        }
        return Ok(Some(STATUS_ACCESS_VIOLATION));
    }
    Ok(None)
}

pub(super) fn publish(
    c: &mut Ctx,
    subject: &Subject,
    expected_type: u32,
    output: u64,
    length: u32,
    returned: u64,
) -> ApiResult {
    let value = subject
        .statistics
        .ok_or_else(|| c.unsupported("token statistics are not captured"))?;
    if value.token_type() != expected_type {
        return Err(c.unsupported("token statistics do not match the selected token type"));
    }
    let wow = c.arch() == WinArch::X86;
    if !wow {
        c.mem().w32(returned, BYTES as u32)?;
    }
    if length < BYTES as u32 {
        if wow && returned != 0 {
            c.mem().w32(returned, BYTES as u32)?;
        }
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    // All 55 interior page crossings retain the entire poisoned output on
    // failure, including WoW64. Probe/copy only these 56 bytes here; the
    // native64 caller has already probed its complete declared capacity.
    c.mem().wr(output, value.bytes())?;
    if wow && returned != 0 {
        c.mem().w32(returned, BYTES as u32)?;
    }
    Flow::ret(STATUS_SUCCESS.into())
}
