//! ProcessRaiseUMExceptionOnInvalidHandleClose for the standalone personality.
//! Native build 29708 stores a process-owned flag. In the standalone probes
//! ordinary invalid-handle NtClose returns were independent of this flag.

use super::query::{probe_write, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::process::family::with_live_handle;

pub(super) const CLASS: u32 = 71;
const BYTES: u32 = 4;
const PROCESS_SET_INFORMATION: u32 = 0x0200;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

pub(super) fn set(c: &mut Ctx, handle: u64, input: u64, length: u32) -> ApiResult {
    if let Err(status) = validate_buffer(c, input, length) {
        return Flow::ret(status.into());
    }
    if length != BYTES {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    // The setter captures the ULONG before checking the handle.
    let enabled = c.mem().u32(input)? != 0;
    with_live_handle(c.p, handle, PROCESS_SET_INFORMATION, |process| {
        process.raise_um_exception_on_invalid_handle_close = enabled;
    })
    .map_or_else(|status| Flow::ret(status.into()), |()| Flow::ret(0))
}

pub(super) fn query(
    c: &mut Ctx,
    handle: u64,
    output: u64,
    length: u32,
    returned: u64,
) -> ApiResult {
    let result = checked_query(c, handle, output, length, returned);
    write_guard_result(c, result)
}

fn checked_query(c: &mut Ctx, handle: u64, output: u64, length: u32, returned: u64) -> ApiResult {
    if let Err(status) = validate_buffer(c, output, length) {
        return Flow::ret(status.into());
    }
    if returned != 0 {
        // A supplied ReturnLength pointer is probed. Its bytes are preserved.
        probe_write(c, returned, BYTES as usize)?;
    }
    if length != BYTES {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    let enabled = match with_live_handle(
        c.p,
        handle,
        PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
        |process| process.raise_um_exception_on_invalid_handle_close,
    ) {
        Ok(enabled) => enabled,
        Err(status) => return Flow::ret(status.into()),
    };
    c.mem().w32(output, u32::from(enabled))?;
    Flow::ret(0)
}

fn validate_buffer(c: &Ctx, buffer: u64, length: u32) -> Result<(), u32> {
    if length != 0 {
        if buffer % u64::from(BYTES) != 0 {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        if c.arch() != WinArch::X86
            && buffer
                .checked_add(u64::from(length))
                .is_none_or(|end| end > c.p.vm.high())
        {
            return Err(STATUS_ACCESS_VIOLATION);
        }
    }
    Ok(())
}
