//! Native ARM64 and WoW64 ProcessQuotaLimits for the selected current process.

use super::super::query::{probe_write, return_length, write_guard_result};
use super::current_process_status;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_SUCCESS,
};
use crate::user::windows::process::quota::{
    BASIC_BYTES, EXTENDED_BYTES, WOW64_BASIC_BYTES, WOW64_EXTENDED_BYTES, WOW64_PADDING,
};

const QUERY_RIGHTS: u32 = 0x0400 | 0x1000;

pub(super) fn query(
    c: &mut Ctx,
    handle: u64,
    output: u64,
    length: u32,
    returned: u64,
) -> ApiResult {
    if c.arch() == WinArch::X86 {
        return wow64(c, handle, output, length, returned);
    }
    if length != 0 {
        if output % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        if output
            .checked_add(u64::from(length))
            .is_none_or(|end| end > c.p.vm.high())
        {
            return Flow::ret(STATUS_ACCESS_VIOLATION.into());
        }
    }
    if returned != 0 {
        probe_write(c, returned, 4)?;
    }
    if !matches!(length, BASIC_BYTES | EXTENDED_BYTES) {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    let status = current_process_status(c, handle, QUERY_RIGHTS, "process quota limits")?;
    if status != STATUS_SUCCESS {
        return Flow::ret(status.into());
    }
    let encoded =
        c.p.quota_limits
            .as_ref()
            .expect("selected process quota limits")
            .encoded();
    let data = &encoded[..length as usize];
    probe_write(c, output, data.len())?;
    c.mem().wr(output, data)?;
    return_length(c, returned, length)?;
    Flow::ret(STATUS_SUCCESS.into())
}

fn wow64(c: &mut Ctx, handle: u64, output: u64, length: u32, returned: u64) -> ApiResult {
    if !matches!(length, WOW64_BASIC_BYTES | WOW64_EXTENDED_BYTES) {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    // The native call probes this destination before resolving the handle.
    if returned != 0 {
        probe_write(c, returned, 4)?;
    }
    let status = current_process_status(c, handle, QUERY_RIGHTS, "process quota limits")?;
    if status != STATUS_SUCCESS {
        return Flow::ret(status.into());
    }
    if output == 0 {
        return Flow::ret(STATUS_ACCESS_VIOLATION.into());
    }
    // Native success publishes the converted length before the thunk probes
    // and copies its converted record into the caller's non-null buffer.
    return_length(c, returned, length)?;
    let result = write_wow64_output(c, output, length as usize);
    write_guard_result(c, result)
}

fn write_wow64_output(c: &Ctx, output: u64, bytes: usize) -> ApiResult {
    let encoded =
        c.p.quota_limits
            .as_ref()
            .and_then(|limits| limits.wow64_encoded())
            .expect("selected WoW64 process quota limits");
    probe_write(c, output, bytes)?;
    c.mem().wr(output, &encoded[..WOW64_PADDING.start])?;
    c.mem().wr(
        output + WOW64_PADDING.end as u64,
        &encoded[WOW64_PADDING.end..bytes],
    )?;
    Flow::ret(STATUS_SUCCESS.into())
}
