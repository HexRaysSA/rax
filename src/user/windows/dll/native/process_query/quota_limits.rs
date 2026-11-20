//! Native ARM64 and WoW64 ProcessQuotaLimits for the selected current process.

use super::super::query::{probe_write, return_length};
use super::{PROCESS_QUERY_RIGHTS, current_process_status, wow64_copy};
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
    let status = current_process_status(c, handle, PROCESS_QUERY_RIGHTS, "process quota limits")?;
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
    let status = wow64_copy::prepare(c, handle, output, length, returned, "process quota limits")?;
    if status != STATUS_SUCCESS {
        return Flow::ret(status.into());
    }
    let encoded =
        c.p.quota_limits
            .as_ref()
            .and_then(|limits| limits.wow64_encoded())
            .expect("selected WoW64 process quota limits");
    wow64_copy::write(c, output, &encoded[..length as usize], WOW64_PADDING)
}
