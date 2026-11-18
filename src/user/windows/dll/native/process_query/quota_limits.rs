//! Native ARM64 ProcessQuotaLimits for the selected, current guest process.

use super::super::query::{probe_write, return_length};
use super::current_process_status;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_SUCCESS,
};
use crate::user::windows::process::quota::{BASIC_BYTES, EXTENDED_BYTES};

pub(super) fn query(
    c: &mut Ctx,
    handle: u64,
    output: u64,
    length: u32,
    returned: u64,
) -> ApiResult {
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
    let status = current_process_status(c, handle, 0x0400 | 0x1000, "process quota limits")?;
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
