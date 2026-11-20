//! Caller-buffer conversion for the measured WoW64 quota and VM queries.

use std::ops::Range;

use super::super::query::{probe_write, return_length, write_guard_result};
use super::{PROCESS_QUERY_RIGHTS, current_process_status};
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{STATUS_ACCESS_VIOLATION, STATUS_SUCCESS};

pub(super) fn prepare(
    c: &Ctx,
    handle: u64,
    output: u64,
    length: u32,
    returned: u64,
    information: &str,
) -> Result<u32, ApiErr> {
    // These thunks resolve the native ReturnLength destination before the
    // handle, then publish the converted length before copying the payload.
    if returned != 0 {
        probe_write(c, returned, 4)?;
    }
    let status = current_process_status(c, handle, PROCESS_QUERY_RIGHTS, information)?;
    if status != STATUS_SUCCESS {
        return Ok(status);
    }
    if output == 0 {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    return_length(c, returned, length)?;
    Ok(STATUS_SUCCESS)
}

pub(super) fn write(c: &mut Ctx, output: u64, data: &[u8], padding: Range<usize>) -> ApiResult {
    let result = write_data(c, output, data, padding);
    write_guard_result(c, result)
}

fn write_data(c: &Ctx, output: u64, data: &[u8], padding: Range<usize>) -> ApiResult {
    probe_write(c, output, data.len())?;
    if padding.start >= data.len() {
        c.mem().wr(output, data)?;
    } else {
        c.mem().wr(output, &data[..padding.start])?;
        c.mem()
            .wr(output + padding.end as u64, &data[padding.end..])?;
    }
    Flow::ret(STATUS_SUCCESS.into())
}
