//! Native-profile alignment and all-or-nothing LARGE_INTEGER time stores.
use super::query::write_guard_result;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{STATUS_DATATYPE_MISALIGNMENT, STATUS_SUCCESS};

pub(super) fn query(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    write_guard_result(c, result)
}

fn checked(c: &mut Ctx) -> ApiResult {
    let output = c.ptr(0)?;
    let installed = c.p.cfg.native_libraries;
    let alignment = crate::user::windows::system_time::output_alignment(installed)
        .map_err(|error| ApiErr::Internal(format!("NtQuerySystemTime profile: {error}")))?;
    if output % alignment != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    let ticks = if installed {
        crate::user::windows::system_time::now()
    } else {
        crate::user::windows::system_time::wall_time()
    }
    .map_err(|error| ApiErr::Internal(format!("NtQuerySystemTime: {error}")))?;
    c.mem().w64(output, ticks)?;
    Flow::ret(STATUS_SUCCESS.into())
}
