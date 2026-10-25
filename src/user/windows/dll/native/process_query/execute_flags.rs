//! Read-only ProcessExecuteFlags for the personality's existing fixed NX
//! profile. Page protections are always enforced; ATL thunk emulation and
//! mutable DEP policy are not implemented. This is guest policy, not a copy
//! of the host's default mask (which also depends on its system DEP policy).
//!
//! Native length, handle-right and destination-order observations:
//! `docs/specifications/windows/native-process-execute-flags/`.

use super::super::query::{probe_write, return_length, write_guard_result};
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_HANDLE,
    STATUS_OBJECT_TYPE_MISMATCH,
};
use crate::user::windows::objects::Object;

// MEM_EXECUTE_OPTION_DISABLE | DISABLE_THUNK_EMULATION | PERMANENT.
// A future mutable/default-DEP profile must own both this value and effective
// page execution permissions rather than changing the reported bits alone.
const FIXED_NX_PROFILE: u32 = 0x0d;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

pub(super) fn query(
    c: &mut Ctx,
    handle: u64,
    output: u64,
    length: u32,
    returned: u64,
) -> ApiResult {
    // The parent already checked output alignment and probed ReturnLength.
    // Output write protection precedes output guard visitation, unlike that
    // earlier ReturnLength probe. Preserve this distinction on all guests.
    let result = checked(c, handle, output, length, returned);
    write_guard_result(c, result)
}

fn checked(c: &mut Ctx, handle: u64, output: u64, length: u32, returned: u64) -> ApiResult {
    if length != 4 {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    if handle != c.arch().ptr(u64::MAX) {
        if handle == c.arch().ptr(u64::MAX - 1) {
            return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
        }
        match c.p.objects.get(handle) {
            None => return Flow::ret(STATUS_INVALID_HANDLE.into()),
            Some(Object::Process { pid, .. }) => {
                if c.p.objects.access(handle).unwrap_or(0) & PROCESS_QUERY_INFORMATION == 0 {
                    return Flow::ret(STATUS_ACCESS_DENIED.into());
                }
                if *pid != c.p.pid {
                    return Err(c.unsupported(
                        "ProcessExecuteFlags for a process outside this personality",
                    ));
                }
            }
            Some(_) => return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into()),
        }
    }
    probe_write(c, output, 4)?;
    c.mem().w32(output, FIXED_NX_PROFILE)?;
    return_length(c, returned, 4)?;
    Flow::ret(0)
}
