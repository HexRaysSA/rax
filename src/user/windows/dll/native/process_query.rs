//! Checked installed-NTDLL process queries. Public API:
//! <https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess>.
//! Class 36's private ULONG layout, handle right and probe ordering are native
//! Windows 10.0.29683.1000 observations, not public SDK guarantees.

use super::query::{guard_result, probe_write, return_length};
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_DATATYPE_MISALIGNMENT, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_HANDLE,
};
use crate::user::windows::objects::Object;

const PROCESS_COOKIE: u32 = 36;
const PROCESS_VM_WRITE: u32 = 0x20;

pub(super) fn information(c: &mut Ctx) -> ApiResult {
    let result = query(c);
    guard_result(c, result)
}

fn query(c: &mut Ctx) -> ApiResult {
    let (handle, class, output, length, returned) =
        (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.u32(3)?, c.ptr(4)?);
    // Native process queries check output alignment before ReturnLength, but
    // defer touching output pages until after class/length/handle validation.
    // This also applies to WoW64 class 36; system-query conversion is different.
    if length != 0 && output % 4 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    if returned != 0 {
        probe_write(c, returned, 4)?;
    }
    if class != PROCESS_COOKIE {
        return Err(c.unsupported(format!("NtQueryInformationProcess class {class}")));
    }
    if length != 4 {
        // Measured private class behavior: no error ReturnLength publication.
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    if handle != c.arch().ptr(u64::MAX) {
        let Some(Object::Process { pid, .. }) = c.p.objects.get(handle) else {
            return Flow::ret(STATUS_INVALID_HANDLE.into());
        };
        if c.p.objects.access(handle).unwrap_or(0) & PROCESS_VM_WRITE == 0 {
            return Flow::ret(STATUS_ACCESS_DENIED.into());
        }
        if *pid != c.p.pid {
            return Err(c.unsupported("ProcessCookie for a process outside this personality"));
        }
    }
    probe_write(c, output, 4)?;
    c.mem().w32(output, c.p.process_cookie)?;
    return_length(c, returned, 4)?;
    Flow::ret(0)
}
