//! ProcessWow64Information describes the existing guest process, including its
//! own PEB32. Copy ordering and failure lengths were measured independently in
//! `docs/specifications/windows/native-process-wow64-information/`.

use super::super::query::{probe_write, return_length, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_HANDLE,
    STATUS_OBJECT_TYPE_MISMATCH,
};
use crate::user::windows::objects::Object;

const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

fn self_handle(c: &Ctx, handle: u64) -> Result<bool, u32> {
    if handle == c.arch().ptr(u64::MAX) {
        return Ok(true);
    }
    if handle == c.arch().ptr(u64::MAX - 1) {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    match c.p.objects.get(handle) {
        Some(Object::Process { pid, .. }) => {
            if c.p.objects.access(handle).unwrap_or(0) & PROCESS_QUERY_LIMITED_INFORMATION == 0 {
                return Err(STATUS_ACCESS_DENIED);
            }
            Ok(*pid == c.p.pid)
        }
        Some(_) => Err(STATUS_OBJECT_TYPE_MISMATCH),
        None => Err(STATUS_INVALID_HANDLE),
    }
}

pub(super) fn query(
    c: &mut Ctx,
    handle: u64,
    output: u64,
    length: u32,
    returned: u64,
) -> ApiResult {
    let result = checked(c, handle, output, length, returned);
    // Native64's early ReturnLength probe belongs to the common entry. These
    // later caller stores reject read-only pages before visiting their guard.
    write_guard_result(c, result)
}

fn checked(c: &mut Ctx, handle: u64, output: u64, length: u32, returned: u64) -> ApiResult {
    let required = c.psize() as u32;
    if length != required {
        // Unlike ProcessDebugPort's conversion, failure leaves the caller's
        // ReturnLength unchanged; there is no translated negative size.
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    match self_handle(c, handle) {
        Ok(true) => {}
        Ok(false) => {
            return Err(c.unsupported("ProcessWow64Information outside this personality"));
        }
        Err(status) => return Flow::ret(status.into()),
    }
    let value = if c.arch() == WinArch::X86 {
        // Synthetic x86 already uses a virtual AMD64 kernel. Installed x86
        // requires captured native64 metadata; unknown metadata is unsupported.
        crate::user::windows::process::processor::native_arch(c.p)
            .map_err(|status| c.unsupported(format!("native system architecture: {status:#x}")))?;
        c.p.peb
    } else {
        0
    };
    probe_write(c, output, required as usize)?;
    c.write_ptr(output, value)?;
    return_length(c, returned, required)?;
    Flow::ret(0)
}
