//! Query immutable security metadata for the selected RPC directory.

use super::query::{probe_write, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_ACCESS_VIOLATION, STATUS_BUFFER_TOO_SMALL,
    STATUS_DATATYPE_MISALIGNMENT, STATUS_INVALID_HANDLE, STATUS_SUCCESS,
};
use crate::user::windows::object_namespace::rpc_security::{
    ACCESS_SYSTEM_SECURITY, CAPTURED_SECURITY_INFORMATION, READ_CONTROL, SACL_SECURITY_INFORMATION,
    SE_SELF_RELATIVE,
};
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};

pub(super) fn query(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    match write_guard_result(c, result) {
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        result => result,
    }
}

fn checked(c: &mut Ctx) -> ApiResult {
    let (handle, mask, output, length, returned) =
        (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.u32(3)?, c.ptr(4)?);
    if length != 0 {
        if output % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        probe_write(c, output, length as usize)?;
    }
    probe_write(c, returned, 4)?;
    if handle == c.arch().ptr(CURRENT_PROCESS) || handle == c.arch().ptr(CURRENT_THREAD) {
        return Err(c.unsupported("security descriptor of a process or thread is not captured"));
    }
    let directory = match c.p.objects.get(handle) {
        Some(Object::Directory(directory)) if directory.is_rpc_control() => directory,
        Some(_) => return Err(c.unsupported("security descriptor of this object is not captured")),
        None => return Flow::ret(STATUS_INVALID_HANDLE.into()),
    };
    let mut access = 0;
    if mask & CAPTURED_SECURITY_INFORMATION != 0 {
        access |= READ_CONTROL;
    }
    if mask & SACL_SECURITY_INFORMATION != 0 {
        access |= ACCESS_SYSTEM_SECURITY;
    }
    if c.p.objects.access(handle).unwrap_or(0) & access != access {
        return Flow::ret(STATUS_ACCESS_DENIED.into());
    }
    let descriptor = directory
        .rpc_security
        .as_ref()
        .and_then(|security| security.descriptor(mask))
        .ok_or_else(|| c.unsupported(format!("RPC directory security information {mask:#x}")))?;
    let required = descriptor.len() as u32;
    let status = if length < required {
        STATUS_BUFFER_TOO_SMALL
    } else {
        c.mem().wr(output, descriptor)?;
        STATUS_SUCCESS
    };
    c.mem().w32(returned, required)?;
    if status == STATUS_SUCCESS
        && c.arch() == WinArch::X86
        && c.mem().u16(output + 2)? & SE_SELF_RELATIVE == 0
    {
        // WoW64 checks Control after the native ReturnLength store. An
        // alias can clear SE_SELF_RELATIVE and trigger in-place narrowing
        // from absolute native pointers at offsets 8, 16, 24 and 32.
        for field in 1..=4 {
            let pointer = c.mem().u32(output + 8 * field)?;
            c.mem().w32(output + 4 * field, pointer)?;
        }
    }
    Flow::ret(status.into())
}
