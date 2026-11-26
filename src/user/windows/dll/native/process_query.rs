//! Checked installed-NTDLL process queries. Public API:
//! <https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess>.
//! Class 36's private ULONG layout, handle right and probe ordering are native
//! Windows 10.0.29683.1000 observations, not public SDK guarantees.

use super::query::{guard_result, probe_write, return_length, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Arg::Ptr, Conv::Stdcall, Ctx, Export, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT,
    STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS,
    STATUS_OBJECT_TYPE_MISMATCH, STATUS_SUCCESS,
};
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};
use crate::user::windows::process::quota;

const PROCESS_WX86_INFORMATION: u32 = 19;
const PROCESS_COOKIE: u32 = 36;
const PROCESS_ENCLAVE_INFORMATION: u32 = 86;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const PROCESS_QUERY_RIGHTS: u32 = PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
const PROCESS_VM_WRITE: u32 = 0x20;

pub(in crate::user::windows::dll) static WIN32_PROCESS_QUERY_EXPORTS: &[Export] = &[Export::func(
    "IsWow64Process",
    Stdcall,
    &[Ptr, Ptr],
    is_wow64_process,
)];

fn is_wow64_process(c: &mut Ctx) -> ApiResult {
    let (handle, out) = (c.ptr(0)?, c.ptr(1)?);
    let status = current_process_status(c, handle, PROCESS_QUERY_RIGHTS, "IsWow64Process")?;
    if status != STATUS_SUCCESS {
        return c.fail(crate::user::windows::nt::status_to_error(status), 0);
    }
    let wow = if c.arch() == WinArch::X86 {
        match crate::user::windows::process::processor::native_arch(c.p) {
            Ok(arch) => arch.is64(),
            Err(status) => return c.fail(crate::user::windows::nt::status_to_error(status), 0),
        }
    } else {
        false
    };
    c.mem().w32(out, u32::from(wow))?;
    Flow::bool(true)
}

mod command_line;
mod debug_port;
mod device_map;
pub(super) mod error_mode;
mod execute_flags;
mod image_information;
mod image_name;
mod quota_limits;
mod vm_counters;
mod wow64_copy;
mod wow64_information;

pub(super) fn information(c: &mut Ctx) -> ApiResult {
    let result = query(c);
    guard_result(c, result)
}

fn query(c: &mut Ctx) -> ApiResult {
    let (handle, class, output, length, returned) =
        (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.u32(3)?, c.ptr(4)?);
    if class == 0 {
        return super::process_basic::query(c, handle, output, length, returned);
    }
    if class == quota::CLASS && c.p.quota_limits.is_some() {
        return quota_limits::query(c, handle, output, length, returned);
    }
    if class == 3 && vm_counters::selected(c) {
        return vm_counters::query(c, handle, output, length, returned);
    }
    if class == image_name::CLASS {
        return image_name::query(c, handle, output, length, returned);
    }
    if class == 60 {
        return command_line::query(c, handle, output, length, returned);
    }
    if class == 49 {
        return super::process_console::query(c, handle, output, length, returned);
    }
    if class == super::process_handle_close::CLASS {
        return super::process_handle_close::query(c, handle, output, length, returned);
    }
    if class == 23 {
        return device_map::query(c, handle, output, length, returned);
    }
    if class == 7 && c.arch() == WinArch::X86 {
        // WoW64 converts this pointer-width record through private backing;
        // its caller stores have no native entry alignment/ReturnLength probe.
        return debug_port::query(c, handle, output, length, returned);
    }
    if class == 37 && c.arch() == WinArch::X86 {
        return image_information::query(c, handle, output, length, returned);
    }
    if class == 26 && c.arch() == WinArch::X86 {
        return wow64_information::query(c, handle, output, length, returned);
    }
    if class == PROCESS_ENCLAVE_INFORMATION && c.arch() == WinArch::X86 {
        // The WoW64 table rejects this class before visiting caller memory.
        return Flow::ret(STATUS_INVALID_INFO_CLASS.into());
    }
    // Native process queries check output alignment before ReturnLength, but
    // defer touching output pages until after class/length/handle validation.
    // This also applies to WoW64 class 36; system-query conversion is different.
    if length != 0 && output % 4 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    if length != 0
        && c.arch() != WinArch::X86
        && matches!(
            class,
            7 | 12
                | PROCESS_WX86_INFORMATION
                | 26
                | 34
                | PROCESS_COOKIE
                | 37
                | PROCESS_ENCLAVE_INFORMATION
        )
        && output
            .checked_add(u64::from(length))
            .is_none_or(|end| end > c.p.vm.high())
    {
        // Native upper-user-span rejection precedes ReturnLength visitation.
        // The measured WoW64 direct class12/34/36 paths omit this check.
        return Flow::ret(STATUS_ACCESS_VIOLATION.into());
    }
    if returned != 0 {
        probe_write(c, returned, 4)?;
    }
    if class == PROCESS_ENCLAVE_INFORMATION {
        return Flow::ret(STATUS_INVALID_INFO_CLASS.into());
    }
    if class == 12 {
        return error_mode::query(c, handle, output, length, returned);
    }
    if class == PROCESS_WX86_INFORMATION {
        let result = wx86_information(c, handle, output, length, returned);
        return write_guard_result(c, result);
    }
    if class == 7 {
        return debug_port::query(c, handle, output, length, returned);
    }
    if class == 26 {
        return wow64_information::query(c, handle, output, length, returned);
    }
    if class == 34 {
        return execute_flags::query(c, handle, output, length, returned);
    }
    if class == 37 {
        return image_information::query(c, handle, output, length, returned);
    }
    if class == 52 {
        return super::process_mitigation::query(c, handle, output, length);
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

pub(super) fn process_query_target(c: &Ctx, handle: u64, rights: u32) -> Result<u32, u32> {
    if handle == c.arch().ptr(CURRENT_PROCESS) {
        return Ok(c.p.pid);
    }
    if handle == c.arch().ptr(CURRENT_THREAD) {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    match c.p.objects.get(handle) {
        None => Err(STATUS_INVALID_HANDLE),
        Some(Object::Process { pid, .. }) => {
            if c.p.objects.access(handle).unwrap_or(0) & rights == 0 {
                Err(STATUS_ACCESS_DENIED)
            } else {
                Ok(*pid)
            }
        }
        Some(_) => Err(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

fn current_process_status(
    c: &Ctx,
    handle: u64,
    rights: u32,
    information: &str,
) -> Result<u32, ApiErr> {
    match process_query_target(c, handle, rights) {
        Ok(pid) if pid == c.p.pid => Ok(STATUS_SUCCESS),
        Ok(_) => Err(c.unsupported(format!(
            "{information} for a process outside this personality"
        ))),
        Err(status) => Ok(status),
    }
}

fn wx86_information(c: &Ctx, handle: u64, output: u64, length: u32, returned: u64) -> ApiResult {
    if length != 4 {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    if let Err(status) = process_query_target(c, handle, PROCESS_QUERY_INFORMATION) {
        return Flow::ret(status.into());
    }
    // The personality has no legacy Wx86 VDM state. Modern WoW64 processes
    // report the same zero value as native processes for this distinct query.
    probe_write(c, output, 4)?;
    c.mem().w32(output, 0)?;
    return_length(c, returned, 4)?;
    Flow::ret(0)
}
