//! Class12 query/set ordering is independent of the Win32 flag translation.
use super::super::query::{probe_write, return_length, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};

fn process_status(c: &Ctx, handle: u64, rights: u32) -> Result<u32, ApiErr> {
    if handle == c.arch().ptr(CURRENT_PROCESS) {
        return Ok(STATUS_SUCCESS);
    }
    if handle == c.arch().ptr(CURRENT_THREAD) {
        return Ok(STATUS_OBJECT_TYPE_MISMATCH);
    }
    match c.p.objects.get(handle) {
        None => Ok(STATUS_INVALID_HANDLE),
        Some(Object::Process { pid, .. }) => {
            if c.p.objects.access(handle).unwrap_or(0) & rights == 0 {
                Ok(STATUS_ACCESS_DENIED)
            } else if *pid != c.p.pid {
                Err(c.unsupported("process error mode for a process outside this personality"))
            } else {
                Ok(STATUS_SUCCESS)
            }
        }
        Some(_) => Ok(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

pub(super) fn query(
    c: &mut Ctx,
    handle: u64,
    output: u64,
    length: u32,
    returned: u64,
) -> ApiResult {
    // Common process-query entry already checked native range/alignment and
    // probed ReturnLength. Late output stores use write-before-guard ordering.
    let result = checked_query(c, handle, output, length, returned);
    write_guard_result(c, result)
}

fn checked_query(c: &mut Ctx, handle: u64, output: u64, length: u32, returned: u64) -> ApiResult {
    if length != 4 {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    let status = process_status(c, handle, 0x0400 | 0x1000)?;
    if status != STATUS_SUCCESS {
        return Flow::ret(status.into());
    }
    probe_write(c, output, 4)?;
    c.mem().w32(output, c.p.error_mode.native())?;
    return_length(c, returned, 4)?;
    Flow::ret(0)
}

pub(in super::super) fn set(c: &mut Ctx, handle: u64, input: u64, length: u32) -> ApiResult {
    if length != 0 {
        if input % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        if c.arch() != WinArch::X86
            && input
                .checked_add(u64::from(length))
                .is_none_or(|end| end > c.p.vm.high())
        {
            return Flow::ret(STATUS_ACCESS_VIOLATION.into());
        }
    }
    if length != 4 {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    // Both native64 and WoW64 capture the ULONG before handle/right checks.
    // Unlike class34, WoW64 does not retry a reached input guard for class12.
    let mode = c.mem().u32(input)?;
    let status = process_status(c, handle, 0x0200)?;
    if status != STATUS_SUCCESS {
        return Flow::ret(status.into());
    }
    c.p.error_mode.set_native(mode);
    Flow::ret(0)
}
