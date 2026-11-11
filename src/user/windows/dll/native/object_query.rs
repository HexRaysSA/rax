//! ObjectHandleFlagInformation is two BOOLEANs owned by the guest handle.
//!
//! The class, layout and API declaration are retained with the independent
//! 29704 native corpus in `docs/specifications/windows/native-object-handle-flags`.
//! Guest pointers and handles never cross into a host NtQueryObject call.

use super::query::{guard_result, probe_write, return_length};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_DATATYPE_MISALIGNMENT, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_HANDLE,
    STATUS_INVALID_INFO_CLASS, STATUS_SUCCESS,
};
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD};

const OBJECT_HANDLE_FLAG_INFORMATION: u32 = 4;

pub(super) fn query(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    guard_result(c, result)
}

fn checked(c: &mut Ctx) -> ApiResult {
    let (handle, class, output, length, returned) =
        (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.u32(3)?, c.ptr(4)?);
    if class < OBJECT_HANDLE_FLAG_INFORMATION {
        return Err(c.unsupported(format!("NtQueryObject information class {class}")));
    }
    // The measured WoW64 thunk rejects unknown classes without entering the
    // native service or visiting either caller destination.
    if c.arch() == WinArch::X86 && class != OBJECT_HANDLE_FLAG_INFORMATION {
        return Flow::ret(STATUS_INVALID_INFO_CLASS.into());
    }
    // Native class4 accepts byte alignment. Other classes require ULONG
    // alignment, even when the class or handle will subsequently be rejected.
    if length != 0 {
        if class != OBJECT_HANDLE_FLAG_INFORMATION && output % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        probe_write(c, output, length as usize)?;
    }
    if returned != 0 {
        probe_write(c, returned, 4)?;
    }
    let flags = if handle == c.arch().ptr(CURRENT_PROCESS) || handle == c.arch().ptr(CURRENT_THREAD)
    {
        0
    } else if let Some(flags) = c.p.objects.flags(handle) {
        flags
    } else {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    };
    if class != OBJECT_HANDLE_FLAG_INFORMATION {
        return Flow::ret(STATUS_INVALID_INFO_CLASS.into());
    }
    let status = if length < 2 {
        STATUS_INFO_LENGTH_MISMATCH
    } else {
        c.mem()
            .wr(output, &[(flags & 1) as u8, ((flags >> 1) & 1) as u8])?;
        STATUS_SUCCESS
    };
    // Native output precedes ReturnLength, including aliases into the record.
    // Invalid handles leave both destinations intact; short valid queries
    // leave the record intact and report its required two-byte size.
    return_length(c, returned, 2)?;
    Flow::ret(status.into())
}
