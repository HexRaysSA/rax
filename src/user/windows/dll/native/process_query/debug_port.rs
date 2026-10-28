//! ProcessDebugPort for the existing guest profile without a debugger.
//! The selected native and WoW64 copy paths are measured independently in
//! `docs/specifications/windows/native-process-debug-port/`. A guest request
//! never queries a host process, and another process remains unsupported.

use super::super::query::{probe_write, return_length, write_guard_result};
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_ACCESS_VIOLATION, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_HANDLE, STATUS_NO_MEMORY, STATUS_OBJECT_TYPE_MISMATCH,
};
use crate::user::windows::objects::Object;

const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const WOW64_LENGTH_FAILURE: u32 = 0xffff_fffc;

fn self_handle(c: &Ctx, handle: u64) -> Result<bool, u32> {
    if handle == c.arch().ptr(u64::MAX) {
        return Ok(true);
    }
    if handle == c.arch().ptr(u64::MAX - 1) {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    match c.p.objects.get(handle) {
        None => Err(STATUS_INVALID_HANDLE),
        Some(Object::Process { pid, .. }) => {
            if c.p.objects.access(handle).unwrap_or(0) & PROCESS_QUERY_INFORMATION == 0 {
                return Err(STATUS_ACCESS_DENIED);
            }
            Ok(*pid == c.p.pid)
        }
        Some(_) => Err(STATUS_OBJECT_TYPE_MISMATCH),
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
    // Caller stores reject read-only guards before visiting the guard. Native
    // ReturnLength's earlier probe remains owned by the common query entry.
    write_guard_result(c, result)
}

fn checked(c: &mut Ctx, handle: u64, output: u64, length: u32, returned: u64) -> ApiResult {
    let wow = c.arch() == WinArch::X86;
    if wow && output != 0 && length != 0 {
        // WoW64 expands the pointer-width result into private native backing.
        // Bound that temporary's minimum page-rounded size by the guest's
        // existing no-paging-file budget, without proportional host allocation.
        // This is a guest resource bound, not a measured native heap threshold.
        let capture = u64::from(length) + 4;
        let charge = (capture + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if charge > c.p.vm.commit_limit() - c.p.vm.committed_bytes()
            || charge > c.p.vm.high() - c.p.vm.low()
        {
            return Flow::ret(STATUS_NO_MEMORY.into());
        }
    }
    let required = c.psize() as u32;
    let status = if length != required {
        STATUS_INFO_LENGTH_MISMATCH
    } else {
        match self_handle(c, handle) {
            Ok(true) if output == 0 => STATUS_ACCESS_VIOLATION,
            Ok(true) => 0,
            Ok(false) => {
                return Err(
                    c.unsupported("ProcessDebugPort for a process outside this personality")
                );
            }
            Err(status) => status,
        }
    };
    if status != 0 {
        if wow {
            // Failed native calls leave their private length zero. Conversion
            // subtracts four bytes before publishing the caller's ULONG.
            return_length(c, returned, WOW64_LENGTH_FAILURE)?;
        }
        return Flow::ret(status.into());
    }
    // Native64 already checked ULONG alignment/range and probed ReturnLength.
    // WoW64 accepts unaligned output and checks just its four converted bytes.
    probe_write(c, output, required as usize)?;
    c.write_ptr(output, 0)?;
    return_length(c, returned, required)?;
    Flow::ret(0)
}
