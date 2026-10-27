//! ProcessExecuteFlags setter for the existing permanently enforced NX policy.
//! Independent native validation/copy observations, including WoW64's input
//! guard retry, are under `native-process-execute-flags-set`. No successful
//! policy transition is represented by this immutable personality profile.

use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT,
    STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_PARAMETER,
};

pub(super) fn information(c: &mut Ctx, handle: u64, input: u64, length: u32) -> ApiResult {
    let wow = c.arch() == WinArch::X86;
    if length != 0 {
        if input % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        if !wow
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
    // This class accepts only the exact current-process pseudo-handle, even
    // when a real self handle has all rights. Rejection precedes input access.
    if handle != c.arch().ptr(u64::MAX) {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let flags = match c.mem().u32(input) {
        Ok(flags) => flags,
        Err(fault) if wow && c.p.vm.take_guard(fault.addr) => {
            // The WoW64 input capture retries the reached read after consuming
            // its guard. It preserves actual invalid flag bits, not a zeroed
            // substitute. Native64's warning is handled by the common entry.
            c.mem().u32(input)?
        }
        Err(fault) => return Err(fault.into()),
    };
    if !wow || flags & !0x7f != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    // Query class34 describes permanent NX (0x0D), with actual non-executable
    // data mappings. A rejected setter changes neither that policy nor
    // execute permissions; mutable/default DEP and ATL emulation require real state.
    Flow::ret(STATUS_ACCESS_DENIED.into())
}
