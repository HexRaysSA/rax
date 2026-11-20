//! ProcessVmCounters for the measured 29708 ARM64 and WoW64 personalities.
use super::super::query::{probe_write, return_length};
use super::{PROCESS_QUERY_RIGHTS, current_process_status, wow64_copy};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_SUCCESS,
};

pub(super) fn selected(c: &Ctx) -> bool {
    matches!(c.arch(), WinArch::Arm64 | WinArch::X86)
        && c.p.native.as_ref().is_some_and(|runtime| {
            matches!(
                (
                    runtime.version.major,
                    runtime.version.minor,
                    runtime.version.build,
                    runtime.object_namespace.native_machine,
                ),
                (10, 0, 29708, Some(0xAA64))
            )
        })
}

pub(super) fn query(
    c: &mut Ctx,
    handle: u64,
    output: u64,
    length: u32,
    returned: u64,
) -> ApiResult {
    if c.arch() == WinArch::X86 {
        return wow64(c, handle, output, length, returned);
    }
    if length != 0 {
        if output % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        if output
            .checked_add(u64::from(length))
            .is_none_or(|end| end > c.p.vm.high())
        {
            return Flow::ret(STATUS_ACCESS_VIOLATION.into());
        }
    }
    if returned != 0 {
        probe_write(c, returned, 4)?;
    }
    if !matches!(length, 88 | 96 | 112) {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    let status =
        current_process_status(c, handle, PROCESS_QUERY_RIGHTS, "process memory counters")?;
    if status != STATUS_SUCCESS {
        return Flow::ret(status.into());
    }
    let counters = c.p.vm.process_counters(length == 112);
    let data = &counters[..length as usize];
    probe_write(c, output, data.len())?;
    c.mem().wr(output, data)?;
    return_length(c, returned, length)?;
    Flow::ret(STATUS_SUCCESS.into())
}

fn wow64(c: &mut Ctx, handle: u64, output: u64, length: u32, returned: u64) -> ApiResult {
    if !matches!(length, 44 | 48 | 64) {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    let status = wow64_copy::prepare(
        c,
        handle,
        output,
        length,
        returned,
        "process memory counters",
    )?;
    if status != STATUS_SUCCESS {
        return Flow::ret(status.into());
    }
    let counters = c.p.vm.wow64_process_counters(length == 64);
    wow64_copy::write(c, output, &counters[..length as usize], 52..56)
}
