//! ProcessImageInformation from the executable's immutable loader snapshot.
//! Native copy granularity and guards depend on the captured kernel profile;
//! WoW64 converts through private backing and validates its whole caller record.

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

const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const WOW64_LENGTH_FAILURE: u32 = 0xffff_fff0;

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
            if c.p.objects.access(handle).unwrap_or(0) & PROCESS_QUERY_LIMITED_INFORMATION == 0 {
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
    if c.arch() == WinArch::X86 {
        // Conversion's output and late ReturnLength stores reject read-only
        // guards before guard visitation on all three captured kernels.
        write_guard_result(c, result)
    } else {
        result
    }
}

fn checked(c: &mut Ctx, handle: u64, output: u64, length: u32, returned: u64) -> ApiResult {
    let wow = c.arch() == WinArch::X86;
    if wow && output != 0 && length != 0 {
        // The native 64-byte backing is 16 bytes wider than the converted
        // 48-byte record. Charge its minimum page-rounded extent against the
        // existing guest budget without allocating length-proportional host RAM.
        // This resource policy does not claim an unmeasured native heap limit.
        let capture = u64::from(length) + 16;
        let charge = (capture + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if charge
            > c.p
                .vm
                .commit_limit()
                .saturating_sub(c.p.vm.committed_bytes())
            || charge > c.p.vm.high() - c.p.vm.low()
        {
            return Flow::ret(STATUS_NO_MEMORY.into());
        }
    }
    let required = if wow { 48 } else { 64 };
    let status = if length != required {
        STATUS_INFO_LENGTH_MISMATCH
    } else {
        match self_handle(c, handle) {
            Ok(true) if output == 0 => STATUS_ACCESS_VIOLATION,
            Ok(true) => 0,
            Ok(false) => {
                return Err(c.unsupported(
                    "ProcessImageInformation for a process outside this personality",
                ));
            }
            Err(status) => status,
        }
    };
    if status != 0 {
        if wow {
            return_length(c, returned, WOW64_LENGTH_FAILURE)?;
        }
        return Flow::ret(status.into());
    }
    let information =
        c.p.image_information
            .as_ref()
            .map_err(|reason| c.unsupported(format!("ProcessImageInformation: {reason}")))?;
    let (record, size) = information
        .encode(c.arch())
        .map_err(|reason| c.unsupported(format!("ProcessImageInformation: {reason}")))?;
    let granule = if let Some(native) = &c.p.native {
        match (
            native.version.major,
            native.version.minor,
            native.version.build,
            native.object_namespace.native_machine,
        ) {
            (10, 0, 29683, Some(0xaa64)) => 8,
            (10, 0, 20348 | 26100, Some(0x8664)) => 16,
            _ => {
                return Err(c.unsupported(
                    "ProcessImageInformation copy for an unqualified installed kernel profile",
                ));
            }
        }
    } else {
        // Built-in DLL mode models its own kernel policy and has no captured
        // installation identity. This choice makes no native-runtime claim.
        if c.arch() == WinArch::Arm64 { 8 } else { 16 }
    };
    if wow {
        probe_write(c, output, size)?;
        c.mem().wr(output, &record[..size])?;
        return_length(c, returned, required)?;
        return Flow::ret(0);
    }

    let result = copy_native(c, output, returned, &record, size, granule);
    if granule == 16 {
        write_guard_result(c, result)
    } else {
        result
    }
}

fn copy_native(
    c: &mut Ctx,
    output: u64,
    returned: u64,
    record: &[u8; 64],
    size: usize,
    granule: usize,
) -> ApiResult {
    for offset in (0..size).step_by(granule) {
        // Preflight each indivisible native copy group. Earlier groups remain
        // visible if a later group crosses into an inaccessible/guarded page.
        let at = output + offset as u64;
        probe_write(c, at, granule)?;
        c.mem().wr(at, &record[offset..offset + granule])?;
    }
    return_length(c, returned, size as u32)?;
    Flow::ret(0)
}
