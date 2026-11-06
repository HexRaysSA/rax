//! Measured ProcessDeviceMap native64 and WoW64 publication contracts.
use super::super::query::{probe_write, return_length, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

fn process_status(c: &Ctx, handle: u64) -> Result<u32, crate::user::windows::hle::ApiErr> {
    if handle == c.arch().ptr(u64::MAX) {
        return Ok(STATUS_SUCCESS);
    }
    let Some(object) = c.p.objects.get(handle) else {
        return Ok(STATUS_INVALID_HANDLE);
    };
    let Object::Process { pid, .. } = object else {
        return Ok(STATUS_OBJECT_TYPE_MISMATCH);
    };
    if c.p.objects.access(handle).unwrap_or(0) & 0x400 == 0 {
        return Ok(STATUS_ACCESS_DENIED);
    }
    if *pid != c.p.pid {
        return Err(c.unsupported("ProcessDeviceMap for a process outside this personality"));
    }
    Ok(STATUS_SUCCESS)
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
    let result = native(c, handle, output, length, returned);
    write_guard_result(c, result)
}

fn native(c: &mut Ctx, handle: u64, output: u64, length: u32, returned: u64) -> ApiResult {
    if length != 0 && output % 4 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    if length != 0
        && output
            .checked_add(u64::from(length))
            .is_none_or(|end| end > c.p.vm.high())
    {
        return Flow::ret(STATUS_ACCESS_VIOLATION.into());
    }
    if returned != 0 {
        probe_write(c, returned, 4)?;
    }
    if !matches!(length, 36 | 48) {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    let flags = if length == 48 {
        let Some(address) = output.checked_add(40) else {
            return Flow::ret(STATUS_ACCESS_VIOLATION.into());
        };
        c.mem().u32(address)?
    } else {
        0
    };
    if flags & !1 != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let status = process_status(c, handle)?;
    if status != STATUS_SUCCESS {
        return Flow::ret(status.into());
    }
    let record = c.p.cfg.drives.device_map(flags != 0);
    // The measured native entry visits the starting byte before publishing
    // eight-byte words. A later fault retains the completed prefix; probing
    // the whole record first would erase that observable publication.
    c.mem().u8(output)?;
    for (index, chunk) in record.chunks(8).enumerate() {
        c.mem().wr(output + (index * 8) as u64, chunk)?;
    }
    return_length(c, returned, length)?;
    Flow::ret(STATUS_SUCCESS.into())
}

fn wow64(c: &mut Ctx, handle: u64, output: u64, length: u32, returned: u64) -> ApiResult {
    let mut status = if matches!(length, 36 | 48) {
        process_status(c, handle)?
    } else {
        STATUS_INFO_LENGTH_MISMATCH
    };
    if status == STATUS_SUCCESS && output == 0 {
        status = STATUS_ACCESS_VIOLATION;
    }
    let published = if status == STATUS_SUCCESS {
        let record = c.p.cfg.drives.device_map(false);
        // WoW64 ignores EX flags, accepts unaligned destinations and publishes
        // the converted record before visiting ReturnLength.
        for (index, chunk) in record.chunks(16).enumerate() {
            c.mem().wr(output + (index * 16) as u64, chunk)?;
        }
        36
    } else {
        0
    };
    return_length(c, returned, published)?;
    Flow::ret(status.into())
}
