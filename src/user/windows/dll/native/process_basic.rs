//! Installed ProcessBasicInformation: public fields, native size/copy ordering.
//! Native observations include exact basic/extended sizes and WoW64's reserved
//! priority word. Values describe the existing virtual process and topology;
//! guest handles and pointers never become host process queries.

use super::query::{probe_write, return_length, write_guard_result};
use crate::user::mm::Perms;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::{Mem, perms_of};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT,
    STATUS_GUARD_PAGE_VIOLATION, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_HANDLE,
    STATUS_OBJECT_TYPE_MISMATCH, STATUS_PENDING,
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
    if c.arch() == WinArch::X86 {
        let result = wow64(c, handle, output, length, returned);
        return write_guard_result(c, result);
    }
    // Native entries check ULONG alignment and the full caller span before the
    // optional length destination. They do not pre-probe all output pages.
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
    if !matches!(length, 48 | 64) {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    let (pid, ppid, peb, exit) = match self_handle(c, handle) {
        Ok(true) => (c.p.pid, c.p.parent_pid, c.p.peb, c.p.exit_code),
        Ok(false) => {
            let Some(Object::Process { pid, .. }) = c.p.objects.get(handle) else {
                unreachable!()
            };
            let Some((info, exit)) = c.p.children.basic(*pid) else {
                return Err(c.unsupported("ProcessBasicInformation outside this personality"));
            };
            (info.pid, c.p.pid, info.peb, exit)
        }
        Err(status) => return Flow::ret(status.into()),
    };
    let values = [
        u64::from(exit.unwrap_or(STATUS_PENDING)),
        peb,
        1,
        8,
        u64::from(pid),
        u64::from(ppid),
    ];
    let base = if length == 64 {
        c.mem().w64(output, 64)?;
        8
    } else {
        0
    };
    // Observed eight-byte stores preserve the native partial-copy boundary.
    for (index, value) in values.into_iter().enumerate() {
        c.mem().w64(output + base + index as u64 * 8, value)?;
    }
    if length == 64 {
        c.mem().w64(output + 56, 0)?;
    }
    return_length(c, returned, length)?;
    Flow::ret(0)
}

fn wow64(c: &mut Ctx, handle: u64, output: u64, length: u32, returned: u64) -> ApiResult {
    if !matches!(length, 24 | 32) {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    // The native query's warning still enters WoW64 conversion. A failed
    // ReturnLength guard probe therefore converts its zeroed basic record;
    // the separate WoW PEB lookup can still identify the current process.
    let mut warning = false;
    if returned != 0
        && let Err(fault) = probe_write(c, returned, 4)
    {
        if c.p.vm.take_guard(fault.addr) {
            warning = true;
        } else {
            return Err(fault.into());
        }
    }
    let current = match self_handle(c, handle) {
        Ok(true) => true,
        Ok(false) => {
            return Err(c.unsupported("ProcessBasicInformation outside this personality"));
        }
        Err(_) if warning => false,
        Err(status) => return Flow::ret(status.into()),
    };
    let exit = if warning {
        0
    } else {
        c.p.exit_code.unwrap_or(STATUS_PENDING)
    };
    let affinity = u32::from(!warning);
    let pid = if warning { 0 } else { c.p.pid };
    let peb = if current { c.p.peb as u32 } else { 0 };
    return_length(c, returned, length)?;
    if length == 32 {
        // Extended conversion rejects an unwritable destination span before
        // visiting its guards: a crossing NOACCESS page leaves even an earlier
        // READWRITE|GUARD page intact. A 32-byte span covers at most two pages.
        if [output, output + 31].into_iter().any(|address| {
            c.p.vm
                .query(address)
                .is_none_or(|region| !perms_of(region.protect).contains(Perms::WRITE))
        }) {
            return Flow::ret(STATUS_ACCESS_VIOLATION.into());
        }
        // Its reserved priority word survives as in the basic conversion.
        probe_write(c, output, 32)?;
        c.mem().w32(output, 32)?;
    }
    let base = if length == 32 { output + 4 } else { output };
    c.mem().w32(base, exit)?;
    c.mem().w32(base + 8, affinity)?;
    c.mem().w32(
        base + 20,
        if current && !warning {
            c.p.parent_pid
        } else {
            0
        },
    )?;
    c.mem().w32(base + 16, pid)?;
    c.mem().w32(base + 4, peb)?;
    if length == 32 {
        c.mem()
            .w32(output + 28, if current && !warning { 2 } else { 0 })?;
    }
    Flow::ret(if warning {
        STATUS_GUARD_PAGE_VIOLATION.into()
    } else {
        0
    })
}
