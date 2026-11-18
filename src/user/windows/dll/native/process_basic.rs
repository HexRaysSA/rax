//! Installed ProcessBasicInformation: public fields, native size/copy ordering.
//! Native observations include exact basic/extended sizes and WoW64's reserved
//! priority word. Values describe the existing virtual process and topology;
//! guest handles and pointers never become host process queries.

use super::query::{probe_write, return_length, write_guard_result};
use crate::user::mm::Perms;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{Mem, perms_of};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT,
    STATUS_GUARD_PAGE_VIOLATION, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_HANDLE,
    STATUS_OBJECT_TYPE_MISMATCH, STATUS_PENDING,
};
use crate::user::windows::objects::Object;
use crate::user::windows::process::family::ChildInfo;

const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const FLAG_WOW64: u32 = 2;
const FLAG_PROCESS_DELETING: u32 = 4;

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

fn child_basic(c: &Ctx, handle: u64) -> Result<(ChildInfo, Option<u32>), ApiErr> {
    let Some(Object::Process { pid, .. }) = c.p.objects.get(handle) else {
        unreachable!("validated process handle");
    };
    c.p.children
        .basic(*pid)
        .ok_or_else(|| c.unsupported("ProcessBasicInformation outside this personality"))
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
    let (pid, ppid, peb, exit, flags) = match self_handle(c, handle) {
        Ok(true) => (c.p.pid, c.p.parent_pid, c.p.peb, c.p.exit_code, 0),
        Ok(false) => {
            let (info, exit) = child_basic(c, handle)?;
            let flags = if exit.is_some() {
                FLAG_PROCESS_DELETING
            } else {
                0
            };
            (info.pid, c.p.pid, info.peb, exit, flags)
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
        c.mem().w64(output + 56, u64::from(flags))?;
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
    let (pid, ppid, peb, exit, flags) = match self_handle(c, handle) {
        Ok(true) => (c.p.pid, c.p.parent_pid, c.p.peb, c.p.exit_code, FLAG_WOW64),
        Ok(false) => {
            let (info, exit) = child_basic(c, handle)?;
            let (peb, flags) = if exit.is_some() {
                (0, FLAG_WOW64 | FLAG_PROCESS_DELETING)
            } else {
                (info.peb, FLAG_WOW64)
            };
            (info.pid, c.p.pid, peb, exit, flags)
        }
        Err(_) if warning => (0, 0, 0, None, 0),
        Err(status) => return Flow::ret(status.into()),
    };
    let (exit, affinity, pid, ppid, flags) = if warning {
        (0, 0, 0, 0, 0)
    } else {
        (exit.unwrap_or(STATUS_PENDING), 1, pid, ppid, flags)
    };
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
    c.mem().w32(base + 20, ppid)?;
    c.mem().w32(base + 16, pid)?;
    c.mem().w32(base + 4, peb as u32)?;
    if length == 32 {
        c.mem().w32(output + 28, flags)?;
    }
    Flow::ret(if warning {
        STATUS_GUARD_PAGE_VIOLATION.into()
    } else {
        0
    })
}
