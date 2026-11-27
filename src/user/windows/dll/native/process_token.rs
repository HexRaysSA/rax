//! Primary-token opening from captured rights, with native caller-store order.

use super::query::{probe_write, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

pub(super) fn open(c: &mut Ctx) -> ApiResult {
    let result = (|| {
        let (process, desired, output) = (c.ptr(0)?, c.u32(1)?, c.ptr(2)?);
        checked(c, process, desired, 0, output)
    })();
    write_guard_result(c, result)
}

pub(super) fn open_ex(c: &mut Ctx) -> ApiResult {
    let qualified = c.arch() == WinArch::Arm64
        && c.p.native.as_ref().is_some_and(|runtime| {
            let version = &runtime.version;
            (version.major, version.minor, version.build) == (10, 0, 29708)
                && runtime.object_namespace.native_machine == Some(0xaa64)
        });
    if !qualified {
        return Err(c.unsupported("unmeasured installed NtOpenProcessTokenEx profile"));
    }
    let (process, desired, attributes, output) = (c.ptr(0)?, c.u32(1)?, c.u32(2)?, c.ptr(3)?);
    let result = checked(c, process, desired, attributes, output);
    write_guard_result(c, result)
}

fn process_status(c: &Ctx, handle: u64) -> Result<u32, ApiErr> {
    if handle == c.arch().ptr(u64::MAX) {
        return Ok(STATUS_SUCCESS);
    }
    if handle == c.arch().ptr(u64::MAX - 1) {
        return Ok(STATUS_OBJECT_TYPE_MISMATCH);
    }
    match c.p.objects.get(handle) {
        None => Ok(STATUS_INVALID_HANDLE),
        Some(Object::Process { pid, .. }) => {
            if c.p.objects.access(handle).unwrap_or(0) & 0x1400 == 0 {
                return Ok(STATUS_ACCESS_DENIED);
            }
            if *pid != c.p.pid {
                return Err(c.unsupported("primary token of another process is not captured"));
            }
            Ok(STATUS_SUCCESS)
        }
        Some(_) => Ok(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

fn failure(c: &Ctx, output: u64, status: u32) -> ApiResult {
    // WoW64 copies its zero temporary HANDLE even on a kernel error. A NULL
    // caller pointer skips that copy; faults of a non-NULL copy override status.
    if c.arch() == WinArch::X86 && output != 0 {
        c.mem().w32(output, 0)?;
    }
    Flow::ret(status.into())
}

fn checked(c: &mut Ctx, process: u64, desired: u32, attributes: u32, output: u64) -> ApiResult {
    let status = process_status(c, process)?;
    if status != STATUS_SUCCESS {
        return failure(c, output, status);
    }
    // The measured user-mode open rejects OBJ_EXCLUSIVE and OBJ_OPENLINK.
    // Of the accepted attribute bits, only OBJ_INHERIT affects the new handle.
    const OBJ_INHERIT: u32 = 0x02;
    const INVALID_ATTRIBUTES: u32 = 0x20 | 0x100;
    if attributes & INVALID_ATTRIBUTES != 0 {
        return failure(c, output, STATUS_INVALID_PARAMETER);
    }
    let grant = match c.p.objects.primary_token_access() {
        Some(profile) => {
            if c.p.objects.primary_token_app_container().is_none() {
                return Err(c.unsupported("primary-token subject is not captured"));
            }
            match profile.grant(desired) {
                Ok(grant) => grant,
                Err(status) => return failure(c, output, status),
            }
        }
        None if super::super::gameos::enabled(c) && desired == 8 => desired,
        None => return Err(c.unsupported("primary-token opening rights are not captured")),
    };
    // Successful native64 and WoW64 calls probe the complete HANDLE before
    // publication. No failed output access creates a guest object or handle.
    probe_write(c, output, c.psize() as usize)?;
    let inherit = attributes & OBJ_INHERIT != 0;
    let Some(handle) = c.p.objects.open_primary_token(grant, inherit) else {
        return failure(c, output, STATUS_INSUFFICIENT_RESOURCES);
    };
    if let Err(fault) = c.write_ptr(output, u64::from(handle)) {
        let _ = c.p.objects.close(u64::from(handle));
        return Err(fault.into());
    }
    Flow::ret(STATUS_SUCCESS.into())
}
