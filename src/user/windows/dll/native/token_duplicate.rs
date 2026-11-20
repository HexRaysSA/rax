//! Installed token duplication for the guest's immutable primary subject.

use super::query::{probe_write, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

const TOKEN_DUPLICATE: u32 = 2;
const TOKEN_IMPERSONATE_QUERY: u32 = 0x0c;
const TOKEN_IMPERSONATION: u32 = 2;
const OBJ_INHERIT: u32 = 2;
const OBJ_KERNEL_HANDLE: u32 = 0x200;
const MEASURED_ATTRIBUTES: u32 =
    OBJ_INHERIT | 0x20 | 0x40 | 0x80 | OBJ_KERNEL_HANDLE | 0x400 | 0x800 | 0x1000 | 0x10000;

pub(super) fn duplicate(c: &mut Ctx) -> ApiResult {
    let arch = c.arch();
    let Some(runtime) = c.p.native.as_ref().filter(|runtime| {
        (runtime.version.major, runtime.version.minor) == (10, 0)
            && runtime.object_namespace.native_machine == Some(arch.machine())
    }) else {
        return Err(c.unsupported("unmeasured installed NtDuplicateToken profile"));
    };
    let stock_request_only = match (arch, runtime.version.build) {
        (WinArch::Arm64, 29708) => false,
        (WinArch::X64, 20348 | 26100) | (WinArch::Arm64, 26200) => true,
        _ => return Err(c.unsupported("unmeasured installed NtDuplicateToken profile")),
    };
    let result = checked(c, stock_request_only);
    write_guard_result(c, result)
}

fn checked(c: &mut Ctx, stock_request_only: bool) -> ApiResult {
    let (source, desired, oa, effective, kind, output) = (
        c.ptr(0)?,
        c.u32(1)?,
        c.ptr(2)?,
        c.u32(3)? as u8,
        c.u32(4)?,
        c.ptr(5)?,
    );
    if stock_request_only
        && (desired != TOKEN_IMPERSONATE_QUERY
            || oa == 0
            || effective != 0
            || kind != TOKEN_IMPERSONATION
            || output == 0)
    {
        return Err(c.unsupported("unmeasured installed NtDuplicateToken request"));
    }
    if !matches!(kind, 1 | TOKEN_IMPERSONATION) {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let (mut attributes, mut level, mut inner_effective) = (0, 0, 0);
    if oa != 0 {
        if oa % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        let mut header = [0; 48];
        c.mem().rd(oa, &mut header)?;
        let word = |offset| u32::from_le_bytes(header[offset..offset + 4].try_into().unwrap());
        let pointer = |offset| u64::from_le_bytes(header[offset..offset + 8].try_into().unwrap());
        if word(0) != 48 {
            return Flow::ret(STATUS_INVALID_PARAMETER.into());
        }
        attributes = word(24);
        if attributes & !(MEASURED_ATTRIBUTES | 0x10) != 0 {
            return Flow::ret(STATUS_INVALID_PARAMETER.into());
        }
        if pointer(8) != 0 || pointer(16) != 0 || pointer(32) != 0 {
            return Err(c.unsupported("named or security-descriptor token duplication"));
        }
        let quality = pointer(40);
        if stock_request_only && (attributes != 0 || quality == 0) {
            return Err(c.unsupported("unmeasured installed NtDuplicateToken attributes"));
        }
        if quality != 0 {
            if quality % 4 != 0 {
                return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
            }
            let mut qos = [0; 12];
            c.mem().rd(quality, &mut qos)?;
            if u32::from_le_bytes(qos[..4].try_into().unwrap()) != 12 {
                return Flow::ret(STATUS_INVALID_PARAMETER.into());
            }
            level = u32::from_le_bytes(qos[4..8].try_into().unwrap());
            if level > 3 {
                return Flow::ret(STATUS_BAD_IMPERSONATION_LEVEL.into());
            }
            if qos[8] > 1 {
                return Err(c.unsupported("unmeasured token context-tracking mode"));
            }
            inner_effective = qos[9];
            if stock_request_only && (level != 2 || qos[8] != 1 || inner_effective != 0) {
                return Err(c.unsupported("unmeasured installed NtDuplicateToken QoS"));
            }
        }
    }
    if source == u64::MAX || source == u64::MAX - 1 {
        return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
    }
    match c.p.objects.get(source) {
        Some(Object::PrimaryToken) => {}
        Some(
            Object::GuestImpersonationToken { .. }
            | Object::ImpersonationToken(_)
            | Object::Opaque("Token"),
        ) => return Err(c.unsupported("duplicate non-primary token")),
        Some(_) => return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into()),
        None => return Flow::ret(STATUS_INVALID_HANDLE.into()),
    }
    let source_grant = c.p.objects.access(source).unwrap_or(0);
    if source_grant & TOKEN_DUPLICATE == 0 {
        return Flow::ret(STATUS_ACCESS_DENIED.into());
    }
    if attributes & 0x10 != 0 {
        return Err(c.unsupported("permanent guest token objects"));
    }
    if kind != TOKEN_IMPERSONATION || effective != 0 || inner_effective != 0 {
        return Err(c.unsupported("primary or effective-only guest token duplication"));
    }
    let Some(subject) = c.p.objects.primary_token_subject() else {
        return Err(c.unsupported("primary subject for token duplication is not captured"));
    };
    let Some(access) = c.p.objects.primary_token_access() else {
        return Err(c.unsupported("primary access for token duplication is not captured"));
    };
    let grant = if desired == 0 {
        source_grant
    } else {
        match access.grant(desired) {
            Ok(grant) => grant,
            Err(status) => return Flow::ret(status.into()),
        }
    };
    probe_write(c, output, 8)?;
    let Some(object) =
        c.p.objects
            .try_create(Object::GuestImpersonationToken { subject, level })
    else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let Some(handle) =
        c.p.objects
            .open_access(object, attributes & OBJ_INHERIT != 0, grant)
    else {
        c.p.objects.release(object);
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    if let Err(fault) = c.write_ptr(output, handle.into()) {
        let _ = c.p.objects.close(handle.into());
        return Err(fault.into());
    }
    Flow::ret(STATUS_SUCCESS.into())
}
