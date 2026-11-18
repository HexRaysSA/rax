//! Guest-memory conversion and captured-subject NtAccessCheck dispatch.
use super::query::write_guard_result;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use crate::user::windows::security::{self, Descriptor, Mapping, Subject};
use std::sync::Arc;

struct Captured {
    owner: Vec<u8>,
    dacl: Option<Vec<u8>>,
}

enum Capture {
    Descriptor(Captured),
    Status(u32),
}

fn sid(c: &Ctx, address: u64) -> Result<Vec<u8>, ApiErr> {
    let header = c.mem().bytes(address, 8)?;
    if header[0] != 1 || header[1] > 15 {
        return Err(c.unsupported("unmodeled malformed access-check SID"));
    }
    Ok(c.mem().bytes(address, 8 + usize::from(header[1]) * 4)?)
}

fn acl(c: &Ctx, address: u64) -> Result<Vec<u8>, ApiErr> {
    let header = c.mem().bytes(address, 8)?;
    let bytes = usize::from(u16::from_le_bytes([header[2], header[3]]));
    if bytes < 8 {
        return Err(c.unsupported("unmodeled malformed access-check ACL extent"));
    }
    Ok(c.mem().bytes(address, bytes)?)
}

fn capture(c: &Ctx, address: u64, wow_header: Option<&[u8]>) -> Result<Capture, ApiErr> {
    if address == 0 {
        return Ok(Capture::Status(STATUS_INVALID_SECURITY_DESCR));
    }
    if address % 4 != 0 {
        return Ok(Capture::Status(STATUS_DATATYPE_MISALIGNMENT));
    }
    let prefix = if let Some(header) = wow_header {
        header.to_vec()
    } else {
        c.mem().bytes(address, 20)?
    };
    let control = u16::from_le_bytes([prefix[2], prefix[3]]);
    if prefix[0] != 1 {
        return Err(c.unsupported("unmodeled access-check descriptor revision"));
    }
    let relative = control & 0x8000 != 0;
    let wide = !relative && c.arch() != WinArch::X86;
    let header = if wide {
        c.mem().bytes(address, 40)?
    } else {
        prefix
    };
    let mut pointers = [0u64; 4];
    for (index, pointer) in pointers.iter_mut().enumerate() {
        let start = if wide { 8 + index * 8 } else { 4 + index * 4 };
        let value = if wide {
            u64::from_le_bytes(header[start..start + 8].try_into().unwrap())
        } else {
            u64::from(u32::from_le_bytes(
                header[start..start + 4].try_into().unwrap(),
            ))
        };
        *pointer = if relative && value != 0 {
            address
                .checked_add(value)
                .ok_or_else(|| c.unsupported("relative access-check descriptor pointer overflow"))?
        } else {
            value
        };
    }
    let owner = if pointers[0] != 0 {
        Some(sid(c, pointers[0])?)
    } else {
        None
    };
    let group = if pointers[1] != 0 {
        Some(sid(c, pointers[1])?)
    } else {
        None
    };
    let dacl = if control & 4 != 0 && pointers[3] != 0 {
        Some(acl(c, pointers[3])?)
    } else {
        None
    };
    if owner.is_none() || group.is_none() {
        return Ok(Capture::Status(STATUS_INVALID_SECURITY_DESCR));
    }
    if control & !0x800F != 0 || header[1] != 0 {
        return Err(c.unsupported("unmodeled access-check descriptor controls or SACL"));
    }
    Ok(Capture::Descriptor(Captured {
        owner: owner.unwrap(),
        dacl,
    }))
}

fn subject(c: &Ctx, token: u64) -> Result<Result<Arc<Subject>, u32>, ApiErr> {
    if token == c.arch().ptr(u64::MAX - 4) {
        return Ok(Err(STATUS_NO_TOKEN));
    }
    if token == c.arch().ptr(u64::MAX - 3) || token == c.arch().ptr(u64::MAX - 5) {
        return c
            .p
            .objects
            .primary_token_subject()
            .map(Ok)
            .ok_or_else(|| c.unsupported("primary access-check subject is not captured"));
    }
    if token == c.arch().ptr(u64::MAX) || token == c.arch().ptr(u64::MAX - 1) {
        return Ok(Err(STATUS_OBJECT_TYPE_MISMATCH));
    }
    match c.p.objects.get(token) {
        None => Ok(Err(STATUS_INVALID_HANDLE)),
        Some(
            Object::PrimaryToken
            | Object::ImpersonationToken(_)
            | Object::GuestImpersonationToken { .. },
        ) if c.p.objects.access(token).unwrap_or(0) & 8 == 0 => Ok(Err(STATUS_ACCESS_DENIED)),
        Some(Object::PrimaryToken) => Ok(Err(STATUS_NO_IMPERSONATION_TOKEN)),
        Some(Object::ImpersonationToken(subject)) => Ok(Ok(subject.clone())),
        // Native NtAccessCheck requires at least SecurityIdentification, after
        // validating TOKEN_QUERY on the supplied guest handle.
        Some(Object::GuestImpersonationToken { level: 0, .. }) => {
            Ok(Err(STATUS_BAD_IMPERSONATION_LEVEL))
        }
        Some(Object::GuestImpersonationToken { subject, .. }) => Ok(Ok(subject.clone())),
        Some(Object::Opaque("Token")) => {
            Err(c.unsupported("opaque access-check token has no captured subject"))
        }
        Some(_) => Ok(Err(STATUS_OBJECT_TYPE_MISMATCH)),
    }
}

pub(super) fn access(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    write_guard_result(c, result)
}

fn checked(c: &mut Ctx) -> ApiResult {
    let (descriptor, token, desired, generic, privileges, length_ptr, granted, status) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.u32(2)?,
        c.ptr(3)?,
        c.ptr(4)?,
        c.ptr(5)?,
        c.ptr(6)?,
        c.ptr(7)?,
    );
    // The WoW64 wrapper captures a non-NULL input header before entering the
    // native service. Native64 reads it only after admitting the token.
    let wow_header = if c.arch() == WinArch::X86 && descriptor != 0 {
        Some(c.mem().bytes(descriptor, 20)?)
    } else {
        None
    };
    let capacity = c.mem().u32(length_ptr)?;
    if capacity >= 20 && privileges != 0 {
        c.mem().w32(privileges, 0)?;
    }
    let raw_mapping = c.mem().bytes(generic, 16)?;
    let mut values = [0; 4];
    for (value, bytes) in values.iter_mut().zip(raw_mapping.chunks_exact(4)) {
        *value = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    if desired & 0xF000_0000 != 0 {
        return Flow::ret(STATUS_GENERIC_NOT_MAPPED.into());
    }
    let subject = match subject(c, token)? {
        Ok(subject) => subject,
        Err(status) => return Flow::ret(status.into()),
    };
    let captured = match capture(c, descriptor, wow_header.as_deref())? {
        Capture::Descriptor(descriptor) => descriptor,
        Capture::Status(status) => return Flow::ret(status.into()),
    };
    let result = security::evaluate(
        &subject,
        Descriptor {
            owner: &captured.owner,
            dacl: captured.dacl.as_deref(),
        },
        Mapping(values),
        desired,
    )
    .map_err(|reason| c.unsupported(reason))?;
    if result.write_header {
        if capacity < result.required_bytes() {
            c.mem().w32(length_ptr, result.required_bytes())?;
            return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
        }
        c.mem().wr(privileges, &result.privilege_bytes())?;
    }
    // Final status precedes the granted mask, including exact aliases.
    c.mem().w32(status, result.status)?;
    c.mem().w32(granted, result.granted)?;
    Flow::ret(STATUS_SUCCESS.into())
}
