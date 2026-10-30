//! Open guest-owned events through the measured NT object-manager contract.
use super::super::named_object::{self, Checked, Failure, attributes, finish_with, status};
use super::super::object_create;
use super::super::query::probe_write;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

const ALL_ACCESS: u32 = 0x001F_0003;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const SYSTEM_SECURITY: u32 = 0x0100_0000;
const ALLOWED_ATTRIBUTES: u32 = 0x1ED2;

pub(in super::super) fn open(c: &mut Ctx) -> ApiResult {
    let result = open_checked(c);
    finish_with(c, result, c.arch() == WinArch::X86)
}

fn open_checked(c: &mut Ctx) -> Checked<u32> {
    let (output, desired, address) = (c.ptr(0)?, c.u32(1)?, c.ptr(2)?);
    let wow = c.arch() == WinArch::X86;
    if !wow {
        probe_write(c, output, c.psize() as usize)?;
    }
    let (captured, pending_name) = attributes::capture_event_open(c, address, wow)?;
    if wow {
        probe_write(c, output, 4)?;
    }
    let result = open_object(c, desired, captured, pending_name);
    let (code, handle) = match result {
        Ok(handle) => (STATUS_SUCCESS, Some(handle)),
        Err(Failure::Status(code)) => (code, None),
        Err(error) => return Err(error),
    };
    // The compatibility thunk copies a zero native HANDLE on kernel errors.
    // Attribute-conversion faults and unsupported policy never reach this copy.
    if handle.is_some() || wow {
        if let Err(fault) = c.write_ptr(output, handle.map_or(0, u64::from)) {
            if let Some(handle) = handle {
                let _ = c.p.objects.close(u64::from(handle));
            }
            return Err(fault.into());
        }
    }
    Ok(code)
}

fn open_object(
    c: &mut Ctx,
    desired: u32,
    attrs: Option<attributes::Attributes>,
    pending_name: Option<u32>,
) -> Checked<u32> {
    let attrs = attrs.ok_or(Failure::Status(STATUS_INVALID_PARAMETER))?;
    if attrs.flags & !0x1EF2 != 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    if let Some(code) = pending_name {
        return status(code);
    }
    if attrs.flags & !ALLOWED_ATTRIBUTES != 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    attributes::supported(c, &attrs, "event")?;
    let Some(name) = named_object::name(c, &attrs, true, "event")? else {
        return status(STATUS_OBJECT_PATH_SYNTAX_BAD);
    };
    let id =
        c.p.objects
            .by_native_name(&name)
            .ok_or(Failure::Status(STATUS_OBJECT_NAME_NOT_FOUND))?;
    if !matches!(c.p.objects.obj(id), Some(Object::Event { .. })) {
        return status(STATUS_OBJECT_TYPE_MISMATCH);
    }
    let requested = desired & 0x0FFF_FFFF;
    // Object-manager illegal bits precede privilege checks. Other unsupported
    // object-specific bits are denied rather than silently removed by mapping.
    if requested & !0x031F_FFFF != 0 {
        return status(STATUS_ACCESS_DENIED);
    }
    let grant = object_create::desired_access(c, desired, "event")?;
    if requested & !(ALL_ACCESS | MAXIMUM_ALLOWED | SYSTEM_SECURITY) != 0 || grant == 0 {
        return status(STATUS_ACCESS_DENIED);
    }
    c.p.objects
        .open_access(id, attrs.flags & 2 != 0, grant)
        .ok_or(Failure::Status(STATUS_INSUFFICIENT_RESOURCES))
}
