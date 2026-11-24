//! Native events use the same reference-counted objects as Win32 waits.
//! Kernel probe order and WoW64 conversion follow the recorded build29683
//! profile in docs/specifications/windows/native-events, not a host NT call.
mod open;
pub(super) use open::open;

use super::object_create::{self, Attributes};
use super::query::{guard_result, probe_write};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use crate::user::windows::security::event::{EventSecurity, HEADER, MAX_ACL_SIZE};

const MODIFY_STATE: u32 = 2;

pub(super) fn create(c: &mut Ctx) -> ApiResult {
    let result = create_checked(c);
    guard_result(c, result)
}
fn create_checked(c: &mut Ctx) -> ApiResult {
    let (out, access, address, kind, initial) =
        (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.u32(3)?, c.u32(4)? as u8);
    let wow = c.arch() == WinArch::X86;
    if !wow {
        // PHANDLE accepts byte alignment, and its full guest pointer width is
        // probed before EventType or any attributes are inspected.
        probe_write(c, out, c.psize() as usize)?;
        if kind > 1 {
            return Flow::ret(STATUS_INVALID_PARAMETER.into());
        }
    }
    let attrs = match object_create::capture_fields(c, address)? {
        Ok(attrs) => attrs,
        Err(status) => return Flow::ret(status.into()),
    };
    let security = if wow {
        let security = capture_security(c, &attrs)?;
        probe_write(c, out, 4)?;
        security
    } else if attrs.flags & !0x1EF2 == 0 {
        capture_security(c, &attrs)?
    } else {
        None
    };
    let result = create_object(c, out, access, kind, initial, attrs, security);
    object_create::wow_failure(c, out, &result)?;
    result
}

fn capture_security(c: &Ctx, attrs: &Attributes) -> Result<Option<EventSecurity>, ApiErr> {
    if attrs.security == 0
        || attrs.root != 0
        || attrs.name != 0
        || attrs.qos != 0
        || attrs.flags != 0
    {
        object_create::supported_attributes(c, attrs, "event")?;
        return Ok(None);
    }
    let unsupported = || c.unsupported("NT event security descriptor");
    attrs
        .security
        .checked_add((HEADER.len() + MAX_ACL_SIZE - 1) as u64)
        .ok_or_else(unsupported)?;
    let dacl_addr = attrs.security + HEADER.len() as u64;
    let mut header = [0; HEADER.len()];
    c.mem().rd(attrs.security, &mut header)?;
    if header != HEADER {
        return Err(unsupported());
    }
    let mut acl = [0; MAX_ACL_SIZE];
    c.mem().rd(dacl_addr, &mut acl[..8])?;
    let size = usize::from(u16::from_le_bytes([acl[2], acl[3]]));
    if !matches!(size, 28 | MAX_ACL_SIZE) {
        return Err(unsupported());
    }
    c.mem().rd(dacl_addr + 8, &mut acl[8..size])?;
    // The guest has no thread-token attachment service. The installed
    // primary subject owns default owner/group selection for this event.
    let subject =
        c.p.objects
            .primary_token_subject()
            .ok_or_else(unsupported)?;
    EventSecurity::capture(&subject, &acl[..size])
        .map(Some)
        .ok_or_else(unsupported)
}

fn create_object(
    c: &mut Ctx,
    out: u64,
    access: u32,
    kind: u32,
    initial: u8,
    attrs: Attributes,
    security: Option<EventSecurity>,
) -> ApiResult {
    if kind > 1 || attrs.flags & !0x1EF2 != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if attrs.root != 0 {
        return Flow::ret(STATUS_OBJECT_NAME_INVALID.into());
    }
    let grant = object_create::desired_access(c, access, "event")?;
    let event = Object::Event {
        manual: kind == 0,
        signaled: i32::from(initial),
    };
    let inherit = attrs.flags & 2 != 0;
    if let Some(security) = security {
        let Some(id) = c.p.objects.try_create(event) else {
            return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
        };
        c.p.objects.set_event_security(id, security);
        object_create::publish_created(c, out, inherit, grant, id)
    } else {
        object_create::publish(c, out, inherit, grant, event)
    }
}

pub(super) fn set(c: &mut Ctx) -> ApiResult {
    state(c, 1)
}
pub(super) fn reset(c: &mut Ctx) -> ApiResult {
    state(c, 0)
}
fn state(c: &mut Ctx, value: i32) -> ApiResult {
    let result = state_checked(c, value);
    guard_result(c, result)
}
pub(super) fn clear(c: &mut Ctx) -> ApiResult {
    let result = (|| {
        let handle = c.ptr(0)?;
        state_for_handle(c, handle, 0, 0)
    })();
    guard_result(c, result)
}
fn state_checked(c: &mut Ctx, value: i32) -> ApiResult {
    let (handle, previous) = (c.ptr(0)?, c.ptr(1)?);
    state_for_handle(c, handle, previous, value)
}
fn state_for_handle(c: &mut Ctx, handle: u64, previous: u64, value: i32) -> ApiResult {
    if previous != 0 {
        probe_write(c, previous, 4)?;
    }
    // Object type is checked before the access grant. Pseudo process/thread
    // handles are valid objects, but never events.
    if handle == c.arch().ptr(u64::MAX) || handle == c.arch().ptr(u64::MAX - 1) {
        return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
    }
    let Some(object) = c.p.objects.get(handle) else {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    };
    if !matches!(object, Object::Event { .. }) {
        return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
    }
    if c.p.objects.access(handle).unwrap_or(0) & MODIFY_STATE == 0 {
        return Flow::ret(STATUS_ACCESS_DENIED.into());
    }
    let Some(Object::Event { signaled, .. }) = c.p.objects.get_mut(handle) else {
        unreachable!("checked event type")
    };
    let old = *signaled;
    *signaled = value;
    if previous != 0 {
        c.mem().w32(previous, old as u32)?;
    }
    Flow::ret(0)
}
