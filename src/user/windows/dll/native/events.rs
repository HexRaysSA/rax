//! Native events use the same reference-counted objects as Win32 waits.
//! Kernel probe order and WoW64 conversion follow the recorded build29683
//! profile in docs/specifications/windows/native-events, not a host NT call.
mod open;
pub(super) use open::open;

use super::object_create::{self, Attributes};
use super::query::{guard_result, probe_write};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

const MODIFY_STATE: u32 = 2;

pub(super) fn create(c: &mut Ctx) -> ApiResult {
    let result = create_checked(c);
    guard_result(c, result)
}
fn create_checked(c: &mut Ctx) -> ApiResult {
    let (out, access, address, kind, initial) =
        (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.u32(3)?, c.u32(4)? as u8);
    let wow = c.arch() == WinArch::X86;
    let attrs = if wow {
        match object_create::capture(c, address, "event")? {
            Ok(attrs) => attrs,
            Err(status) => return Flow::ret(status.into()),
        }
    } else {
        // PHANDLE accepts byte alignment, and its full guest pointer width is
        // probed before EventType or any attributes are inspected.
        probe_write(c, out, c.psize() as usize)?;
        if kind > 1 {
            return Flow::ret(STATUS_INVALID_PARAMETER.into());
        }
        match object_create::capture(c, address, "event")? {
            Ok(attrs) => attrs,
            Err(status) => return Flow::ret(status.into()),
        }
    };
    if wow {
        probe_write(c, out, 4)?;
    }
    let result = create_object(c, out, access, kind, initial, attrs);
    object_create::wow_failure(c, out, &result)?;
    result
}
fn create_object(
    c: &mut Ctx,
    out: u64,
    access: u32,
    kind: u32,
    initial: u8,
    attrs: Attributes,
) -> ApiResult {
    if kind > 1 || attrs.flags & !0x1EF2 != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    object_create::supported_attributes(c, &attrs, "event")?;
    if attrs.root != 0 {
        return Flow::ret(STATUS_OBJECT_NAME_INVALID.into());
    }
    let grant = object_create::desired_access(c, access, "event")?;
    object_create::publish(
        c,
        out,
        attrs.flags & 2 != 0,
        grant,
        Object::Event {
            manual: kind == 0,
            signaled: i32::from(initial),
        },
    )
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
fn state_checked(c: &mut Ctx, value: i32) -> ApiResult {
    let (handle, previous) = (c.ptr(0)?, c.ptr(1)?);
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
