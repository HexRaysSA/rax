//! Native events use the same reference-counted objects as Win32 waits.
//! Kernel probe order and WoW64 conversion follow the recorded build29683
//! profile in docs/specifications/windows/native-events, not a host NT call.
use super::query::{guard_result, probe_write};
use crate::error::MemoryAccessKind;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

const ALL_ACCESS: u32 = 0x001F_0003;
const MODIFY_STATE: u32 = 2;

#[derive(Default)]
struct Attributes {
    root: u64,
    name: u64,
    flags: u32,
    security: u64,
    qos: u64,
}

/// Capture before publication, including output/attribute aliases. Native
/// OBJECT_ATTRIBUTES is 48 bytes aligned to 8; WoW64's conversion reads the
/// 24-byte structure unaligned and validates Length before output probing.
fn capture(c: &Ctx, address: u64) -> Result<Result<Attributes, u32>, ApiErr> {
    if address == 0 {
        return Ok(Ok(Attributes::default()));
    }
    let wow = c.arch() == WinArch::X86;
    let size = if wow { 24 } else { 48 };
    if !wow && address % 8 != 0 {
        return Ok(Err(STATUS_DATATYPE_MISALIGNMENT));
    }
    if wow && c.mem().u32(address)? != size as u32 {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    c.mem()
        .probe(address, size, MemoryAccessKind::Read)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: false,
        })?;
    if c.mem().u32(address)? != size as u32 {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    let ptr = c.psize();
    let root = if wow { 4 } else { 8 };
    let attrs = Attributes {
        root: c.read_ptr(address + root)?,
        name: c.read_ptr(address + root + ptr)?,
        flags: c.mem().u32(address + root + ptr * 2)?,
        security: c.read_ptr(address + if wow { 16 } else { 32 })?,
        qos: c.read_ptr(address + if wow { 20 } else { 40 })?,
    };
    // Conversion of named/security structures needs its own object-manager
    // contract. Never interpret an NT directory name as a Win32 Local name.
    if wow {
        supported_attributes(c, &attrs)?;
    }
    Ok(Ok(attrs))
}
fn supported_attributes(c: &Ctx, attrs: &Attributes) -> Result<(), ApiErr> {
    if attrs.name != 0 {
        return Err(c.unsupported("named NT event object namespace"));
    }
    if attrs.security != 0 {
        return Err(c.unsupported("NT event security descriptor"));
    }
    if attrs.qos != 0 {
        return Err(c.unsupported("NT event security quality of service"));
    }
    Ok(())
}

/// Mapping for a newly created process-local, one-principal event. Explicit
/// type/standard rights are masked to the valid event grant as measured.
/// This is not token, DACL, SACL, impersonation or cross-process authorization.
fn desired_access(c: &Ctx, access: u32) -> Result<u32, ApiErr> {
    if access & 0x0100_0000 != 0 {
        return Err(c.unsupported("NT event ACCESS_SYSTEM_SECURITY privilege"));
    }
    let mut grant = access & ALL_ACCESS;
    for (generic, specific) in [
        (0x8000_0000, 0x0002_0001),
        (0x4000_0000, 0x0002_0002),
        (0x2000_0000, 0x0012_0000),
        (0x1000_0000, ALL_ACCESS),
        (0x0200_0000, ALL_ACCESS),
    ] {
        if access & generic != 0 {
            grant |= specific;
        }
    }
    Ok(grant)
}

pub(super) fn create(c: &mut Ctx) -> ApiResult {
    let result = create_checked(c);
    guard_result(c, result)
}
fn create_checked(c: &mut Ctx) -> ApiResult {
    let (out, access, address, kind, initial) =
        (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.u32(3)?, c.u32(4)? as u8);
    let wow = c.arch() == WinArch::X86;
    let attrs = if wow {
        match capture(c, address)? {
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
        match capture(c, address)? {
            Ok(attrs) => attrs,
            Err(status) => return Flow::ret(status.into()),
        }
    };
    if wow {
        probe_write(c, out, 4)?;
    }
    let result = create_object(c, out, access, kind, initial, attrs);
    // WoW64 conversion copies its zero-initialized native HANDLE on kernel
    // validation failures, but not on conversion or output-probe failures.
    if wow
        && let Ok(Flow::Ret(crate::user::windows::hle::Value::Int(status))) = &result
        && (*status as u32 as i32) < 0
    {
        c.write_ptr(out, 0)?;
    }
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
    supported_attributes(c, &attrs)?;
    if attrs.root != 0 {
        return Flow::ret(STATUS_OBJECT_NAME_INVALID.into());
    }
    let grant = desired_access(c, access)?;
    let Some(id) = c.p.objects.try_create(Object::Event {
        manual: kind == 0,
        signaled: i32::from(initial),
    }) else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let Some(handle) = c.p.objects.open_access(id, attrs.flags & 2 != 0, grant) else {
        c.p.objects.release(id);
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    if let Err(fault) = c.write_ptr(out, u64::from(handle)) {
        let _ = c.p.objects.close(u64::from(handle));
        return Err(fault.into());
    }
    Flow::ret(0)
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
