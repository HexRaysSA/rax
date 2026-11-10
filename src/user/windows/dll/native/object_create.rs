//! Measured object-manager mechanics shared by events and completion ports.
use crate::error::MemoryAccessKind;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

const ALL_ACCESS: u32 = 0x001F_0003;

#[derive(Default)]
pub(super) struct Attributes {
    pub(super) root: u64,
    pub(super) name: u64,
    pub(super) flags: u32,
    pub(super) security: u64,
    pub(super) qos: u64,
}

/// Capture before publication, including output/attribute aliases. Native
/// OBJECT_ATTRIBUTES is 48 bytes aligned to 8; WoW64's conversion reads the
/// 24-byte structure unaligned and validates Length before output probing.
pub(super) fn capture(
    c: &Ctx,
    address: u64,
    kind: &str,
) -> Result<Result<Attributes, u32>, ApiErr> {
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
        supported_attributes(c, &attrs, kind)?;
    }
    Ok(Ok(attrs))
}

pub(super) fn supported_attributes(c: &Ctx, attrs: &Attributes, kind: &str) -> Result<(), ApiErr> {
    if attrs.name != 0 {
        return Err(c.unsupported(format!("named NT {kind} object namespace")));
    }
    if attrs.security != 0 {
        return Err(c.unsupported(format!("NT {kind} security descriptor")));
    }
    if attrs.qos != 0 {
        return Err(c.unsupported(format!("NT {kind} security quality of service")));
    }
    Ok(())
}

/// The measured mappings for new process-local, one-principal events and
/// completion ports coincide. This is not token, DACL, SACL, impersonation or
/// cross-process authorization; ACCESS_SYSTEM_SECURITY remains unsupported.
pub(super) fn desired_access(c: &Ctx, access: u32, kind: &str) -> Result<u32, ApiErr> {
    if access & 0x0100_0000 != 0 {
        return Err(c.unsupported(format!("NT {kind} ACCESS_SYSTEM_SECURITY privilege")));
    }
    Ok(map_access(access))
}

pub(super) fn map_access(access: u32) -> u32 {
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
    grant
}

/// Publish a real guest object and handle. Failure rolls back either resource.
pub(super) fn publish(c: &mut Ctx, out: u64, inherit: bool, grant: u32, obj: Object) -> ApiResult {
    let Some(id) = c.p.objects.try_create(obj) else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let Some(handle) = c.p.objects.open_access(id, inherit, grant) else {
        c.p.objects.release(id);
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    if let Err(fault) = c.write_ptr(out, u64::from(handle)) {
        let _ = c.p.objects.close(u64::from(handle));
        return Err(fault.into());
    }
    Flow::ret(0)
}

/// WoW64 copies a zero native HANDLE on kernel validation failures, after
/// conversion and the destination probe. Faults and unsupported policy do not
/// reach that publication point.
pub(super) fn wow_failure(c: &Ctx, out: u64, result: &ApiResult) -> Result<(), ApiErr> {
    if c.arch() == WinArch::X86
        && let Ok(Flow::Ret(crate::user::windows::hle::Value::Int(status))) = result
        && (*status as u32 as i32) < 0
    {
        c.write_ptr(out, 0)?;
    }
    Ok(())
}
