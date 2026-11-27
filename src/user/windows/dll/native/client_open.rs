//! Native and WoW64 capture of handle outputs, attributes and client IDs.
use super::query::probe_write;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::ObjId;

pub(super) struct ClientOpen {
    pub output: u64,
    pub attributes_present: bool,
    pub desired: u32,
    pub name: u64,
    pub flags: u32,
    pub client: Option<(u64, u64)>,
}

struct Attributes {
    name: u64,
    flags: u32,
}

/// The thunk widens pointed-to headers before the kernel sees the output.
/// The native entries ignore RootDirectory, Length, SD and QoS. Native64
/// reads only through Attributes (28 bytes), with four-byte input alignment.
fn attributes(c: &Ctx, pointer: u64, wow: bool) -> Result<Result<Attributes, u32>, ApiErr> {
    if wow && pointer == 0 {
        return Ok(Ok(Attributes { name: 0, flags: 0 }));
    }
    if !wow && pointer % 4 != 0 {
        return Ok(Err(STATUS_DATATYPE_MISALIGNMENT));
    }
    if wow {
        if c.mem().u32(pointer)? != 24 {
            return Ok(Err(STATUS_INVALID_PARAMETER));
        }
        let data = c.mem().bytes(pointer, 24)?;
        let at = |offset| {
            u64::from(u32::from_le_bytes(
                data[offset..offset + 4].try_into().unwrap(),
            ))
        };
        let name = at(8);
        if name != 0 {
            c.mem().bytes(name, 8)?;
        }
        let security = at(16);
        let qos = at(20);
        if qos != 0 {
            c.mem().bytes(qos, 12)?;
        }
        if security != 0 {
            c.mem().bytes(security, 20)?;
        }
        Ok(Ok(Attributes {
            name,
            flags: at(12) as u32,
        }))
    } else {
        // Do not probe ignored trailing fields or the whole nominal structure.
        if pointer > c.p.vm.high().saturating_sub(28) {
            return Ok(Err(STATUS_ACCESS_VIOLATION));
        }
        let name = c.mem().u64(pointer + 16)?;
        let flags = c.mem().u32(pointer + 24)?;
        Ok(Ok(Attributes { name, flags }))
    }
}

pub(super) fn capture(c: &Ctx) -> Result<Result<ClientOpen, u32>, ApiErr> {
    let (output, desired, oa, cid) = (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.ptr(3)?);
    let wow = c.arch() == WinArch::X86;
    if !wow {
        probe_write(c, output, 8)?;
    }
    let attrs = match attributes(c, oa, wow)? {
        Ok(attrs) => attrs,
        Err(status) => return Ok(Err(status)),
    };
    let client = if cid == 0 {
        None
    } else {
        if !wow && cid % 4 != 0 {
            return Ok(Err(STATUS_DATATYPE_MISALIGNMENT));
        }
        let bytes = c.mem().bytes(cid, 2 * c.psize() as usize)?;
        let read = |offset| {
            if wow {
                u64::from(u32::from_le_bytes(
                    bytes[offset..offset + 4].try_into().unwrap(),
                ))
            } else {
                u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
            }
        };
        Some((read(0), read(c.psize() as usize)))
    };
    if wow {
        probe_write(c, output, 4)?;
    }
    Ok(Ok(ClientOpen {
        output,
        attributes_present: oa != 0,
        desired,
        name: attrs.name,
        flags: attrs.flags,
        client,
    }))
}

pub(super) fn publish(c: &mut Ctx, output: u64, id: ObjId, flags: u32, grant: u32) -> ApiResult {
    let Some(handle) = c.p.objects.open_access(id, flags & 2 != 0, grant) else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    if let Err(fault) = c.write_ptr(output, u64::from(handle)) {
        let _ = c.p.objects.close(u64::from(handle));
        return Err(fault.into());
    }
    Flow::ret(STATUS_SUCCESS.into())
}
