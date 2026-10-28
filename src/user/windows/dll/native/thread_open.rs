//! Guest thread identity, opening rights and measured native/WoW64 capture order.
use super::query::{guard_result, probe_write, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

pub(super) fn open(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    if c.arch() == WinArch::X86 {
        write_guard_result(c, result)
    } else {
        guard_result(c, result)
    }
}

struct Attributes {
    name: u64,
    flags: u32,
}

/// The thunk widens pointed-to headers before the kernel sees the output.
/// NtOpenThread itself ignores RootDirectory, Length, SD and QoS. Native64
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

fn checked(c: &mut Ctx) -> ApiResult {
    let (output, desired, oa, cid) = (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.ptr(3)?);
    let wow = c.arch() == WinArch::X86;
    if !wow {
        probe_write(c, output, 8)?;
    }
    let attrs = match attributes(c, oa, wow)? {
        Ok(attrs) => attrs,
        Err(status) => return Flow::ret(status.into()),
    };
    let client = if cid == 0 {
        None
    } else {
        if !wow && cid % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
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
        if oa == 0 {
            return Flow::ret(STATUS_ACCESS_VIOLATION.into());
        }
    }
    let Some((pid, tid)) = client.filter(|_| attrs.name == 0) else {
        return Flow::ret(STATUS_INVALID_PARAMETER_MIX.into());
    };
    if pid != 0 && pid != u64::from(c.p.pid) {
        return Flow::ret(STATUS_INVALID_CID.into());
    }
    // Exited objects remain discoverable while handles/waits retain them. The
    // current thread is absent from p.threads during dispatch, so that map is
    // neither the identity namespace nor the object lifetime authority.
    let Some(id) = c.p.objects.iter().find_map(|(id, object)| {
        matches!(object, Object::Thread { tid: target, .. } if u64::from(*target) == tid & !3)
            .then_some(id)
    }) else {
        return Flow::ret(STATUS_INVALID_CID.into());
    };
    if attrs.flags & 0xb0 != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let access =
        c.p.thread_access
            .as_ref()
            .map_err(|error| c.unsupported(format!("thread opening rights: {error}")))?;
    let grant = match access.grant(desired) {
        Ok(grant) => grant,
        Err(status) => return Flow::ret(status.into()),
    };
    let Some(handle) = c.p.objects.open_access(id, attrs.flags & 2 != 0, grant) else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    if let Err(fault) = c.write_ptr(output, u64::from(handle)) {
        let _ = c.p.objects.close(u64::from(handle));
        return Err(fault.into());
    }
    Flow::ret(STATUS_SUCCESS.into())
}
