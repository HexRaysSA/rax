//! Six-pointer WNF query conversion over immutable selected state.
use super::query::{guard_result, probe_write};
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use crate::user::windows::wnf::{Name, Record};

pub(super) fn query(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    guard_result(c, result)
}

fn checked(c: &mut Ctx) -> ApiResult {
    let (input, type_ptr, explicit, stamp_ptr, output, length_ptr) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.ptr(2)?,
        c.ptr(3)?,
        c.ptr(4)?,
        c.ptr(5)?,
    );
    let name = c.mem().u64(input)?;
    let Some(parsed) = Name::decode(name) else {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    };
    let type_id = if type_ptr == 0 {
        None
    } else {
        Some(<[u8; 16]>::try_from(c.mem().bytes(type_ptr, 16)?).unwrap())
    };
    let capacity = c.mem().u32(length_ptr)?;
    probe_write(c, length_ptr, 4)?;
    probe_write(c, stamp_ptr, 4)?;
    if capacity != 0 {
        probe_write(c, output, capacity as usize)?;
    }
    if c.p.cfg.gameos_analysis
        && let Some(data) = super::super::gameos::wnf::runtime_state(name)
    {
        if explicit != 0 || type_id.is_some() {
            return Flow::ret(STATUS_INVALID_PARAMETER.into());
        }
        // No publisher exists in the offline profile. A subscription at
        // change stamp zero starts without an initial callback.
        c.mem().w32(stamp_ptr, 0)?;
        c.mem().w32(length_ptr, data.len() as u32)?;
        if (capacity as usize) < data.len() {
            return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
        }
        if !data.is_empty() {
            c.mem().wr(output, data)?;
        }
        return Flow::ret(STATUS_SUCCESS.into());
    }
    let queries = c.p.objects.wnf_queries().ok_or_else(|| {
        c.unsupported(format!(
            "WNF query-state metadata was not selected for {name:#018x}"
        ))
    })?;
    if explicit != 0 {
        match parsed.scope {
            0 | 4 => return Flow::ret(STATUS_INVALID_PARAMETER.into()),
            1 => {
                if c.mem().u32(explicit)? != queries.session {
                    return Err(c.unsupported("WNF query targets an uncaptured session"));
                }
            }
            2 => {
                let header = c.mem().bytes(explicit, 8)?;
                if header[0] != 1 || header[1] > 15 {
                    return Flow::ret(STATUS_INVALID_SID.into());
                }
                let sid = c.mem().bytes(explicit, 8 + 4 * usize::from(header[1]))?;
                let subject =
                    c.p.objects
                        .primary_token_subject()
                        .ok_or_else(|| c.unsupported("WNF user scope has no captured subject"))?;
                if sid != subject.user {
                    return Err(c.unsupported("WNF query targets an uncaptured user"));
                }
            }
            3 => {
                if explicit != c.arch().ptr(u64::MAX) {
                    if explicit == c.arch().ptr(u64::MAX - 1) {
                        return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
                    }
                    match c.p.objects.get(explicit) {
                        None => return Flow::ret(STATUS_INVALID_HANDLE.into()),
                        Some(Object::Process { pid, .. }) if *pid == c.p.pid => {}
                        Some(Object::Process { .. }) => {
                            return Err(
                                c.unsupported("WNF scope targets a different guest process")
                            );
                        }
                        Some(_) => return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into()),
                    }
                    // Native scope resolution accepts a process handle with
                    // granted access zero; it does not impose a query-right gate.
                }
            }
            _ => return Err(c.unsupported("unmeasured explicit WNF physical-machine scope")),
        }
    }
    let Some((definition, record)) = queries.get(name) else {
        if parsed.lifetime != 0 {
            return Err(c.unsupported("WNF nonprovisioned lifetime has no guest-owned state"));
        }
        return Flow::ret(STATUS_OBJECT_NAME_NOT_FOUND.into());
    };
    let data = match record {
        Record::Status(status) => return Flow::ret(u64::from(*status)),
        Record::Unavailable(reason) => return Err(c.unsupported(*reason)),
        Record::Data(data) => data,
    };
    if definition.type_id.is_some() && definition.type_id != type_id {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let bytes = data.bytes.len() as u32;
    c.mem().w32(stamp_ptr, data.stamp)?;
    c.mem().w32(length_ptr, bytes)?;
    if capacity < bytes {
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    if bytes != 0 {
        c.mem().wr(output, &data.bytes)?;
    }
    Flow::ret(STATUS_SUCCESS.into())
}
