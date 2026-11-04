//! Section metadata with independently captured native/WoW64 copy-back order.
use super::query::{guard_result, probe_write};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

pub(super) fn query(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    guard_result(c, result)
}

struct Answer {
    status: u32,
    basic: Option<(u64, u32)>,
}
impl Answer {
    fn status(status: u32) -> Self {
        Self {
            status,
            basic: None,
        }
    }
}

fn capture(c: &Ctx, handle: u64, class: u32) -> Result<Answer, ApiErr> {
    let object = match c.p.objects.get(handle) {
        Some(
            object @ (Object::FileSection(_)
            | Object::ImageSection(_)
            | Object::DataSection(_)
            | Object::Mapping { .. }),
        ) => object,
        Some(_) => return Ok(Answer::status(STATUS_OBJECT_TYPE_MISMATCH)),
        None if handle == c.arch().ptr(u64::MAX) || handle == c.arch().ptr(u64::MAX - 1) => {
            return Ok(Answer::status(STATUS_OBJECT_TYPE_MISMATCH));
        }
        None => return Ok(Answer::status(STATUS_INVALID_HANDLE)),
    };
    if c.p.objects.access(handle).unwrap_or(0) & 1 == 0 {
        return Ok(Answer::status(STATUS_ACCESS_DENIED));
    }
    if class != 0 {
        return if matches!(object, Object::ImageSection(_)) {
            Err(c.unsupported(format!("NtQuerySection image information class {class}")))
        } else {
            Ok(Answer::status(STATUS_SECTION_NOT_IMAGE))
        };
    }
    let (size, attributes) = match object {
        Object::FileSection(section) => (section.size, 0x00800000),
        Object::ImageSection(section) => (section.size, section.attributes),
        Object::Mapping {
            size, attributes, ..
        } => (*size, *attributes),
        Object::DataSection(_) => {
            return Err(c.unsupported(
                "selected data-section basic allocation attributes were not captured",
            ));
        }
        _ => unreachable!("typed Section"),
    };
    Ok(Answer {
        status: STATUS_SUCCESS,
        basic: Some((size, attributes)),
    })
}

fn checked(c: &mut Ctx) -> ApiResult {
    let (handle, class, output, length, returned) =
        (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.ptr(3)?, c.ptr(4)?);
    let wow = c.arch() == WinArch::X86;
    let returned = if wow {
        compatibility_destination(c, returned)
    } else {
        returned
    };
    if !wow {
        if length != 0 {
            // NtQuerySection uses ULONG alignment, including native64 output.
            if output % 4 != 0 {
                return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
            }
            let bytes =
                usize::try_from(length).map_err(|_| crate::user::windows::memory::MemFault {
                    addr: output,
                    write: true,
                })?;
            probe_write(c, output, bytes)?;
        }
        if returned != 0 {
            probe_write(c, returned, c.psize() as usize)?;
        }
    }
    // Native supports class3; the measured WoW64 converter ends at class2.
    let (required, delta) = match (wow, class) {
        (true, 0) => (16, 8u32),
        (true, 1) => (48, 16),
        (true, 2) => (4, 4),
        (false, 0) => (24, 0),
        (false, 1) => (64, 0),
        (false, 2 | 3) => (8, 0),
        _ => return Flow::ret(STATUS_INVALID_INFO_CLASS.into()),
    };
    let answer = if wow && output == 0 && length != 0 {
        Answer::status(STATUS_ACCESS_VIOLATION)
    } else if length < required {
        Answer::status(STATUS_INFO_LENGTH_MISMATCH)
    } else {
        capture(c, handle, class)?
    };
    if let Some((size, attributes)) = answer.basic {
        let mut bytes = [0u8; 24];
        let width = c.psize() as usize;
        bytes[width..width + 4].copy_from_slice(&attributes.to_le_bytes());
        let size_offset = if wow { 8 } else { 16 };
        bytes[size_offset..size_offset + 8].copy_from_slice(&size.to_le_bytes());
        c.mem().wr(output, &bytes[..required as usize])?;
    }
    if returned != 0 {
        if wow {
            // The thunk subtracts its layout delta even when native failure
            // left the private native ReturnLength at zero. A late caller
            // store can fail after successfully publishing the basic record.
            let value = if answer.status == 0 {
                required as u32
            } else {
                0u32.wrapping_sub(delta)
            };
            c.mem().w32(returned, value)?;
        } else if answer.status == 0 {
            c.write_ptr(returned, required)?;
        }
    }
    Flow::ret(answer.status.into())
}

fn compatibility_destination(c: &mut Ctx, address: u64) -> u64 {
    if address == 0 {
        return 0;
    }
    if let Err(fault) = probe_write(c, address, 4) {
        // The captured converter discards an absent or guarded destination;
        // a mapped read-only destination remains a late copy-back failure.
        if c.p.vm.take_guard(fault.addr) || c.p.vm.allocation(fault.addr).is_none() {
            return 0;
        }
    }
    address
}
