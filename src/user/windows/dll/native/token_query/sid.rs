//! Guest SID size and copy operations.

use crate::user::windows::hle::{ApiErr, ApiResult, Arg::*, Conv::Stdcall, Ctx, Export, Flow};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::{
    error::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER},
    status::*,
    status_to_error,
};
use crate::user::windows::security;

// A synthetic account SID from a private domain for offline GameOS queries.
// It is only returned by TokenUser and does not create a security subject.
pub(super) const OFFLINE_GAMEOS_USER: &[u8] =
    b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00RAX\0GameOS\0\0\xe8\x03\x00\x00";

pub(in crate::user::windows::dll) static NTDLL_SID_EXPORTS: &[Export] = &[
    Export::func("RtlLengthSid", Stdcall, &[Ptr], rtl_length),
    Export::func("RtlCopySid", Stdcall, &[I32, Ptr, Ptr], rtl_copy),
    Export::func(
        "RtlConvertSidToUnicodeString",
        Stdcall,
        &[Ptr, Ptr, I32],
        convert_to_unicode,
    ),
    Export::func("RtlFreeUnicodeString", Stdcall, &[Ptr], free_unicode),
];

pub(in crate::user::windows::dll) static WIN32_SID_EXPORTS: &[Export] = &[
    Export::func("GetLengthSid", Stdcall, &[Ptr], win32_length),
    Export::func("CopySid", Stdcall, &[I32, Ptr, Ptr], win32_copy),
];

pub(in crate::user::windows::dll) static WELL_KNOWN_SID_EXPORTS: &[Export] = &[Export::func(
    "CreateWellKnownSid",
    Stdcall,
    &[I32, Ptr, Ptr, Ptr],
    create_well_known,
)];

fn create_well_known(c: &mut Ctx) -> ApiResult {
    let (kind, domain, output, size) = (c.u32(0)?, c.ptr(1)?, c.ptr(2)?, c.ptr(3)?);
    if size == 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let mut bytes = [0u8; 68];
    let mut count = 0;
    if domain != 0 {
        let domain_size = length(c, domain)?;
        if domain_size > bytes.len() || c.mem().u8(domain)? != 1 {
            return c.fail(ERROR_INVALID_PARAMETER, 0);
        }
        if matches!(kind, 38..=50) {
            bytes[..domain_size].copy_from_slice(&c.mem().bytes(domain, domain_size)?);
            count = bytes[1] as usize;
            if count == 15 {
                return c.fail(ERROR_INVALID_PARAMETER, 0);
            }
        }
    }
    bytes[0] = 1;
    // WELL_KNOWN_SID_TYPE identifiers 0 through 50, using the authority and
    // subauthorities from the Windows well-known SID table.
    let (authority, rid) = match kind {
        0..=2 => (kind as u8, Some(0)),
        3..=6 => (3, Some(kind - 3)),
        7 => (5, None),
        8..=11 => (5, Some(kind - 7)),
        12..=20 => (5, Some(kind - 6)),
        22..=24 => (5, Some(kind - 4)),
        25 => (5, Some(32)),
        26..=37 => {
            bytes[8..12].copy_from_slice(&32u32.to_le_bytes());
            count = 1;
            (
                5,
                Some(
                    [544, 545, 546, 547, 548, 549, 550, 551, 552, 554, 555, 556]
                        [(kind - 26) as usize],
                ),
            )
        }
        38..=50 if domain != 0 => (
            bytes[7],
            Some(
                [
                    500, 501, 502, 512, 513, 514, 515, 516, 517, 518, 519, 520, 553,
                ][(kind - 38) as usize],
            ),
        ),
        _ => return c.fail(ERROR_INVALID_PARAMETER, 0),
    };
    bytes[7] = authority;
    if let Some(rid) = rid {
        let offset = 8 + count * 4;
        bytes[offset..offset + 4].copy_from_slice(&rid.to_le_bytes());
        count += 1;
    }
    bytes[1] = count as u8;
    let required = 8 + count * 4;
    let capacity = c.mem().u32(size)? as usize;
    if capacity >= required && output != 0 {
        super::super::query::probe_write(c, output, required)?;
    }
    c.mem().w32(size, required as u32)?;
    if capacity < required {
        return c.fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    if output == 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    c.mem().wr(output, &bytes[..required])?;
    Flow::bool(true)
}

fn length(c: &Ctx, sid: u64) -> Result<usize, MemFault> {
    let count = sid.checked_add(1).ok_or(MemFault {
        addr: sid,
        write: false,
    })?;
    Ok(8 + usize::from(c.mem().u8(count)?) * 4)
}

fn rtl_length(c: &mut Ctx) -> ApiResult {
    Flow::ret(length(c, c.ptr(0)?)? as u64)
}

fn win32_length(c: &mut Ctx) -> ApiResult {
    c.set_last_error(0)?;
    rtl_length(c)
}

fn copy(c: &Ctx) -> Result<u32, ApiErr> {
    let (capacity, destination, source) = (c.u32(0)?, c.ptr(1)?, c.ptr(2)?);
    let length = length(c, source)?;
    if (capacity as usize) < length {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    // Windows uses memmove, so a destination overlapping the source is valid.
    let bytes = c.mem().bytes(source, length)?;
    c.mem().wr(destination, &bytes)?;
    Ok(STATUS_SUCCESS)
}

fn rtl_copy(c: &mut Ctx) -> ApiResult {
    Flow::ret(u64::from(copy(c)?))
}

fn win32_copy(c: &mut Ctx) -> ApiResult {
    let status = copy(c)?;
    if status == STATUS_SUCCESS {
        Flow::bool(true)
    } else {
        c.fail(status_to_error(status), 0)
    }
}

fn convert_to_unicode(c: &mut Ctx) -> ApiResult {
    let (output, sid, allocate) = (c.ptr(0)?, c.ptr(1)?, c.u32(2)? as u8 != 0);
    if sid == 0 {
        return Flow::ret(STATUS_INVALID_SID.into());
    }
    let size = length(c, sid)?;
    if size > 68 || c.mem().u8(sid)? != 1 {
        return Flow::ret(STATUS_INVALID_SID.into());
    }
    let bytes = c.mem().bytes(sid, size)?;
    let Some(text) = security::sid_text(&bytes) else {
        return Flow::ret(STATUS_INVALID_SID.into());
    };
    let units: Vec<_> = text.encode_utf16().collect();
    let length = (units.len() * 2) as u16;
    let maximum = length + 2;
    let width = c.psize();
    if allocate {
        super::super::query::probe_write(c, output, (2 * width) as usize)?;
        let heap = c.p.process_heap;
        let Some(buffer) = c.p.heaps.alloc(&mut c.p.vm, heap, maximum.into(), false) else {
            return Flow::ret(STATUS_NO_MEMORY.into());
        };
        let publish = || -> Result<(), MemFault> {
            c.mem().put_wstr(buffer, &units)?;
            c.mem().wptr(
                output,
                width,
                u64::from(length) | (u64::from(maximum) << 16),
            )?;
            c.mem().wptr(output + width, width, buffer)
        };
        if let Err(error) = publish() {
            let _ = c.p.heaps.free(heap, buffer);
            return Err(error.into());
        }
    } else {
        if c.mem().u16(output.wrapping_add(2))? <= length {
            return Flow::ret(STATUS_BUFFER_OVERFLOW.into());
        }
        let buffer = c.read_ptr(output.wrapping_add(width))?;
        c.mem().w16(output, length)?;
        if c.mem().u16(output.wrapping_add(2))? >= maximum {
            c.mem().put_wstr(buffer, &units)?;
        } else {
            c.mem().put_wunits(buffer, &units)?;
        }
    }
    Flow::ret(STATUS_SUCCESS.into())
}

fn free_unicode(c: &mut Ctx) -> ApiResult {
    let output = c.ptr(0)?;
    let width = c.psize();
    let buffer = c.read_ptr(output.wrapping_add(width))?;
    if buffer != 0 {
        super::super::query::probe_write(c, output, (2 * width) as usize)?;
        let _ = c.p.heaps.free(c.p.process_heap, buffer);
        c.mem().wr(output, &[0; 16][..(2 * width) as usize])?;
    }
    Flow::void()
}
