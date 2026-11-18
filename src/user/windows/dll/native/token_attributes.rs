//! Measured six-argument native/WoW64 token security-attribute query.
use super::query::{guard_result, probe_write, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL,
    STATUS_DATATYPE_MISALIGNMENT, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_NO_TOKEN,
    STATUS_NOT_FOUND, STATUS_OBJECT_TYPE_MISMATCH,
};
use crate::user::windows::objects::Object;
use crate::user::windows::security::{
    Subject,
    token::attributes::{MAX_ATTRIBUTES, MAX_CAPTURE},
};
use std::sync::Arc;

pub(super) fn query(c: &mut Ctx) -> ApiResult {
    let mut copying = false;
    let result = checked(c, &mut copying);
    if copying {
        write_guard_result(c, result)
    } else {
        guard_result(c, result)
    }
}

fn subject(c: &Ctx, token: u64) -> Result<Arc<Subject>, u32> {
    let arch = c.arch();
    if token == arch.ptr(u64::MAX - 4) {
        return Err(STATUS_NO_TOKEN);
    }
    if token == arch.ptr(u64::MAX) || token == arch.ptr(u64::MAX - 1) {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    if token != arch.ptr(u64::MAX - 3) && token != arch.ptr(u64::MAX - 5) {
        match c.p.objects.get(token) {
            Some(Object::PrimaryToken) => {}
            Some(
                Object::ImpersonationToken(subject)
                | Object::GuestImpersonationToken { subject, .. },
            ) => {
                if c.p.objects.access(token).unwrap_or(0) & 8 == 0 {
                    return Err(STATUS_ACCESS_DENIED);
                }
                return Ok(subject.clone());
            }
            None => return Err(STATUS_INVALID_HANDLE),
            Some(Object::Opaque("Token")) => return Err(0),
            Some(_) => return Err(STATUS_OBJECT_TYPE_MISMATCH),
        }
        if c.p.objects.access(token).unwrap_or(0) & 8 == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
    }
    c.p.objects.primary_token_subject().ok_or(0)
}

fn descriptors(
    c: &Ctx,
    names: u64,
    count: u32,
    wow: bool,
) -> Result<Vec<u8>, crate::user::windows::hle::ApiErr> {
    // NULL is forwarded by the WoW converter. Its consistency rejection occurs
    // in native validation, after the caller ReturnLength probe.
    if count == 0 || names == 0 {
        return Ok(Vec::new());
    }
    let size = u64::from(count) * 2 * c.psize();
    if count as usize > MAX_ATTRIBUTES {
        // Do not allocate a guest-declared descriptor array. Preserve the
        // address fault first; bounded capture is an explicit frontier.
        c.mem()
            .probe(names, size as usize, crate::error::MemoryAccessKind::Read)
            .map_err(|fault| crate::user::windows::memory::MemFault {
                addr: fault.address,
                write: false,
            })?;
        return Err(c.unsupported("token security-attribute request exceeds 4096 names"));
    }
    debug_assert!(wow || names % 4 == 0);
    Ok(c.mem().bytes(names, size as usize)?)
}

fn checked(c: &mut Ctx, copying: &mut bool) -> ApiResult {
    let (token, names, count, output, length, returned) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.u32(2)?,
        c.ptr(3)?,
        c.u32(4)?,
        c.ptr(5)?,
    );
    let wow = c.arch() == WinArch::X86;
    let mut raw = if wow {
        descriptors(c, names, count, true)?
    } else {
        Vec::new()
    };
    if !wow {
        if (output == 0) != (length == 0) {
            return Flow::ret(STATUS_INVALID_PARAMETER.into());
        }
        if length != 0 {
            if output % 4 != 0 {
                return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
            }
            probe_write(c, output, length as usize)?;
        }
    }
    if returned % 4 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    probe_write(c, returned, 4)?;
    if (count != 0 && names == 0) || (!wow && count == 0 && names != 0) {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if !wow && count != 0 {
        if names % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        raw = descriptors(c, names, count, false)?;
    }
    let width = c.psize() as usize;
    let mut captured = Vec::with_capacity(count as usize);
    let mut captured_bytes = 0usize;
    for descriptor in raw.chunks_exact(2 * width) {
        let size = usize::from(u16::from_le_bytes([descriptor[0], descriptor[1]]));
        let mut pointer = [0; 8];
        pointer[..width].copy_from_slice(&descriptor[width..2 * width]);
        let address = u64::from_le_bytes(pointer);
        if address % 2 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        // MaximumLength is not a query bound. Native captures Length bytes,
        // including an odd final byte, before type/right/name validation.
        captured_bytes += size;
        if captured_bytes > MAX_CAPTURE {
            // Preserve a reached address/guard fault before declaring this
            // bounded capture unavailable. Never allocate the oversized name.
            c.mem()
                .probe(address, size, crate::error::MemoryAccessKind::Read)
                .map_err(|fault| crate::user::windows::memory::MemFault {
                    addr: fault.address,
                    write: false,
                })?;
            return Err(c.unsupported("token security-attribute names exceed 1 MiB"));
        }
        captured.push(c.mem().bytes(address, size)?);
    }
    let subject = match subject(c, token) {
        Ok(value) => value,
        Err(0) => return Err(c.unsupported("token security-attribute subject is not captured")),
        Err(status) => return Flow::ret(status.into()),
    };
    let attributes = subject
        .attributes
        .as_ref()
        .ok_or_else(|| c.unsupported("token security attributes are not captured"))?;
    if captured.iter().any(Vec::is_empty) {
        c.mem().w32(returned, 0)?;
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let upcase = c.p.registry.upcase_table();
    if count != 0 && upcase.len() != 65536 {
        return Err(c.unsupported("token security-attribute name folding is not captured"));
    }
    let mut selected = if count == 0 {
        attributes.all()
    } else {
        Vec::new()
    };
    for name in &captured {
        let units: Vec<_> = name
            .chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
            .collect();
        let found = if name.len() % 2 == 0 {
            attributes.find(&units, &upcase)
        } else {
            None
        };
        let Some(attribute) = found else {
            c.mem().w32(returned, 0)?;
            return Flow::ret(STATUS_NOT_FOUND.into());
        };
        selected.push(attribute);
    }
    let native = attributes
        .pack(&selected, 8, 0, MAX_CAPTURE)
        .ok_or_else(|| c.unsupported("token security-attribute result exceeds 1 MiB"))?;
    let needed = native.required;
    if length < needed {
        c.mem().w32(returned, needed)?;
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    if !wow && selected.is_empty() {
        // The measured empty native result publishes only its fixed header;
        // unlike nonempty packing it does not clear the supplied capacity.
        c.mem().wr(output, &native.bytes)?;
        c.mem().w32(returned, needed)?;
        return Flow::ret(0);
    }
    if wow {
        // Native ReturnLength is published before the converter first touches
        // caller output. A conversion fault leaves this native capacity.
        c.mem().w32(returned, needed)?;
        *copying = true;
    }
    // Native probes already covered the whole extent. WoW's first zero store
    // spans 16 bytes; a cross-page fault there leaves the output unchanged.
    let zeros = [0u8; 16];
    c.mem().wr(output, &zeros)?;
    if length <= 32 {
        c.mem().wr(output + u64::from(length - 16), &zeros)?;
    } else {
        let mut offset = (16 - output % 16) as usize;
        while offset < length as usize - 32 {
            c.mem().wr(output + offset as u64, &zeros)?;
            offset += 16;
        }
        for offset in [length - 32, length - 16] {
            c.mem().wr(output + u64::from(offset), &zeros)?;
        }
    }
    let packet = attributes
        .pack(&selected, width, output, length as usize)
        .ok_or_else(|| {
            c.unsupported("token security-attribute address or packed result exceeds its bounds")
        })?;
    // The packed header is published last, after names, values and pointers.
    let header = if width == 8 { 16 } else { 12 };
    c.mem()
        .wr(output + header as u64, &packet.bytes[header..])?;
    c.mem().wr(output, &packet.bytes[..header])?;
    c.mem()
        .w32(returned, if wow { packet.required } else { needed })?;
    Flow::ret(if packet.complete {
        0
    } else {
        u64::from(STATUS_BUFFER_OVERFLOW)
    })
}
