//! Bulk reads from one immutable guest key. Native64 captures after handle and
//! output probing; WoW64 widens caller entries before entering the native path.
use super::{Checked, Descriptor, Failure, finish, key, name, status, text, write_pages};
use crate::error::MemoryAccessKind;
use crate::user::windows::arch::WinArch;
use crate::user::windows::dll::native::query::probe_write;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::{
    STATUS_BUFFER_OVERFLOW, STATUS_DATATYPE_MISALIGNMENT, STATUS_GUARD_PAGE_VIOLATION,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
};

const CAPTURE_LIMIT: usize = 16 << 20;

struct Entry {
    descriptor: u64,
    captured_name: Option<Descriptor>,
    fields: [u32; 3],
}

pub(in super::super) fn query_multiple(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    finish(c, result)
}

fn checked(c: &mut Ctx) -> Checked<u32> {
    let (handle, entries, count, output, length, required) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.u32(2)?,
        c.ptr(3)?,
        c.ptr(4)?,
        c.ptr(5)?,
    );
    let wow = c.arch() == WinArch::X86;
    let stride = if wow { 16 } else { 24 };
    let mut captured = if wow {
        if u64::from(count) * stride > CAPTURE_LIMIT as u64 {
            // The measured thunk allocation failure publishes Win32 error 8
            // while retaining LastStatusValue and every caller destination.
            c.set_last_error(8)?;
            return status(STATUS_NO_MEMORY);
        }
        capture(c, entries, count, stride, true)?
    } else {
        Vec::new()
    };
    let result = native(
        c,
        handle,
        entries,
        count,
        output,
        length,
        required,
        &mut captured,
    );
    if !wow || matches!(&result, Err(Failure::Api(ApiErr::Unimplemented(_)))) {
        return result;
    }
    // The thunk copies metadata even after native failure. Consume a native
    // guard before copy-back so a later caller fault has its own precedence.
    let result = match result {
        Err(Failure::Api(ApiErr::Fault(fault))) if c.p.vm.take_guard(fault.addr) => {
            Ok(STATUS_GUARD_PAGE_VIOLATION)
        }
        result => result,
    };
    copy_fields(c, entries, stride, &captured)?;
    result
}

fn capture(c: &Ctx, entries: u64, count: u32, stride: u64, wow: bool) -> Checked<Vec<Entry>> {
    let bytes = u64::from(count) * stride;
    c.mem()
        .probe(entries, bytes as usize, MemoryAccessKind::Read)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: false,
        })?;
    if bytes > CAPTURE_LIMIT as u64 {
        return Err(c
            .unsupported("bulk registry entry capture exceeds 16 MiB")
            .into());
    }
    let mut captured = Vec::new();
    captured
        .try_reserve_exact(count as usize)
        .map_err(|_| Failure::Status(STATUS_NO_MEMORY))?;
    for index in 0..count {
        let address = entries + u64::from(index) * stride;
        let descriptor = c.read_ptr(address)?;
        let fields = [
            c.mem().u32(address + c.psize())?,
            c.mem().u32(address + c.psize() + 4)?,
            c.mem().u32(address + c.psize() + 8)?,
        ];
        let captured_name = if !wow || descriptor != 0 {
            Some(name(c, descriptor)?)
        } else {
            None
        };
        if !wow
            && captured_name
                .as_ref()
                .is_some_and(|name| name.length % 2 != 0)
        {
            return status(STATUS_INVALID_PARAMETER);
        }
        captured.push(Entry {
            descriptor,
            captured_name,
            fields,
        });
    }
    Ok(captured)
}

#[allow(clippy::too_many_arguments)]
fn native(
    c: &Ctx,
    handle: u64,
    entries: u64,
    count: u32,
    output: u64,
    length: u64,
    required: u64,
    captured: &mut Vec<Entry>,
) -> Checked<u32> {
    let key = key(c, handle, true)?;
    let capacity = c.mem().u32(length)?;
    if c.arch() != WinArch::X86 && u64::from(count) * 24 > CAPTURE_LIMIT as u64 {
        return status(STATUS_INSUFFICIENT_RESOURCES);
    }
    let wow = c.arch() == WinArch::X86;
    if !wow && count != 0 {
        if entries % 4 != 0 {
            return status(STATUS_DATATYPE_MISALIGNMENT);
        }
        probe_write(c, entries, count as usize * 24)?;
    }
    if required != 0 {
        probe_write(c, required, 4)?;
    }
    if capacity != 0 {
        if output % 4 != 0 {
            return status(STATUS_DATATYPE_MISALIGNMENT);
        }
        probe_write(c, output, capacity as usize)?;
    }
    if !wow {
        *captured = capture(c, entries, count, 24, false)?;
    }
    // Native capture validates every descriptor before reading any name text.
    // The WoW64 widening pass above captures headers without this validation.
    for entry in captured.iter_mut() {
        if entry.captured_name.is_none() {
            entry.captured_name = Some(name(c, entry.descriptor)?);
        }
        if entry
            .captured_name
            .as_ref()
            .is_some_and(|name| name.length % 2 != 0)
        {
            return status(STATUS_INVALID_PARAMETER);
        }
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(count as usize)
        .map_err(|_| Failure::Status(STATUS_NO_MEMORY))?;
    let mut name_bytes = 0;
    let mut missing = false;
    for entry in captured.iter() {
        let descriptor = match &entry.captured_name {
            Some(descriptor) => descriptor.clone(),
            None => name(c, entry.descriptor)?,
        };
        name_bytes += descriptor.length;
        if name_bytes > CAPTURE_LIMIT {
            return Err(c
                .unsupported("bulk registry name capture exceeds 16 MiB")
                .into());
        }
        if descriptor.length % 2 == 0 && descriptor.length != 0 && descriptor.buffer % 2 != 0 {
            return status(STATUS_DATATYPE_MISALIGNMENT);
        }
        let name = text(c, descriptor, false)?;
        let value = key.value(&name.units);
        missing |= value.is_none();
        values.push(value);
    }
    // ULONG reports wrap independently of the logical position. Retaining the
    // latter prevents a wrapped required length from suppressing overflow or
    // making a later value appear to fit at the start of the caller's buffer.
    let mut needed = 0u64;
    if !missing {
        for value in values.iter().flatten() {
            needed = needed
                .checked_add(3)
                .map(|v| v & !3)
                .and_then(|v| {
                    u32::try_from(value.data.len())
                        .ok()
                        .and_then(|n| v.checked_add(u64::from(n)))
                })
                .ok_or(Failure::Status(STATUS_INVALID_PARAMETER))?;
        }
    }
    if required != 0 {
        c.mem().w32(required, needed as u32)?;
    }
    if missing {
        if count != 0 {
            c.mem().w32(length, capacity)?;
        }
        return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    let mut offset = 0u64;
    let mut copied = 0u64;
    let mut fields = Vec::new();
    fields
        .try_reserve_exact(count as usize)
        .map_err(|_| Failure::Status(STATUS_NO_MEMORY))?;
    for (index, value) in values.into_iter().enumerate() {
        let value = value.expect("all missing values returned before publication");
        offset = offset
            .checked_add(3)
            .map(|v| v & !3)
            .ok_or(Failure::Status(STATUS_INVALID_PARAMETER))?;
        let end = offset + value.data.len() as u64;
        let mut record = [0; 3];
        if end <= u64::from(capacity) {
            write_pages(c, output + offset, &value.data)?;
            record = [value.data.len() as u32, offset as u32, value.kind];
            copied = end;
            if index + 1 < count as usize {
                let next = end
                    .checked_add(3)
                    .map(|v| v & !3)
                    .ok_or(Failure::Status(STATUS_INVALID_PARAMETER))?;
                write_pages(c, output + end, &[0; 3][..(next - end) as usize])?;
                copied = next;
            }
        }
        fields.push(record);
        offset = end;
    }
    if count != 0 {
        c.mem().w32(length, copied as u32)?;
    }
    for (entry, fields) in captured.iter_mut().zip(fields) {
        entry.fields = fields;
    }
    if !wow {
        copy_fields(c, entries, 24, captured)?;
    }
    Ok(if needed > u64::from(capacity) {
        STATUS_BUFFER_OVERFLOW
    } else {
        STATUS_SUCCESS
    })
}

fn copy_fields(c: &Ctx, entries: u64, stride: u64, captured: &[Entry]) -> Checked<()> {
    for (index, entry) in captured.iter().enumerate() {
        let address = entries + index as u64 * stride + c.psize();
        for (index, field) in entry.fields.iter().enumerate() {
            c.mem().w32(address + index as u64 * 4, *field)?;
        }
    }
    Ok(())
}
