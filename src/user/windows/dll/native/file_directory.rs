//! Directory queries through retained file objects and private host buffers.
//! The native ordinary-call corpus owns packing, cursor, and restart behavior.
mod host;
#[cfg(unix)]
mod portable;
mod records;

use super::named_object::{Checked, finish_with, status};
use super::query::probe_write;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};

const MAX_OUTPUT: usize = 16 << 20;

#[derive(Clone, Copy)]
struct Layout {
    name: usize,
    length: usize,
    minimum: usize,
    alignment: u64,
}

impl Layout {
    fn of(class: u32) -> Option<Self> {
        let (name, minimum) = match class {
            1 => (64, 72),
            2 => (68, 72),
            3 => (94, 96),
            12 => (12, 16),
            37 => (104, 112),
            38 => (80, 88),
            60 => (88, 96),
            63 => (114, 120),
            _ => return None,
        };
        Some(Self {
            name,
            length: if class == 12 { 8 } else { 60 },
            minimum,
            alignment: if class == 12 { 4 } else { 8 },
        })
    }
}

struct Request {
    handle: u64,
    class: u32,
    flags: u32,
    pattern: Option<Vec<u16>>,
    bytes: Vec<u8>,
}

struct Completion {
    code: u32,
    bytes: Vec<u8>,
    status: Option<u32>,
    information: Option<u64>,
}

pub(super) fn query_ex(c: &mut Ctx) -> ApiResult {
    dispatch(c, false)
}

pub(super) fn query(c: &mut Ctx) -> ApiResult {
    dispatch(c, true)
}

fn dispatch(c: &mut Ctx, legacy: bool) -> ApiResult {
    let mut caller_store = false;
    let result = checked(c, legacy, &mut caller_store);
    finish_with(c, result, caller_store)
}

fn pattern(c: &Ctx, address: u64) -> Checked<Option<Vec<u16>>> {
    if address == 0 {
        return Ok(None);
    }
    let header = c.mem().bytes(address, (2 * c.psize()) as usize)?;
    let length = usize::from(u16::from_le_bytes(header[..2].try_into().unwrap()));
    if length % 2 != 0 {
        return status(STATUS_OBJECT_NAME_INVALID);
    }
    let buffer = c.read_ptr(address + c.psize())?;
    if length != 0 && buffer % 2 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    let bytes = c.mem().bytes(buffer, length)?;
    Ok(Some(
        bytes
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect(),
    ))
}

fn checked(c: &mut Ctx, legacy: bool, caller_store: &mut bool) -> Checked<u32> {
    let (handle, event, apc, _context, io, output, length, class) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.ptr(2)?,
        c.ptr(3)?,
        c.ptr(4)?,
        c.ptr(5)?,
        c.u32(6)? as usize,
        c.u32(7)?,
    );
    let flags = if legacy {
        u32::from(c.u32(8)? as u8 != 0) * 2 | u32::from(c.u32(10)? as u8 != 0)
    } else {
        c.u32(8)?
    };
    let name = c.ptr(9)?;
    let Some(layout) = Layout::of(class) else {
        return Err(c
            .unsupported(format!("directory information class {class}"))
            .into());
    };
    if length < layout.minimum {
        return status(STATUS_INFO_LENGTH_MISMATCH);
    }
    if flags & !0x1f != 0 || flags & 4 != 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    if length > MAX_OUTPUT {
        return Err(c.unsupported("directory query larger than 16 MiB").into());
    }
    let wow = c.arch() == WinArch::X86;
    if wow {
        if io == 0 {
            return status(STATUS_ACCESS_VIOLATION);
        }
    } else {
        probe_write(c, io, 4)?;
        if output % layout.alignment != 0 {
            return status(STATUS_DATATYPE_MISALIGNMENT);
        }
    }
    probe_write(c, output, length)?;
    match c.p.objects.get(handle) {
        Some(Object::SecurityFile(_)) => {
            return Err(c
                .unsupported("security-device directory queries are not selected")
                .into());
        }
        Some(Object::File(file)) if file.directory => {
            if c.p.objects.access(handle).unwrap_or(0) & (0x8000_0000 | 1) == 0 {
                return status(STATUS_ACCESS_DENIED);
            }
            if file.overlapped {
                return Err(c
                    .unsupported("asynchronous directory completion scheduling")
                    .into());
            }
        }
        Some(Object::File(_)) | Some(Object::Console(_) | Object::Null | Object::Pipe { .. }) => {
            return status(STATUS_INVALID_PARAMETER);
        }
        Some(_) => return status(STATUS_OBJECT_TYPE_MISMATCH),
        None if handle == c.arch().ptr(CURRENT_PROCESS)
            || handle == c.arch().ptr(CURRENT_THREAD) =>
        {
            return status(STATUS_OBJECT_TYPE_MISMATCH);
        }
        None => return status(STATUS_INVALID_HANDLE),
    }
    if event != 0 {
        match c.p.objects.get(event) {
            Some(Object::Event { .. }) if c.p.objects.access(event).unwrap_or(0) & 2 != 0 => {}
            Some(Object::Event { .. }) => return status(STATUS_ACCESS_DENIED),
            Some(_) => return status(STATUS_OBJECT_TYPE_MISMATCH),
            None => return status(STATUS_INVALID_HANDLE),
        }
    }
    if apc != 0 {
        return Err(c
            .unsupported("directory query APC completion delivery")
            .into());
    }
    let request = Request {
        handle,
        class,
        flags,
        pattern: pattern(c, name)?,
        bytes: c.mem().bytes(output, length)?,
    };
    if let Some(Object::Event { signaled, .. }) = c.p.objects.get_mut(event) {
        *signaled = 0;
    }
    let completion = host::query(c, request)?;
    records::validate(c, layout, &completion)?;
    if completion.status.is_some() || completion.information.is_some() {
        if let Some(Object::Event { signaled, .. }) = c.p.objects.get_mut(event) {
            *signaled = 1;
        }
    }
    // Enumeration advances before caller publication. A later IOSB fault does
    // not rewind the retained object's directory cursor.
    if let Some(information) = completion.information.filter(|&size| size != 0) {
        *caller_store = true;
        c.mem()
            .wr(output, &completion.bytes[..information as usize])?;
    }
    if let Some(code) = completion.status {
        *caller_store = true;
        c.mem().w32(io, code)?;
    }
    if let Some(information) = completion.information {
        *caller_store = true;
        let at = io.checked_add(c.psize()).ok_or(MemFault {
            addr: io,
            write: true,
        })?;
        c.mem().wptr(at, c.psize(), information)?;
    }
    Ok(completion.code)
}
