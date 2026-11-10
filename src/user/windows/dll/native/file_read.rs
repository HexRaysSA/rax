//! Reads through guest-owned objects; the installed NTDLL supplies service numbers.
//! Host adapters receive retained regular files and private bounded storage.
mod host;

use super::named_object::{Checked, Failure, finish_with, status};
use super::query::probe_write;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{Object, StdStream};

const MAX_IO: usize = 16 << 20;
const STATUS_DATATYPE_MISALIGNMENT_ERROR: u32 = 0xc000_02c5;
const STATUS_CONSOLE_INVALID_HANDLE: u32 = 0xc007_0006;
const STATUS_CONSOLE_INSUFFICIENT_BUFFER: u32 = 0xc007_0023;

pub(super) struct Completion {
    code: u32,
    bytes: Vec<u8>,
    full_status: bool,
    published: bool,
}

pub(super) fn read(c: &mut Ctx) -> ApiResult {
    let mut caller_store = false;
    let result = checked(c, &mut caller_store);
    finish_with(c, result, caller_store)
}

fn checked(c: &mut Ctx, caller_store: &mut bool) -> Checked<u32> {
    let (handle, event, apc, _context, io, output, length, offset, key) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.ptr(2)?,
        c.ptr(3)?,
        c.ptr(4)?,
        c.ptr(5)?,
        c.u32(6)? as usize,
        c.ptr(7)?,
        c.ptr(8)?,
    );
    let grant = c.p.objects.access(handle).unwrap_or(0);
    if matches!(c.p.objects.get(handle), Some(Object::SecurityFile(_))) {
        return Err(c
            .unsupported("security-device read requests are not selected")
            .into());
    }
    match c.p.objects.get(handle) {
        Some(Object::File(_) | Object::Console(_) | Object::Null | Object::Pipe { .. }) => {
            if grant & (0x8000_0000 | 1) == 0 {
                return status(STATUS_ACCESS_DENIED);
            }
        }
        Some(_) => return status(STATUS_OBJECT_TYPE_MISMATCH),
        None if handle == c.arch().ptr(u64::MAX) || handle == c.arch().ptr(u64::MAX - 1) => {
            return status(STATUS_OBJECT_TYPE_MISMATCH);
        }
        None => return status(STATUS_INVALID_HANDLE),
    }
    let wow = c.arch() == WinArch::X86;
    if wow {
        if io == 0 {
            return status(STATUS_ACCESS_VIOLATION);
        }
    } else {
        probe_write(c, io, 4)?;
    }
    let position = if offset == 0 {
        -2
    } else {
        if offset % 8 != 0 {
            return status(STATUS_DATATYPE_MISALIGNMENT_ERROR);
        }
        c.mem().u64(offset)? as i64
    };
    if key != 0 {
        c.mem().u32(key)?;
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
        return Err(c.unsupported("NtReadFile APC completion delivery").into());
    }
    if length > MAX_IO {
        return Err(c
            .unsupported("NtReadFile request larger than 16 MiB")
            .into());
    }
    probe_write(c, output, length)?;
    // The admitted event is reset before offset-value validation by the I/O manager.
    if let Some(Object::Event { signaled, .. }) = c.p.objects.get_mut(event) {
        *signaled = 0;
    }
    if position < 0 && position != -2 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let file_state = c.p.objects.file_state(handle).unwrap();
    if matches!(c.p.objects.get(handle), Some(Object::File(file)) if file.overlapped) {
        if position < 0 {
            return status(STATUS_INVALID_PARAMETER);
        }
        return Err(c
            .unsupported("asynchronous NtReadFile completion scheduling")
            .into());
    }
    let completion = match c.p.objects.get(handle) {
        Some(Object::File(file)) if file.directory => Completion {
            code: STATUS_INVALID_DEVICE_REQUEST,
            bytes: Vec::new(),
            full_status: false,
            published: true,
        },
        Some(Object::File(file)) if file.null => eof(),
        Some(Object::File(_)) => host::read(c, handle, output, length, position, file_state)?,
        Some(Object::Null) => eof(),
        Some(Object::Console(StdStream::In)) if length == 0 => Completion {
            code: STATUS_CONSOLE_INSUFFICIENT_BUFFER,
            bytes: Vec::new(),
            full_status: false,
            published: true,
        },
        Some(Object::Console(StdStream::In)) => {
            let mut bytes = allocate(length)?;
            let count =
                c.p.cfg
                    .console
                    .read(&mut bytes)
                    .map_err(|e| c.unsupported(format!("NtReadFile console input: {e}")))?;
            bytes.truncate(count);
            Completion {
                code: STATUS_SUCCESS,
                bytes,
                full_status: false,
                published: true,
            }
        }
        Some(Object::Console(_)) => Completion {
            code: STATUS_CONSOLE_INVALID_HANDLE,
            bytes: Vec::new(),
            full_status: false,
            published: true,
        },
        Some(Object::Pipe { .. }) => {
            return Err(c
                .unsupported("NtReadFile guest pipe completion and buffering")
                .into());
        }
        _ => unreachable!("validated object remains live during synchronous read"),
    };
    if !completion.published {
        return Ok(completion.code);
    }
    if let Some(Object::Event { signaled, .. }) = c.p.objects.get_mut(event) {
        *signaled = 1;
    }
    *caller_store = true;
    // Data effects precede IOSB publication; publication faults cannot undo a read.
    c.mem().wr(output, &completion.bytes)?;
    let information = io.checked_add(c.psize()).ok_or(MemFault {
        addr: io,
        write: true,
    })?;
    if completion.full_status && !wow {
        c.mem().wptr(io, c.psize(), u64::from(completion.code))?;
    } else {
        c.mem().w32(io, completion.code)?;
    }
    c.mem()
        .wptr(information, c.psize(), completion.bytes.len() as u64)?;
    Ok(completion.code)
}

fn allocate(length: usize) -> Checked<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Failure::Status(STATUS_INSUFFICIENT_RESOURCES))?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn eof() -> Completion {
    Completion {
        code: STATUS_END_OF_FILE,
        bytes: Vec::new(),
        full_status: true,
        published: true,
    }
}
