//! Synchronous writes through guest-owned file and console objects.
//! Native64 probes Status before the operation; WoW64 publishes its private
//! IOSB afterward. Observations and the Microsoft contract are retained under
//! docs/specifications/windows/native-file-write.

use super::named_object::{Checked, finish_with, status};
use super::query::probe_write;
use crate::user::console::OutputStream;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{Object, StdStream};
use std::io::{Seek, SeekFrom, Write};

const MAX_IO: usize = 16 << 20;
const STATUS_DATATYPE_MISALIGNMENT_ERROR: u32 = 0xC000_02C5;

pub(super) fn write(c: &mut Ctx) -> ApiResult {
    let mut caller_store = false;
    let result = checked(c, &mut caller_store);
    finish_with(c, result, caller_store)
}

fn checked(c: &mut Ctx, caller_store: &mut bool) -> Checked<u32> {
    let (handle, event, apc, context, io, buffer, length, offset, key) = (
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
    let append_only = grant & 4 != 0 && grant & (0x4000_0000 | 2) == 0;
    match c.p.objects.get(handle) {
        Some(Object::File(file)) => {
            if file.directory || grant & (0x4000_0000 | 2 | 4) == 0 {
                return status(STATUS_ACCESS_DENIED);
            }
            if file.overlapped {
                return Err(c.unsupported("asynchronous NtWriteFile file handle").into());
            }
        }
        Some(Object::Console(StdStream::In)) => return status(STATUS_ACCESS_DENIED),
        Some(Object::Console(_) | Object::Null) => {
            if grant & (0x4000_0000 | 2 | 4) == 0 {
                return status(STATUS_ACCESS_DENIED);
            }
        }
        Some(Object::Pipe { .. }) => {
            return Err(c.unsupported("NtWriteFile guest pipe object").into());
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
    if apc != 0 || context != 0 {
        return Err(c
            .unsupported("NtWriteFile APC/completion-context delivery")
            .into());
    }
    if length > MAX_IO {
        return Err(c
            .unsupported("NtWriteFile request larger than 16 MiB")
            .into());
    }
    if position < -2 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| super::named_object::Failure::Status(STATUS_INSUFFICIENT_RESOURCES))?;
    bytes.resize(length, 0);
    c.mem().rd(buffer, &mut bytes)?;
    if let Some(Object::Event { signaled, .. }) = c.p.objects.get_mut(event) {
        *signaled = 0;
    }
    let result = match c.p.objects.get_mut(handle) {
        Some(Object::File(file)) if file.null => Ok(()),
        Some(Object::File(file)) => {
            let Some(host) = file.host.as_mut() else {
                return status(STATUS_INVALID_HANDLE);
            };
            let seek = if append_only || position == -1 {
                host.seek(SeekFrom::End(0)).map(|_| ())
            } else if position >= 0 {
                host.seek(SeekFrom::Start(position as u64)).map(|_| ())
            } else {
                Ok(())
            };
            seek.and_then(|()| host.write_all(&bytes))
        }
        Some(Object::Console(StdStream::Out)) => {
            c.p.cfg.console.write_all(OutputStream::Stdout, &bytes)
        }
        Some(Object::Console(StdStream::Err)) => {
            c.p.cfg.console.write_all(OutputStream::Stderr, &bytes)
        }
        Some(Object::Null) => Ok(()),
        _ => unreachable!("validated object cannot change during synchronous write"),
    };
    if let Some(Object::Event { signaled, .. }) = c.p.objects.get_mut(event) {
        *signaled = 1;
    }
    let code = match result {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => match error.kind() {
            std::io::ErrorKind::PermissionDenied => STATUS_ACCESS_DENIED,
            std::io::ErrorKind::BrokenPipe => STATUS_PIPE_BROKEN,
            std::io::ErrorKind::StorageFull => STATUS_DISK_FULL,
            std::io::ErrorKind::WouldBlock => {
                return Err(c
                    .unsupported("NtWriteFile output requires draining captured console")
                    .into());
            }
            _ => STATUS_UNSUCCESSFUL,
        },
    };
    *caller_store = true;
    // Complete stores remain visible if Information crosses an inaccessible
    // page. A WoW64 copy fault does not undo the already completed write.
    c.mem().wptr(io, c.psize(), u64::from(code))?;
    let information = io
        .checked_add(c.psize())
        .ok_or(super::named_object::Failure::Status(
            STATUS_ACCESS_VIOLATION,
        ))?;
    c.mem().wptr(
        information,
        c.psize(),
        if code == STATUS_SUCCESS {
            length as u64
        } else {
            0
        },
    )?;
    Ok(code)
}
