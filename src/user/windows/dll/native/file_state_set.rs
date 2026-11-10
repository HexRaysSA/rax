//! Fixed file-object setters. Native controls define capture and copyback order.
mod host;
mod probe;

use super::named_object::{Checked, Failure, finish_with, status};
use super::query::{probe_write, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};

pub(super) fn set(c: &mut Ctx) -> ApiResult {
    let mut caller_store = false;
    let result = checked(c, &mut caller_store);
    finish_with(c, result, caller_store)
}

fn checked(c: &mut Ctx, caller_store: &mut bool) -> Checked<u32> {
    let (handle, io, input, length, class) =
        (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?, c.u32(3)?, c.u32(4)?);
    let wow = c.arch() == WinArch::X86;
    if wow && input != 0 {
        probe::wow64_span(c, input, length)?;
    }
    let (bytes, alignment) = match class {
        14 => (8, 8),
        16 | 41 => (4, 4),
        43 => (4, 8),
        0 | 90..=u32::MAX => return status(STATUS_INVALID_INFO_CLASS),
        _ => {
            return Err(c
                .unsupported(format!("file state setter class {class}"))
                .into());
        }
    };
    if length < bytes {
        return status(STATUS_INFO_LENGTH_MISMATCH);
    }
    if wow {
        if io == 0 {
            return status(STATUS_ACCESS_VIOLATION);
        }
    } else {
        probe_write(c, io, 4)?;
        if input % alignment != 0 {
            return status(STATUS_DATATYPE_MISALIGNMENT);
        }
    }
    probe::native_span(c, input, length)?;
    // The WoW64 converters capture nonnull position input before
    // object lookup. Native and directly forwarded classes capture afterward.
    if wow && input != 0 && class == 14 {
        probe::read(c, input, length as usize)?;
    }
    let Some(object) = c.p.objects.get(handle) else {
        return status(
            if handle == c.arch().ptr(CURRENT_PROCESS) || handle == c.arch().ptr(CURRENT_THREAD) {
                STATUS_OBJECT_TYPE_MISMATCH
            } else {
                STATUS_INVALID_HANDLE
            },
        );
    };
    if matches!(object, Object::SecurityFile(_)) {
        return Err(c
            .unsupported("security-device file state setters are not selected")
            .into());
    }
    if !matches!(
        object,
        Object::File(_) | Object::Console(_) | Object::Null | Object::Pipe { .. }
    ) {
        return status(STATUS_OBJECT_TYPE_MISMATCH);
    }
    probe::read(c, input, length as usize)?;
    // Capture before any caller IOSB store: input and IOSB may alias.
    let value = if bytes == 8 {
        c.mem().u64(input)?
    } else {
        u64::from(c.mem().u32(input)?)
    };
    let state =
        c.p.objects
            .file_state(handle)
            .expect("resolved file object");
    let mut changed = state;
    match class {
        14 => {
            if value > i64::MAX as u64 {
                return status(STATUS_INVALID_PARAMETER);
            }
            // The portable mapped Windows disk has 512 B logical sectors.
            // FileAlignmentInformation is a distinct device alignment mask.
            if (!cfg!(windows) || !matches!(object, Object::File(f) if f.host.is_some()))
                && state.mode & 8 != 0
                && value % 512 != 0
            {
                return status(STATUS_INVALID_PARAMETER);
            }
            changed.position = value;
        }
        16 => {
            let mode = value as u32;
            let synchronous = state.mode & 0x30 != 0;
            if mode & !0x36 != 0 || mode & 0x30 == 0x30 || synchronous != (mode & 0x30 != 0) {
                return status(STATUS_INVALID_PARAMETER);
            }
            changed.mode = (state.mode & 8) | mode;
            if changed.mode & 8 != 0 {
                changed.mode &= !2;
            }
        }
        41 => {
            if state.mode & 0x30 != 0 {
                return status(STATUS_INVALID_PARAMETER);
            }
            changed.notification |= value as u32 & 7;
        }
        43 => {
            if value > 2 {
                return status(STATUS_INVALID_PARAMETER);
            }
            changed.priority = value as u32;
        }
        _ => unreachable!("fixed class admitted above"),
    }
    if let Object::File(file) = object
        && !file.null
    {
        host::set(c, file, class, value)?;
    }
    *c.p.objects
        .file_state_mut(handle)
        .expect("resolved file object") = changed;
    *caller_store = wow;
    publish(c, io, input, class == 14 && state.mode & 0x30 != 0, wow)
}

fn publish(c: &mut Ctx, io: u64, input: u64, full_status: bool, wow: bool) -> Checked<u32> {
    let information = io
        .checked_add(c.psize())
        .ok_or(Failure::Status(STATUS_ACCESS_VIOLATION))?;
    // WoW64 copies back Status first and preserves a captured Information
    // slot when it was also the input buffer. Its late fault does not undo state.
    if wow {
        let aliased = if input == information {
            Some(c.mem().u32(information)?)
        } else {
            None
        };
        c.mem().w32(io, 0)?;
        c.mem().w32(information, aliased.unwrap_or(0))?;
        return Ok(STATUS_SUCCESS);
    }
    let result: Checked<()> = (|| {
        if full_status {
            c.mem().wptr(io, c.psize(), 0)?;
            c.mem().wptr(information, c.psize(), 0)?;
        } else {
            c.mem().wptr(information, c.psize(), 0)?;
            c.mem().w32(io, 0)?;
        }
        Ok(())
    })();
    match result {
        Err(Failure::Api(crate::user::windows::hle::ApiErr::Fault(fault))) => {
            let _ = write_guard_result(c, Err(fault.into()));
        }
        result => result?,
    }
    Ok(STATUS_SUCCESS)
}
