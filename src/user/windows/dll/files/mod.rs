//! Synchronous Win32 file services.
//!
//! Primary contracts are retained in `docs/specifications/windows/services/file`.
//! Guest threads execute on one scheduler host thread: preflight and copy cannot
//! race guest protection changes. Host filesystem mutations by other processes
//! are not part of that guarantee. Buffers are bounded to 16 MiB per request.

mod io;
mod open;
mod paths;
#[cfg(test)]
mod tests;

use crate::error::MemoryAccessKind;
use crate::user::windows::hle::{ApiResult, Arg::*, Conv::Stdcall, Ctx, Export};
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::error::*;
use std::path::Path;

/// Finalizes an object returned by `Objects::close`, including close-source
/// duplication. Destruction without an API caller uses FileLifetime's Drop.
pub(crate) fn finish_close(
    object: Option<crate::user::windows::objects::Object>,
) -> Result<(), u32> {
    io::finish_close(object)
}

pub(super) static EXPORTS: &[Export] = &[
    Export::func(
        "CreateFileW",
        Stdcall,
        &[Ptr, I32, I32, Ptr, I32, I32, Ptr],
        open::create_w,
    ),
    Export::func(
        "CreateFileA",
        Stdcall,
        &[Ptr, I32, I32, Ptr, I32, I32, Ptr],
        open::create_a,
    ),
    Export::func("ReadFile", Stdcall, &[Ptr, Ptr, I32, Ptr, Ptr], io::read),
    Export::func("WriteFile", Stdcall, &[Ptr, Ptr, I32, Ptr, Ptr], io::write),
    Export::func("GetFileSizeEx", Stdcall, &[Ptr, Ptr], io::size),
    Export::func("SetFilePointerEx", Stdcall, &[Ptr, I64, Ptr, I32], io::seek),
    Export::func("SetEndOfFile", Stdcall, &[Ptr], io::set_end),
    Export::func("FlushFileBuffers", Stdcall, &[Ptr], io::flush),
    Export::func("GetFileType", Stdcall, &[Ptr], io::kind),
    Export::func("CloseHandle", Stdcall, &[Ptr], io::close),
    Export::func("DeleteFileW", Stdcall, &[Ptr], paths::delete_w),
    Export::func("DeleteFileA", Stdcall, &[Ptr], paths::delete_a),
];

const MAX_IO: usize = 16 << 20;
const MAX_PATH_UNITS: usize = 32767;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const READ_DATA: u32 = 1;
const WRITE_DATA: u32 = 2;
const APPEND_DATA: u32 = 4;
const DELETE: u32 = 0x0001_0000;
const SHARE_READ: u32 = 1;
const SHARE_WRITE: u32 = 2;
const SHARE_DELETE: u32 = 4;
const DELETE_ON_CLOSE: u32 = 0x0400_0000;
const BACKUP_SEMANTICS: u32 = 0x0200_0000;

fn can_read(access: u32) -> bool {
    access & (GENERIC_READ | READ_DATA) != 0
}
fn can_write(access: u32) -> bool {
    access & (GENERIC_WRITE | WRITE_DATA | APPEND_DATA) != 0
}
fn can_set_end(access: u32) -> bool {
    access & (GENERIC_WRITE | WRITE_DATA) != 0
}

/// Expand generic file rights for explicit reduced-grant duplication, retaining
/// the generic bits as well as the corresponding FILE_GENERIC_* masks.
pub(super) fn effective_access(mut access: u32) -> u32 {
    if access & GENERIC_READ != 0 {
        access |= 0x0012_0089;
    }
    if access & GENERIC_WRITE != 0 {
        access |= 0x0012_0116;
    }
    access
}

fn share_access(access: u32) -> u32 {
    u32::from(can_read(access)) * SHARE_READ
        | u32::from(can_write(access)) * SHARE_WRITE
        | u32::from(access & DELETE != 0) * SHARE_DELETE
}

fn probe(c: &Ctx, address: u64, length: usize, write: bool) -> Result<(), MemFault> {
    let access = if write {
        MemoryAccessKind::Write
    } else {
        MemoryAccessKind::Read
    };
    c.mem()
        .probe(address, length, access)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write,
        })
}

// Last-error stores must not fault after a host filesystem effect.
fn preflight_error(c: &Ctx) -> Result<(), MemFault> {
    let address =
        c.t.teb
            .checked_add(offsets(c.arch()).teb_last_error)
            .ok_or(MemFault {
                addr: u64::MAX,
                write: true,
            })?;
    probe(c, address, 4, true)
}

fn host_error(error: &std::io::Error, path: Option<&Path>, fallback: u32) -> u32 {
    use std::io::ErrorKind::*;
    match error.kind() {
        NotFound => {
            if path.and_then(Path::parent).is_some_and(|p| !p.is_dir()) {
                ERROR_PATH_NOT_FOUND
            } else {
                ERROR_FILE_NOT_FOUND
            }
        }
        PermissionDenied => ERROR_ACCESS_DENIED,
        AlreadyExists => ERROR_FILE_EXISTS,
        InvalidInput => ERROR_INVALID_PARAMETER,
        Unsupported => ERROR_NOT_SUPPORTED,
        OutOfMemory => ERROR_NOT_ENOUGH_MEMORY,
        StorageFull => ERROR_DISK_FULL,
        _ => fallback,
    }
}

enum NameError {
    Error(u32),
    Unsupported(&'static str),
}

// Unlike Mem::wstr/cstr, a maximum-length scan must not silently truncate a
// filename and thereby create/delete a different host file.
fn name(c: &Ctx, address: u64, wide: bool) -> Result<Result<String, NameError>, MemFault> {
    let mut text = String::new();
    if wide {
        let mut units = Vec::new();
        for i in 0..=MAX_PATH_UNITS {
            let at = address.checked_add((i as u64) * 2).ok_or(MemFault {
                addr: u64::MAX,
                write: false,
            })?;
            let unit = c.mem().u16(at)?;
            if unit == 0 {
                return Ok(String::from_utf16(&units)
                    .map_err(|_| NameError::Unsupported("unpaired UTF-16 pathname surrogate")));
            }
            if i == MAX_PATH_UNITS {
                return Ok(Err(NameError::Error(ERROR_FILENAME_EXCED_RANGE)));
            }
            units.push(unit);
        }
    } else {
        for i in 0..=MAX_PATH_UNITS {
            let at = address.checked_add(i as u64).ok_or(MemFault {
                addr: u64::MAX,
                write: false,
            })?;
            let byte = c.mem().u8(at)?;
            if byte == 0 {
                return Ok(Ok(text));
            }
            if i == MAX_PATH_UNITS {
                return Ok(Err(NameError::Error(ERROR_FILENAME_EXCED_RANGE)));
            }
            if !byte.is_ascii() {
                return Ok(Err(NameError::Unsupported(
                    "non-ASCII ANSI pathname conversion",
                )));
            }
            text.push(char::from(byte));
        }
    }
    unreachable!("bounded filename scan returns at its final iteration")
}

fn bad_name(c: &mut Ctx, error: NameError, value: u64) -> ApiResult {
    match error {
        NameError::Error(code) => c.fail(code, value),
        NameError::Unsupported(what) => Err(c.unsupported(what)),
    }
}
