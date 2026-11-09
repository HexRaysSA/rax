//! Retained-file signing metadata with guest-owned, ordered output publication.
use super::named_object::{Checked, Failure, finish_with, status};
use super::query::probe_write;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};

#[cfg(test)]
mod tests;
#[cfg(windows)]
mod windows;

#[derive(Clone, Copy, Debug)]
struct Request {
    thumbprint: bool,
    size: bool,
    algorithm: bool,
}

/// Fields actually returned by the host query, captured in private storage.
#[derive(Debug)]
struct Completion {
    status: u32,
    flags: Option<u32>,
    level: Option<u8>,
    thumbprint: Vec<u8>,
    size: Option<u32>,
    algorithm: Option<u32>,
}

#[derive(Debug)]
enum Error {
    NoMemory,
    Inconsistent(&'static str),
    Unavailable(&'static str),
}

pub(super) fn get(c: &mut Ctx) -> ApiResult {
    query_with(c, host)
}

/// Captured kernel relation: row is the first signing class; bit is the second.
/// Only the low nibble participates. Reserved classes are not necessarily
/// reflexive, and numeric ordering does not describe this relation.
const SIGNING_DOMINANCE: [u16; 16] = [
    0x0001, 0x0003, 0x020f, 0x000b, 0x021f, 0x027b, 0x025b, 0x028f, 0x037f, 0x0003, 0x0003, 0x0b7f,
    0x13ff, 0x0003, 0x53ff, 0x0003,
];

pub(super) fn compare(c: &mut Ctx) -> ApiResult {
    let first = c.u32(0)? as u8;
    let second = c.u32(1)? as u8;
    let admitted = SIGNING_DOMINANCE[usize::from(first & 15)] & (1 << (second & 15)) != 0;
    Flow::ret(u64::from(if admitted {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_IMAGE_HASH
    }))
}

fn host(file: &std::fs::File, request: Request) -> Result<Completion, Error> {
    #[cfg(windows)]
    return windows::query(file, request);
    #[cfg(not(windows))]
    {
        let _ = (file, request);
        Err(Error::Unavailable(
            "NtGetCachedSigningLevel requires Windows retained-file signing metadata",
        ))
    }
}

fn query_with(
    c: &mut Ctx,
    query: impl FnOnce(&std::fs::File, Request) -> Result<Completion, Error>,
) -> ApiResult {
    let mut caller_store = true;
    let result = query_inner(c, query, &mut caller_store);
    finish_with(c, result, caller_store)
}

fn query_inner(
    c: &mut Ctx,
    query: impl FnOnce(&std::fs::File, Request) -> Result<Completion, Error>,
    caller_store: &mut bool,
) -> Checked<u32> {
    let (handle, flags, level, thumbprint, size, algorithm) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.ptr(2)?,
        c.ptr(3)?,
        c.ptr(4)?,
        c.ptr(5)?,
    );
    if handle == 0 || flags == 0 || level == 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    if handle == c.arch().ptr(CURRENT_PROCESS) || handle == c.arch().ptr(CURRENT_THREAD) {
        return status(STATUS_OBJECT_TYPE_MISMATCH);
    }
    let object =
        c.p.objects
            .get(handle)
            .ok_or(Failure::Status(STATUS_INVALID_HANDLE))?;
    if matches!(object, Object::Null) {
        return status(
            if c.p.objects.access(handle).unwrap_or(0) & (0x8000_0000 | 1) == 0 {
                STATUS_ACCESS_DENIED
            } else {
                STATUS_INVALID_INFO_CLASS
            },
        );
    }
    let Object::File(file) = object else {
        return status(STATUS_OBJECT_TYPE_MISMATCH);
    };
    // The native file query requires FILE_READ_DATA, independently of the
    // stronger host handle retained when this guest capability was admitted.
    if c.p.objects.access(handle).unwrap_or(0) & (0x8000_0000 | 1) == 0 {
        return status(STATUS_ACCESS_DENIED);
    }
    if file.null {
        return status(STATUS_INVALID_INFO_CLASS);
    }
    let file = file.host.as_ref().ok_or_else(|| {
        Failure::Api(
            c.unsupported("NtGetCachedSigningLevel requires an admitted retained file handle"),
        )
    })?;
    let request = Request {
        thumbprint: thumbprint != 0,
        size: size != 0,
        algorithm: algorithm != 0,
    };
    let record = query(file, request).map_err(|error| match error {
        Error::NoMemory => Failure::Status(STATUS_NO_MEMORY),
        Error::Inconsistent(reason) | Error::Unavailable(reason) => c.unsupported(reason).into(),
    })?;
    // Missing signing-cache metadata and handle/access failures precede every
    // caller-buffer access, including the input/output length field.
    if !matches!(record.status, STATUS_SUCCESS | STATUS_BUFFER_TOO_SMALL) {
        return Ok(record.status);
    }
    let (Some(captured_flags), Some(captured_level)) = (record.flags, record.level) else {
        return Err(c
            .unsupported("native signing query omitted mandatory outputs")
            .into());
    };
    c.mem().w32(flags, captured_flags)?;
    c.mem().w8(level, captured_level)?;
    if size == 0 {
        return Ok(record.status);
    }
    let Some(required) = record.size else {
        return Err(c
            .unsupported("native signing query omitted its length")
            .into());
    };
    // Native ProbeForWrite(ULONG) alignment is observable after the preceding
    // flags/level stores. Probe before reading: a read-only length fails even
    // though its input value could have been read successfully.
    if size % 4 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    // Unlike direct output stores, the length probe consumes a read-only
    // guard. Preserve that distinction in the common fault conversion seam.
    *caller_store = false;
    probe_write(c, size, 4)?;
    let capacity = c.mem().u32(size)?;
    *caller_store = true;
    let mut result = record.status;
    if thumbprint != 0 {
        if capacity < required {
            result = STATUS_BUFFER_TOO_SMALL;
        } else {
            if record.thumbprint.len() != required as usize {
                return Err(c
                    .unsupported("native signing hash length is inconsistent")
                    .into());
            }
            // Represent the measured read-before-write behavior at the first
            // three hash bytes. A crossing read consumes a read-only guard;
            // a later write-protection failure leaves that guard untouched.
            *caller_store = false;
            let mut probe = [0u8; 3];
            c.mem()
                .rd(thumbprint, &mut probe[..record.thumbprint.len().min(3)])?;
            *caller_store = true;
            // Preserve completed eight-byte stores when a later store faults.
            for (index, chunk) in record.thumbprint.chunks(8).enumerate() {
                let destination = thumbprint
                    .checked_add(index as u64 * 8)
                    .ok_or(Failure::Status(STATUS_ACCESS_VIOLATION))?;
                c.mem().wr(destination, chunk)?;
            }
        }
    }
    c.mem().w32(size, required)?;
    if algorithm != 0
        && let Some(captured_algorithm) = record.algorithm
    {
        c.mem().w32(algorithm, captured_algorithm)?;
    }
    Ok(result)
}
