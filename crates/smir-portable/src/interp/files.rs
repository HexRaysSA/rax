//! The `file` services that name files: opening, closing, positioning,
//! removing and renaming.
//!
//! A path is counted bytes of guest memory: strict UTF-8 without a NUL, of
//! at least one byte and at most [`PATH_LIMIT`]. What a path names is the
//! host's to decide; nothing here reads it as a path of the machine. A path
//! that is not well formed fails with a status, as a path that names nothing
//! does: `ENAMETOOLONG` for one that is too long, `EILSEQ` for bytes that
//! are not UTF-8, `EINVAL` for an empty one or one with a NUL.

use crate::ir::{Pointer, Value};

use super::host::{Errno, OpenFlags, Whence};
use super::memory::Fault;
use super::process::{Context, locked};

/// Most bytes of a path.
pub(super) const PATH_LIMIT: u64 = 4096;

fn succeeded(value: u64) -> Vec<Value> {
    vec![Value::Int(0), Value::Int(u128::from(value))]
}

fn failed(errno: Errno) -> Vec<Value> {
    vec![Value::Int(u128::from(errno.code())), Value::Int(0)]
}

fn finished(outcome: Result<u64, Errno>) -> Vec<Value> {
    match outcome {
        Ok(value) => succeeded(value),
        Err(errno) => failed(errno),
    }
}

/// The path of `length` bytes at `pointer`. The outer error is the fault of
/// a span the program may not read; the inner one the status of a path that
/// is not well formed.
fn path(context: &Context, pointer: Pointer, length: u64) -> Result<Result<String, Errno>, Fault> {
    if length == 0 {
        return Ok(Err(Errno::EINVAL));
    }
    if length > PATH_LIMIT {
        return Ok(Err(Errno::ENAMETOOLONG));
    }
    let bytes = context
        .process
        .memory
        .read_bytes(pointer, length, PATH_LIMIT as usize)?;
    if bytes.contains(&0) {
        return Ok(Err(Errno::EINVAL));
    }
    Ok(String::from_utf8(bytes).map_err(|_| Errno::EILSEQ))
}

/// `file.open(path, length, flags, mode) -> (status, handle)`.
///
/// `flags` are those of [`OpenFlags::from_bits`], and `mode` the permission
/// bits of a file this makes; flags or a mode with other bits fail with
/// `EINVAL`.
pub(super) fn open(
    context: &Context,
    pointer: Pointer,
    length: u64,
    flags: u64,
    mode: u64,
) -> Result<Vec<Value>, Fault> {
    let name = match path(context, pointer, length)? {
        Ok(name) => name,
        Err(errno) => return Ok(failed(errno)),
    };
    let (Some(flags), true) = (OpenFlags::from_bits(flags), mode & !0o7777 == 0) else {
        return Ok(failed(Errno::EINVAL));
    };
    Ok(finished(locked(&context.process.host).open(
        &name,
        flags,
        mode as u32,
    )))
}

/// `file.close(handle) -> (status, 0)`.
pub(super) fn close(context: &Context, handle: u64) -> Vec<Value> {
    finished(locked(&context.process.host).close(handle).map(|()| 0))
}

/// `file.seek(handle, offset, whence) -> (status, position)`.
///
/// `whence` is 0 for the start of the file, 1 for the position it has and 2
/// for its end; any other, and a position before the start, is `EINVAL`.
pub(super) fn seek(context: &Context, handle: u64, offset: u64, whence: u64) -> Vec<Value> {
    let whence = match whence {
        0 => Whence::Start,
        1 => Whence::Current,
        2 => Whence::End,
        _ => return failed(Errno::EINVAL),
    };
    finished(locked(&context.process.host).seek(handle, offset as i64, whence))
}

/// `file.unlink(path, length) -> (status, 0)`.
pub(super) fn unlink(
    context: &Context,
    pointer: Pointer,
    length: u64,
) -> Result<Vec<Value>, Fault> {
    Ok(match path(context, pointer, length)? {
        Ok(name) => finished(locked(&context.process.host).unlink(&name).map(|()| 0)),
        Err(errno) => failed(errno),
    })
}

/// `file.rename(source, source_length, destination, destination_length) ->
/// (status, 0)`. Both spans are guarded before either name is looked at.
pub(super) fn rename(
    context: &Context,
    source: (Pointer, u64),
    destination: (Pointer, u64),
) -> Result<Vec<Value>, Fault> {
    let from = path(context, source.0, source.1)?;
    let to = path(context, destination.0, destination.1)?;
    Ok(match (from, to) {
        (Ok(from), Ok(to)) => {
            finished(locked(&context.process.host).rename(&from, &to).map(|()| 0))
        }
        (Err(errno), _) | (_, Err(errno)) => failed(errno),
    })
}
