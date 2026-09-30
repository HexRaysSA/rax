use super::*;
use crate::user::console::OutputStream;
use crate::user::windows::hle::Flow;
use crate::user::windows::objects::{Object, StdStream};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;

fn transfer(c: &mut Ctx, write: bool) -> ApiResult {
    let (handle, buffer, count, result, overlapped) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.u32(2)? as usize,
        c.ptr(3)?,
        c.ptr(4)?,
    );
    preflight_error(c)?;
    if result == 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    probe(c, result, 4, true)?;
    // Documented before any work/error checking, including aliased buffers.
    c.mem().w32(result, 0)?;
    if overlapped != 0 {
        return Err(c.unsupported("nonzero OVERLAPPED file request"));
    }
    if count > MAX_IO {
        return Err(c.unsupported("file request larger than 16 MiB"));
    }
    let grant = c.p.objects.access(handle).unwrap_or(0);
    match c.p.objects.get(handle) {
        Some(Object::File(file)) => {
            if file.overlapped {
                return Err(c.unsupported("overlapped file handle"));
            }
            if file.directory
                || (if write {
                    !can_write(grant)
                } else {
                    !can_read(grant)
                })
            {
                return c.fail(ERROR_ACCESS_DENIED, 0);
            }
        }
        Some(Object::Console(stream)) => {
            if (*stream == StdStream::In) == write
                || (if write {
                    !can_write(grant)
                } else {
                    !can_read(grant)
                })
            {
                return c.fail(ERROR_ACCESS_DENIED, 0);
            }
        }
        Some(Object::Null) => {
            if if write {
                !can_write(grant)
            } else {
                !can_read(grant)
            } {
                return c.fail(ERROR_ACCESS_DENIED, 0);
            }
        }
        Some(Object::Pipe { .. }) => return Err(c.unsupported("pipe I/O")),
        _ => return c.fail(ERROR_INVALID_HANDLE, 0),
    }
    probe(c, buffer, count, !write)?;
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(count).is_err() {
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    }
    bytes.resize(count, 0);
    if write {
        c.mem().rd(buffer, &mut bytes)?;
    }
    // A single scheduler host thread keeps every guest output valid until copy.
    // Host read/write failures can have partial host effects; they are not
    // misrepresented as an atomic transaction or retried from byte zero.
    let host_result = match c.p.objects.get_mut(handle) {
        Some(Object::File(file)) if file.null => Ok(if write { count } else { 0 }),
        Some(Object::File(file)) => match file.host.as_mut() {
            Some(file) => {
                if write {
                    if count != 0 && grant & APPEND_DATA != 0 && !can_set_end(grant) {
                        file.seek(SeekFrom::End(0))
                            .and_then(|_| write_all(file, &bytes))
                            .map(|_| count)
                    } else {
                        write_all(file, &bytes).map(|_| count)
                    }
                } else {
                    read_file(file, &mut bytes)
                }
            }
            None => return c.fail(ERROR_INVALID_HANDLE, 0),
        },
        Some(Object::Console(StdStream::In)) => c.p.cfg.console.read(&mut bytes),
        Some(Object::Console(StdStream::Out)) => {
            c.p.cfg
                .console
                .write_all(OutputStream::Stdout, &bytes)
                .map(|_| count)
        }
        Some(Object::Console(StdStream::Err)) => {
            c.p.cfg
                .console
                .write_all(OutputStream::Stderr, &bytes)
                .map(|_| count)
        }
        Some(Object::Null) => Ok(if write { count } else { 0 }),
        _ => unreachable!("validated object cannot change during synchronous transfer"),
    };
    match host_result {
        Ok(transferred) => {
            if !write {
                c.mem().wr(buffer, &bytes[..transferred])?;
            }
            c.mem().w32(result, transferred as u32)?;
            Flow::bool(true)
        }
        Err(error) => c.fail(
            host_error(
                &error,
                None,
                if write {
                    ERROR_WRITE_FAULT
                } else {
                    ERROR_READ_FAULT
                },
            ),
            0,
        ),
    }
}

fn read_file(file: &mut std::fs::File, bytes: &mut [u8]) -> std::io::Result<usize> {
    let mut done = 0;
    while done < bytes.len() {
        match file.read(&mut bytes[done..]) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    // The dedicated Microsoft EOF reference distinguishes synchronous success
    // with zero bytes from the asynchronous ERROR_HANDLE_EOF path.
    Ok(done)
}

fn write_all(writer: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    writer.write_all(bytes)
}

pub(super) fn read(c: &mut Ctx) -> ApiResult {
    transfer(c, false)
}
pub(super) fn write(c: &mut Ctx) -> ApiResult {
    transfer(c, true)
}

pub(super) fn size(c: &mut Ctx) -> ApiResult {
    let (handle, output) = (c.ptr(0)?, c.ptr(1)?);
    preflight_error(c)?;
    probe(c, output, 8, true)?;
    let result = match c.p.objects.get(handle) {
        Some(Object::File(file)) if !file.directory && !file.null => {
            let metadata = file.host.as_ref().map_or_else(
                || std::fs::metadata(&file.host_path),
                std::fs::File::metadata,
            );
            if file.host.is_none()
                && metadata.as_ref().is_ok_and(|metadata| {
                    crate::user::windows::fs::FileIdentity::of(&file.host_path, metadata)
                        .is_ok_and(|identity| identity != file.lifetime.identity)
                })
            {
                return Err(c.unsupported("metadata-only handle pathname was replaced"));
            }
            metadata.map(|metadata| metadata.len())
        }
        _ => return c.fail(ERROR_INVALID_HANDLE, 0),
    };
    match result {
        Ok(length) if length <= i64::MAX as u64 => {
            c.mem().w64(output, length)?;
            Flow::bool(true)
        }
        Ok(_) => c.fail(ERROR_INVALID_PARAMETER, 0),
        Err(error) => c.fail(host_error(&error, None, ERROR_READ_FAULT), 0),
    }
}

pub(super) fn seek(c: &mut Ctx) -> ApiResult {
    let (handle, distance, output, method) = (c.ptr(0)?, c.arg(1)?, c.ptr(2)?, c.u32(3)?);
    preflight_error(c)?;
    if output != 0 {
        probe(c, output, 8, true)?;
    }
    if method > 2 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let grant = c.p.objects.access(handle).unwrap_or(0);
    let file = match c.p.objects.get_mut(handle) {
        Some(Object::File(file)) if !file.directory && !file.null => {
            if !can_read(grant) && !can_write(grant) {
                return c.fail(ERROR_ACCESS_DENIED, 0);
            }
            match file.host.as_mut() {
                Some(file) => file,
                None => return c.fail(ERROR_INVALID_HANDLE, 0),
            }
        }
        Some(Object::Console(_) | Object::Null | Object::File(_)) => {
            return c.fail(ERROR_INVALID_FUNCTION, 0);
        }
        _ => return c.fail(ERROR_INVALID_HANDLE, 0),
    };
    let base = match method {
        0 => Ok(0),
        1 => file.stream_position(),
        2 => file.metadata().map(|m| m.len()),
        _ => unreachable!("move method validated"),
    };
    let base = match base {
        Ok(n) => n,
        Err(e) => return c.fail(host_error(&e, None, ERROR_SEEK), 0),
    };
    // FILE_BEGIN interprets the raw LARGE_INTEGER as unsigned. CURRENT/END
    // interpret it as signed; i128 avoids signed 64-bit intermediate overflow.
    let target = if method == 0 {
        i128::from(distance)
    } else {
        i128::from(base) + i128::from(distance as i64)
    };
    if target < 0 {
        return c.fail(ERROR_NEGATIVE_SEEK, 0);
    }
    // The supported host file-offset/size profile is 0 ..= i64::MAX bytes.
    if target > i128::from(i64::MAX) {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    match file.seek(SeekFrom::Start(target as u64)) {
        Ok(position) => {
            if output != 0 {
                c.mem().w64(output, position)?;
            }
            Flow::bool(true)
        }
        Err(error) => c.fail(host_error(&error, None, ERROR_SEEK), 0),
    }
}

pub(super) fn set_end(c: &mut Ctx) -> ApiResult {
    let handle = c.ptr(0)?;
    preflight_error(c)?;
    let grant = c.p.objects.access(handle).unwrap_or(0);
    let file = match c.p.objects.get_mut(handle) {
        Some(Object::File(file)) if !file.directory && !file.null => {
            if !can_set_end(grant) {
                return c.fail(ERROR_ACCESS_DENIED, 0);
            }
            match file.host.as_mut() {
                Some(file) => file,
                None => return c.fail(ERROR_INVALID_HANDLE, 0),
            }
        }
        _ => return c.fail(ERROR_INVALID_HANDLE, 0),
    };
    let result = file
        .stream_position()
        .and_then(|position| file.set_len(position));
    match result {
        Ok(()) => Flow::bool(true),
        Err(error) => c.fail(host_error(&error, None, ERROR_WRITE_FAULT), 0),
    }
}

pub(super) fn flush(c: &mut Ctx) -> ApiResult {
    let handle = c.ptr(0)?;
    preflight_error(c)?;
    let grant = c.p.objects.access(handle).unwrap_or(0);
    let result = match c.p.objects.get(handle) {
        Some(Object::File(file)) if !file.directory && !file.null => {
            if !can_set_end(grant) {
                return c.fail(ERROR_ACCESS_DENIED, 0);
            }
            match file.host.as_ref() {
                Some(file) => file.sync_all(),
                None => return c.fail(ERROR_INVALID_HANDLE, 0),
            }
        }
        Some(Object::File(file)) if file.null => {
            return Err(c.unsupported("FlushFileBuffers on NUL"));
        }
        _ => return c.fail(ERROR_INVALID_HANDLE, 0),
    };
    match result {
        Ok(()) => Flow::bool(true),
        Err(error) => c.fail(host_error(&error, None, ERROR_WRITE_FAULT), 0),
    }
}

pub(super) fn kind(c: &mut Ctx) -> ApiResult {
    let handle = c.ptr(0)?;
    preflight_error(c)?;
    match c.p.objects.get(handle) {
        Some(Object::File(file)) => Flow::ret(if file.null { 2 } else { 1 }),
        Some(Object::Console(_) | Object::Null) => Flow::ret(2),
        Some(Object::Pipe { .. }) => Flow::ret(3),
        _ => c.fail(ERROR_INVALID_HANDLE, 0),
    }
}

pub(super) fn finish_close(object: Option<Object>) -> Result<(), u32> {
    if let Some(Object::File(mut file)) = object {
        // Close the host descriptor before the final lifetime unlinks its path.
        drop(file.host.take());
        if Arc::strong_count(&file.lifetime) == 1 {
            file.lifetime
                .finish_delete()
                .map_err(|e| host_error(&e, Some(&file.host_path), ERROR_ACCESS_DENIED))?;
        }
    }
    Ok(())
}

pub(super) fn close(c: &mut Ctx) -> ApiResult {
    let handle = c.ptr(0)?;
    preflight_error(c)?;
    match c.p.objects.close(handle) {
        Ok(object) => match finish_close(object) {
            Ok(()) => Flow::bool(true),
            Err(error) => c.fail(error, 0),
        },
        Err(()) => c.fail(ERROR_INVALID_HANDLE, 0),
    }
}
