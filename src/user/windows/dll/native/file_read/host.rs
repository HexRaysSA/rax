use super::super::named_object::{Checked, Failure, status};
use super::{Completion, allocate};
use crate::user::windows::hle::Ctx;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{FileState, Object};
use std::io::Seek;
#[cfg(unix)]
use std::io::{Read, SeekFrom};
#[cfg(windows)]
mod windows;

pub(super) fn read(
    c: &mut Ctx,
    handle: u64,
    output: u64,
    length: usize,
    position: i64,
    state: FileState,
) -> Checked<Completion> {
    let Some(Object::File(file)) = c.p.objects.get(handle) else {
        unreachable!()
    };
    if file.host.is_none() {
        return Err(c
            .unsupported("NtReadFile requires a retained data handle")
            .into());
    }
    if state.mode & 8 != 0 {
        let target = if position < 0 {
            let mut retained = file.host.as_ref().unwrap();
            retained
                .stream_position()
                .map_err(|e| c.unsupported(format!("NtReadFile current offset: {e}")))?
        } else {
            position as u64
        };
        // The portable mounted-disk contract exposes512 B sectors and the
        // FILE_ALIGNMENT_INFORMATION mask1. Native file reads retain the
        // kernel's independent request validation inside the host adapter.
        if length % 512 != 0 || target % 512 != 0 || output & 1 != 0 {
            return status(STATUS_INVALID_PARAMETER);
        }
    }
    #[cfg(windows)]
    let completion = windows::read(c, file.host.as_ref().unwrap(), length, position)?;
    #[cfg(unix)]
    let completion = {
        let Some(Object::File(file)) = c.p.objects.get_mut(handle) else {
            unreachable!()
        };
        let file = file.host.as_mut().unwrap();
        portable(
            file,
            length,
            position,
            state.cached_io_initialized && state.mode & 8 == 0,
        )?
    };
    #[cfg(not(any(windows, unix)))]
    return Err(c
        .unsupported("NtReadFile host file adapter unavailable")
        .into());
    #[cfg(any(windows, unix))]
    {
        if !completion.bytes.is_empty() && state.mode & 8 == 0 {
            c.p.objects.note_file_io(handle);
        }
        Ok(completion)
    }
}

#[cfg(unix)]
fn portable(
    file: &mut std::fs::File,
    length: usize,
    position: i64,
    cached: bool,
) -> Checked<Completion> {
    let mut bytes = allocate(length)?;
    if length == 0 {
        return Ok(Completion {
            code: STATUS_SUCCESS,
            bytes,
            full_status: cached,
            published: true,
        });
    }
    let start = if position < 0 {
        file.stream_position()
    } else {
        Ok(position as u64)
    }
    .map_err(|e| Failure::Status(error(&e)))?;
    if cached
        && start
            >= file
                .metadata()
                .map_err(|e| Failure::Status(error(&e)))?
                .len()
    {
        return Ok(Completion {
            code: STATUS_END_OF_FILE,
            bytes: Vec::new(),
            full_status: true,
            published: true,
        });
    }
    if position >= 0 {
        file.seek(SeekFrom::Start(start))
            .map_err(|e| Failure::Status(error(&e)))?;
    }
    let mut done = 0;
    let mut code = STATUS_SUCCESS;
    while done < length {
        match file.read(&mut bytes[done..]) {
            Ok(0) => {
                if done == 0 {
                    code = STATUS_END_OF_FILE;
                }
                break;
            }
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                code = error(&e);
                break;
            }
        }
    }
    bytes.truncate(done);
    Ok(Completion {
        code,
        bytes,
        full_status: cached,
        published: true,
    })
}

#[cfg(unix)]
fn error(error: &std::io::Error) -> u32 {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => STATUS_ACCESS_DENIED,
        std::io::ErrorKind::BrokenPipe => STATUS_PIPE_BROKEN,
        std::io::ErrorKind::UnexpectedEof => STATUS_END_OF_FILE,
        _ => STATUS_UNSUCCESSFUL,
    }
}
