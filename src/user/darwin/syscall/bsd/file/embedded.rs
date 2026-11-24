//! Bounded guest-memory transfers for descriptors without a host handle.

use super::{CHUNK, Ctx, Errno, FileKind, Rv, SysResult};
use crate::error::MemoryAccessKind;
use crate::user::darwin::fd::EmbeddedFile;
use crate::user::darwin::io::{O_ACCMODE, O_RDONLY};
use crate::user::supplied_fs::Entry;

const EXTENDED_DIRECTORY_BUFFER: u64 = 1024;
const END_OF_DIRECTORY: u64 = i32::MAX as u64;

pub(super) fn preallocate(ctx: &Ctx<'_>, file: &EmbeddedFile, arg: u64) -> SysResult {
    const PHYSICAL_EOF: i32 = 3;
    const VOLUME_POSITION: i32 = 4;
    const ALLOCATION_FLAGS: u32 = 0x0e;

    let access = match file {
        EmbeddedFile::Workspace { access, .. }
        | EmbeddedFile::Null { access, .. }
        | EmbeddedFile::Zero { access, .. }
        | EmbeddedFile::Resource { access, .. } => *access,
        _ => return Err(Errno::EBADF),
    };
    if access & O_ACCMODE == O_RDONLY
        || matches!(file, EmbeddedFile::Workspace { .. }) && file.workspace().is_none()
    {
        return Err(Errno::EBADF);
    }
    let mut request = ctx.read(arg, 32)?;
    let flags = u32::from_le_bytes(request[..4].try_into().unwrap()) & ALLOCATION_FLAGS;
    let mode = i32::from_le_bytes(request[4..8].try_into().unwrap());
    let offset = i64::from_le_bytes(request[8..16].try_into().unwrap());
    let length = i64::from_le_bytes(request[16..24].try_into().unwrap());
    match mode {
        PHYSICAL_EOF if offset == 0 => {}
        VOLUME_POSITION if offset > 0 => {}
        _ => return Err(Errno::EINVAL),
    }

    let (result, allocated): (Result<(), Errno>, i64) = match file {
        EmbeddedFile::Workspace { .. } | EmbeddedFile::Resource { .. }
            if length < 0 || mode == VOLUME_POSITION =>
        {
            (Err(Errno::EINVAL), 0)
        }
        #[cfg(target_os = "macos")]
        EmbeddedFile::Workspace { .. } => {
            let (file, _) = file.workspace().ok_or(Errno::EBADF)?;
            let (result, allocated) = file.darwin_preallocate(flags, length as u64);
            (result.map_err(Errno::from), allocated)
        }
        #[cfg(target_os = "macos")]
        EmbeddedFile::Resource { fork, .. } => {
            let (result, allocated) = fork.preallocate(flags, length as u64);
            (result.map_err(Errno::from), allocated)
        }
        _ => {
            let _ = flags;
            (Err(Errno::ENOTSUP), 0)
        }
    };
    request[24..32].copy_from_slice(&allocated.to_le_bytes());
    let copyout = ctx.write(arg, &request);
    result.and(copyout).map(|()| Rv::one(0))
}

/// Closed VFS directory records and the caller's independent position and EOF
/// outputs. Directory positions belong to the open description and are opaque.
pub(super) fn getdirentries64(
    ctx: &Ctx<'_>,
    fd: i32,
    buffer: u64,
    size: u64,
    position: u64,
) -> SysResult {
    let file = ctx.proc.fds.file(fd)?;
    let FileKind::Embedded(data) = &file.kind else {
        return Err(Errno::EBADF);
    };
    if data.search_only() {
        return Err(Errno::EINVAL);
    }
    let EmbeddedFile::Supplied { entry, cursor, .. } = data else {
        return Err(if data.entry().is_some() {
            Errno::EINVAL
        } else {
            Errno::EBADF
        });
    };
    if !entry.is_dir() {
        return Err(Errno::EINVAL);
    }
    let path = file.path.as_deref().ok_or(Errno::EIO)?;
    let path = std::str::from_utf8(path).map_err(|_| Errno::EIO)?;
    let files = ctx.proc.vfs.files().ok_or(Errno::EIO)?;
    let extended = size >= EXTENDED_DIRECTORY_BUFFER;
    let payload = size - if extended { 4 } else { 0 };
    let capacity = payload.min(128 << 20) as usize;
    let mut cursor = cursor.lock().map_err(|_| Errno::EIO)?;
    let initial = *cursor;
    let mut output = Vec::new();
    let mut next = usize::try_from(initial).unwrap_or(usize::MAX);
    let mut eof = initial == END_OF_DIRECTORY;
    if !eof {
        let directory = files.directory_entries(path, entry)?;
        if !directory.is_empty() && next == 0 && capacity < 64 {
            return Err(Errno::EINVAL);
        }
        for (name, child) in directory.iter().skip(next) {
            let length = dirent_length(name.len());
            if output.len() + length > capacity {
                break;
            }
            encode_dirent(&mut output, name.as_bytes(), child, length);
            next += 1;
        }
        eof = next >= directory.len();
        if output.is_empty() && !eof {
            return Err(Errno::EINVAL);
        }
    }
    if !output.is_empty() {
        ctx.write(buffer, &output)?;
    }
    *cursor = if eof { END_OF_DIRECTORY } else { next as u64 };
    ctx.write(position, &initial.to_le_bytes())?;
    if extended {
        let flags = buffer.checked_add(payload).ok_or(Errno::EFAULT)?;
        ctx.write(flags, &u32::from(eof).to_le_bytes())?;
    }
    Ok(Rv::one(output.len() as u64))
}

fn dirent_length(name_bytes: usize) -> usize {
    // The native APFS records include padding through byte 24 before rounding
    // for the null-terminated name. The name itself starts at offset 21.
    (24 + name_bytes + 1).next_multiple_of(8)
}

fn encode_dirent(output: &mut Vec<u8>, name: &[u8], entry: &Entry, length: usize) {
    let start = output.len();
    let dtype = if entry.is_dir() {
        4
    } else if entry.link_target().is_some() {
        10
    } else if entry.device().is_some() {
        2
    } else {
        8
    };
    output.extend_from_slice(&entry.ino.to_le_bytes());
    output.extend_from_slice(&0u64.to_le_bytes()); // APFS leaves d_seekoff zero.
    output.extend_from_slice(&(length as u16).to_le_bytes());
    output.extend_from_slice(&(name.len() as u16).to_le_bytes());
    output.push(dtype);
    output.extend_from_slice(name);
    output.resize(start + length, 0);
}

fn position(offset: Option<i64>, done: u64) -> Result<Option<i64>, Errno> {
    offset
        .map(|n| n.checked_add(done as i64).ok_or(Errno::EOVERFLOW))
        .transpose()
}

/// The caller validates the vector count and aggregate byte limit. Transfers
/// use O(CHUNK) scratch space, including when an iovec spans most of IO_MAX.
pub(super) fn vector(
    ctx: &Ctx<'_>,
    file: &EmbeddedFile,
    vectors: &[(u64, u64)],
    offset: Option<i64>,
    reading: bool,
) -> SysResult {
    let transfer = if reading { read } else { write };
    // Empty vectors still validate the descriptor and positional operation.
    transfer(ctx, file, 0, 0, offset)?;
    let mut done = 0;
    for &(base, len) in vectors {
        let result = position(offset, done).and_then(|pos| transfer(ctx, file, base, len, pos));
        let n = match result {
            Ok(value) => value.0,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        done += n;
        if n < len {
            break;
        }
    }
    Ok(Rv::one(done))
}

pub(super) fn read(
    ctx: &Ctx<'_>,
    file: &EmbeddedFile,
    buf: u64,
    nbyte: u64,
    offset: Option<i64>,
) -> SysResult {
    // Validate descriptor direction and positional semantics even for an empty
    // transfer, without consuming bytes.
    file.read(&mut [], offset)?;
    if matches!(file, EmbeddedFile::Null { .. }) {
        return Ok(Rv::one(0));
    }
    ctx.space()
        .probe(buf, nbyte as usize, MemoryAccessKind::Write)
        .map_err(|_| Errno::EFAULT)?;
    let mut chunk = vec![0; (nbyte as usize).min(CHUNK)];
    let mut done = 0;
    while done < nbyte {
        let want = ((nbyte - done) as usize).min(CHUNK);
        let result = position(offset, done).and_then(|pos| file.read(&mut chunk[..want], pos));
        let n = match result {
            Ok(n) => n,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        ctx.write(buf.checked_add(done).ok_or(Errno::EFAULT)?, &chunk[..n])?;
        done += n as u64;
        if n < want {
            break;
        }
    }
    Ok(Rv::one(done))
}

pub(super) fn write(
    ctx: &Ctx<'_>,
    file: &EmbeddedFile,
    buf: u64,
    nbyte: u64,
    offset: Option<i64>,
) -> SysResult {
    if file.device_access().is_some() {
        return file.discard_device_write(nbyte, offset).map(Rv::one);
    }
    file.write(&[], offset)?;
    let mut done = 0;
    while done < nbyte {
        let want = ((nbyte - done) as usize).min(CHUNK);
        let result = (|| {
            let address = buf.checked_add(done).ok_or(Errno::EFAULT)?;
            let data = ctx.read(address, want)?;
            file.write(&data, position(offset, done)?)
        })();
        let n = match result {
            Ok(n) => n,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        done += n as u64;
        if n < want {
            break;
        }
    }
    Ok(Rv::one(done))
}
