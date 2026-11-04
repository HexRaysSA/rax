//! Descriptor-owned NT metadata on POSIX filesystems. Private xattrs retain
//! attributes and EAs across close/reopen; allocation does not change EOF.
//!
//! Both records start with `RAX\x01`. Attribute payloads are one little-endian
//! ULONG; EA payloads are validated FILE_FULL_EA_INFORMATION bytes. An unknown
//! or malformed record is an error, never silently treated as absent.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const MAGIC: &[u8; 4] = b"RAX\x01";
const ATTRIBUTES: &CStr = c"user.rax.windows.attributes";
const EA: &CStr = c"user.rax.windows.ea";

enum Source<'a> {
    File(&'a File),
    Path(&'a CStr),
}

fn get(source: Source<'_>, key: &CStr, maximum: usize) -> io::Result<Option<Vec<u8>>> {
    let mut raw = vec![0; maximum];
    // SAFETY: the file, terminated key and exclusive writable buffer remain
    // live for the synchronous call; neither platform retains these pointers.
    #[cfg(target_os = "linux")]
    let length = unsafe {
        match source {
            Source::File(file) => get_file(file, key, &mut raw),
            Source::Path(path) => libc::getxattr(
                path.as_ptr(),
                key.as_ptr(),
                raw.as_mut_ptr().cast(),
                raw.len(),
            ),
        }
    };
    #[cfg(target_os = "macos")]
    let length = unsafe {
        match source {
            Source::File(file) => libc::fgetxattr(
                file.as_raw_fd(),
                key.as_ptr(),
                raw.as_mut_ptr().cast(),
                raw.len(),
                0,
                0,
            ),
            Source::Path(path) => libc::getxattr(
                path.as_ptr(),
                key.as_ptr(),
                raw.as_mut_ptr().cast(),
                raw.len(),
                0,
                0,
            ),
        }
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let length = {
        let _ = (source, key);
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    };
    if length < 0 {
        let error = io::Error::last_os_error();
        #[cfg(target_os = "linux")]
        let absent = error.raw_os_error() == Some(libc::ENODATA);
        #[cfg(target_os = "macos")]
        let absent = error.raw_os_error() == Some(libc::ENOATTR);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let absent = false;
        return if absent { Ok(None) } else { Err(error) };
    }
    raw.truncate(length as usize);
    if !raw.starts_with(MAGIC) {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(Some(raw.split_off(4)))
}

#[cfg(target_os = "linux")]
fn get_file(file: &File, key: &CStr, raw: &mut [u8]) -> isize {
    // SAFETY: file and key are live; raw is exclusive writable storage.
    let length = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            key.as_ptr(),
            raw.as_mut_ptr().cast(),
            raw.len(),
        )
    };
    if length >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
        return length;
    }
    // Linux rejects fgetxattr on O_PATH references used by metadata-only
    // traversal. Follow the live descriptor's proc link, never its original
    // pathname: rename, replacement and unlink must not select another inode.
    // SAFETY: F_GETFL reads flags from the borrowed descriptor.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) } & libc::O_PATH == 0 {
        return length;
    }
    let path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
    // SAFETY: the descriptor remains owned throughout this synchronous call;
    // both strings are terminated and raw is a valid writable buffer.
    unsafe {
        libc::getxattr(
            path.as_ptr(),
            key.as_ptr(),
            raw.as_mut_ptr().cast(),
            raw.len(),
        )
    }
}

fn set(file: &File, key: &CStr, payload: &[u8]) -> io::Result<()> {
    let mut raw = Vec::with_capacity(4 + payload.len());
    raw.extend_from_slice(MAGIC);
    raw.extend_from_slice(payload);
    // SAFETY: the owned file, terminated key and immutable record remain live
    // for the call. The length describes the entire initialized byte slice.
    #[cfg(target_os = "linux")]
    let code = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            key.as_ptr(),
            raw.as_ptr().cast(),
            raw.len(),
            0,
        )
    };
    #[cfg(target_os = "macos")]
    let code = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            key.as_ptr(),
            raw.as_ptr().cast(),
            raw.len(),
            0,
            0,
        )
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let code = {
        let _ = (file, key);
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    };
    if code < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(in super::super) fn attributes(file: &File) -> io::Result<Option<u32>> {
    decode_attributes(get(Source::File(file), ATTRIBUTES, 8)?)
}

/// Captured Windows EA records; unrelated host xattrs are never enumerated.
pub(in super::super) fn directory_ea(file: &File) -> io::Result<Option<Vec<u8>>> {
    get(Source::File(file), EA, 65540)
}

pub(in super::super) fn attributes_path(path: &Path) -> io::Result<Option<u32>> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    decode_attributes(get(Source::Path(&path), ATTRIBUTES, 8)?)
}

fn decode_attributes(raw: Option<Vec<u8>>) -> io::Result<Option<u32>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let bytes: [u8; 4] = raw
        .try_into()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let value = u32::from_le_bytes(bytes);
    if value & !0x137 != 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(Some(value))
}

pub(in super::super) fn set_attributes(file: &File, attributes: u32) -> io::Result<()> {
    set(file, ATTRIBUTES, &attributes.to_le_bytes())?;
    if attributes & 1 != 0 {
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(permissions.mode() & !0o222);
        file.set_permissions(permissions)?;
    }
    Ok(())
}

pub(in super::super) fn set_ea(file: &File, captured: &[u8]) -> io::Result<()> {
    if captured.len() > 65536 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut canonical = captured.to_vec();
    if !canonical.is_empty() {
        let mut at = 0;
        loop {
            let header = canonical
                .get(at..at + 8)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
            let next = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
            let name = usize::from(header[5]);
            let value = usize::from(u16::from_le_bytes(header[6..8].try_into().unwrap()));
            let end = at + 8 + name + 1 + value;
            if end > canonical.len() || canonical[at + 8 + name] != 0 {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            canonical[at + 8..at + 8 + name].make_ascii_uppercase();
            if next == 0 {
                canonical.truncate(end);
                break;
            }
            if next % 4 != 0 || next < end - at || next > canonical.len() - at {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            at += next;
        }
    }
    set(file, EA, &canonical)
}

pub(in super::super) fn reserve(file: &File, bytes: i64) -> io::Result<()> {
    if bytes == 0 {
        return Ok(());
    }
    if bytes < 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    #[cfg(target_os = "linux")]
    // SAFETY: a live file descriptor, KEEP_SIZE mode, offset zero, and a
    // positive representable length; the logical EOF remains unchanged.
    let code = unsafe { libc::fallocate(file.as_raw_fd(), libc::FALLOC_FL_KEEP_SIZE, 0, bytes) };
    #[cfg(target_os = "macos")]
    let code = {
        let mut store = libc::fstore_t {
            fst_flags: libc::F_ALLOCATEALL,
            fst_posmode: libc::F_PEOFPOSMODE,
            fst_offset: 0,
            fst_length: bytes,
            fst_bytesalloc: 0,
        };
        // SAFETY: fstore_t has the native fcntl layout and exclusive local
        // storage. F_PREALLOCATE reserves physical space without extending EOF.
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &mut store) }
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let code = {
        let _ = file;
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    };
    if code < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
