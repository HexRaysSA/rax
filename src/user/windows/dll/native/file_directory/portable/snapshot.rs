//! Enumerate and open children relative to the still-owned directory descriptor.
use super::super::super::file_attributes::{metadata, posix};
use super::super::{Checked, Ctx};
use crate::user::windows::objects::{DirectoryEntry, Object};
use std::ffi::CStr;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::fs::MetadataExt;

struct Directory(*mut libc::DIR);
impl Drop for Directory {
    fn drop(&mut self) {
        // SAFETY: fdopendir transferred this unique nonnull stream; no borrow
        // or kernel operation survives snapshot collection or its error paths.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

fn reset_errno() {
    // SAFETY: each platform returns this thread's live writable errno slot.
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location() = 0;
    }
    #[cfg(target_os = "macos")]
    unsafe {
        *libc::__error() = 0;
    }
}

pub(super) fn collect(c: &Ctx, handle: u64) -> Checked<Vec<DirectoryEntry>> {
    let Some(Object::File(file)) = c.p.objects.get(handle) else {
        return Err(c
            .unsupported("directory object disappeared during capture")
            .into());
    };
    let retained = file
        .host
        .as_ref()
        .ok_or_else(|| c.unsupported("mapped directory requires a retained descriptor"))?;
    let duplicate = retained
        .try_clone()
        .map_err(|error| c.unsupported(format!("duplicate directory descriptor: {error}")))?;
    // SAFETY: the borrowed duplicate is a live directory descriptor. A nonnull
    // result takes ownership; on failure the File below still owns its fd.
    let stream = unsafe { libc::fdopendir(duplicate.as_raw_fd()) };
    if stream.is_null() {
        return Err(c
            .unsupported(format!(
                "retained fdopendir: {}",
                std::io::Error::last_os_error()
            ))
            .into());
    }
    let _ = duplicate.into_raw_fd();
    let directory = Directory(stream);
    // SAFETY: exclusively owned directory stream; its descriptor remains live.
    unsafe {
        libc::rewinddir(directory.0);
    }
    let mut entries = Vec::new();
    let mut bytes = 0usize;
    loop {
        reset_errno();
        // SAFETY: this exclusive stream stays live. The returned dirent is
        // consumed before the next readdir or stream destruction.
        let entry = unsafe { libc::readdir(directory.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(c.unsupported(format!("retained readdir: {error}")).into());
            }
            break;
        }
        // SAFETY: successful readdir supplies a NUL-terminated d_name whose
        // storage remains live until the next readdir on this same stream.
        let native_name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let name = native_name
            .to_str()
            .map_err(|_| c.unsupported("directory entry has no UTF-8 Windows mapping"))?;
        let units: Vec<_> = name.encode_utf16().collect();
        bytes = bytes
            .checked_add(256 + units.len() * 2)
            .ok_or_else(|| c.unsupported("directory snapshot size overflow"))?;
        if bytes > 16 << 20 || entries.len() >= 65536 {
            return Err(c
                .unsupported("directory snapshot exceeds 16 MiB or 65536 entries")
                .into());
        }
        #[cfg(target_os = "linux")]
        let flags = libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        #[cfg(target_os = "macos")]
        let flags = libc::O_EVTONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        // SAFETY: retained directory fd and terminated dirent name stay live.
        // Metadata-only flags cannot block on a FIFO or open a replacement path
        // through the old absolute directory name. A new fd is owned below.
        let descriptor = unsafe { libc::openat(retained.as_raw_fd(), native_name.as_ptr(), flags) };
        if descriptor < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                continue;
            }
            return Err(c
                .unsupported(format!("retained directory child open: {error}"))
                .into());
        }
        // SAFETY: successful openat transferred one fresh descriptor.
        let child = unsafe { File::from_raw_fd(descriptor) };
        let stat = child
            .metadata()
            .map_err(|error| c.unsupported(format!("directory child identity: {error}")))?;
        let info = metadata::descriptor(c, &file.host_path.join(name), &child)?;
        let ea = posix::directory_ea(&child)
            .map_err(|error| c.unsupported(format!("directory child Windows EAs: {error}")))?;
        bytes = bytes
            .checked_add(ea.as_ref().map_or(0, Vec::len))
            .filter(|&bytes| bytes <= 16 << 20)
            .ok_or_else(|| c.unsupported("directory snapshot including EAs exceeds 16 MiB"))?;
        entries.push(DirectoryEntry {
            name: units,
            short_name: Vec::new(),
            times: info.times,
            allocation: info.allocation,
            size: info.size,
            attributes: info.attributes,
            ea,
            file_id: stat.ino(),
        });
    }
    Ok(entries)
}
