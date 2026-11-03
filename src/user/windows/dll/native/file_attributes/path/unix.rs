//! Descriptor-relative traversal preserves a retained directory across rename.
use crate::user::windows::dll::native::file_attributes::path::{Resolved, equal};
use crate::user::windows::hle::Ctx;
use crate::user::windows::objects::Object;
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct LookupError {
    status: u32,
    source: io::Error,
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(f)
    }
}

impl std::error::Error for LookupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn failed(code: u32, source: io::Error) -> io::Error {
    io::Error::new(
        source.kind(),
        LookupError {
            status: code,
            source,
        },
    )
}

pub(in crate::user::windows::dll::native) fn nt_status(error: &io::Error) -> Option<u32> {
    error
        .get_ref()?
        .downcast_ref::<LookupError>()
        .map(|e| e.status)
}

fn at(directory: &File, name: &CStr, flags: i32) -> io::Result<File> {
    // SAFETY: the descriptor and NUL-terminated name are borrowed for this
    // synchronous call. O_CREAT is never supplied; no mode argument is read.
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: openat returned a fresh descriptor owned exactly once.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn spelling(c: &Ctx, directory: &File, component: &OsStr) -> io::Result<CString> {
    let exact = CString::new(component.as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat writes into an adequately sized local buffer. The result is
    // used only as an existence test, without following a final symbolic link.
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            exact.as_ptr(),
            info.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(exact);
    }
    let Some(component) = component.to_str() else {
        return Ok(exact);
    };
    let wanted: Vec<u16> = component.encode_utf16().collect();
    let dot = c".";
    let scan = at(
        directory,
        dot,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    )?;
    let fd = scan.into_raw_fd();
    // SAFETY: the fresh directory descriptor is transferred to DIR on success.
    let raw = unsafe { libc::fdopendir(fd) };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed, so ownership did not transfer.
        drop(unsafe { File::from_raw_fd(fd) });
        return Err(error);
    }
    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            // SAFETY: this guard uniquely owns the live DIR and its descriptor.
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let directory = Directory(raw);
    let mut found = None;
    loop {
        #[cfg(target_os = "linux")]
        // SAFETY: errno is thread-local; this thread exclusively owns DIR.
        unsafe {
            *libc::__errno_location() = 0;
        }
        #[cfg(target_os = "macos")]
        // SAFETY: errno is thread-local; this thread exclusively owns DIR.
        unsafe {
            *libc::__error() = 0;
        }
        // SAFETY: readdir's borrowed record is consumed before the next call.
        let entry = unsafe { libc::readdir(directory.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error().is_some_and(|code| code != 0) {
                return Err(error);
            }
            break;
        }
        // SAFETY: a successful readdir supplies a terminated d_name array.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let Ok(text) = name.to_str() else {
            continue;
        };
        if equal(c, &wanted, &text.encode_utf16().collect::<Vec<_>>()) {
            if found.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "ambiguous case-insensitive retained directory entry",
                ));
            }
            found = Some(name.to_owned());
        }
    }
    Ok(found.unwrap_or(exact))
}

fn current(file: &File) -> io::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
    }
    #[cfg(target_os = "macos")]
    {
        let mut bytes = [0u8; libc::PATH_MAX as usize];
        // SAFETY: F_GETPATH writes at most PATH_MAX bytes into this local buffer.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, bytes.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let length = bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        Ok(Path::new(OsStr::from_bytes(&bytes[..length])).to_path_buf())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = file;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Pins the parent directory before any create/overwrite. The returned path is
/// bookkeeping; all namespace effects must use the returned directory and name.
pub(in crate::user::windows::dll::native) fn parent(
    c: &Ctx,
    path: &Resolved,
    attributes: u32,
) -> io::Result<(File, CString, PathBuf)> {
    let Some(relative) = &path.relative else {
        if attributes & 0x1000 != 0 {
            let mut part = Some(path.host.as_path());
            while let Some(p) = part {
                if p == path.base {
                    break;
                }
                if std::fs::symlink_metadata(p).is_ok_and(|m| m.is_symlink()) {
                    return Err(failed(
                        0xc000_050b,
                        io::Error::from_raw_os_error(libc::ELOOP),
                    ));
                }
                part = p.parent();
            }
        }
        let parent = path
            .host
            .parent()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(parent)?;
        let name = CString::new(
            path.host
                .file_name()
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?
                .as_bytes(),
        )
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        return Ok((file, name, path.host.clone()));
    };
    let root = path
        .root
        .and_then(|h| c.p.objects.get(h))
        .and_then(|o| match o {
            Object::File(f) => f.host.as_ref(),
            _ => None,
        })
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut actual = current(root).or_else(|error| {
        if root.metadata()?.is_dir() {
            Ok(path.base.clone())
        } else {
            Err(error)
        }
    })?;
    let parts: Vec<_> = relative.components().collect();
    let mut directory = root.try_clone()?;
    for (i, part) in parts.iter().enumerate() {
        let name = spelling(c, &directory, part.as_os_str())?;
        actual.push(OsStr::from_bytes(name.to_bytes()));
        if i + 1 == parts.len() {
            return Ok((directory, name, actual));
        }
        let flags = libc::O_RDONLY
            | libc::O_DIRECTORY
            | libc::O_CLOEXEC
            | if attributes & 0x1000 != 0 {
                libc::O_NOFOLLOW
            } else {
                0
            };
        directory = at(&directory, &name, flags).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => failed(0xc000_003a, e),
            _ => e,
        })?;
    }
    Ok((directory, c".".to_owned(), actual))
}

pub(in crate::user::windows::dll::native) fn open(
    c: &Ctx,
    path: &Resolved,
    flags: i32,
    read: bool,
    write: bool,
    append: bool,
    attributes: u32,
) -> io::Result<(File, PathBuf)> {
    let root = path
        .root
        .and_then(|handle| c.p.objects.get(handle))
        .and_then(|object| match object {
            Object::File(file) => file.host.as_ref(),
            _ => None,
        })
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let relative = path.relative.as_ref().expect("retained child path");
    let metadata = root.metadata()?;
    // A directory traversal needs only openat, including on Linux hosts with
    // no mounted /proc. Its spelling is bookkeeping, never lookup authority.
    let mut actual = current(root).or_else(|error| {
        if metadata.is_dir() {
            Ok(path.base.clone())
        } else {
            Err(error)
        }
    })?;
    if relative.as_os_str().is_empty() && !metadata.is_dir() {
        // POSIX has no portable reopen-by-file-ID call. Revalidate identity
        // after reopening the vnode's current spelling, never a replaced path.
        let file = std::fs::OpenOptions::new()
            .read(read)
            .write(write)
            .append(append)
            .custom_flags(flags)
            .open(&actual)?;
        use std::os::unix::fs::MetadataExt;
        let a = root.metadata()?;
        let b = file.metadata()?;
        if a.dev() != b.dev() || a.ino() != b.ino() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "retained file was replaced during reopen",
            ));
        }
        return Ok((file, actual));
    }
    let access = if read && write {
        libc::O_RDWR
    } else if write {
        libc::O_WRONLY
    } else {
        libc::O_RDONLY
    };
    let access = access | if append { libc::O_APPEND } else { 0 };
    let parts: Vec<_> = relative.components().collect();
    let mut directory = root.try_clone()?;
    if parts.is_empty() {
        return at(&directory, c".", flags | access).map(|file| (file, actual));
    }
    for (index, part) in parts.iter().enumerate() {
        let name = spelling(c, &directory, part.as_os_str())?;
        let last = index + 1 == parts.len();
        let mut native = if last {
            flags | access
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC
        };
        if attributes & 0x1000 != 0 {
            let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: this no-follow lookup writes one initialized stat record
            // on success and never follows the component being checked.
            if unsafe {
                libc::fstatat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    info.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0
            {
                // SAFETY: the preceding successful fstatat initialized info.
                if unsafe { info.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFLNK {
                    return Err(failed(
                        0xc000_050b,
                        io::Error::from_raw_os_error(libc::ELOOP),
                    ));
                }
            }
            native |= libc::O_NOFOLLOW;
        }
        directory = at(&directory, &name, native).map_err(|error| {
            let code = match error.kind() {
                io::ErrorKind::NotFound => {
                    if last {
                        0xc000_0034
                    } else {
                        0xc000_003a
                    }
                }
                io::ErrorKind::NotADirectory => {
                    if last && flags & libc::O_DIRECTORY != 0 {
                        0xc000_0103
                    } else {
                        0xc000_003a
                    }
                }
                _ => return error,
            };
            failed(code, error)
        })?;
        actual.push(OsStr::from_bytes(name.to_bytes()));
    }
    Ok((directory, actual))
}

use std::os::unix::fs::OpenOptionsExt;
