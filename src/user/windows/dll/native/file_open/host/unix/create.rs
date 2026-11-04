//! POSIX creates retain directory authority and check sharing before truncation.
use super::{Acquired, Checked, Ctx, FileIdentity, io_error, relative, status};
use crate::user::windows::dll::native::file_attributes::path::Resolved;
use crate::user::windows::dll::native::file_attributes::posix;
use crate::user::windows::dll::native::file_open::{host::Creation, shared_lifetime};
use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};

fn at(directory: &File, name: &CStr, flags: i32) -> io::Result<File> {
    // SAFETY: live owned directory, terminated child name, and an explicit mode
    // for O_CREAT. Every returned descriptor is transferred exactly once.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags,
            0o666 as libc::c_uint,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn prepare(c: &Ctx, request: &Creation) -> Checked<()> {
    let mut at = 0;
    while at < request.ea.len() {
        let name_bytes = usize::from(request.ea[at + 5]);
        let name = &request.ea[at + 8..at + 8 + name_bytes];
        if request.ea[at + 4] != 0 || name.is_empty() || !name.is_ascii() {
            return Err(c
                .unsupported(
                    "NT create EA flags or non-ASCII names require an additional POSIX adapter",
                )
                .into());
        }
        let next = u32::from_le_bytes(request.ea[at..at + 4].try_into().unwrap()) as usize;
        if next == 0 {
            break;
        }
        at += next;
    }
    if request.attributes & !(0x127 | 0x80 | 0x10) != 0 {
        return Err(c
            .unsupported("requested NT create attribute has no qualified POSIX representation")
            .into());
    }
    Ok(())
}

fn initialize(c: &Ctx, file: &File, request: &Creation, directory: bool) -> Checked<()> {
    if !directory {
        posix::reserve(file, request.allocation.unwrap_or(0))
            .map_err(|e| c.unsupported(format!("NT allocation reservation: {e}")))?;
    }
    // The measured filesystem replaces the complete EA list on both supersede
    // and overwrite, including removing it when no list was supplied.
    posix::set_ea(file, &request.ea)
        .map_err(|e| c.unsupported(format!("NT EA replacement: {e}")))?;
    let prior = if matches!(request.disposition, 4 | 5) {
        posix::attributes(file)
            .map_err(|e| c.unsupported(format!("NT prior attributes: {e}")))?
            .unwrap_or(0)
    } else {
        0
    };
    let attributes = (prior | request.attributes) & 0x127 | if directory { 0x10 } else { 0x20 };
    posix::set_attributes(file, attributes)
        .map_err(|e| c.unsupported(format!("NT create attributes: {e}")))?;
    Ok(())
}

pub(in super::super) fn create(
    c: &Ctx,
    path: &Resolved,
    access: u32,
    share: u32,
    options: u32,
    flags: u32,
    request: Creation,
) -> Checked<Acquired> {
    // OPEN neither changes allocation nor applies the supplied EA/attributes.
    if request.disposition == 1 {
        return super::open(c, path, access, options, flags);
    }
    let (parent, name, host_path) = match relative::parent(c, path, flags) {
        Ok(v) => v,
        Err(e) if relative::nt_status(&e).is_some() => {
            return status(relative::nt_status(&e).unwrap());
        }
        Err(e) => return io_error(c, e, &path.host),
    };
    let overwrite = matches!(request.disposition, 0 | 4 | 5);
    let write = access & 6 != 0 || overwrite;
    let read = access & 0x21 != 0 || !write;
    let mut native = libc::O_CLOEXEC
        | if read && write {
            libc::O_RDWR
        } else if write {
            libc::O_WRONLY
        } else {
            libc::O_RDONLY
        };
    if options & 2 != 0 {
        native |= libc::O_SYNC;
    }
    if flags & 0x1000 != 0 {
        native |= libc::O_NOFOLLOW;
    }
    let mut acquired = None;
    for _ in 0..8 {
        let old = if request.disposition == 2 {
            None
        } else {
            match at(&parent, &name, native) {
                Ok(f) => Some(f),
                Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                Err(e) => return io_error(c, e, &host_path),
            }
        };
        if let Some(file) = old {
            let metadata = file
                .metadata()
                .map_err(|e| c.unsupported(format!("NT create metadata: {e}")))?;
            let directory = metadata.is_dir();
            if options & 1 != 0 && !directory {
                return status(0xc000_0103);
            }
            if options & 0x40 != 0 && directory {
                return status(0xc000_00ba);
            }
            if directory && overwrite {
                return status(0xc000_00ba);
            }
            if !directory && !metadata.is_file() {
                return Err(c
                    .unsupported("NT create of non-regular POSIX object")
                    .into());
            }
            let identity = FileIdentity::of(&host_path, &metadata)
                .map_err(|e| c.unsupported(format!("NT create identity: {e}")))?;
            let operation_access = access
                | if request.disposition == 0 {
                    0x10000
                } else if overwrite {
                    2
                } else {
                    0
                };
            shared_lifetime(c, &identity, operation_access, share)?;
            if overwrite && metadata.permissions().readonly() {
                return status(0xc000_0022);
            }
            if overwrite {
                if crate::user::windows::object_namespace::file_data::is_live(c.p, &identity) {
                    return Err(c.unsupported("overwriting a file with live data sections requires the section-resize contract").into());
                }
                prepare(c, &request)?;
                file.set_len(0)
                    .map_err(|e| c.unsupported(format!("NT overwrite: {e}")))?;
                initialize(c, &file, &request, false)?;
            }
            acquired = Some(Acquired {
                file,
                path: host_path.clone(),
                identity,
                directory,
                access,
                information: if request.disposition == 0 {
                    0
                } else if overwrite {
                    3
                } else {
                    1
                },
            });
            break;
        }
        if request.disposition == 4 {
            return status(0xc000_0034);
        }
        prepare(c, &request)?;
        if options & 1 != 0 {
            // SAFETY: the parent and terminated child name are live; mode is
            // an ordinary directory permission mask subject to the host umask.
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o777) } < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::AlreadyExists && request.disposition != 2 {
                    continue;
                }
                return io_error(c, e, &host_path);
            }
            let file = at(
                &parent,
                &name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
            .map_err(|e| c.unsupported(format!("retained newly created directory: {e}")))?;
            let metadata = file
                .metadata()
                .map_err(|e| c.unsupported(format!("new directory identity: {e}")))?;
            let identity = FileIdentity::of(&host_path, &metadata)
                .map_err(|e| c.unsupported(format!("new directory identity: {e}")))?;
            initialize(c, &file, &request, true)?;
            acquired = Some(Acquired {
                file,
                path: host_path.clone(),
                identity,
                directory: true,
                access,
                information: 2,
            });
            break;
        }
        // Creation itself needs a writable descriptor even for a read-only
        // result grant. Subsequent guest I/O remains gated by `access`.
        match at(
            &parent,
            &name,
            (native & !libc::O_ACCMODE) | libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        ) {
            Ok(file) => {
                let metadata = file
                    .metadata()
                    .map_err(|e| c.unsupported(format!("new NT file metadata: {e}")))?;
                let identity = FileIdentity::of(&host_path, &metadata)
                    .map_err(|e| c.unsupported(format!("new NT file identity: {e}")))?;
                initialize(c, &file, &request, false)?;
                acquired = Some(Acquired {
                    file,
                    path: host_path.clone(),
                    identity,
                    directory: false,
                    access,
                    information: 2,
                });
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && request.disposition != 2 => {
                continue;
            }
            Err(e) => return io_error(c, e, &host_path),
        }
    }
    acquired.ok_or_else(|| {
        c.unsupported("NT create namespace changed during every bounded retry")
            .into()
    })
}
