//! fdescfs opens name guest descriptor slots, including through host aliases.
use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::io;
use crate::user::darwin::syscall::Ctx;

/// `dupfdopen`: preserve descriptor flags and the shared open description.
pub(crate) fn open_descriptor(ctx: &mut Ctx<'_>, fd: i32, flags: u32) -> SysResult {
    let access = flags & io::O_ACCMODE;
    if access == 3 {
        return Err(Errno::EINVAL);
    }
    // fdescfs directory entries are not directory vnodes, even for a DIR fd.
    if flags & io::O_CREAT != 0 && flags & io::O_EXCL != 0 {
        return Err(Errno::EEXIST);
    }
    if flags & io::O_DIRECTORY != 0 {
        return Err(Errno::ENOTDIR);
    }
    let limit = ctx.proc.rlimits[8].0;
    ctx.proc.fds.lowest_free(0, limit)?;
    let source = ctx.proc.fds.get(fd)?.clone();
    if source
        .guard
        .is_some_and(|guard| guard.attributes & super::super::guarded::DUP != 0)
    {
        // dupfdopen refuses this without posting the fatal dup exception.
        return Err(Errno::EPERM);
    }
    let original = *source.file.flags.lock().map_err(|_| Errno::EIO)?;
    if original & io::O_SYMLINK != 0 && flags & io::O_SYMLINK == 0 {
        return Err(Errno::ELOOP);
    }
    let permissions = |mode| match mode {
        io::O_RDONLY => 1,
        io::O_WRONLY => 2,
        _ => 3,
    };
    if permissions(access) & !permissions(original & io::O_ACCMODE) != 0 {
        return Err(Errno::EACCES);
    }
    let descriptor = ctx.proc.fds.install_with(
        source.file,
        source.cloexec || flags & io::O_CLOEXEC != 0,
        source.clofork || flags & io::O_CLOFORK != 0,
        0,
        limit,
    )?;
    Ok(Rv::one(descriptor as u64))
}

/// Resolve host fdescfs aliases without opening a descriptor in the host table.
#[cfg(unix)]
pub(super) fn number(path: &std::ffi::CStr, directory: i32, flags: u32) -> Option<i32> {
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    let native_directory = std::fs::canonicalize("/dev/fd").ok()?;
    let mut path = PathBuf::from(std::ffi::OsStr::from_bytes(path.to_bytes()));
    if !path.is_absolute() {
        let base = if directory == libc::AT_FDCWD {
            std::env::current_dir().ok()?
        } else {
            PathBuf::from(std::ffi::OsStr::from_bytes(
                &crate::user::darwin::host::fd_path(directory)?,
            ))
        };
        path = base.join(path);
    }
    for _ in 0..32 {
        let parent = path.parent()?;
        if flags & io::O_NOFOLLOW_ANY != 0 {
            let mut prefix = PathBuf::new();
            for component in parent.components() {
                prefix.push(component.as_os_str());
                if std::fs::symlink_metadata(&prefix).is_ok_and(|meta| meta.is_symlink()) {
                    // Let the native open report ELOOP before guard lookup.
                    return None;
                }
            }
        }
        if std::fs::canonicalize(parent).ok().as_deref() == Some(native_directory.as_path()) {
            let name = path.file_name()?.as_bytes();
            if name.is_empty() || !name.iter().all(u8::is_ascii_digit) {
                return None;
            }
            return std::str::from_utf8(name).ok()?.parse().ok();
        }
        // A request for the final link itself remains an ordinary host open.
        if flags & (io::O_SYMLINK | io::O_NOFOLLOW | io::O_NOFOLLOW_ANY) != 0 {
            return None;
        }
        let target = std::fs::read_link(&path).ok()?;
        path = if target.is_absolute() {
            target
        } else {
            parent.join(target)
        };
        // Preserve native paths; guest URL and IPC grammars never reach here.
        if path == Path::new("/") {
            return None;
        }
    }
    None
}
