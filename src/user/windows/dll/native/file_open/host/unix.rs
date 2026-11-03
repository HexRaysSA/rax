use super::{Acquired, Checked, Ctx, FileIdentity, io_error, status};
use crate::user::windows::dll::native::file_attributes::path::Resolved;
use crate::user::windows::dll::native::file_attributes::path::unix as relative;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

mod create;
pub(super) use create::create;

pub(super) fn open(
    c: &Ctx,
    path: &Resolved,
    access: u32,
    options: u32,
    flags: u32,
) -> Checked<Acquired> {
    if flags & 0x1000 != 0 && path.relative.is_none() {
        let mut part = Some(path.host.as_path());
        while let Some(p) = part {
            if p == path.base {
                break;
            }
            if std::fs::symlink_metadata(p).is_ok_and(|m| m.is_symlink()) {
                return status(0xc000_050b);
            }
            part = p.parent();
        }
    }
    let write = access & 6 != 0;
    let read = access & 0x21 != 0 || !write;
    let mut native_flags = libc::O_CLOEXEC;
    if options & 1 != 0 {
        native_flags |= libc::O_DIRECTORY;
    }
    if options & 2 != 0 {
        native_flags |= libc::O_SYNC;
    }
    #[cfg(target_os = "linux")]
    if options & 8 != 0 {
        native_flags |= libc::O_DIRECT;
    }
    let mut opts = OpenOptions::new();
    opts.read(read)
        .write(write)
        .append(access & 4 != 0 && access & 2 == 0)
        .custom_flags(native_flags);
    let opened = if path.relative.is_some() {
        relative::open(
            c,
            path,
            native_flags,
            read,
            write,
            access & 4 != 0 && access & 2 == 0,
            flags,
        )
    } else {
        opts.open(&path.host).map(|file| (file, path.host.clone()))
    };
    let (file, host_path) = match opened {
        Ok(file) => file,
        Err(error) if relative::nt_status(&error).is_some() => {
            return status(relative::nt_status(&error).unwrap());
        }
        Err(e)
            if e.kind() == std::io::ErrorKind::NotADirectory
                && options & 1 != 0
                && path.host.parent().is_some_and(|p| p.is_dir()) =>
        {
            return status(0xc000_0103);
        }
        Err(e) => return io_error(c, e, &path.host),
    };
    let metadata = file
        .metadata()
        .map_err(|e| c.unsupported(format!("opened file metadata: {e}")))?;
    let directory = metadata.is_dir();
    if options & 1 != 0 && !directory {
        return status(0xc000_0103);
    }
    if options & 0x40 != 0 && directory {
        return status(0xc000_00ba);
    }
    if path.directory && !directory {
        return status(0xc000_0103);
    }
    if !metadata.is_file() && !directory {
        return Err(c
            .unsupported("NT open for a non-regular mapped object")
            .into());
    }
    let identity = FileIdentity::of(&host_path, &metadata)
        .map_err(|e| c.unsupported(format!("opened file identity: {e}")))?;
    Ok(Acquired {
        file,
        path: host_path,
        identity,
        directory,
        access,
        information: 1,
    })
}
