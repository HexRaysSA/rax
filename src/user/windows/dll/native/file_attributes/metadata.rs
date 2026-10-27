//! Native host metadata is translated into the common NT record once.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use super::super::named_object::{Checked, status};
use super::path::Resolved;
use crate::user::windows::fs::FileIdentity;
use crate::user::windows::hle::Ctx;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_INSUFFICIENT_RESOURCES, STATUS_NOT_A_DIRECTORY,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_REPARSE_POINT_ENCOUNTERED,
};
use crate::user::windows::objects::Object;
use std::path::Path;

pub(super) struct Information {
    pub(super) times: [u64; 4],
    pub(super) allocation: u64,
    pub(super) size: u64,
    pub(super) attributes: u32,
}

pub(super) fn io_error(c: &Ctx, error: std::io::Error, path: &Path) -> Checked<Information> {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::NotFound | ErrorKind::NotADirectory => {
            status(if path.parent().is_some_and(|parent| !parent.is_dir()) {
                STATUS_OBJECT_PATH_NOT_FOUND
            } else {
                STATUS_OBJECT_NAME_NOT_FOUND
            })
        }
        ErrorKind::PermissionDenied => status(STATUS_ACCESS_DENIED),
        ErrorKind::OutOfMemory => status(STATUS_INSUFFICIENT_RESOURCES),
        _ => Err(c.unsupported(format!("host file metadata: {error}")).into()),
    }
}

pub(super) fn query(c: &Ctx, resolved: &Resolved, no_reparse: bool) -> Checked<Information> {
    if no_reparse && resolved.relative.is_none() {
        let mut parent = Some(resolved.host.as_path());
        while let Some(path) = parent {
            // The selected/mapped root is already an admitted namespace
            // boundary. Only components supplied by this query are reparsed.
            if path == resolved.base {
                break;
            }
            if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_symlink()) {
                return status(STATUS_REPARSE_POINT_ENCOUNTERED);
            }
            parent = path.parent();
        }
    }
    let file = if let Some(handle) = resolved.root {
        let Some(Object::File(file)) = c.p.objects.get(handle) else {
            return Err(c
                .unsupported("file metadata root changed during synchronous query")
                .into());
        };
        if file.host.is_none() {
            if let Ok(metadata) = std::fs::metadata(&file.host_path)
                && FileIdentity::of(&file.host_path, &metadata)
                    .is_ok_and(|identity| identity != file.lifetime.identity)
            {
                return Err(c
                    .unsupported("metadata-only root file pathname was replaced")
                    .into());
            }
        }
        file.host.as_ref()
    } else {
        None
    };
    #[cfg(windows)]
    let info = windows::query(
        c,
        &resolved.host,
        file,
        resolved.relative.as_deref(),
        no_reparse,
    )?;
    #[cfg(unix)]
    let info = {
        let child = if resolved
            .relative
            .as_ref()
            .is_some_and(|name| !name.as_os_str().is_empty())
        {
            #[cfg(target_os = "linux")]
            let flags = libc::O_PATH | libc::O_CLOEXEC;
            #[cfg(target_os = "macos")]
            let flags = libc::O_EVTONLY | libc::O_CLOEXEC;
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            let flags = libc::O_RDONLY | libc::O_CLOEXEC;
            match super::path::unix::open(
                c,
                resolved,
                flags,
                false,
                false,
                false,
                if no_reparse { 0x1000 } else { 0 },
            ) {
                Ok((file, _)) => Some(file),
                Err(error) if super::path::unix::nt_status(&error).is_some() => {
                    return status(super::path::unix::nt_status(&error).unwrap());
                }
                Err(error) => return io_error(c, error, &resolved.host),
            }
        } else {
            None
        };
        unix::query(c, &resolved.host, child.as_ref().or(file))?
    };
    #[cfg(not(any(windows, unix)))]
    return Err(c
        .unsupported("host file metadata has no platform adapter")
        .into());
    #[cfg(any(windows, unix))]
    {
        if resolved.directory && info.attributes & 0x10 == 0 {
            return status(STATUS_NOT_A_DIRECTORY);
        }
        Ok(info)
    }
}
