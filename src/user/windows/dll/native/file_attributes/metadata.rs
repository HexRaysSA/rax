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

pub(in super::super) struct Information {
    pub(in super::super) times: [u64; 4],
    pub(in super::super) allocation: u64,
    pub(in super::super) size: u64,
    pub(in super::super) attributes: u32,
}

pub(in super::super) fn guest_directory() -> Information {
    Information {
        times: [0; 4],
        allocation: 0,
        size: 0,
        attributes: 0x10, // FILE_ATTRIBUTE_DIRECTORY
    }
}

/// Metadata for an entry obtained from an already admitted file object.
pub(in super::super) fn descriptor(
    c: &Ctx,
    path: &Path,
    file: &std::fs::File,
) -> Checked<Information> {
    #[cfg(windows)]
    return windows::query(c, path, Some(file), None, false);
    #[cfg(unix)]
    return unix::query(c, path, Some(file));
    #[cfg(not(any(unix, windows)))]
    return Err(c.unsupported("file metadata adapter unavailable").into());
}

/// Query an already admitted object; a legacy pathname cannot substitute a new file.
#[cfg(unix)]
pub(in super::super) fn retained(
    c: &Ctx,
    file: &crate::user::windows::objects::FileObj,
) -> Checked<Information> {
    let reopened;
    let retained = if let Some(retained) = &file.host {
        retained
    } else {
        // Reopening may acquire a different object after rename/replacement.
        // Admit it only after fstat proves the original captured identity, then
        // keep that descriptor for every timestamp/xattr query below.
        reopened = std::fs::File::open(&file.host_path)
            .map_err(|error| c.unsupported(format!("metadata-only file open: {error}")))?;
        let metadata = reopened
            .metadata()
            .map_err(|error| c.unsupported(format!("retained file metadata: {error}")))?;
        if FileIdentity::of(&file.host_path, &metadata)
            .map_err(|error| c.unsupported(format!("retained file identity: {error}")))?
            != file.lifetime.identity
        {
            return Err(c
                .unsupported("metadata-only file pathname was replaced")
                .into());
        }
        &reopened
    };
    unix::query(c, &file.host_path, Some(retained))
}

pub(super) fn io_error<T>(c: &Ctx, error: std::io::Error, path: &Path) -> Checked<T> {
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

pub(super) fn resolved_attributes(c: &Ctx, path: &Path) -> Checked<u32> {
    #[cfg(unix)]
    return unix::query_attributes(c, path);
    #[cfg(windows)]
    return windows::query(c, path, None, None, false).map(|info| info.attributes);
    #[cfg(not(any(unix, windows)))]
    return Err(c.unsupported("file metadata adapter unavailable").into());
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

#[cfg(windows)]
pub(super) fn by_name(
    c: &Ctx,
    attrs: &super::attributes::Attributes,
    name: Option<&[u16]>,
    layout: super::by_name::Layout,
) -> Checked<super::by_name::Completion> {
    use super::super::file_open;
    use super::by_name::Completion;
    use super::path;
    use crate::user::windows::nt::status::{STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS};

    // Closed installed paths always reject reparsing. Only the case flag and
    // the caller's explicit no-reparse flag reach an authorized host query.
    let flags = attrs.flags & 0x1040 | if c.p.cfg.host_filesystem { 0 } else { 0x1000 };
    if let Some(name) = name {
        if let Some(directory) = path::guest_directory(c, attrs.root, name)? {
            let host = match directory.framework.as_deref() {
                Some(host) => host,
                None => path::installed_directory(c, &directory.guest)?,
            };
            return windows::by_name(c, host, None, None, flags, layout);
        }
        if let Some((root, leaf)) = path::installed_entry(c, attrs.root, name)? {
            let directory = Resolved {
                host: root.to_owned(),
                base: root.to_owned(),
                root: None,
                relative: None,
                directory: true,
                runtime_library: true,
            };
            // SYNCHRONIZE | FILE_LIST_DIRECTORY, shared synchronous directory
            // open with reparsing forbidden throughout the retained query.
            let handle = file_open::host::open(c, &directory, 0x100001, 7, 0x21, 0x1040)?;
            let outcome =
                windows::by_name(c, root, Some(&handle.file), Some(&leaf), flags, layout)?;
            if outcome.code != STATUS_SUCCESS {
                return Ok(outcome);
            }
            let attributes = if layout.class != 71 {
                // All three FILE_STAT variants place FileAttributes at byte 56.
                u32::from_le_bytes(outcome.data[56..60].try_into().unwrap())
            } else {
                // FileCaseSensitiveInformation has no file type field.
                windows::query(c, root, Some(&handle.file), Some(&leaf), true)?.attributes
            };
            if attributes & (0x10 | 0x400) != 0 {
                return Ok(Completion {
                    code: STATUS_OBJECT_NAME_NOT_FOUND,
                    information: Some(0),
                    data: [0; 104],
                });
            }
            return Ok(outcome);
        }
    }
    let resolved = path::resolve(c, attrs, name)?;
    let file = if let Some(root) = resolved.root {
        let Some(Object::File(file)) = c.p.objects.get(root) else {
            return Err(c
                .unsupported("file metadata root changed during the query")
                .into());
        };
        Some(
            file.host
                .as_ref()
                .ok_or_else(|| c.unsupported("by-name metadata requires a retained host file"))?,
        )
    } else {
        None
    };
    windows::by_name(
        c,
        &resolved.host,
        file,
        resolved.relative.as_deref(),
        flags,
        layout,
    )
}
