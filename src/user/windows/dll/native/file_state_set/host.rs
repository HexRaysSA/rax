//! Only an already admitted retained file reaches these mechanics.
use super::super::named_object::Checked;
use crate::user::windows::hle::Ctx;
#[cfg(unix)]
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_INVALID_PARAMETER, STATUS_UNSUCCESSFUL,
};
use crate::user::windows::objects::FileObj;

pub(super) fn set(c: &Ctx, file: &FileObj, class: u32, value: u64) -> Checked<()> {
    let Some(handle) = &file.host else {
        // Legacy metadata-only opens have no host open-file description.
        // Their position remains in process-owned FileState, never a new open.
        return Ok(());
    };
    #[cfg(windows)]
    return super::super::file_information::host::set(c, handle, class, value);
    #[cfg(unix)]
    {
        use std::io::{Seek, SeekFrom};
        if class == 14 && !file.directory {
            let mut handle = handle;
            handle.seek(SeekFrom::Start(value)).map_err(|error| {
                super::super::named_object::Failure::Status(match error.kind() {
                    std::io::ErrorKind::InvalidInput => STATUS_INVALID_PARAMETER,
                    std::io::ErrorKind::PermissionDenied => STATUS_ACCESS_DENIED,
                    _ => STATUS_UNSUCCESSFUL,
                })
            })?;
        }
        // Mode is enforced by write consumers. Sequential-scan and priority
        // are per-open advisory hints for the modeled mounted disk; no host
        // thread, process, pathname or unrelated descriptor is modified.
        let _ = c;
        return Ok(());
    }
    #[cfg(not(any(windows, unix)))]
    Err(c.unsupported("owned file-state adapter unavailable").into())
}
