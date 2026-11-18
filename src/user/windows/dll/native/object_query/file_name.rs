//! The local-disk native64 profile for ObjectNameInformation on ARM64 29708.
use super::super::query::{probe_destinations, return_length};
use super::super::unicode_name::write_inline;
use crate::user::windows::arch::WinArch;
use crate::user::windows::fs::FileNameOrigin;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};

pub(super) fn query(c: &Ctx, handle: u64, output: u64, length: u32, returned: u64) -> ApiResult {
    let captured = c.p.native.as_ref().is_some_and(|runtime| {
        (
            runtime.version.major,
            runtime.version.minor,
            runtime.version.build,
        ) == (10, 0, 29708)
            && runtime.object_namespace.native_machine == Some(0xAA64)
    });
    if c.arch() != WinArch::Arm64 || !captured {
        return Err(
            c.unsupported("NtQueryObject information class 1 has no measured native profile")
        );
    }
    query_with(c, output, length, returned, || retained_name(c, handle))
}

fn retained_name(c: &Ctx, handle: u64) -> Result<Option<(Vec<u16>, usize)>, ApiErr> {
    if handle == c.arch().ptr(CURRENT_PROCESS) || handle == c.arch().ptr(CURRENT_THREAD) {
        return Err(c.unsupported("ObjectNameInformation requires a regular file handle"));
    }
    let Some(object) = c.p.objects.get(handle) else {
        return Ok(None);
    };
    let Object::File(file) = object else {
        return Err(c.unsupported("ObjectNameInformation requires a regular file handle"));
    };
    let Some(retained) = file.host.as_ref().filter(|_| !file.null && !file.directory) else {
        return Err(c.unsupported("ObjectNameInformation requires a retained regular file"));
    };
    let identity = FileNameOrigin::identity(retained, &file.host_path)
        .map_err(|e| c.unsupported(format!("ObjectNameInformation file identity: {e}")))?;
    if identity != file.lifetime.identity {
        return Err(c.unsupported("ObjectNameInformation file identity changed"));
    }
    let origin =
        c.p.objects
            .file_name_origin(handle)
            .ok_or_else(|| c.unsupported("ObjectNameInformation has no retained guest volume"))?
            .as_ref()
            .map_err(|e| c.unsupported(format!("ObjectNameInformation guest volume: {e}")))?;
    origin
        .local_nt_name(retained)
        .map(Some)
        .map_err(|e| c.unsupported(format!("ObjectNameInformation retained name: {e}")))
}

pub(crate) fn query_with(
    c: &Ctx,
    output: u64,
    length: u32,
    returned: u64,
    resolve: impl FnOnce() -> Result<Option<(Vec<u16>, usize)>, ApiErr>,
) -> ApiResult {
    if let Some(status) = probe_destinations(c, output, length, returned)? {
        return Flow::ret(status.into());
    }
    let Some((name, device_units)) = resolve()? else {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    };
    if name.len() > 32766 || device_units >= name.len() || name.contains(&0) {
        return Err(c.unsupported("ObjectNameInformation exceeds the native name profile"));
    }

    const HEADER_BYTES: u32 = 16;
    let required = HEADER_BYTES + 2 * (name.len() as u32 + 1);
    let finish = |status: u32, bytes| {
        // Returning the length after the name also preserves output aliases.
        return_length(c, returned, bytes)?;
        Flow::ret(status.into())
    };
    if length < HEADER_BYTES {
        return finish(STATUS_INFO_LENGTH_MISMATCH, required);
    }
    let capacity = ((length - HEADER_BYTES) / 2) as usize;
    if capacity <= device_units {
        return finish(STATUS_BUFFER_OVERFLOW, required);
    }
    let copied = name.len().min(capacity - 1);
    write_inline(c, output, &name[..copied])?;
    if copied == device_units {
        return finish(STATUS_OBJECT_PATH_INVALID, 0);
    }
    finish(
        if copied == name.len() {
            STATUS_SUCCESS
        } else {
            STATUS_BUFFER_OVERFLOW
        },
        required,
    )
}
