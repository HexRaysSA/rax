//! NT opens capture guest arguments before publishing owned file handles.
//! Native IO_STATUS_BLOCK probing and WoW64 copyback have distinct failure effects.

pub(super) mod host;

use super::file_attributes::{attributes, path};
use super::named_object::{Checked, Failure, finish_with, status};
use super::query::probe_write;
use crate::user::windows::arch::WinArch;
use crate::user::windows::fs::FileLifetime;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{FileObj, Object};
use std::sync::Arc;

const ATTRIBUTES: u32 = 0x11ec2;
const LIBRARY_READ: u32 = 0x0012_00a9;

#[derive(Clone, Copy)]
pub(super) struct Request {
    pub output: u64,
    pub access: u32,
    pub attributes: u64,
    pub io: u64,
    pub share: u32,
    pub options: u32,
}

pub(super) fn open(c: &mut Ctx) -> ApiResult {
    let mut caller_store = false;
    let result = checked(c, &mut caller_store);
    finish_with(c, result, caller_store)
}

fn mapped_access(mut access: u32) -> u32 {
    for (generic, specific) in [
        (0x8000_0000, 0x120089),
        (0x4000_0000, 0x120116),
        (0x2000_0000, 0x1200a0),
        (0x1000_0000, 0x1f01ff),
    ] {
        if access & generic != 0 {
            access = (access & !generic) | specific;
        }
    }
    access
}

fn parameters(r: Request) -> Checked<()> {
    if r.share & !7 != 0
        || r.options & !0x20ff_ffff != 0
        || r.options & 0x30 == 0x30
        || r.options & 0x41 == 0x41
        || r.options & 0x30 != 0 && r.access & 0x100000 == 0
        || r.options & 0x1000 != 0 && r.access & 0x10000 == 0
        || r.access & !0xf31f_01ff != 0
    {
        return status(STATUS_INVALID_PARAMETER);
    }
    if r.access == 0 {
        return status(STATUS_ACCESS_DENIED);
    }
    Ok(())
}

fn checked(c: &mut Ctx, caller_store: &mut bool) -> Checked<u32> {
    let r = Request {
        output: c.ptr(0)?,
        access: c.u32(1)?,
        attributes: c.ptr(2)?,
        io: c.ptr(3)?,
        share: c.u32(4)?,
        options: c.u32(5)?,
    };
    let wow = c.arch() == WinArch::X86;
    let captured = if wow {
        Some(attributes::capture_open(c, r.attributes, true)?)
    } else {
        None
    };
    if !wow {
        parameters(r)?;
        probe_write(c, r.output, c.psize() as usize)?;
        probe_write(c, r.io, 4)?;
    }
    let core = match parameters(r) {
        Err(error) => Err(error),
        Ok(()) if wow && (r.output == 0 || r.io == 0) => status(STATUS_ACCESS_VIOLATION),
        Ok(()) => kernel(c, r, captured, None).map(|(handle, _)| handle),
    };
    let (code, handle) = match core {
        Ok(handle) => (STATUS_SUCCESS, handle),
        Err(Failure::Status(s)) => (s, 0),
        Err(Failure::Api(ApiErr::Fault(fault))) if wow => {
            let code = if c.p.vm.take_guard(fault.addr) {
                STATUS_GUARD_PAGE_VIOLATION
            } else {
                STATUS_ACCESS_VIOLATION
            };
            (code, 0)
        }
        Err(error) => return Err(error),
    };
    if !wow && code != STATUS_SUCCESS {
        return Ok(code);
    }
    *caller_store = true;
    let result = publish(c, r, code, handle);
    if wow && result.is_err() && handle != 0 {
        // WoW64 closes the temporary native result after any caller copyback
        // fault. Bytes already written to the handle slot remain observable.
        let _ = c.p.objects.close(handle);
    }
    result
}

fn publish(c: &Ctx, r: Request, code: u32, handle: u64) -> Checked<u32> {
    if r.output != 0 {
        c.mem().wptr(r.output, c.psize(), handle)?;
    }
    if code == STATUS_SUCCESS {
        c.mem().wptr(r.io, c.psize(), 0)?;
        let information =
            r.io.checked_add(c.psize())
                .ok_or(crate::user::windows::memory::MemFault {
                    addr: u64::MAX,
                    write: true,
                })?;
        c.mem().wptr(information, c.psize(), 1)?;
    }
    Ok(code)
}

fn sharing(access: u32) -> u32 {
    u32::from(access & 0x21 != 0)
        | (u32::from(access & 6 != 0) << 1)
        | (u32::from(access & 0x10000 != 0) << 2)
}

pub(in super::super) fn shared_lifetime(
    c: &Ctx,
    identity: &crate::user::windows::fs::FileIdentity,
    access: u32,
    share: u32,
) -> Checked<Option<Arc<FileLifetime>>> {
    let mut lifetime = None;
    for (_, object) in c.p.objects.iter() {
        let Object::File(file) = object else {
            continue;
        };
        if &file.lifetime.identity != identity {
            continue;
        }
        if file.lifetime.blocks_opens() {
            return status(0xc000_0056);
        }
        let requested = sharing(access);
        let existing = sharing(mapped_access(file.access));
        // Attribute/EA-only references do not participate in data sharing.
        // They still retain the same object lifetime and deletion identity.
        if requested != 0
            && existing != 0
            && (requested & !file.share != 0
                || existing & !share != 0
                || file.lifetime.delete_requested() && share & 4 == 0)
        {
            return status(0xc000_0043);
        }
        lifetime = Some(file.lifetime.clone());
    }
    Ok(lifetime)
}

pub(super) fn kernel(
    c: &mut Ctx,
    r: Request,
    converted: Option<Option<attributes::Attributes>>,
    mut creation: Option<host::Creation>,
) -> Checked<(u64, u64)> {
    if r.options & 0x2000 != 0 {
        return Err(c
            .unsupported("NT file-ID opens require a captured file-ID namespace")
            .into());
    }
    let attrs = match converted {
        Some(attrs) => attrs,
        None => attributes::capture_open(c, r.attributes, false)?,
    };
    let Some(attrs) = attrs else {
        return status(STATUS_INVALID_PARAMETER);
    };
    if attrs.flags & !ATTRIBUTES != 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let name = attributes::validate(c, &attrs)?;
    let resolved = path::resolve_open(c, &attrs, name.as_deref())?;
    let mut access = mapped_access(r.access);
    if access & 0x0200_0000 != 0 {
        access = (access & !0x0200_0000)
            | if resolved.runtime_library {
                LIBRARY_READ
            } else {
                0x1f01ff
            };
    }
    if resolved.runtime_library && (access & !LIBRARY_READ != 0 || r.options & 0x1000 != 0) {
        return status(STATUS_ACCESS_DENIED);
    }
    if resolved.runtime_library
        && let Some(request) = &mut creation
    {
        if !matches!(request.disposition, 1 | 3) {
            // The disposition can overwrite even when DesiredAccess is read-only.
            return status(STATUS_ACCESS_DENIED);
        }
        // A selected DLL is an existing read-only capability. OPEN_IF must not
        // create a replacement if another host process removes it during lookup.
        request.disposition = 1;
    }
    if creation
        .as_ref()
        .is_some_and(|request| matches!(request.disposition, 0 | 4 | 5))
        && let Ok(metadata) = std::fs::metadata(&resolved.host)
        && let Ok(identity) = crate::user::windows::fs::FileIdentity::of(&resolved.host, &metadata)
        && crate::user::windows::object_namespace::file_data::is_live(c.p, &identity)
    {
        return Err(c
            .unsupported(
                "overwriting a file with live data sections requires the section-resize contract",
            )
            .into());
    }
    let acquired = match creation {
        Some(request) => host::create(
            c,
            &resolved,
            access,
            r.share,
            r.options,
            attrs.flags,
            request,
        )?,
        None => host::open(c, &resolved, access, r.share, r.options, attrs.flags)?,
    };
    if resolved.runtime_library && acquired.directory {
        return status(STATUS_ACCESS_DENIED);
    }
    let lifetime = shared_lifetime(c, &acquired.identity, acquired.access, r.share)?;
    let lifetime = lifetime.unwrap_or_else(|| Arc::new(FileLifetime::new(acquired.identity)));
    #[cfg(unix)]
    if r.options & 0x1000 != 0 {
        lifetime
            .mark_delete(acquired.path.clone(), false)
            .map_err(|e| c.unsupported(format!("deferred NT delete: {e}")))?;
    }
    let file = FileObj {
        host: Some(acquired.file),
        host_path: acquired.path,
        path: name
            .as_deref()
            .map(String::from_utf16_lossy)
            .unwrap_or_default(),
        access: acquired.access,
        share: r.share,
        lifetime,
        null: false,
        append: acquired.access & 4 != 0 && acquired.access & 2 == 0,
        delete_on_close: r.options & 0x1000 != 0,
        directory: acquired.directory,
        overlapped: r.options & 0x30 == 0,
    };
    let id =
        c.p.objects
            .try_create(Object::File(file))
            .ok_or(Failure::Status(STATUS_INSUFFICIENT_RESOURCES))?;
    c.p.objects.set_file_mode(id, r.options);
    if resolved.runtime_library {
        c.p.objects.mark_runtime_library(id);
    }
    let handle =
        c.p.objects
            .open_access(id, attrs.flags & 2 != 0, acquired.access);
    match handle {
        Some(handle) => Ok((u64::from(handle), acquired.information)),
        None => {
            c.p.objects.release(id);
            status(STATUS_INSUFFICIENT_RESOURCES)
        }
    }
}
