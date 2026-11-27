//! NT opens capture guest arguments before publishing owned file handles.
//! Native IO_STATUS_BLOCK probing and WoW64 copyback have distinct failure effects.

mod guest_directory;
pub(super) mod host;
mod null;
mod security_device;

use super::file_attributes::{attributes, path};
use super::named_object::{Checked, Failure, finish_with, status};
use super::query::probe_write;
use crate::user::windows::arch::WinArch;
use crate::user::windows::fs::FileLifetime;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{FileObj, Object};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

const ATTRIBUTES: u32 = 0x11ec2;
const LIBRARY_READ: u32 = 0x0012_00a9;

// Microsoft .NET Framework v4 factory file on Windows build 29708. The
// installed default and active files matched on ARM64, x64, and x86.
const CLR_MACHINE_CONFIG_BYTES: u64 = 35_982;
const CLR_MACHINE_CONFIG_SHA256: [u8; 32] = [
    0x68, 0xe0, 0xdc, 0x6f, 0xef, 0x3f, 0xf0, 0xdf, 0x42, 0x84, 0xc4, 0x7b, 0x93, 0x5a, 0xcc, 0xf4,
    0x31, 0x5d, 0xfc, 0x82, 0x28, 0xfb, 0xa8, 0x09, 0xcb, 0x18, 0x12, 0x58, 0xc7, 0x8c, 0xb5, 0xe1,
];

/// Verify the same handle the guest will read. No guest handle is live yet;
/// reset the shared file position before returning it.
fn stock_clr_machine_config(mut file: &std::fs::File) -> bool {
    let mut data = Vec::new();
    if (&mut file)
        .take(CLR_MACHINE_CONFIG_BYTES + 1)
        .read_to_end(&mut data)
        .is_err()
        || file.seek(SeekFrom::Start(0)).is_err()
    {
        return false;
    }
    data.len() as u64 == CLR_MACHINE_CONFIG_BYTES
        && Sha256::digest(&data)[..] == CLR_MACHINE_CONFIG_SHA256
}

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

pub(super) fn mapped_access(mut access: u32) -> u32 {
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
        Ok(()) => kernel(c, r, captured, None),
    };
    let (code, handle, information) = match core {
        Ok((handle, information)) => (STATUS_SUCCESS, handle, information),
        Err(Failure::Status(s)) => (s, 0, 0),
        Err(Failure::Api(ApiErr::Fault(fault))) if wow => {
            let code = if c.p.vm.take_guard(fault.addr) {
                STATUS_GUARD_PAGE_VIOLATION
            } else {
                STATUS_ACCESS_VIOLATION
            };
            (code, 0, 0)
        }
        Err(error) => return Err(error),
    };
    if !wow && code != STATUS_SUCCESS {
        return Ok(code);
    }
    *caller_store = true;
    let result = publish(c, r, code, handle, information);
    if wow && result.is_err() && handle != 0 {
        // WoW64 closes the temporary native result after any caller copyback
        // fault. Bytes already written to the handle slot remain observable.
        let _ = c.p.objects.close(handle);
    }
    result
}

pub(super) fn publish(
    c: &Ctx,
    r: Request,
    code: u32,
    handle: u64,
    information: u64,
) -> Checked<u32> {
    if r.output != 0 {
        c.mem().wptr(r.output, c.psize(), handle)?;
    }
    if code == STATUS_SUCCESS {
        c.mem().wptr(r.io, c.psize(), 0)?;
        let address =
            r.io.checked_add(c.psize())
                .ok_or(crate::user::windows::memory::MemFault {
                    addr: u64::MAX,
                    write: true,
                })?;
        c.mem().wptr(address, c.psize(), information)?;
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
    if !c.p.cfg.host_filesystem
        && c.p.native.is_some()
        && tracing::enabled!(target: "rax::windows::ntstatus", tracing::Level::TRACE)
    {
        tracing::trace!(
            target: "rax::windows::ntstatus",
            pid = c.p.pid,
            path = ?name.as_deref().map(String::from_utf16_lossy),
            root = attrs.root,
            attributes = %format_args!("{:#010x}", attrs.flags),
            access = %format_args!("{:#010x}", r.access),
            share = r.share,
            options = %format_args!("{:#010x}", r.options),
            "guest file open request"
        );
    }
    if creation.is_none()
        && let Some(result) = super::file_pipe::open(c, r, &attrs, name.as_deref())
    {
        return result;
    }
    if let Some(result) = null::open(c, r, &attrs, name.as_deref()) {
        return result;
    }
    if let Some(result) = security_device::open(c, r, &attrs, name.as_deref(), creation.as_ref()) {
        return result;
    }
    if let Some(result) = super::gameos_xvc::open(c, r, &attrs, name.as_deref(), creation.as_ref())
    {
        return result;
    }
    // These restrictions belong to filesystems. The native null device
    // accepts directory and non-directory flags together.
    if r.options & 0x41 == 0x41
        || creation
            .as_ref()
            .is_some_and(|request| r.options & 1 != 0 && !matches!(request.disposition, 1..=3))
    {
        return status(STATUS_INVALID_PARAMETER);
    }
    if let Some(result) = guest_directory::open(c, r, &attrs, name.as_deref(), creation.as_ref()) {
        return result;
    }
    let resolved = path::resolve_open(c, &attrs, name.as_deref())?;
    let stock_config = resolved.is_clr_machine_config();
    let installed_read_access = if stock_config {
        LIBRARY_READ & !0x20
    } else {
        LIBRARY_READ
    };
    let mut access = mapped_access(r.access);
    if access & 0x0200_0000 != 0 {
        access = (access & !0x0200_0000)
            | if resolved.runtime_library {
                installed_read_access
            } else {
                0x1f01ff
            };
    }
    if resolved.runtime_library && (access & !installed_read_access != 0 || r.options & 0x1000 != 0)
    {
        return status(STATUS_ACCESS_DENIED);
    }
    if stock_config && access & 1 != 0 && r.options & 0x30 == 0 {
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
    // On Windows, deny host writers and replacements through the lifetime of the
    // verified handle. The guest's ordinary sharing model uses r.share.
    let host_share = if stock_config { r.share & 1 } else { r.share };
    let flags = attrs.flags | if resolved.no_reparse { 0x1000 } else { 0 };
    let acquired = match creation {
        Some(request) => host::create(c, &resolved, access, host_share, r.options, flags, request)?,
        None => host::open(c, &resolved, access, host_share, r.options, flags)?,
    };
    if stock_config && acquired.access & 1 != 0 && !stock_clr_machine_config(&acquired.file) {
        return status(STATUS_ACCESS_DENIED);
    }
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
    let name_origin =
        super::file_name_origin::nt(c, attrs.root, name.as_deref(), resolved.runtime_library);
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
    c.p.objects.set_file_name_origin(id, name_origin);
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
