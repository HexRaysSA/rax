//! Host-owned NT arguments and handles. Guest inheritance never leaks to the host.
use super::{Acquired, Checked, Ctx, FileIdentity, status};
use crate::user::windows::dll::native::file_attributes::path::Resolved;
use crate::user::windows::objects::Object;
use std::ffi::c_void;
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};

#[repr(C)]
struct Unicode {
    length: u16,
    maximum: u16,
    buffer: *const u16,
}
#[repr(C)]
struct Attributes {
    length: u32,
    root: *mut c_void,
    name: *const Unicode,
    flags: u32,
    security: *mut c_void,
    qos: *mut c_void,
}
#[repr(C)]
struct Io {
    status: usize,
    information: usize,
}
#[repr(C, align(8))]
struct Buffer<const N: usize>([u8; N]);

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtOpenFile(
        out: *mut *mut c_void,
        access: u32,
        attrs: *const Attributes,
        io: *mut Io,
        share: u32,
        options: u32,
    ) -> i32;
    fn NtCreateFile(
        out: *mut *mut c_void,
        access: u32,
        attrs: *const Attributes,
        io: *mut Io,
        allocation: *const i64,
        file_attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
        ea: *const u8,
        ea_bytes: u32,
    ) -> i32;
    fn NtQueryInformationFile(
        file: *mut c_void,
        io: *mut Io,
        info: *mut c_void,
        length: u32,
        class: u32,
    ) -> i32;
    fn NtQueryObject(
        object: *mut c_void,
        class: u32,
        info: *mut c_void,
        size: u32,
        returned: *mut u32,
    ) -> i32;
}

pub(super) fn open(
    c: &Ctx,
    path: &Resolved,
    access: u32,
    share: u32,
    options: u32,
    flags: u32,
) -> Checked<Acquired> {
    acquire(c, path, access, share, options, flags, None)
}

pub(super) fn create(
    c: &Ctx,
    path: &Resolved,
    access: u32,
    share: u32,
    options: u32,
    flags: u32,
    request: super::Creation,
) -> Checked<Acquired> {
    acquire(c, path, access, share, options, flags, Some(request))
}

fn acquire(
    c: &Ctx,
    path: &Resolved,
    access: u32,
    share: u32,
    options: u32,
    flags: u32,
    creation: Option<super::Creation>,
) -> Checked<Acquired> {
    let retained = path
        .root
        .and_then(|h| c.p.objects.get(h))
        .and_then(|o| match o {
            Object::File(f) => f.host.as_ref(),
            _ => None,
        });
    let mut units = Vec::new();
    if retained.is_some() {
        if let Some(relative) = &path.relative {
            units.extend(relative.as_os_str().encode_wide());
        }
    } else {
        let absolute = std::path::absolute(&path.host)
            .map_err(|e| c.unsupported(format!("absolute NT host path: {e}")))?;
        let raw: Vec<u16> = absolute.as_os_str().encode_wide().collect();
        units.extend("\\??\\".encode_utf16());
        if raw.starts_with(&[92, 92, 63, 92]) || raw.starts_with(&[92, 63, 63, 92]) {
            units.extend_from_slice(&raw[4..]);
        } else if raw.starts_with(&[92, 92]) {
            units.extend("UNC\\".encode_utf16());
            units.extend_from_slice(&raw[2..]);
        } else if raw.len() >= 3 && raw[1] == 58 && raw[2] == 92 {
            units.extend_from_slice(&raw);
        } else {
            return Err(c
                .unsupported("host path has no absolute NT DOS spelling")
                .into());
        }
    }
    if units.len() > 32766 || units.contains(&0) {
        return Err(c.unsupported("host NT name is not representable").into());
    }
    let name = Unicode {
        length: (units.len() * 2) as u16,
        maximum: (units.len() * 2) as u16,
        buffer: units.as_ptr(),
    };
    let attrs = Attributes {
        length: std::mem::size_of::<Attributes>() as u32,
        root: retained.map_or(std::ptr::null_mut(), AsRawHandle::as_raw_handle),
        name: &name,
        flags: flags & 0x1040,
        security: std::ptr::null_mut(),
        qos: std::ptr::null_mut(),
    };
    let mut handle = std::ptr::null_mut();
    let mut io = Io {
        status: 0,
        information: 0,
    };
    // The host NT entry probes EA input with ULONG alignment. Vec<u8>'s type
    // does not promise that alignment, even when the guest address was aligned.
    let ea: Vec<u32> = creation.as_ref().map_or_else(Vec::new, |request| {
        request
            .ea
            .chunks(4)
            .map(|chunk| {
                let mut bytes = [0; 4];
                bytes[..chunk.len()].copy_from_slice(chunk);
                u32::from_le_bytes(bytes)
            })
            .collect()
    });
    // SAFETY: all pointer arguments reference exclusive live host buffers of the
    // declared ABI layouts. The optional root is borrowed from an owned File.
    // Masks are validated; host inheritance/security/QoS are never delegated.
    let code = unsafe {
        match &creation {
            Some(request) => NtCreateFile(
                &mut handle,
                access,
                &attrs,
                &mut io,
                request.allocation.as_ref().map_or(std::ptr::null(), |v| v),
                request.attributes,
                share,
                request.disposition,
                options,
                if ea.is_empty() {
                    std::ptr::null()
                } else {
                    ea.as_ptr().cast()
                },
                request.ea.len() as u32,
            ),
            None => NtOpenFile(&mut handle, access, &attrs, &mut io, share, options),
        }
    };
    if code != 0 {
        if !handle.is_null() && handle != (-1isize as *mut c_void) {
            // SAFETY: only this call can populate the private, initially NULL
            // result. Retire any transferred file even for an unmodeled status.
            drop(unsafe { File::from_raw_handle(handle) });
        }
        if code > 0 {
            return Err(c
                .unsupported(format!("NtOpenFile informational completion {code:#x}"))
                .into());
        }
        return status(code as u32);
    }
    if handle.is_null() || handle == (-1isize as *mut c_void) {
        return Err(c
            .unsupported("native open returned no valid owned handle")
            .into());
    }
    // SAFETY: the successful call transferred a fresh handle, owned exactly once.
    let file = unsafe { File::from_raw_handle(handle) };
    let information = io.information as u64;
    let mut basic = Buffer([0u8; 56]);
    let mut standard = Buffer([0u8; 24]);
    let mut returned = 0;
    // SAFETY: borrowed handle and initialized aligned buffers remain live; the
    // synchronous queries retain no pointer. StandardInformation needs no added
    // READ_ATTRIBUTES grant, unlike Basic/NetworkOpenInformation.
    let (a, b) = unsafe {
        (
            NtQueryObject(
                file.as_raw_handle(),
                0,
                basic.0.as_mut_ptr().cast(),
                56,
                &mut returned,
            ),
            NtQueryInformationFile(
                file.as_raw_handle(),
                &mut io,
                standard.0.as_mut_ptr().cast(),
                24,
                5,
            ),
        )
    };
    if a != 0 || b != 0 {
        return Err(c
            .unsupported(format!("owned NT file grant/type query: {a:#x}/{b:#x}"))
            .into());
    }
    let granted = u32::from_le_bytes(basic.0[4..8].try_into().unwrap());
    let identity = FileIdentity::retained(&file)
        .map_err(|error| c.unsupported(format!("owned Windows file identity: {error}")))?;
    Ok(Acquired {
        file,
        path: path.host.clone(),
        identity,
        directory: standard.0[21] != 0,
        access: granted,
        information,
    })
}
