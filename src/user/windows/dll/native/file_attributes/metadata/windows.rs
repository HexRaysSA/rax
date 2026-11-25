//! Host-owned native arguments preserve NTFS timestamps and allocation size.
//! Neither guest addresses, guest handles nor unvalidated flags cross this FFI.

use super::super::super::named_object::{Checked, status};
use super::super::by_name::{Completion, Layout};
use super::Information;
use crate::user::windows::hle::Ctx;
use std::ffi::c_void;
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::sync::OnceLock;

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

#[repr(C, align(8))]
#[derive(Default)]
struct Network {
    times: [u64; 4],
    allocation: u64,
    size: u64,
    attributes: u32,
    padding: u32,
}

const _: [(); 56] = [(); std::mem::size_of::<Network>()];

#[repr(C)]
struct IoStatus {
    status: usize,
    information: usize,
}

#[repr(align(8))]
struct StatBuffer([u8; 104]);

type QueryByName =
    unsafe extern "system" fn(*const Attributes, *mut IoStatus, *mut u8, u32, u32) -> i32;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryFullAttributesFile(attributes: *const Attributes, info: *mut Network) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleA(name: *const std::ffi::c_char) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
}

fn query_by_name_export() -> Option<QueryByName> {
    static EXPORT: OnceLock<Option<QueryByName>> = OnceLock::new();
    *EXPORT.get_or_init(|| {
        // SAFETY: these fixed C strings are terminated. NTDLL remains loaded
        // through the ordinary static NT import in this module.
        let address = unsafe {
            let module = GetModuleHandleA(c"ntdll.dll".as_ptr());
            if module.is_null() {
                return None;
            }
            GetProcAddress(module, c"NtQueryInformationByName".as_ptr().cast())
        };
        if address.is_null() {
            None
        } else {
            // SAFETY: the named NTDLL export has the declared native ABI.
            Some(unsafe { std::mem::transmute::<*mut c_void, QueryByName>(address) })
        }
    })
}

pub(super) fn query(
    c: &Ctx,
    path: &Path,
    file: Option<&File>,
    relative: Option<&Path>,
    no_reparse: bool,
) -> Checked<Information> {
    let mut info = Network::default();
    let flags = 0x40 | if no_reparse { 0x1000 } else { 0 };
    let result = with_attributes(c, path, file, relative, flags, |attrs| {
        // SAFETY: the NT name and borrowed handle stay live throughout the
        // synchronous call. The initialized output has the native layout.
        unsafe { NtQueryFullAttributesFile(attrs, &mut info) }
    })?;
    if result != 0 {
        return status(result as u32);
    }
    Ok(Information {
        times: info.times,
        allocation: info.allocation,
        size: info.size,
        attributes: info.attributes,
    })
}

pub(super) fn by_name(
    c: &Ctx,
    path: &Path,
    file: Option<&File>,
    relative: Option<&Path>,
    flags: u32,
    layout: Layout,
) -> Checked<Completion> {
    let query = query_by_name_export()
        .ok_or_else(|| c.unsupported("host NTDLL lacks NtQueryInformationByName"))?;
    let mut record = StatBuffer([0; 104]);
    let mut io = IoStatus {
        status: usize::MAX,
        information: usize::MAX,
    };
    let code = with_attributes(c, path, file, relative, flags, |attrs| {
        // SAFETY: the name, retained handle and output storage are host-owned.
        // The fixed class size fits the aligned buffer and the call is synchronous.
        unsafe {
            query(
                attrs,
                &mut io,
                record.0.as_mut_ptr(),
                layout.bytes,
                layout.class,
            ) as u32
        }
    })?;
    let io = if io.status == usize::MAX && io.information == usize::MAX {
        None
    } else {
        if io.status as u32 != code
            || io.information != if code == 0 { layout.bytes as usize } else { 0 }
        {
            return Err(c
                .unsupported("host returned an inconsistent file metadata result")
                .into());
        }
        Some(io.information as u32)
    };
    if code == 0 && io.is_none() {
        return Err(c
            .unsupported("host omitted successful file metadata status")
            .into());
    }
    Ok(Completion {
        code,
        information: io,
        data: record.0,
    })
}

fn with_attributes<T>(
    c: &Ctx,
    path: &Path,
    file: Option<&File>,
    relative: Option<&Path>,
    flags: u32,
    call: impl FnOnce(&Attributes) -> T,
) -> Checked<T> {
    let units: Vec<u16> = if file.is_some() {
        let units = relative.map_or_else(Vec::new, |name| name.as_os_str().encode_wide().collect());
        if units.len() > 32766 || units.contains(&0) {
            return Err(c
                .unsupported("retained NT metadata name is not representable")
                .into());
        }
        units
    } else {
        let absolute = std::path::absolute(path)
            .map_err(|error| c.unsupported(format!("absolute host metadata path: {error}")))?;
        let raw: Vec<u16> = absolute.as_os_str().encode_wide().collect();
        let mut native: Vec<u16> = "\\??\\".encode_utf16().collect();
        if raw.starts_with(&[92, 92, 63, 92]) || raw.starts_with(&[92, 63, 63, 92]) {
            native.extend_from_slice(&raw[4..]);
        } else if raw.starts_with(&[92, 92]) {
            native.extend("UNC\\".encode_utf16());
            native.extend_from_slice(&raw[2..]);
        } else if raw.len() >= 3 && raw[1] == 58 && raw[2] == 92 {
            native.extend_from_slice(&raw);
        } else {
            return Err(c
                .unsupported("host metadata path has no absolute NT DOS spelling")
                .into());
        }
        if native.contains(&0) || native.len() > 32766 {
            return Err(c
                .unsupported("host metadata path exceeds counted NT name bounds")
                .into());
        }
        native
    };
    let unicode = Unicode {
        length: (units.len() * 2) as u16,
        maximum: (units.len() * 2) as u16,
        buffer: units.as_ptr(),
    };
    let attrs = Attributes {
        length: std::mem::size_of::<Attributes>() as u32,
        root: file.map_or(std::ptr::null_mut(), AsRawHandle::as_raw_handle),
        name: &unicode,
        flags,
        security: std::ptr::null_mut(),
        qos: std::ptr::null_mut(),
    };
    Ok(call(&attrs))
}
