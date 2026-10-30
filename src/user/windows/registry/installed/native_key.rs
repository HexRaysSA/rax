//! Narrow native key primitives used only during fixed snapshot acquisition.
use super::*;
#[repr(C)]
struct Unicode {
    length: u16,
    maximum: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct Attributes {
    length: u32,
    root: Hkey,
    name: *mut Unicode,
    flags: u32,
    security: *mut c_void,
    qos: *mut c_void,
}
const _: [(); if std::mem::size_of::<usize>() == 8 {
    48
} else {
    24
}] = [(); std::mem::size_of::<Attributes>()];

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtOpenKeyEx(out: *mut Hkey, access: u32, attributes: *mut Attributes, options: u32) -> i32;
    fn NtQueryObject(
        handle: Hkey,
        class: u32,
        buffer: *mut u32,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

pub(super) fn open(path: &[u16], access: u32) -> Result<OwnedKey, u32> {
    if !matches!(access, 0x0200_0000 | 0x0100_0000) {
        return Err(super::super::super::nt::status::STATUS_INVALID_PARAMETER);
    }
    open_fixed(path, access)
}

pub(super) fn open_view(path: &[u16], view: super::super::RegistryView) -> Result<OwnedKey, u32> {
    open_fixed(path, 0x0200_0000 | view.flag())
}

fn open_fixed(path: &[u16], access: u32) -> Result<OwnedKey, u32> {
    if path.is_empty()
        || path.len() > super::super::MAX_NAME_UNITS
        || path.first() != Some(&92)
        || path.get(1) == Some(&92)
        || path.contains(&0)
        || path.len() * 2 > u16::MAX as usize
    {
        return Err(super::super::super::nt::status::STATUS_INVALID_PARAMETER);
    }
    let mut path = path.to_vec();
    let mut name = Unicode {
        length: (path.len() * 2) as u16,
        maximum: (path.len() * 2) as u16,
        buffer: path.as_mut_ptr(),
    };
    let mut attributes = Attributes {
        length: std::mem::size_of::<Attributes>() as u32,
        root: null_mut(),
        name: &mut name,
        flags: 0x40,
        security: null_mut(),
        qos: null_mut(),
    };
    let mut handle = null_mut();
    // SAFETY: only selection-validated fixed paths and compile-time access probes reach
    // this API. The counted UTF-16 buffer and attributes live for the call.
    // A successful real HKEY is owned and closes through RegCloseKey.
    let status = unsafe { NtOpenKeyEx(&mut handle, access, &mut attributes, 0) };
    if status == 0 && !handle.is_null() {
        Ok(OwnedKey(handle))
    } else {
        if !handle.is_null() {
            drop(OwnedKey(handle));
        }
        Err(status as u32)
    }
}

pub(super) fn basic(key: &OwnedKey, subject: &str) -> io::Result<u32> {
    let mut words = [0u32; 14];
    let mut returned = 0;
    // SAFETY: live owned key, initialized 56-byte OBJECT_BASIC_INFORMATION
    // storage and exclusive ULONG result; only GrantedAccess is retained.
    let status = unsafe { NtQueryObject(key.0, 0, words.as_mut_ptr(), 56, &mut returned) };
    if status != 0 || returned != 56 {
        return Err(invalid(&format!(
            "{subject} key grant query failed: 0x{:08X}, length {returned}",
            status as u32
        )));
    }
    Ok(words[1])
}
