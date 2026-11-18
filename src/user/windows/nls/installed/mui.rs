//! Fixed query-only native acquisition; guest flags and pointers never enter it.
use super::super::mui::MAX_MUI_BYTES;
use super::{invalid, invalid_status};
use std::ffi::c_void;
use std::io;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtGetMUIRegistryInfo(flags: u32, size: *mut u32, data: *mut c_void) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
}

pub(super) fn capture_ui_language_commitment() -> Option<u32> {
    let name: Vec<_> = "ntdll.dll\0".encode_utf16().collect();
    // SAFETY: fixed terminated NTDLL name. The process owns its resident
    // NTDLL module for its lifetime, so no reference or unload is needed.
    let module = unsafe { GetModuleHandleW(name.as_ptr()) };
    if module.is_null() {
        return None;
    }
    // SAFETY: live module and a fixed terminated export name.
    let address = unsafe { GetProcAddress(module, c"NtIsUILanguageComitted".as_ptr().cast()) };
    if address.is_null() {
        return None;
    }
    // SAFETY: measured zero-argument NTSTATUS query on the selected host
    // profile. No guest state, pointers or inputs cross this boundary.
    let query = unsafe { std::mem::transmute::<_, unsafe extern "system" fn() -> u32>(address) };
    // SAFETY: the resolved zero-argument query stays live in resident NTDLL.
    let (first, second) = unsafe { (query(), query()) };
    (first == second).then_some(first)
}

fn query() -> io::Result<Vec<u8>> {
    let mut size = 0u32;
    // SAFETY: fixed query operation, exclusive ULONG output, NULL data. The
    // measured entry returns success and the required size for this query.
    let status = unsafe { NtGetMUIRegistryInfo(0, &mut size, std::ptr::null_mut()) };
    if status < 0 {
        return Err(invalid_status("NtGetMUIRegistryInfo sizing", status));
    }
    if size == 0 || size as usize > MAX_MUI_BYTES {
        return Err(invalid("installed MUI query exceeds one MiB"));
    }
    let capacity = size;
    let mut bytes = vec![0; capacity as usize];
    // SAFETY: fixed query-only flags, exclusive initialized native outputs
    // sized by the preceding bounded query. No host pointer escapes the copy.
    let status = unsafe { NtGetMUIRegistryInfo(0, &mut size, bytes.as_mut_ptr().cast()) };
    if status < 0 {
        return Err(invalid_status("NtGetMUIRegistryInfo data", status));
    }
    if size != capacity {
        return Err(invalid("installed MUI query changed size during capture"));
    }
    Ok(bytes)
}

pub(super) fn capture() -> io::Result<Vec<u8>> {
    for _ in 0..3 {
        let first = query()?;
        // Keep both native allocations live: self-relative query data must
        // agree at different output addresses as well as across queries.
        if first == query()? {
            return Ok(first);
        }
    }
    Err(invalid(
        "installed MUI query changed during bounded capture",
    ))
}
