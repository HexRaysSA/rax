//! Fixed query-only native acquisition; guest flags and pointers never enter it.
use super::super::mui::{MAX_MUI_BYTES, language_generation};
use super::{invalid, invalid_status};
use crate::user::windows::layout::{KUSER_SHARED_DATA, kuser};
use std::ffi::{CStr, c_void};
use std::io;
use std::ptr::NonNull;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtGetMUIRegistryInfo(flags: u32, size: *mut u32, data: *mut c_void) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn ReadProcessMemory(
        process: *mut c_void,
        address: *const c_void,
        output: *mut c_void,
        bytes: usize,
        returned: *mut usize,
    ) -> i32;
}

fn resident_ntdll_export(export: &CStr) -> Option<NonNull<c_void>> {
    let name: Vec<_> = "ntdll.dll\0".encode_utf16().collect();
    // SAFETY: fixed terminated NTDLL name. The process owns its resident
    // NTDLL module for its lifetime, so no reference or unload is needed.
    let module = unsafe { GetModuleHandleW(name.as_ptr()) };
    if module.is_null() {
        return None;
    }
    // SAFETY: live resident module and a terminated export name.
    NonNull::new(unsafe { GetProcAddress(module, export.as_ptr().cast()) })
}

pub(super) fn capture_ui_language_commitment() -> Option<u32> {
    let address = resident_ntdll_export(c"NtIsUILanguageComitted")?;
    // SAFETY: measured zero-argument NTSTATUS query on the selected host
    // profile. No guest state, pointers or inputs cross this boundary.
    let query =
        unsafe { std::mem::transmute::<_, unsafe extern "system" fn() -> u32>(address.as_ptr()) };
    // SAFETY: the resolved zero-argument query stays live in resident NTDLL.
    let (first, second) = unsafe { (query(), query()) };
    (first == second).then_some(first)
}

pub(super) fn capture_installed_ui_language() -> Option<u16> {
    let address = resident_ntdll_export(c"NtQueryInstallUILanguage")?;
    // SAFETY: the admitted export accepts one writable LANGID and returns
    // NTSTATUS. Its resident module keeps the pointer valid during capture.
    let query = unsafe {
        std::mem::transmute::<_, unsafe extern "system" fn(*mut u16) -> i32>(address.as_ptr())
    };
    let (mut first, mut second) = (0, u16::MAX);
    // SAFETY: both outputs are exclusive native u16 values with no guest data.
    let (first_status, second_status) = unsafe { (query(&mut first), query(&mut second)) };
    (first_status == 0 && second_status == 0 && first == second).then_some(first)
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

fn shared_language_generation() -> io::Result<u32> {
    let mut value = 0u32;
    let mut returned = 0usize;
    // SAFETY: the current-process pseudo-handle reads one fixed word from
    // the installed readonly shared page into exclusive native output.
    let status = unsafe {
        ReadProcessMemory(
            (-1isize) as *mut c_void,
            (KUSER_SHARED_DATA + kuser::LANG_GENERATION_COUNT) as *const c_void,
            (&mut value as *mut u32).cast(),
            size_of::<u32>(),
            &mut returned,
        )
    };
    if status == 0 || returned != size_of::<u32>() {
        return Err(invalid(
            "cannot read the installed shared MUI language generation",
        ));
    }
    Ok(value)
}

pub(super) fn capture(check_shared_generation: bool) -> io::Result<Vec<u8>> {
    for _ in 0..3 {
        let before = check_shared_generation
            .then(shared_language_generation)
            .transpose()?;
        let first = query()?;
        // Keep both native allocations live: self-relative query data must
        // agree at different output addresses as well as across queries.
        if first == query()? {
            if let Some(before) = before
                && (language_generation(&first) != Some(before)
                    || shared_language_generation()? != before)
            {
                continue;
            }
            return Ok(first);
        }
    }
    Err(invalid(if check_shared_generation {
        "installed MUI query data or language generation disagreed during bounded capture"
    } else {
        "installed MUI query changed during bounded capture"
    }))
}
