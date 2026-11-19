//! Fixed borrowed-desktop queries on the already converted native GUI helper.
use super::{Handle, Module, invalid};
use crate::user::windows::objects::Desktop;
use std::ffi::c_void;
use std::io;
use std::sync::Arc;

pub(super) type Information =
    unsafe extern "system" fn(Handle, i32, *mut c_void, u32, *mut u32) -> i32;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentThreadId() -> u32;
    pub(super) fn GetHandleInformation(handle: Handle, flags: *mut u32) -> i32;
}

pub(super) fn text(query: Information, handle: Handle, class: i32) -> io::Result<Vec<u16>> {
    let mut output = [0u16; 1024];
    let mut returned = 0;
    // SAFETY: fixed current-process borrowed desktop and fixed query class;
    // exclusive initialized output/length, no guest pointer or argument.
    let ok = unsafe {
        query(
            handle,
            class,
            output.as_mut_ptr().cast(),
            2048,
            &mut returned,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let count = returned as usize / 2;
    if returned % 2 != 0 || count == 0 || count > output.len() || output[count - 1] != 0 {
        return Err(invalid("selected desktop text extent differs"));
    }
    Ok(output[..count - 1].to_vec())
}

pub(super) fn capture(user: &Module, win32u: &Module) -> io::Result<(usize, Arc<Desktop>)> {
    // SAFETY: live owned selected modules, static terminated export names.
    let query = unsafe { super::GetProcAddress(win32u.0, c"NtUserGetThreadDesktop".as_ptr()) };
    let information =
        unsafe { super::GetProcAddress(user.0, c"GetUserObjectInformationW".as_ptr()) };
    if query.is_null() || information.is_null() {
        return Err(invalid("selected runtime has no desktop metadata query"));
    }
    // SAFETY: measured DWORD -> native handle ABI and documented fixed
    // GetUserObjectInformationW ABI, resolved only from the selected modules.
    let query: unsafe extern "system" fn(u32) -> Handle = unsafe { std::mem::transmute(query) };
    let information: Information = unsafe { std::mem::transmute(information) };
    // SAFETY: current native helper thread only; no guest identifier is forwarded.
    let handle = unsafe { query(GetCurrentThreadId()) };
    if handle.is_null() {
        return Err(invalid("native helper has no assigned desktop"));
    }
    if text(information, handle, 3)? != "Desktop".encode_utf16().collect::<Vec<_>>() {
        return Err(invalid("selected desktop object type differs"));
    }
    let name = text(information, handle, 2)?;
    let mut basic = [0u32; 14];
    let mut returned = 0;
    // SAFETY: exact measured 56-byte native basic-information output. This
    // handle is borrowed; it is neither closed nor copied into guest state.
    let status = unsafe {
        super::super::NtQueryObject(handle, 0, basic.as_mut_ptr().cast(), 56, &mut returned)
    };
    super::super::check(status, "query selected desktop access")?;
    if returned != 56 {
        return Err(invalid("selected desktop basic-information extent differs"));
    }
    let mut flags = 0;
    // SAFETY: fixed borrowed handle and exclusive initialized ULONG output.
    if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((handle as usize, Desktop::selected(name, basic[1], flags)?))
}
