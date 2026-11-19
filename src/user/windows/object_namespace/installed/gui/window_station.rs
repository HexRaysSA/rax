//! Fixed metadata queries for the already assigned native window station.
use super::desktop::{GetHandleInformation, Information, text};
use super::{Handle, Module, invalid};
use crate::user::windows::objects::WindowStation;
use std::io;
use std::sync::Arc;

pub(super) fn capture(user: &Module, win32u: &Module) -> io::Result<(usize, Arc<WindowStation>)> {
    // SAFETY: live selected modules, static terminated export names.
    let query =
        unsafe { super::GetProcAddress(win32u.0, c"NtUserGetProcessWindowStation".as_ptr()) };
    let information =
        unsafe { super::GetProcAddress(user.0, c"GetUserObjectInformationW".as_ptr()) };
    if query.is_null() || information.is_null() {
        return Err(invalid(
            "selected runtime has no assigned window station query",
        ));
    }
    // SAFETY: fixed native ABIs, resolved from the selected installed modules.
    let query: unsafe extern "system" fn() -> Handle = unsafe { std::mem::transmute(query) };
    let information: Information = unsafe { std::mem::transmute(information) };
    // SAFETY: query the helper's own borrowed handle with no forwarded arguments.
    let handle = unsafe { query() };
    if handle.is_null()
        || text(information, handle, 3)? != "WindowStation".encode_utf16().collect::<Vec<_>>()
    {
        return Err(invalid("native helper has no typed process window station"));
    }
    let name = text(information, handle, 2)?;
    let mut basic = [0u32; 14];
    let mut returned = 0;
    // SAFETY: query a fixed class on the borrowed handle into exclusive outputs.
    super::super::check(
        unsafe {
            super::super::NtQueryObject(handle, 0, basic.as_mut_ptr().cast(), 56, &mut returned)
        },
        "query selected window station access",
    )?;
    if returned != 56 {
        return Err(invalid(
            "selected window station basic-information extent differs",
        ));
    }
    let mut flags = 0;
    // SAFETY: borrowed handle and exclusive ULONG output.
    if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut attributes = [0u32; 3];
    // SAFETY: fixed UOI_FLAGS class with the documented 12-byte output.
    if unsafe { information(handle, 1, attributes.as_mut_ptr().cast(), 12, &mut returned) } == 0
        || returned != 12
        || attributes[0] != flags & 1
        || attributes[1] != 0
    {
        return Err(invalid("selected window station flag record differs"));
    }
    let mut sid = [0u16; 34];
    // SAFETY: own station only, fixed UOI_USER_SID class and bounded aligned storage.
    if unsafe { information(handle, 4, sid.as_mut_ptr().cast(), 68, &mut returned) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if returned > 68 || returned % 2 != 0 {
        return Err(invalid("selected window station SID extent differs"));
    }
    let sid = sid[..returned as usize / 2]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    Ok((
        handle as usize,
        WindowStation::selected(name, basic[1], flags, attributes[2], sid)?,
    ))
}
