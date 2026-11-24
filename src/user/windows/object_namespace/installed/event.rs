//! Read-only launch-time capture of the fixed LSA authentication readiness event.

use super::{Attributes, Handle, LSA_AUTHENTICATION_EVENT, Owned, Unicode, null_mut};
use std::ffi::c_void;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtOpenEvent(out: *mut Handle, access: u32, attributes: *mut Attributes) -> i32;
    fn NtQueryEvent(
        handle: Handle,
        class: u32,
        buffer: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

pub(in super::super) fn capture_lsa_authentication() -> bool {
    let mut text: Vec<u16> = LSA_AUTHENTICATION_EVENT.encode_utf16().collect();
    let length = (text.len() * 2) as u16;
    let mut name = Unicode {
        length,
        maximum: length,
        buffer: text.as_mut_ptr(),
    };
    let mut attributes = Attributes {
        length: std::mem::size_of::<Attributes>() as u32,
        root: null_mut(),
        name: &mut name,
        flags: 0x40,
        security: null_mut(),
        qos: null_mut(),
    };
    let mut event = Owned(null_mut());
    // SAFETY: fixed counted name and live native attributes, with a sole output handle.
    let status = unsafe { NtOpenEvent(&mut event.0, 0x0010_0001, &mut attributes) };
    if status != 0 || event.0.is_null() {
        return false;
    }
    let mut information = [-1i32; 2];
    let mut returned = 0;
    // SAFETY: class 0 writes the event type and signal state as two LONGs.
    let status = unsafe {
        NtQueryEvent(
            event.0,
            0,
            information.as_mut_ptr().cast(),
            8,
            &mut returned,
        )
    };
    status == 0 && returned == 8 && information == [0, 1]
}
