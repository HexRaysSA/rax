//! Fixed read-only statistics acquisition from the subject's private token.
use super::{Handle, Token};
use crate::user::windows::security::token::statistics::{self, Statistics};
use std::ffi::c_void;
use std::io;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationToken(
        token: Handle,
        class: u32,
        output: *mut c_void,
        bytes: u32,
        returned: *mut u32,
    ) -> i32;
}

pub(super) fn capture(token: &Token) -> io::Result<Statistics> {
    statistics::capture_with(|words, returned| {
        // SAFETY: selected private token and two exclusively borrowed,
        // initialized, eight-byte-aligned 56-byte outputs. The selector and
        // length are fixed. No host handle or pointer escapes to the guest.
        unsafe {
            NtQueryInformationToken(
                token.0,
                10,
                words.as_mut_ptr().cast(),
                statistics::BYTES as u32,
                returned,
            )
        }
    })
    .map_err(io::Error::other)
}
