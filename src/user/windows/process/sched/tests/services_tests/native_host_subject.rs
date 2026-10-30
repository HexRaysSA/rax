//! Independent typed Win32 token controls, separate from the capture parser.
use super::{CloseHandle, GetCurrentProcess, GetTokenInformation, OpenProcessToken};
use crate::user::windows::security::{Group, Privilege, Subject};
use std::ffi::c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct SidAttributes {
    sid: *const c_void,
    attributes: u32,
}

#[repr(C)]
struct Groups {
    count: u32,
    first: SidAttributes,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LuidAttributes {
    low: u32,
    high: u32,
    attributes: u32,
}

#[repr(C)]
struct Privileges {
    count: u32,
    first: LuidAttributes,
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn IsValidSid(sid: *const c_void) -> i32;
    fn GetLengthSid(sid: *const c_void) -> u32;
}

struct Token(*mut c_void);

impl Token {
    fn current() -> Self {
        let mut token = std::ptr::null_mut();
        // SAFETY: fixed current-process pseudo-handle, TOKEN_QUERY and one
        // initialized exclusive output. No host token state is changed.
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut token) },
            0
        );
        Self(token)
    }

    fn information(&self, class: u32) -> Buffer {
        let mut required = 0;
        // SAFETY: live query-only handle and exclusive DWORD sizing output.
        assert_eq!(
            unsafe { GetTokenInformation(self.0, class, std::ptr::null_mut(), 0, &mut required) },
            0
        );
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(122));
        assert!((4..=65536).contains(&required));
        let mut words = vec![0usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];
        let mut got = 0;
        // SAFETY: initialized native-pointer-aligned storage with at least the
        // requested capacity. Every retained embedded pointer is checked below.
        assert_ne!(
            unsafe {
                GetTokenInformation(self.0, class, words.as_mut_ptr().cast(), required, &mut got)
            },
            0
        );
        assert!((4..=required).contains(&got));
        Buffer {
            words,
            bytes: got as usize,
        }
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: the unique successful OpenProcessToken reference, never
        // passed to the guest or closed anywhere else.
        unsafe { CloseHandle(self.0) };
    }
}

struct Buffer {
    words: Vec<usize>,
    bytes: usize,
}

impl Buffer {
    fn bytes(&self) -> &[u8] {
        // SAFETY: all backing words were initialized; the API's returned span
        // was checked against capacity and is borrowed without mutation.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.bytes) }
    }

    fn dword(&self) -> u32 {
        u32::from_ne_bytes(self.bytes()[..4].try_into().unwrap())
    }

    fn group(&self, offset: usize) -> Group {
        assert!(offset + std::mem::size_of::<SidAttributes>() <= self.bytes);
        // SAFETY: a complete initialized native SID_AND_ATTRIBUTES record at
        // an ABI-derived offset. Raw pointers and integers admit all bit patterns.
        let record = unsafe {
            self.words
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<SidAttributes>()
                .read_unaligned()
        };
        let base = self.words.as_ptr() as usize;
        let sid_offset = (record.sid as usize).checked_sub(base).unwrap();
        assert!(sid_offset.checked_add(8).unwrap() <= self.bytes);
        let header_extent = 8 + usize::from(self.bytes()[sid_offset + 1]) * 4;
        assert!(sid_offset.checked_add(header_extent).unwrap() <= self.bytes);
        // SAFETY: the complete SID extent named by the native header lies
        // inside its still-owned query buffer. Validate before GetLengthSid.
        assert_ne!(unsafe { IsValidSid(record.sid) }, 0);
        // SAFETY: the native SID header lies inside the still-owned query
        // buffer. GetLengthSid supplies an independent native extent control.
        let length = unsafe { GetLengthSid(record.sid) } as usize;
        assert!((8..=68).contains(&length));
        assert!(sid_offset.checked_add(length).unwrap() <= self.bytes);
        Group {
            sid: self.bytes()[sid_offset..sid_offset + length].to_vec(),
            attributes: record.attributes,
        }
    }

    fn groups(&self) -> Vec<Group> {
        let count = self.dword() as usize;
        let offset = std::mem::offset_of!(Groups, first);
        let stride = std::mem::size_of::<SidAttributes>();
        assert!(count <= 4096 && offset + count * stride <= self.bytes);
        (0..count)
            .map(|index| self.group(offset + index * stride))
            .collect()
    }

    fn privileges(&self) -> Vec<Privilege> {
        let count = self.dword() as usize;
        let offset = std::mem::offset_of!(Privileges, first);
        let stride = std::mem::size_of::<LuidAttributes>();
        assert_eq!(stride, 12);
        assert!(count <= 4096 && offset + count * stride <= self.bytes);
        (0..count)
            .map(|index| {
                // SAFETY: complete initialized native LUID_AND_ATTRIBUTES records
                // fit inside the checked query span. Their fields are all DWORDs.
                let record = unsafe {
                    self.words
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset + index * stride)
                        .cast::<LuidAttributes>()
                        .read_unaligned()
                };
                Privilege {
                    luid: u64::from(record.low) | (u64::from(record.high) << 32),
                    attributes: record.attributes,
                }
            })
            .collect()
    }
}

pub(super) fn capture() -> Subject {
    let token = Token::current();
    let user = token.information(1).group(0);
    Subject {
        statistics: Some(
            crate::user::windows::security::token::statistics::Statistics::selected(
                token.information(10).bytes().try_into().unwrap(),
            )
            .unwrap(),
        ),
        user_attributes: user.attributes,
        user: user.sid,
        groups: token.information(2).groups(),
        restricted: token.information(11).groups(),
        app_container: token.information(29).dword() != 0,
        privileges: token.information(3).privileges(),
        attributes: None,
    }
}
