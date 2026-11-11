//! An adapter-owned host section pins Windows file-section lifetime rules.
//! Only validated scalar policy and an already admitted file handle cross this
//! seam. Guest pointers, handles, names and security descriptors never do.
use super::{Error, MAX_BYTES};
use std::ffi::c_void;
use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

type Handle = *mut c_void;
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateSection(
        section: *mut Handle,
        access: u32,
        attributes: Handle,
        maximum: *const i64,
        protection: u32,
        allocation: u32,
        file: Handle,
    ) -> i32;
    fn NtQuerySection(
        section: Handle,
        class: u32,
        output: Handle,
        length: usize,
        returned: *mut usize,
    ) -> i32;
}
#[repr(C)]
struct Basic {
    base: usize,
    attributes: u32,
    maximum: i64,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CompareObjectHandles(first: Handle, second: Handle) -> i32;
}

pub(super) fn same_object(first: &OwnedHandle, second: &OwnedHandle) -> bool {
    // SAFETY: live adapter-owned Section handles, borrowed only for the query.
    unsafe { CompareObjectHandles(first.as_raw_handle(), second.as_raw_handle()) != 0 }
}

pub(super) fn create(
    file: &File,
    maximum: u64,
    protection: u32,
) -> Result<(OwnedHandle, u64), Error> {
    let maximum = maximum as i64;
    let mut handle = std::ptr::null_mut();
    // SAFETY: owned local output, validated size/protection, unnamed fixed data
    // allocation, and borrowed admitted host file. No guest address is used.
    let status = unsafe {
        NtCreateSection(
            &mut handle,
            1 | 4 | if matches!(protection, 4 | 0x40) { 2 } else { 0 },
            std::ptr::null_mut(),
            if maximum == 0 {
                std::ptr::null()
            } else {
                &maximum
            },
            protection,
            0x08000000,
            file.as_raw_handle(),
        )
    };
    if status < 0 {
        return Err(Error::Status(status as u32));
    }
    if handle.is_null() {
        return Err(Error::Unavailable(
            "host file section returned no handle".into(),
        ));
    }
    // SAFETY: one successful native creation transfers its unique handle.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    let mut basic = Basic {
        base: 0,
        attributes: 0,
        maximum: 0,
    };
    let mut returned = 0;
    // SAFETY: live exclusively owned section, correctly aligned initialized
    // host structure and an exclusive host SIZE_T destination.
    let status = unsafe {
        NtQuerySection(
            handle.as_raw_handle(),
            0,
            (&mut basic as *mut Basic).cast(),
            std::mem::size_of::<Basic>(),
            &mut returned,
        )
    };
    if status != 0
        || returned != std::mem::size_of::<Basic>()
        || basic.base != 0
        || basic.attributes != 0x00800000
        || !(1..=MAX_BYTES as i64).contains(&basic.maximum)
    {
        return Err(Error::Unavailable(format!(
            "host file-section basic contract changed: {status:#010x}"
        )));
    }
    Ok((handle, basic.maximum as u64))
}
