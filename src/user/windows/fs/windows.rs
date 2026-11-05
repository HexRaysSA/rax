//! One handle identity contract for native NT and Win32-emulated file objects.
use super::FileIdentity;
use std::ffi::c_void;
use std::fs::File;
use std::os::windows::io::AsRawHandle;

#[repr(C)]
struct FileId {
    volume: u64,
    id: [u8; 16],
}

const _: [(); 24] = [(); std::mem::size_of::<FileId>()];

// FILE_STANDARD_INFO is 24 bytes; EndOfFile is the signed LARGE_INTEGER at 8.
#[repr(C, align(8))]
struct Standard([u8; 24]);

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandleEx(
        file: *mut c_void,
        class: i32,
        information: *mut c_void,
        bytes: u32,
    ) -> i32;
}

pub(super) fn length(file: &File) -> std::io::Result<u64> {
    let mut standard = Standard([0; 24]);
    // SAFETY: the documented synchronous FileStandardInfo call borrows a live
    // retained handle and this initialized, aligned, exact-size host buffer.
    // It retains no pointer and receives no guest address or pathname. Native
    // data-only handles, with and without SYNCHRONIZE, independently succeed.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            1,
            (&mut standard as *mut Standard).cast(),
            24,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let end = i64::from_ne_bytes(standard.0[8..16].try_into().unwrap());
    u64::try_from(end).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "negative retained file length",
        )
    })
}

pub(super) fn identity(file: &File) -> std::io::Result<FileIdentity> {
    let mut id = FileId {
        volume: 0,
        id: [0; 16],
    };
    // SAFETY: the borrowed File owns a live handle. FileIdInfo writes exactly
    // this initialized 24-byte SDK structure and retains no pointer. Native
    // read/execute and synchronization-only grants were independently exercised.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            18,
            (&mut id as *mut FileId).cast(),
            24,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(FileIdentity::Windows(id.volume, id.id))
}
