//! Sparse storage for a guest file while its section views are live.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::ptr;

const FSCTL_SET_SPARSE: u32 = 0x900c4;
const FSCTL_SET_ZERO_DATA: u32 = 0x980c8;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn DeviceIoControl(
        file: *mut c_void,
        code: u32,
        input: *const c_void,
        input_bytes: u32,
        output: *mut c_void,
        output_bytes: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
}

pub(super) fn mark_sparse(file: &File) -> io::Result<()> {
    control(file, FSCTL_SET_SPARSE, ptr::null(), 0)
}

pub(super) fn zero_range(file: &File, start: u64, end: u64) -> io::Result<()> {
    // FILE_ZERO_DATA_INFORMATION holds two consecutive LARGE_INTEGERs.
    let range = [start as i64, end as i64];
    control(
        file,
        FSCTL_SET_ZERO_DATA,
        range.as_ptr().cast(),
        size_of_val(&range) as u32,
    )
}

fn control(file: &File, code: u32, input: *const c_void, input_bytes: u32) -> io::Result<()> {
    let mut returned = 0;
    // SAFETY: The file remains open for this synchronous call. The input
    // bytes are initialized and neither control expects an output buffer.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            input,
            input_bytes,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
