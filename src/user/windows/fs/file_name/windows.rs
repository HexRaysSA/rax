use std::ffi::{OsString, c_void};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFinalPathNameByHandleW(
        file: *mut c_void,
        output: *mut u16,
        capacity: u32,
        flags: u32,
    ) -> u32;
}

pub(super) fn open_root(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(0)
        .share_mode(7)
        .custom_flags(0x0200_0000)
        .open(path)
}

pub(super) fn current(file: &File) -> io::Result<PathBuf> {
    let mut buffer = vec![0u16; 512];
    loop {
        // SAFETY: the borrowed handle and initialized UTF-16 allocation remain
        // live for this synchronous system call. FILE_NAME_OPENED (8) queries
        // the retained open without imposing normalized-parent access rights.
        let count = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                8,
            )
        };
        if count == 0 {
            return Err(io::Error::last_os_error());
        }
        if (count as usize) < buffer.len() {
            return Ok(PathBuf::from(OsString::from_wide(
                &buffer[..count as usize],
            )));
        }
        // NT counted names are bounded by a 16-bit byte length. This also
        // leaves room for the Win32 volume prefix and terminating character.
        let capacity = (count as usize)
            .checked_add(1)
            .filter(|n| *n <= 65536)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "native file name length"))?;
        buffer.resize(capacity, 0);
    }
}
