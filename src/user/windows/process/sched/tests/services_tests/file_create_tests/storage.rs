//! Independent OS readback of data produced by the emulated create service.
use std::fs::File;

#[cfg(unix)]
pub(super) fn ea(file: &File) -> Vec<u8> {
    use std::os::fd::AsRawFd;
    let mut raw = [0u8; 68];
    // SAFETY: an owned live descriptor, literal terminated key and exclusive
    // bounded output. The readback does not call the production metadata codec.
    #[cfg(target_os = "linux")]
    let n = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"user.rax.windows.ea".as_ptr(),
            raw.as_mut_ptr().cast(),
            raw.len(),
        )
    };
    #[cfg(target_os = "macos")]
    let n = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"user.rax.windows.ea".as_ptr(),
            raw.as_mut_ptr().cast(),
            raw.len(),
            0,
            0,
        )
    };
    assert!(n >= 4, "EA readback: {}", std::io::Error::last_os_error());
    assert_eq!(&raw[..4], b"RAX\x01");
    raw[4..n as usize].to_vec()
}

#[cfg(unix)]
pub(super) fn allocation(file: &File) -> u64 {
    use std::os::unix::fs::MetadataExt;
    file.metadata().unwrap().blocks().checked_mul(512).unwrap()
}

#[cfg(windows)]
mod native {
    use std::ffi::c_void;
    #[repr(C)]
    pub(super) struct Io {
        pub status: usize,
        pub information: usize,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        pub(super) fn NtQueryEaFile(
            file: *mut c_void,
            io: *mut Io,
            output: *mut c_void,
            bytes: u32,
            single: u8,
            list: *const c_void,
            list_bytes: u32,
            index: *const u32,
            restart: u8,
        ) -> i32;
        pub(super) fn NtQueryInformationFile(
            file: *mut c_void,
            io: *mut Io,
            output: *mut c_void,
            bytes: u32,
            class: u32,
        ) -> i32;
    }
}

#[cfg(windows)]
pub(super) fn ea(file: &File) -> Vec<u8> {
    use std::os::windows::io::AsRawHandle;
    let mut output = [0u32; 16];
    let mut io = native::Io {
        status: 0,
        information: 0,
    };
    // SAFETY: literal query selectors, borrowed owned handle and initialized
    // aligned local buffers. No guest input or address is passed to the kernel.
    let code = unsafe {
        native::NtQueryEaFile(
            file.as_raw_handle(),
            &mut io,
            output.as_mut_ptr().cast(),
            64,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            1,
        )
    } as u32;
    if code == 0xc0000052 {
        return Vec::new();
    }
    assert_eq!(code, 0);
    assert!(io.information <= 64);
    output
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .take(io.information)
        .collect()
}

#[cfg(windows)]
pub(super) fn allocation(file: &File) -> u64 {
    use std::os::windows::io::AsRawHandle;
    let mut output = [0u64; 3];
    let mut io = native::Io {
        status: 0,
        information: 0,
    };
    // SAFETY: a borrowed live file and exclusive aligned FILE_STANDARD_INFORMATION
    // buffer of its exact 24-byte native layout; class 5 is fixed by this test.
    assert_eq!(
        unsafe {
            native::NtQueryInformationFile(
                file.as_raw_handle(),
                &mut io,
                output.as_mut_ptr().cast(),
                24,
                5,
            )
        },
        0
    );
    output[0]
}
