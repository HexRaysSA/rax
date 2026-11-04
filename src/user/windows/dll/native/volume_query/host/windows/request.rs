//! Stable request storage remains owned until the original NT IOSB is terminal.
use super::Error;
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;

#[repr(C)]
struct Io {
    status: usize,
    information: usize,
}
#[repr(C)]
struct Overlapped {
    io: Io,
    offset: [u32; 2],
    event: *mut c_void,
}
const _: () = assert!(std::mem::offset_of!(Overlapped, offset) == 2 * std::mem::size_of::<usize>());

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryVolumeInformationFile(
        file: *mut c_void,
        io: *mut Io,
        output: *mut c_void,
        length: u32,
        class: u32,
    ) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetOverlappedResult(
        file: *mut c_void,
        io: *mut Overlapped,
        bytes: *mut u32,
        wait: i32,
    ) -> i32;
}

pub(super) fn run(
    handle: &std::fs::File,
    class: u32,
    length: u32,
) -> Result<(u32, Vec<u8>), Error> {
    let io = Box::new(UnsafeCell::new(Overlapped {
        io: Io {
            status: 0x103,
            information: 0,
        },
        offset: [0; 2],
        event: std::ptr::null_mut(),
    }));
    // Each UnsafeCell holds one aligned native word. The vector's allocation
    // cannot move while the request owns it; no reference reads kernel output.
    let output: Vec<UnsafeCell<u64>> = (0..u64::from(length).div_ceil(8))
        .map(|_| UnsafeCell::new(0))
        .collect();
    // SAFETY: private aligned storage covers length bytes and the native IOSB
    // ABI. No guest address/handle is passed to NT. The borrowed File, IOSB and
    // output remain owned until immediate return or original-request completion.
    let mut status = unsafe {
        NtQueryVolumeInformationFile(
            handle.as_raw_handle(),
            io.get().cast(),
            output.as_ptr().cast_mut().cast(),
            length,
            class,
        )
    } as u32;
    if status == 0x103 {
        loop {
            let mut bytes = 0;
            // SAFETY: OVERLAPPED has the IOSB as its prefix. FALSE polls the
            // original operation without a file wait or extra SYNCHRONIZE grant.
            // An API error alone does not establish that NT released the buffers.
            unsafe { GetOverlappedResult(handle.as_raw_handle(), io.get(), &mut bytes, 0) };
            // SAFETY: the OS completion contract publishes the pointer-sized
            // status field last. Volatile observation avoids retaining a Rust
            // reference while NT owns/mutates this UnsafeCell allocation.
            status = unsafe { std::ptr::read_volatile(std::ptr::addr_of!((*io.get()).io.status)) }
                as u32;
            if status != 0x103 {
                std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    if status != 0 && status != 0x8000_0005 {
        return Err(Error::Status(status));
    }
    // SAFETY: immediate non-pending return or the original terminal IOSB ends
    // kernel ownership. Information is validated before reading output bytes.
    let information = unsafe { (*io.get()).io.information };
    if information > length as usize {
        return Err(Error::Unavailable(
            "native volume information exceeds supplied buffer".into(),
        ));
    }
    // SAFETY: the initialized allocation spans at least length bytes and is no
    // longer kernel-owned. Copy only the validated initialized result extent.
    let data =
        unsafe { std::slice::from_raw_parts(output.as_ptr().cast::<u8>(), information) }.to_vec();
    Ok((status, data))
}
