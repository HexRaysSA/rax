//! Fixed read-only NT records use an owned handle and private stable buffers.
use super::super::super::named_object::{Checked, status};
use crate::user::windows::fs::FileIdentity;
use crate::user::windows::hle::Ctx;
use crate::user::windows::objects::FileObj;
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::os::windows::fs::OpenOptionsExt;
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
#[repr(C, align(8))]
struct Buffer([u8; 64]);
const _: () = assert!(std::mem::offset_of!(Overlapped, offset) == 2 * std::mem::size_of::<usize>());

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationFile(
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
    fn GetLastError() -> u32;
}

pub(super) fn query(c: &Ctx, file: &FileObj, class: u32) -> Checked<Vec<u8>> {
    // This whitelist contains no pointer, handle, process-id or pathname fields.
    let length = match class {
        4 => 40,
        5 | 59 => 24,
        6 | 14 | 35 => 8,
        7 | 17 => 4,
        34 => 56,
        51 => 1,
        _ => {
            return Err(c
                .unsupported(format!("owned native file information class {class}"))
                .into());
        }
    };
    let reopened;
    let handle = if let Some(handle) = &file.host {
        handle
    } else {
        reopened = std::fs::OpenOptions::new()
            .access_mode(0)
            .share_mode(7)
            .custom_flags(0x02000000)
            .open(&file.host_path)
            .map_err(|error| c.unsupported(format!("metadata-only file open: {error}")))?;
        if FileIdentity::retained(&reopened)
            .map_err(|error| c.unsupported(format!("metadata identity: {error}")))?
            != file.lifetime.identity
        {
            return Err(c
                .unsupported("metadata-only file pathname was replaced")
                .into());
        }
        &reopened
    };
    let io = Box::new(UnsafeCell::new(Overlapped {
        io: Io {
            status: 0x103,
            information: 0,
        },
        offset: [0; 2],
        event: std::ptr::null_mut(),
    }));
    let output = Box::new(UnsafeCell::new(Buffer([0; 64])));
    // SAFETY: the system ABI receives only the borrowed owned handle and
    // repr(C), initialized, suitably aligned host allocations. The whitelisted
    // length is at most56 B inside the64 B buffer. UnsafeCell admits kernel
    // mutation without shared Rust references. No callback can unwind here;
    // both boxes and the handle remain live until terminal completion below.
    let result = unsafe {
        NtQueryInformationFile(
            handle.as_raw_handle(),
            io.get().cast(),
            output.get().cast(),
            length,
            class,
        )
    } as u32;
    if result == 0x103 {
        loop {
            let mut transferred = 0;
            // SAFETY: the asserted repr(C) IOSB/OVERLAPPED layout, initialized
            // boxes and borrowed handle remain valid and uniquely available
            // to this system-ABI request. FALSE observes completion without a
            // SYNCHRONIZE grant; the API retains no pointer and cannot unwind.
            if unsafe { GetOverlappedResult(handle.as_raw_handle(), io.get(), &mut transferred, 0) }
                != 0
            {
                break;
            }
            // SAFETY: this system-ABI thread-local scalar query takes no
            // pointer, retains no borrow, and cannot call back or unwind.
            let error = unsafe { GetLastError() };
            if error != 996 {
                // SAFETY: GetOverlappedResult reported a terminal error. Its
                // synchronization makes the completed IOSB observable here.
                let completed = unsafe { (*io.get()).io.status as u32 };
                if completed != 0x103 {
                    return status(completed);
                }
            }
            // A surprising observation error is not proof that the kernel
            // released these buffers. Keep their owner alive and keep observing.
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    } else if result != 0 {
        return status(result);
    }
    // SAFETY: synchronous success or observed terminal completion establishes
    // that the kernel no longer accesses either host-local allocation.
    let (status_code, information, data) = unsafe {
        (
            (*io.get()).io.status as u32,
            (*io.get()).io.information,
            (*output.get()).0,
        )
    };
    if status_code != 0 {
        return status(status_code);
    }
    if information != length as usize {
        return Err(c
            .unsupported(format!(
                "owned file class {class} returned {information} bytes, expected {length}"
            ))
            .into());
    }
    Ok(data[..length as usize].to_vec())
}
