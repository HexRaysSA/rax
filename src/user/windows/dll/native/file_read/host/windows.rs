//! Only a retained owned file, private aligned output and private IOSB reach NT.
use super::super::super::named_object::{Checked, Failure};
use super::super::Completion;
use crate::user::windows::hle::Ctx;
use crate::user::windows::nt::status::STATUS_INSUFFICIENT_RESOURCES;
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

#[repr(C)]
struct Io {
    status: usize,
    information: usize,
}
#[repr(C, align(4096))]
struct Block([u8; 4096]);
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtReadFile(
        file: *mut c_void,
        event: *mut c_void,
        apc: *mut c_void,
        context: *mut c_void,
        io: *mut Io,
        output: *mut c_void,
        length: u32,
        offset: *const i64,
        key: *const u32,
    ) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateEventW(
        attributes: *mut c_void,
        manual: i32,
        signaled: i32,
        name: *const u16,
    ) -> *mut c_void;
    fn WaitForSingleObject(event: *mut c_void, milliseconds: u32) -> u32;
}

pub(super) fn read(
    c: &Ctx,
    file: &std::fs::File,
    length: usize,
    position: i64,
) -> Checked<Completion> {
    let count = length.max(1).div_ceil(4096);
    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(count)
        .map_err(|_| Failure::Status(STATUS_INSUFFICIENT_RESOURCES))?;
    for _ in 0..count {
        blocks.push(UnsafeCell::new(Block([0; 4096])));
    }
    let output = blocks.as_mut_ptr().cast::<u8>();
    let sentinel = usize::from_ne_bytes([0xa5; std::mem::size_of::<usize>()]);
    let io = Box::new(UnsafeCell::new(Io {
        status: sentinel,
        information: 0,
    }));
    // SAFETY: the system ABI receives null optional security/name pointers and
    // valid scalar flags. It returns a fresh process-owned handle, retains no
    // Rust borrow, and cannot call back or unwind.
    let raw_event = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
    if raw_event.is_null() {
        return Err(Failure::Status(STATUS_INSUFFICIENT_RESOURCES));
    }
    // SAFETY: CreateEventW returned a new nonnull owned handle. No other Rust
    // owner or close path exists; OwnedHandle closes it after request completion.
    let event = unsafe { OwnedHandle::from_raw_handle(raw_event) };
    let offset = if position < 0 {
        std::ptr::null()
    } else {
        &position
    };
    // SAFETY: file is the borrowed retained owned descriptor, never a guest
    // handle. The bounded length fits contiguous initialized4096-aligned
    // UnsafeCell blocks. The repr(C) IOSB is initialized and pointer-aligned.
    // Kernel mutation has no competing Rust data access. No APC, guest pointer
    // or callback is forwarded. The immutable offset and every allocation and
    // handle stay live through terminal observation. System calls cannot unwind.
    let initial = unsafe {
        NtReadFile(
            file.as_raw_handle(),
            event.as_raw_handle(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            io.get(),
            output.cast(),
            length as u32,
            offset,
            std::ptr::null(),
        )
    } as u32;
    if initial == 0x103 {
        loop {
            // SAFETY: the private event is an exclusively owned valid handle
            // associated with this request. Successful waiting synchronizes all
            // kernel IOSB/output writes. It retains no pointer or callback and
            // cannot unwind. No IOSB byte is polled concurrently with the kernel.
            if unsafe { WaitForSingleObject(event.as_raw_handle(), u32::MAX) } == 0 {
                break;
            }
            // An unexpected observation failure does not release kernel-owned
            // buffers. Keep every allocation, offset, file and event alive.
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    // SAFETY: synchronous completion or observed terminal completion releases
    // all kernel access. The owned allocations remain initialized and live;
    // reading the private IOSB has no aliasing or synchronization conflict.
    let (raw_status, information) = unsafe { ((*io.get()).status, (*io.get()).information) };
    let published = raw_status != sentinel;
    if information > length {
        return Err(c
            .unsupported("owned NtReadFile returned an oversized count")
            .into());
    }
    let bytes = if published {
        // SAFETY: information was bounded by the initialized contiguous output
        // allocation; terminal observation excludes further kernel writes.
        // u8 needs no alignment and to_vec owns its copy before blocks drop.
        unsafe { std::slice::from_raw_parts(output, information).to_vec() }
    } else {
        Vec::new()
    };
    Ok(Completion {
        code: if published {
            raw_status as u32
        } else {
            initial
        },
        bytes,
        full_status: (raw_status as u64) >> 32 == 0,
        published,
    })
}
