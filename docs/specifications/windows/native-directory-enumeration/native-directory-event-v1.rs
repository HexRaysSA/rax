use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

#[repr(C)]
struct Io {
    status: usize,
    information: usize,
}
#[repr(C)]
struct Unicode {
    length: u16,
    maximum: u16,
    buffer: *const u16,
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryDirectoryFileEx(
        file: *mut c_void,
        event: *mut c_void,
        apc: *mut c_void,
        context: *mut c_void,
        io: *mut Io,
        output: *mut c_void,
        length: u32,
        class: u32,
        flags: u32,
        name: *const Unicode,
    ) -> i32;
    fn NtQueryDirectoryFile(
        file: *mut c_void,
        event: *mut c_void,
        apc: *mut c_void,
        context: *mut c_void,
        io: *mut Io,
        output: *mut c_void,
        length: u32,
        class: u32,
        single: u8,
        name: *const Unicode,
        restart: u8,
    ) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateEventW(
        attributes: *mut c_void,
        manual: i32,
        initial: i32,
        name: *const u16,
    ) -> *mut c_void;
    fn WaitForSingleObject(event: *mut c_void, milliseconds: u32) -> u32;
}
fn main() {
    let root = std::env::temp_dir().join(format!(
        "rax-native-directory-events-{}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("alpha.txt"), b"owned").unwrap();
    for legacy in [false, true] {
        for initial in [false, true] {
            for kind in ["success", "overflow", "missing"] {
                let file = std::fs::OpenOptions::new()
                    .access_mode(0x100001)
                    .share_mode(7)
                    .custom_flags(0x02000000)
                    .open(&root)
                    .unwrap();
                // SAFETY: optional security/name are null; a successful event is a new owned handle.
                let raw = unsafe {
                    CreateEventW(
                        std::ptr::null_mut(),
                        1,
                        i32::from(initial),
                        std::ptr::null(),
                    )
                };
                assert!(!raw.is_null());
                // SAFETY: CreateEventW transferred a unique nonnull handle.
                let event = unsafe { OwnedHandle::from_raw_handle(raw) };
                let units: Vec<_> = if kind == "missing" {
                    "absent.bin"
                } else {
                    "alpha.txt"
                }
                .encode_utf16()
                .collect();
                let name = Unicode {
                    length: (units.len() * 2) as u16,
                    maximum: (units.len() * 2) as u16,
                    buffer: units.as_ptr(),
                };
                let io = UnsafeCell::new(Io {
                    status: usize::MAX / 255 * 0xa5,
                    information: usize::MAX / 255 * 0xa5,
                });
                let output = UnsafeCell::new([0xa5a5a5a5a5a5a5a5u64; 77]);
                let length = if kind == "overflow" { 96 } else { 616 };
                // SAFETY: retained private handles and initialized, aligned storage stay live until
                // observed completion. No callback or untrusted address crosses the native API.
                let code = unsafe {
                    if legacy {
                        NtQueryDirectoryFile(
                            file.as_raw_handle(),
                            event.as_raw_handle(),
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            io.get(),
                            (*output.get()).as_mut_ptr().cast(),
                            length,
                            3,
                            1,
                            &name,
                            0,
                        )
                    } else {
                        NtQueryDirectoryFileEx(
                            file.as_raw_handle(),
                            event.as_raw_handle(),
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            io.get(),
                            (*output.get()).as_mut_ptr().cast(),
                            length,
                            3,
                            2,
                            &name,
                        )
                    }
                } as u32;
                if code == 0x103 {
                    loop {
                        // SAFETY: the private event remains owned; successful wait synchronizes buffers.
                        if unsafe { WaitForSingleObject(event.as_raw_handle(), u32::MAX) } == 0 {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
                // SAFETY: sync return or terminal event observation excludes native writes.
                let (status, information) =
                    unsafe { ((*io.get()).status, (*io.get()).information) };
                // SAFETY: a zero-time probe of the private live event retains nothing.
                let wait = unsafe { WaitForSingleObject(event.as_raw_handle(), 0) };
                assert!(wait == 0 || wait == 258);
                println!(
                    "{{\"legacy\":{legacy},\"initial\":{initial},\"case\":\"{kind}\",\"returned\":{code},\"io_status\":{status},\"information\":{information},\"event_signaled\":{}}}",
                    wait == 0
                );
            }
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
