//! Independent, read-only class 9 observations. No RAX code is linked.
//! Only this process's handles and initialized private buffers reach NTDLL.

#[cfg(not(windows))]
compile_error!("This standalone native reference requires Windows NTDLL.");

use std::cell::UnsafeCell;
use std::ffi::{OsString, c_void};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::time::Duration;

#[repr(C)]
struct Io {
    status: usize,
    information: usize,
}

#[repr(C)]
struct ProcessMachineInformation {
    machine: u16,
    reserved: u16,
    attributes: u32,
}

#[repr(C, align(8))]
struct Buffer([u8; 4096]);

#[repr(C)]
struct Version {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    service_pack: [u16; 128],
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationFile(
        file: *mut c_void,
        io: *mut Io,
        output: *mut c_void,
        length: u32,
        class: u32,
    ) -> i32;
    fn RtlGetVersion(version: *mut Version) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemDirectoryW(output: *mut u16, length: u32) -> u32;
    fn GetCurrentProcess() -> *mut c_void;
    fn GetProcessInformation(
        process: *mut c_void,
        class: u32,
        information: *mut ProcessMachineInformation,
        bytes: u32,
    ) -> i32;
    fn IsWow64Process2(
        process: *mut c_void,
        process_machine: *mut u16,
        native_machine: *mut u16,
    ) -> i32;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *mut c_void,
        disposition: u32,
        flags: u32,
        template: *mut c_void,
    ) -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
    fn SetLastError(value: u32);
    fn GetLastError() -> u32;
}

struct Handle(*mut c_void);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: successful CreateFileW transferred this unique handle to us.
        // Every request has reached terminal completion before its owner drops.
        assert_ne!(unsafe { CloseHandle(self.0) }, 0);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

fn main() {
    assert_eq!(std::mem::size_of::<Io>(), 16, "64-bit native reference");
    let compiled_machine = if cfg!(target_arch = "aarch64") {
        0xaa64
    } else if cfg!(target_arch = "x86_64") {
        0x8664
    } else {
        panic!("this reference qualifies ARM64 and x64 callers only");
    };
    let mut process_machine = 0u16;
    let mut native_machine = 0u16;
    // SAFETY: the pseudo-handle is borrowed and the two initialized scalar
    // outputs remain writable for the synchronous system-ABI call.
    assert_ne!(
        unsafe {
            IsWow64Process2(
                GetCurrentProcess(),
                &mut process_machine,
                &mut native_machine,
            )
        },
        0
    );
    let mut machine_information = ProcessMachineInformation {
        machine: 0,
        reserved: 0,
        attributes: 0,
    };
    // SAFETY: ProcessMachineTypeInfo (9) writes exactly the initialized 8-byte
    // repr(C) structure. The borrowed pseudo-handle and scalar outputs live
    // throughout this synchronous system call; no pointer is retained.
    assert_ne!(
        unsafe { GetProcessInformation(GetCurrentProcess(), 9, &mut machine_information, 8) },
        0
    );
    let machine = machine_information.machine;
    assert_eq!(
        machine, compiled_machine,
        "actual caller ABI must match compiled machine code"
    );
    let mut version = Version {
        size: std::mem::size_of::<Version>() as u32,
        major: 0,
        minor: 0,
        build: 0,
        platform: 0,
        service_pack: [0; 128],
    };
    // SAFETY: repr(C), initialized OSVERSIONINFOW has its exact byte size.
    // NTDLL fills only this live allocation and retains no pointer or callback.
    assert_eq!(unsafe { RtlGetVersion(&mut version) }, 0);
    println!(
        "{{\"kind\":\"host\",\"machine\":{machine},\"process_machine\":{process_machine},\"native_machine\":{native_machine},\"managed_caller\":false,\"pointer_bytes\":8,\"major\":{},\"minor\":{},\"build\":{}}}",
        version.major, version.minor, version.build
    );
    let mut system = vec![0u16; 32768];
    // SAFETY: the writable UTF-16 allocation has the supplied capacity and
    // remains live for this synchronous system-ABI call; no pointer is retained.
    let length = unsafe { GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32) };
    assert!(length > 0 && (length as usize) < system.len());
    let directory = PathBuf::from(OsString::from_wide(&system[..length as usize]));
    let file = directory.join("ntdll.dll");
    let lengths = [
        0, 1, 3, 4, 5, 7, 8, 9, 10, 11, 12, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512,
        1024,
    ];
    let mut cases = 0;
    let mut total_success = 0;
    let mut pending = 0;
    for (label, path, flags) in [("directory", directory, 0x0200_0080), ("file", file, 0x80)] {
        let mut name: Vec<u16> = path.as_os_str().encode_wide().collect();
        let raw_name: Vec<u8> = name.iter().flat_map(|value| value.to_le_bytes()).collect();
        name.push(0);
        println!(
            "{{\"kind\":\"input\",\"object\":\"{label}\",\"name_hex\":\"{}\"}}",
            hex(&raw_name)
        );
        for asynchronous in [false, true] {
            for request in [0u32, 0x80, 0x8000_0000] {
                let access = request | if asynchronous { 0x0010_0000 } else { 0 };
                let flags = flags | if asynchronous { 0x4000_0000 } else { 0 };
                // SAFETY: terminated native path lives through this call. OPEN_EXISTING,
                // read-only/metadata access and sharing 7 neither create nor modify an
                // installed object. The asynchronous variant adds OVERLAPPED and an
                // explicit SYNCHRONIZE grant so pending ownership can be observed.
                let raw = unsafe {
                    CreateFileW(
                        name.as_ptr(),
                        access,
                        7,
                        std::ptr::null_mut(),
                        3,
                        flags,
                        std::ptr::null_mut(),
                    )
                };
                assert_ne!(raw as usize, usize::MAX, "open {label}, access={access:#x}");
                let handle = Handle(raw);
                let mut successes = 0;
                for length in lengths {
                    for offset in [0usize, 1, 2, 3, 4, 7, 8] {
                        let start = 16 + offset;
                        let captured = start + length as usize + 16;
                        assert!(captured <= 4096);
                        let io = Box::new(UnsafeCell::new(Io {
                            status: 0xa5a5_a5a5_0000_0103,
                            information: 0xa5a5_a5a5_a5a5_a5a5,
                        }));
                        let buffer = Box::new(UnsafeCell::new(Buffer([0xa5; 4096])));
                        // SAFETY: both boxes are initialized, stable and privately
                        // owned; repr(C) IOSB is naturally aligned. The pointer is
                        // within the 4096-byte output allocation and the complete
                        // requested span fits. Offset 1 deliberately tests alignment,
                        // never address validity. UnsafeCell permits kernel stores.
                        // No guest pointer, Rust callback or RAX API is involved.
                        let returned = unsafe {
                            SetLastError(0x1234_5678);
                            NtQueryInformationFile(
                                handle.0,
                                io.get(),
                                buffer.get().cast::<u8>().add(start).cast(),
                                length,
                                9,
                            ) as u32
                        };
                        // SAFETY: the scalar thread-local query retains no pointer.
                        let last_error = unsafe { GetLastError() };
                        if returned == 0x103 {
                            pending += 1;
                            loop {
                                // SAFETY: the unique handle owns the only
                                // outstanding request. Wait completion synchronizes
                                // the private IOSB and output writes. Keep all owners
                                // live across timeouts and surprising wait failures.
                                let wait = unsafe { WaitForSingleObject(handle.0, 1000) };
                                if wait == 0 {
                                    // SAFETY: the successful wait makes IOSB stores
                                    // observable; no Rust reference aliases the kernel.
                                    let status = unsafe { (*io.get()).status as u32 };
                                    if status != 0x103 && status != 0xa5a5_a5a5 {
                                        break;
                                    }
                                }
                                std::thread::sleep(Duration::from_millis(1));
                            }
                        }
                        // SAFETY: non-pending return or observed file completion
                        // ended kernel access to these initialized allocations.
                        let (status, information, data) = unsafe {
                            (
                                (*io.get()).status,
                                (*io.get()).information,
                                (*buffer.get()).0,
                            )
                        };
                        let iosb: Vec<u8> = status
                            .to_le_bytes()
                            .into_iter()
                            .chain(information.to_le_bytes())
                            .collect();
                        let completed = if returned == 0x103 {
                            status as u32
                        } else {
                            returned
                        };
                        assert!(data[..start].iter().all(|byte| *byte == 0xa5));
                        assert!(
                            data[start + length as usize..captured]
                                .iter()
                                .all(|byte| *byte == 0xa5)
                        );
                        if completed == 0 {
                            assert!(information >= 4 && information <= length as usize);
                            successes += 1;
                        }
                        cases += 1;
                        println!(
                            "{{\"kind\":\"query\",\"object\":\"{label}\",\"asynchronous\":{asynchronous},\"access\":{access},\"length\":{length},\"offset\":{offset},\"returned\":{returned},\"completed\":{completed},\"last_error\":{last_error},\"initial_iosb_hex\":\"03010000a5a5a5a5a5a5a5a5a5a5a5a5\",\"iosb_hex\":\"{}\",\"output_hex\":\"{}\"}}",
                            hex(&iosb),
                            hex(&data[..captured])
                        );
                    }
                }
                assert!(successes > 0, "no successful class 9 queries for {label}");
                total_success += successes;
            }
        }
    }
    assert_eq!(cases, 2016);
    println!(
        "{{\"kind\":\"complete\",\"queries\":{cases},\"successes\":{total_success},\"pending\":{pending},\"skipped\":0}}"
    );
}
