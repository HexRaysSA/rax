//! Independent 264-case matrices for all four native execution views.
use super::*;
use crate::user::windows::fs::{FileIdentity, FileLifetime};
use crate::user::windows::objects::FileObj;
use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

fn disk() -> (Object, PathBuf, Option<[u8; 8]>) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "rax-volume-device-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.write_all(b"volume-query").unwrap();
    file.seek(SeekFrom::Start(7)).unwrap();
    #[cfg(windows)]
    let device = Some(native_device(&file));
    #[cfg(not(windows))]
    let device = None;
    let identity = FileIdentity::of_open(&path, Some(&file), &file.metadata().unwrap()).unwrap();
    (
        Object::File(FileObj {
            host: Some(file),
            host_path: path.clone(),
            path: "C:\\fixture.bin".into(),
            access: 0x12019f,
            share: 7,
            lifetime: Arc::new(FileLifetime::new(identity)),
            null: false,
            append: false,
            delete_on_close: false,
            directory: false,
            overlapped: false,
        }),
        path,
        device,
    )
}

#[cfg(windows)]
fn native_device(file: &std::fs::File) -> [u8; 8] {
    use std::cell::UnsafeCell;
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct Io {
        status: usize,
        information: usize,
    }
    #[repr(C, align(8))]
    struct Data([u8; 8]);
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
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtWaitForSingleObject(file: *mut c_void, alertable: u8, timeout: *const i64) -> i32;
    }
    let io = Box::new(UnsafeCell::new(Io {
        status: 0x103,
        information: 0,
    }));
    let data = Box::new(UnsafeCell::new(Data([0; 8])));
    // SAFETY: the independently opened fixture file remains owned with
    // SYNCHRONIZE access. Stable, aligned, initialized ABI buffers are private
    // to this request; UnsafeCell admits kernel writes through completion.
    let status = unsafe {
        NtQueryVolumeInformationFile(file.as_raw_handle(), io.get(), data.get().cast(), 8, 4)
    };
    if status as u32 == 0x103 {
        // SAFETY: only this metadata request uses the private file handle;
        // nonalertable completion waiting keeps both buffers alive. This raw
        // kernel oracle does not call the production polling adapter.
        let waited = unsafe { NtWaitForSingleObject(file.as_raw_handle(), 0, std::ptr::null()) };
        if waited != 0 {
            // Unknown completion must not free kernel-owned request buffers.
            std::mem::forget(io);
            std::mem::forget(data);
            panic!("native calibration completion wait failed: {waited:#x}");
        }
    } else {
        assert_eq!(status, 0, "native fixture calibration status");
    }
    // SAFETY: terminal synchronous return or the private request's signaled
    // file establishes completion; the kernel no longer accesses the boxes.
    let (io, data) = unsafe { (&*io.get(), (*data.get()).0) };
    assert_eq!((io.status as u32, io.information), (0, 8));
    data
}

const CAPTURED_DISK: [u8; 8] = [7, 0, 0, 0, 0x20, 0, 2, 0];

// Bind only bytes proven to originate from the captured device payload. Native
// success completes both IOSB fields after data; those aliasing stores win.
// On fault rows, the original capture must independently show the entire data
// store before calibration is admitted. No RAX result selects expected writes.
fn bind_device(
    windows: &mut [(u64, Vec<u8>)],
    output: u64,
    io: u64,
    pointer_bytes: u64,
    recorded_status: u32,
    device: [u8; 8],
) {
    let data_reached = recorded_status == STATUS_SUCCESS
        || windows.iter().any(|(at, bytes)| {
            output
                .checked_sub(*at)
                .and_then(|offset| bytes.get(offset as usize..offset as usize + 8))
                == Some(CAPTURED_DISK.as_slice())
        });
    if !data_reached {
        return;
    }
    if recorded_status != STATUS_SUCCESS {
        assert!(
            output + 8 <= io || io + 2 * pointer_bytes <= output,
            "an aliased fault needs separately captured publication metadata"
        );
    }
    for (at, bytes) in windows {
        for (index, byte) in bytes.iter_mut().enumerate() {
            let address = *at + index as u64;
            let payload = (output..output + 8).contains(&address);
            let overwritten = recorded_status == STATUS_SUCCESS
                && (io..io + 2 * pointer_bytes).contains(&address);
            if payload && !overwritten {
                assert_eq!(*byte, CAPTURED_DISK[(address - output) as usize]);
                *byte = device[(address - output) as usize];
            }
        }
    }
}

#[test]
fn native_volume_device_binding_preserves_iosb_aliases_and_failed_probes() {
    let replacement = [0x11, 2, 3, 4, 5, 6, 7, 8];
    // x86 output=IOSB+4: Information overwrites DeviceType; flags survive.
    let mut bytes = vec![0; 16];
    bytes[4..8].copy_from_slice(&8u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&CAPTURED_DISK[4..]);
    let mut windows = [(100, bytes)];
    bind_device(&mut windows, 104, 100, 4, STATUS_SUCCESS, replacement);
    assert_eq!(&windows[0].1[4..8], &8u32.to_le_bytes());
    assert_eq!(&windows[0].1[8..12], &replacement[4..]);
    // IOSB=output+4: Status overwrites Characteristics; DeviceType survives.
    let mut bytes = vec![0; 16];
    bytes[..4].copy_from_slice(&CAPTURED_DISK[..4]);
    bytes[8..12].copy_from_slice(&8u32.to_le_bytes());
    let mut windows = [(100, bytes)];
    bind_device(&mut windows, 100, 104, 4, STATUS_SUCCESS, replacement);
    assert_eq!(&windows[0].1[..4], &replacement[..4]);
    assert_eq!(&windows[0].1[4..8], &[0; 4]);
    assert_eq!(&windows[0].1[8..12], &8u32.to_le_bytes());
    // A late IOSB fault preserves the independently observed full output.
    let mut windows = [(100, CAPTURED_DISK.to_vec())];
    bind_device(
        &mut windows,
        100,
        200,
        8,
        STATUS_ACCESS_VIOLATION,
        replacement,
    );
    assert_eq!(windows[0].1, replacement);
    // A rejected output probe never receives a fabricated payload.
    let mut windows = [(100, vec![0xA5; 8])];
    bind_device(
        &mut windows,
        100,
        200,
        8,
        STATUS_ACCESS_VIOLATION,
        replacement,
    );
    assert_eq!(windows[0].1, [0xA5; 8]);
}

fn hex(raw: &str) -> Vec<u8> {
    raw.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn value(raw: &str) -> u32 {
    u32::from_str_radix(raw, 16).unwrap()
}

#[test]
fn native_volume_device_query_replays_all_1056_pointer_guard_alias_and_kind_observations() {
    let controls: [(WinArch, &str); 4] = [
        (
            WinArch::Arm64,
            include_str!(
                "../../../../../../../../docs/specifications/windows/native-volume-query/validation/native-volume-query-v4-four-views-arm64.log"
            ),
        ),
        (
            WinArch::X64,
            include_str!(
                "../../../../../../../../docs/specifications/windows/native-volume-query/validation/native-volume-query-v4-four-views-x64.log"
            ),
        ),
        (
            WinArch::X86,
            include_str!(
                "../../../../../../../../docs/specifications/windows/native-volume-query/validation/native-volume-query-v4-four-views-x86.log"
            ),
        ),
        (
            WinArch::X86,
            include_str!(
                "../../../../../../../../docs/specifications/windows/native-volume-query/validation/native-volume-query-v4-four-views-x86-laa.log"
            ),
        ),
    ];
    let mut failures = Vec::new();
    let mut total = 0;
    for (profile_index, (arch, text)) in controls.into_iter().enumerate() {
        let mut count = 0;
        for line in text.lines().filter(|s| s.starts_with("role=")) {
            let fields: BTreeMap<_, _> = line
                .split_whitespace()
                .map(|s| s.split_once('=').unwrap())
                .collect();
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let ib = base;
            let ob = base + 3 * PAGE_SIZE;
            let mut path = None;
            let mut device = None;
            let handle = if fields["role"] == "invalid" {
                0xDEAD
            } else {
                let object = match fields["role"] {
                    "conin" => Object::Console(StdStream::In),
                    "nul" => Object::Null,
                    "pipe-read" => Object::Pipe {
                        pipe: 1,
                        write: false,
                    },
                    "event" => Object::Event {
                        manual: false,
                        signaled: 0,
                    },
                    "disk" => {
                        let (object, name, calibrated) = disk();
                        path = Some(name);
                        device = calibrated;
                        object
                    }
                    role => panic!("unrecognized native role {role}"),
                };
                let id = p.objects.create(object);
                u64::from(p.objects.open_access(id, false, 0).unwrap())
            };
            let (mut io, mut out) = (ib + PAGE_SIZE + 256, ob + PAGE_SIZE + 256);
            let guarded = prot::READWRITE | prot::GUARD;
            match fields["case"] {
                "valid" => {}
                "io-null" => io = 0,
                "out-null" => out = 0,
                "both-null" => {
                    io = 0;
                    out = 0;
                }
                "io-bad" => io = 0xDEAD0000,
                "out-bad" => out = 0xDEAD0000,
                "io-readonly" => {
                    p.vm.protect(ib + PAGE_SIZE, PAGE_SIZE, prot::READONLY)
                        .unwrap();
                }
                "out-readonly" => {
                    p.vm.protect(ob + PAGE_SIZE, PAGE_SIZE, prot::READONLY)
                        .unwrap();
                }
                "io-guard" => {
                    p.vm.protect(ib + PAGE_SIZE, PAGE_SIZE, guarded).unwrap();
                }
                "out-guard" => {
                    p.vm.protect(ob + PAGE_SIZE, PAGE_SIZE, guarded).unwrap();
                }
                "io-noaccess" => {
                    p.vm.protect(ib + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                        .unwrap();
                }
                "out-noaccess" => {
                    p.vm.protect(ob + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                        .unwrap();
                }
                "io-unaligned" => io += 1,
                "out-unaligned" => out += 1,
                "same" => out = io,
                "out-io-plus4" => out = io + 4,
                "io-out-plus4" => io = out + 4,
                "io-cross-noaccess" => {
                    io = ib + 2 * PAGE_SIZE - 8;
                    p.vm.protect(ib + 2 * PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                        .unwrap();
                }
                "out-cross-noaccess" => {
                    out = ob + 2 * PAGE_SIZE - 4;
                    p.vm.protect(ob + 2 * PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                        .unwrap();
                }
                "both-guard" => {
                    p.vm.protect(ib + PAGE_SIZE, PAGE_SIZE, guarded).unwrap();
                    p.vm.protect(ob + PAGE_SIZE, PAGE_SIZE, guarded).unwrap();
                }
                "io-readonly-guard" => {
                    p.vm.protect(ib + PAGE_SIZE, PAGE_SIZE, prot::READONLY | prot::GUARD)
                        .unwrap();
                }
                "out-readonly-guard" => {
                    p.vm.protect(ob + PAGE_SIZE, PAGE_SIZE, prot::READONLY | prot::GUARD)
                        .unwrap();
                }
                case => panic!("unrecognized native case {case}"),
            }
            let before = p.objects.iter().map(|(id, _)| id).collect::<Vec<_>>();
            let status = invoke(
                p,
                &mut t,
                &[handle, io, out, fields["len"].parse().unwrap(), 4],
            );
            let protections = [
                ("io-protect", ib + PAGE_SIZE),
                ("out-protect", ob + PAGE_SIZE),
                ("io-tail", ib + 2 * PAGE_SIZE),
                ("out-tail", ob + 2 * PAGE_SIZE),
            ];
            let mut ok = status == value(fields["status"]) && fields["returned"] == "1";
            for (name, address) in protections {
                ok &= p.vm.query(address).unwrap().protect == value(fields[name]);
            }
            p.vm.protect(base, 6 * PAGE_SIZE, prot::READWRITE).unwrap();
            let locations = [
                ("io", ib + PAGE_SIZE + 240),
                ("out", ob + PAGE_SIZE + 240),
                ("io-edge", ib + 2 * PAGE_SIZE - 32),
                ("out-edge", ob + 2 * PAGE_SIZE - 32),
            ];
            let mut expected = locations.map(|(name, address)| (address, hex(fields[name])));
            if let Some(device) = device {
                bind_device(
                    &mut expected,
                    out,
                    io,
                    arch.ptr_size(),
                    value(fields["status"]),
                    device,
                );
            }
            for (address, expected) in expected {
                ok &= p.space.bytes(address, expected.len()).unwrap() == expected;
            }
            ok &= p.objects.iter().map(|(id, _)| id).collect::<Vec<_>>() == before;
            if let Some(Object::File(file)) = p.objects.get_mut(handle) {
                ok &= file.host.as_mut().unwrap().stream_position().unwrap() == 7;
            }
            if !ok {
                failures.push(format!(
                    "profile{profile_index}/{arch}/{}/len{} expected{} got{status:08X} role{}",
                    fields["case"], fields["len"], fields["status"], fields["role"]
                ));
            }
            if handle != 0xDEAD {
                drop(p.objects.close(handle).unwrap());
            }
            if let Some(path) = path {
                std::fs::remove_file(path).unwrap();
            }
            count += 1;
            total += 1;
        }
        assert_eq!(count, 264);
    }
    assert_eq!(total, 1056);
    assert!(
        failures.is_empty(),
        "{} mismatches: {:?}",
        failures.len(),
        &failures[..failures.len().min(12)]
    );
}
