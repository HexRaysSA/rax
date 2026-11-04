//! Independent class5 matrices cover every measured length, grant and mode.
use super::*;
use crate::user::windows::fs::{FileIdentity, FileLifetime};
use crate::user::windows::objects::FileObj;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const NTFS: [u8; 20] = [
    0xff, 0x2e, 0xe7, 3, 255, 0, 0, 0, 8, 0, 0, 0, 78, 0, 84, 0, 70, 0, 83, 0,
];

pub(super) fn disk(directory: bool, asynchronous: bool) -> (Object, PathBuf, [u8; 8]) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "rax-volume-attributes-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = std::fs::OpenOptions::new();
    if directory {
        std::fs::create_dir(&path).unwrap();
        options.read(true);
    } else {
        options.read(true).write(true).create_new(true);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options
            .share_mode(7)
            .custom_flags(0x0200_0000 | if asynchronous { 0x4000_0000 } else { 0 });
    }
    let mut file = options.open(&path).unwrap();
    if !directory && !asynchronous {
        file.write_all(b"volume-attributes").unwrap();
        file.seek(SeekFrom::Start(7)).unwrap();
    }
    #[cfg(windows)]
    let payload = native_payload(&file);
    #[cfg(not(windows))]
    let payload = NTFS[..8].try_into().unwrap();
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
            directory,
            overlapped: asynchronous,
        }),
        path,
        payload,
    )
}

#[cfg(windows)]
fn native_payload(file: &std::fs::File) -> [u8; 8] {
    use std::cell::UnsafeCell;
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    #[repr(C)]
    struct Io {
        status: usize,
        information: usize,
    }
    #[repr(C, align(8))]
    struct Data([u8; 512]);
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryVolumeInformationFile(
            file: *mut c_void,
            io: *mut Io,
            data: *mut c_void,
            len: u32,
            class: u32,
        ) -> i32;
        fn NtWaitForSingleObject(file: *mut c_void, alertable: u8, timeout: *const i64) -> i32;
    }
    let io = Box::new(UnsafeCell::new(Io {
        status: 0x103,
        information: 0,
    }));
    let data = Box::new(UnsafeCell::new(Data([0; 512])));
    // SAFETY: the fixture owns its SYNCHRONIZE-capable native file and private,
    // aligned stable storage. No production volume adapter supplies this oracle.
    let status = unsafe {
        NtQueryVolumeInformationFile(file.as_raw_handle(), io.get(), data.get().cast(), 512, 5)
    };
    if status as u32 == 0x103 {
        // SAFETY: no concurrent operation uses the private fixture handle. A
        // native wait keeps both buffers alive through the original completion.
        let waited = unsafe { NtWaitForSingleObject(file.as_raw_handle(), 0, std::ptr::null()) };
        if waited != 0 {
            std::mem::forget(io);
            std::mem::forget(data);
            panic!("native filesystem calibration wait failed: {waited:#x}");
        }
    } else {
        assert_eq!(status, 0);
    }
    // SAFETY: the original private request is terminal; buffers remain owned.
    let (io, data) = unsafe { (&*io.get(), &(*data.get()).0) };
    assert_eq!(
        (io.status as u32, io.information),
        (0, 20),
        "captured NTFS matrix requires an NTFS fixture volume"
    );
    assert_eq!(&data[8..20], &NTFS[8..]);
    data[..8].try_into().unwrap()
}

pub(super) fn hex(raw: &str) -> Vec<u8> {
    raw.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

pub(super) fn bind_payload(
    windows: &mut [(u64, Vec<u8>)],
    output: u64,
    io: u64,
    arch: WinArch,
    synchronous: bool,
    result: u32,
    payload: [u8; 8],
) {
    let reached = matches!(result, STATUS_SUCCESS | STATUS_BUFFER_OVERFLOW)
        || windows.iter().any(|(at, bytes)| {
            output
                .checked_sub(*at)
                .and_then(|offset| bytes.get(offset as usize..offset as usize + 20))
                == Some(NTFS.as_slice())
        });
    if !reached {
        return;
    }
    for (at, bytes) in windows {
        for (index, byte) in bytes.iter_mut().enumerate() {
            let address = *at + index as u64;
            let overwritten = matches!(result, STATUS_SUCCESS | STATUS_BUFFER_OVERFLOW)
                && ((io..io + if synchronous { 4 } else { arch.ptr_size() }).contains(&address)
                    || (io + arch.ptr_size()..io + 2 * arch.ptr_size()).contains(&address));
            if (output..output + 8).contains(&address) && !overwritten {
                assert_eq!(*byte, NTFS[(address - output) as usize]);
                *byte = payload[(address - output) as usize];
            }
        }
    }
}

#[test]
fn native_volume_attributes_replays_11424_length_alignment_grant_and_mode_observations() {
    let profiles = [
        (
            WinArch::Arm64,
            include_str!(
                "../../../../../../../../docs/specifications/windows/native-volume-attributes/observations-arm64-29698-v1.json"
            ),
        ),
        (
            WinArch::X64,
            include_str!(
                "../../../../../../../../docs/specifications/windows/native-volume-attributes/observations-x64-29698-v1.json"
            ),
        ),
        (
            WinArch::X86,
            include_str!(
                "../../../../../../../../docs/specifications/windows/native-volume-attributes/observations-x86-29698-v1.json"
            ),
        ),
    ];
    let mut total = 0;
    for (arch, text) in profiles {
        let data: serde_json::Value = serde_json::from_str(text).unwrap();
        let mut count = 0;
        for row in data["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["kind"] == "query")
        {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let asynchronous = row["asynchronous"].as_bool().unwrap();
            let (object, path, payload) = disk(row["object"] == "directory", asynchronous);
            let id = p.objects.create(object);
            let granted = row["granted_access"].as_u64().unwrap() as u32;
            let handle = p.objects.open_access(id, false, granted).unwrap();
            let io = base;
            let out = base + PAGE_SIZE + 16 + row["offset"].as_u64().unwrap();
            let initial = hex(row["initial_iosb_hex"].as_str().unwrap());
            p.space.wr(io, &initial).unwrap();
            let error = t.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
            p.space.w32(error, 0x1234_5678).unwrap();
            let expected = row["returned"].as_u64().unwrap() as u32;
            let actual = invoke(
                p,
                &mut t,
                &[
                    u64::from(handle),
                    io,
                    out,
                    row["length"].as_u64().unwrap(),
                    5,
                ],
            );
            let mut windows = [(base + PAGE_SIZE, hex(row["output_hex"].as_str().unwrap()))];
            bind_payload(
                &mut windows,
                out,
                io,
                arch,
                !asynchronous,
                expected,
                payload,
            );
            assert_eq!(actual, expected, "{arch}: {row}");
            assert_eq!(
                p.space.bytes(io, initial.len()).unwrap(),
                hex(row["iosb_hex"].as_str().unwrap()),
                "{arch}: {row}"
            );
            assert_eq!(
                p.space.bytes(windows[0].0, windows[0].1.len()).unwrap(),
                windows[0].1,
                "{arch}: {row}"
            );
            assert_eq!(p.space.u32(error).unwrap(), 0x1234_5678);
            assert_eq!(p.objects.access(u64::from(handle)), Some(granted));
            drop(p.objects.close(u64::from(handle)).unwrap());
            if row["object"] == "directory" {
                std::fs::remove_dir(path).unwrap();
            } else {
                std::fs::remove_file(path).unwrap();
            }
            count += 1;
        }
        assert_eq!(count, 3808);
        total += count;
    }
    assert_eq!(total, 11424);
}

#[test]
fn native_volume_attributes_sync_only_nt_open_and_selected_library_keep_identity_after_remap() {
    use super::super::file_open_tests::{Harness, selection};
    for arch in WinArch::ALL {
        for selected in [false, true] {
            let mut h = Harness::new(arch);
            let path = if selected {
                let directory = selection(&mut h);
                h.name("\\??\\C:\\Windows\\System32\\fixture.dll");
                directory.join("fixture.dll")
            } else {
                h.directory.0.join("fixture.bin")
            };
            assert_eq!(
                h.invoke_api(
                    "NtOpenFile",
                    &[h.base, 0x100000, h.attrs(), h.base + PAGE_SIZE, 7, 0x60]
                ),
                STATUS_SUCCESS
            );
            let handle = h
                .process
                .state()
                .space
                .ptr(h.base, arch.ptr_size())
                .unwrap();
            let p = h.process.state();
            assert_eq!(p.objects.access(handle), Some(0x100000));
            assert_eq!(p.objects.runtime_library(handle), selected);
            let Object::File(file) = p.objects.get(handle).unwrap() else {
                panic!("opened file")
            };
            let identity = file.lifetime.identity.clone();
            #[cfg(windows)]
            let payload = native_payload(file.host.as_ref().unwrap());
            #[cfg(not(windows))]
            let payload: [u8; 8] = NTFS[..8].try_into().unwrap();
            let output = h.base + 4 * PAGE_SIZE;
            let io = h.base + PAGE_SIZE;
            for moved in [false, true] {
                if moved {
                    std::fs::rename(&path, path.with_extension("retained")).unwrap();
                    std::fs::write(&path, b"replacement inode").unwrap();
                    Arc::make_mut(&mut h.process.state_mut().cfg)
                        .drives
                        .set('C', &h.directory.0.join("unselected-root"));
                }
                assert_eq!(
                    h.invoke_api(
                        "NtQueryVolumeInformationFile",
                        &[handle, io, output, 512, 5]
                    ),
                    STATUS_SUCCESS
                );
                let p = h.process.state();
                let mut expected = NTFS;
                expected[..8].copy_from_slice(&payload);
                assert_eq!(p.space.bytes(output, 20).unwrap(), expected);
                assert_eq!(
                    p.space.ptr(io + arch.ptr_size(), arch.ptr_size()).unwrap(),
                    20
                );
                assert_eq!(p.objects.access(handle), Some(0x100000));
                let Object::File(file) = p.objects.get(handle).unwrap() else {
                    panic!("retained file")
                };
                assert_eq!(file.lifetime.identity, identity);
                assert_eq!(
                    crate::user::windows::fs::FileNameOrigin::identity(
                        file.host.as_ref().unwrap(),
                        &file.host_path
                    )
                    .unwrap(),
                    identity
                );
            }
            h.process.state_mut().objects.close(handle).unwrap();
        }
    }
}

#[test]
fn native_volume_attributes_metadata_only_replacement_is_explicit_before_publication() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let (mut object, path, _) = disk(false, false);
        let Object::File(file) = &mut object else {
            unreachable!()
        };
        drop(file.host.take());
        let retained = path.with_extension("retained");
        std::fs::rename(&path, &retained).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        let handle = p.objects.insert(object);
        super::super::nls_tests::arguments(
            p,
            &mut t,
            &[u64::from(handle), base, base + PAGE_SIZE, 512, 5],
        );
        if arch != WinArch::Arm64 {
            t.cpu.set_gpr(0, 0x49);
        }
        let outcome = if arch == WinArch::X86 {
            super::super::super::super::super::services::wow64(p, &mut t, 0x1234_0000)
        } else {
            handle_stop(p, &mut t, stop(arch, 0x49))
        };
        assert!(
            matches!(outcome, Outcome::Fail(message) if message.contains("pathname was replaced"))
        );
        assert_eq!(p.space.bytes(base, 32).unwrap(), [0xA5; 32]);
        assert_eq!(p.space.bytes(base + PAGE_SIZE, 512).unwrap(), [0xA5; 512]);
        drop(p.objects.close(u64::from(handle)).unwrap());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(retained).unwrap();
    }
}
