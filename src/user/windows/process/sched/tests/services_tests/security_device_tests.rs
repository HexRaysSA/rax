//! Native device observations replay through each guest service ABI.
use super::file_open_tests::Harness;
use crate::user::windows::arch::WinArch;
use crate::user::windows::memory::Mem;
use crate::user::windows::object_namespace::security_device::SecurityDevice;
use crate::user::windows::objects::Object;
use serde_json::Value;

fn profile() -> SecurityDevice {
    SecurityDevice {
        kernel: (10, 0, 29704),
        revision: 1010,
        native_machine: 0xaa64,
        device_type: 0x39,
        characteristics: 0x100,
    }
}

fn bytes(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("captured bytes");
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn word(value: &Value) -> u64 {
    value.as_u64().expect("captured integer")
}

fn reset(harness: &mut Harness, address: u64, length: usize) {
    harness
        .process
        .state_mut()
        .space
        .wr(address, &vec![0xa5; length])
        .unwrap();
}

fn open_captured(arch: WinArch, row: &Value) -> (Harness, u64) {
    let mut harness = Harness::new(arch);
    let namespace = &mut harness.process.state_mut().object_namespace;
    namespace.native_machine = Some(0xaa64);
    namespace.select_security_device(profile()).unwrap();
    harness.name("\\Device\\KsecDD");
    let attributes = harness.attrs();
    let output = harness.base;
    let width = arch.ptr_size();
    harness
        .process
        .state_mut()
        .space
        .w32(attributes + 3 * width, word(&row["attributes"]) as u32)
        .unwrap();
    assert_eq!(
        harness.invoke_api(
            "NtOpenFile",
            &[
                output,
                word(&row["access"]),
                attributes,
                output + 64,
                word(&row["share"]),
                word(&row["options"]),
            ]
        ),
        0
    );
    let handle = harness.process.state().space.ptr(output, width).unwrap();
    (harness, handle)
}

#[test]
fn native_security_device_open_create_and_query_replay_all_abis() {
    let corpus: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-ksecdd/native-open-controls-v2.json"
    )))
    .unwrap();
    let mut observations = 0;
    for arch in WinArch::ALL {
        let key = match arch {
            WinArch::X86 => "x86",
            WinArch::X64 => "x64",
            WinArch::Arm64 => "arm64",
        };
        for row in corpus["callers"][key]["rows"].as_array().unwrap() {
            let label = row["label"].as_str().unwrap();
            let mut harness = Harness::new(arch);
            let namespace = &mut harness.process.state_mut().object_namespace;
            namespace.native_machine = Some(0xaa64);
            namespace.select_security_device(profile()).unwrap();
            let name = match label {
                "lower_case_insensitive" | "lower_case_sensitive" => "\\device\\ksecdd",
                "child_name" => "\\Device\\KsecDD\\child",
                _ => "\\Device\\KsecDD",
            };
            harness.name(name);
            let attributes = harness.attrs();
            let output = harness.base;
            let io = harness.base + 64;
            let data = harness.base + 512;
            let width = arch.ptr_size();
            harness
                .process
                .state_mut()
                .space
                .w32(attributes + 3 * width, word(&row["attributes"]) as u32)
                .unwrap();
            harness
                .process
                .state_mut()
                .space
                .wptr(output, width, 0x1357_9bdf)
                .unwrap();
            reset(&mut harness, io, 2 * width as usize);
            let handles = harness.process.state().objects.handle_count();
            let access = word(&row["access"]);
            let share = word(&row["share"]);
            let options = word(&row["options"]);
            let status = if row["create"].as_bool().unwrap() {
                harness.invoke_api(
                    "NtCreateFile",
                    &[
                        output, access, attributes, io, 0, 0, share, 1, options, 0, 0,
                    ],
                )
            } else {
                harness.invoke_api(
                    "NtOpenFile",
                    &[output, access, attributes, io, share, options],
                )
            };
            assert_eq!(status as u64, word(&row["status"]), "{arch}/{label}");
            assert_eq!(
                harness
                    .process
                    .state()
                    .space
                    .bytes(io, 2 * width as usize)
                    .unwrap(),
                bytes(&row["io"]),
                "{arch}/{label}/open IOSB"
            );
            let handle = harness.process.state().space.ptr(output, width).unwrap();
            assert_eq!(
                handle != 0x1357_9bdf,
                row["handle_changed"].as_bool().unwrap()
            );
            observations += 1;
            if status != 0 {
                assert_eq!(harness.process.state().objects.handle_count(), handles);
                continue;
            }
            assert!(matches!(
                harness.process.state().objects.get(handle),
                Some(Object::SecurityFile(_))
            ));
            let basic = bytes(&row["object_basic"]);
            let grant = u32::from_le_bytes(basic[4..8].try_into().unwrap());
            assert_eq!(harness.process.state().objects.access(handle), Some(grant));
            for query in row["queries"].as_array().unwrap() {
                reset(&mut harness, io, 2 * width as usize);
                reset(&mut harness, data, 64);
                let class = word(&query["class"]);
                let status =
                    harness.invoke_api("NtQueryInformationFile", &[handle, io, data, 64, class]);
                assert_eq!(
                    status as u64,
                    word(&query["status"]),
                    "{arch}/{label}/class{class}"
                );
                assert_eq!(
                    harness
                        .process
                        .state()
                        .space
                        .bytes(io, 2 * width as usize)
                        .unwrap(),
                    bytes(&query["io"]),
                    "{arch}/{label}/class{class}/IOSB"
                );
                assert_eq!(
                    harness.process.state().space.bytes(data, 64).unwrap(),
                    bytes(&query["data"]),
                    "{arch}/{label}/class{class}/data"
                );
            }
            reset(&mut harness, io, 2 * width as usize);
            reset(&mut harness, data, 8);
            assert_eq!(
                harness.invoke_api("NtQueryVolumeInformationFile", &[handle, io, data, 8, 4])
                    as u64,
                word(&row["volume_device_status"])
            );
            assert_eq!(
                harness.process.state().space.bytes(data, 8).unwrap(),
                bytes(&row["volume_device"])
            );
            assert_eq!(
                harness
                    .process
                    .state()
                    .space
                    .bytes(io, 2 * width as usize)
                    .unwrap(),
                bytes(&row["volume_device_io"])
            );
            let duplicate = harness.base + 128;
            let current = arch.ptr(u64::MAX);
            assert_eq!(
                harness.invoke_api(
                    "NtDuplicateObject",
                    &[current, handle, current, duplicate, 0, 0, 2]
                ) as u64,
                word(&row["duplicate_status"])
            );
            let duplicate = harness.process.state().space.ptr(duplicate, width).unwrap();
            assert_ne!(duplicate, handle);
            assert_eq!(
                harness.process.state().objects.id(duplicate),
                harness.process.state().objects.id(handle)
            );
            assert_eq!(
                harness.process.state().objects.access(duplicate),
                Some(grant)
            );
            assert_eq!(harness.process.state().objects.handle_count(), handles + 2);
            assert_eq!(
                harness.invoke_api("NtClose", &[duplicate]) as u64,
                word(&row["duplicate_close_status"])
            );
            assert!(harness.process.state().objects.get(handle).is_some());
            assert_eq!(
                harness.invoke_api("NtClose", &[handle]) as u64,
                word(&row["close_status"])
            );
            assert_eq!(harness.process.state().objects.handle_count(), handles);
        }
    }
    assert_eq!(observations, 102);
}

#[test]
fn native_security_device_selection_rejects_changed_identity() {
    for changed in [
        SecurityDevice {
            kernel: (10, 0, 29705),
            ..profile()
        },
        SecurityDevice {
            revision: 1000,
            ..profile()
        },
        SecurityDevice {
            native_machine: 0x8664,
            ..profile()
        },
        SecurityDevice {
            device_type: 0x15,
            ..profile()
        },
        SecurityDevice {
            characteristics: 0,
            ..profile()
        },
    ] {
        assert!(changed.selected().is_err());
    }
    let mut namespace = crate::user::windows::object_namespace::Namespace::default();
    assert!(namespace.security_device().is_none());
    assert!(namespace.select_security_device(profile()).is_err());
    namespace.native_machine = Some(0xaa64);
    namespace.select_security_device(profile()).unwrap();
    assert!(namespace.select_security_device(profile()).is_err());
}

#[test]
fn native_security_device_query_lengths_and_aliases_all_abis() {
    let corpus: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-ksecdd/native-query-boundaries-v1.json"
    )))
    .unwrap();
    let mut observations = 0;
    for arch in WinArch::ALL {
        let key = match arch {
            WinArch::X86 => "x86",
            WinArch::X64 => "x64",
            WinArch::Arm64 => "arm64",
        };
        for row in corpus["callers"][key]["rows"].as_array().unwrap() {
            let (mut harness, handle) = open_captured(arch, row);
            let width = arch.ptr_size();
            let region = harness.base + 1024;
            let io = region + 128;
            for query in row["queries"].as_array().unwrap() {
                reset(&mut harness, region, 256);
                let data = match word(&query["layout"]) {
                    0 => region,
                    1 => io,
                    2 => io + width,
                    _ => panic!("unknown captured caller layout"),
                };
                let class = word(&query["class"]);
                let length = word(&query["length"]);
                assert_eq!(
                    harness.invoke_api("NtQueryInformationFile", &[handle, io, data, length, class])
                        as u64,
                    word(&query["status"]),
                    "{arch}/{class}/{length}/{data:#x}"
                );
                assert_eq!(
                    harness.process.state().space.bytes(region, 256).unwrap(),
                    bytes(&query["region"]),
                    "{arch}/{class}/{length}/{data:#x}/publication"
                );
                observations += 1;
            }
            assert_eq!(harness.invoke_api("NtClose", &[handle]), 0);
        }
    }
    assert_eq!(observations, 864);
}

#[test]
fn native_security_device_iosb_fault_prefixes_all_abis() {
    use crate::user::mm::PAGE_SIZE;
    use crate::user::windows::memory::prot;

    let corpus: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-ksecdd/native-query-iosb-faults-v1.json"
    )))
    .unwrap();
    let mut observations = 0;
    for arch in WinArch::ALL {
        let key = match arch {
            WinArch::X86 => "x86",
            WinArch::X64 => "x64",
            WinArch::Arm64 => "arm64",
        };
        for row in corpus["callers"][key]["rows"].as_array().unwrap() {
            let (mut harness, handle) = open_captured(arch, row);
            let boundary = harness.base + 6 * PAGE_SIZE;
            let data = harness.base + 512;
            harness
                .process
                .state_mut()
                .vm
                .protect(boundary, PAGE_SIZE, prot::NOACCESS)
                .unwrap();
            for query in row["queries"].as_array().unwrap() {
                let prefix = word(&query["prefix"]) as usize;
                let io = boundary - prefix as u64;
                reset(&mut harness, boundary - PAGE_SIZE, PAGE_SIZE as usize);
                reset(&mut harness, data, 64);
                let class = word(&query["class"]);
                assert_eq!(word(&query["exception"]), 0);
                assert_eq!(
                    harness.invoke_api("NtQueryInformationFile", &[handle, io, data, 64, class])
                        as u64,
                    word(&query["status"]),
                    "{arch}/{class}/IOSB-prefix{prefix}"
                );
                let io_bytes = if prefix == 0 {
                    Vec::new()
                } else {
                    harness.process.state().space.bytes(io, prefix).unwrap()
                };
                assert_eq!(
                    io_bytes,
                    bytes(&query["io"]),
                    "{arch}/{class}/IOSB-prefix{prefix}/publication"
                );
                assert_eq!(
                    harness.process.state().space.bytes(data, 64).unwrap(),
                    bytes(&query["data"]),
                    "{arch}/{class}/IOSB-prefix{prefix}/data"
                );
                observations += 1;
            }
            assert_eq!(harness.invoke_api("NtClose", &[handle]), 0);
        }
    }
    assert_eq!(observations, 288);
}
