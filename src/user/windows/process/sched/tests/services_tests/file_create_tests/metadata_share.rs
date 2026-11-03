//! Metadata references must not become data-sharing reservations.
use super::{Harness, Mem, WinArch, create};
use serde_json::Value;

fn hex(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

#[test]
fn native_file_create_metadata_only_handles_do_not_reserve_data_sharing() {
    for (arch, corpus) in [
        (
            WinArch::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-file-create/metadata-share-arm64-v1.json"
            )),
        ),
        (
            WinArch::X64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-file-create/metadata-share-x64-v1.json"
            )),
        ),
        (
            WinArch::X86,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-file-create/metadata-share-x86-v1.json"
            )),
        ),
    ] {
        let data: Value = serde_json::from_str(corpus).unwrap();
        let cases = data["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 36);
        for case in cases {
            let mut h = Harness::new(arch);
            h.name("\\??\\C:\\metadata.dat");
            let path = h.directory.0.join("metadata.dat");
            assert_eq!(create(&mut h, 0xC0110080, 2), 0);
            let initial = h
                .process
                .state()
                .space
                .ptr(h.base, arch.ptr_size())
                .unwrap();
            drop(h.process.state_mut().objects.close(initial).unwrap());
            std::fs::write(&path, b"original").unwrap();
            let held_share = if case["held_mode"].as_u64().unwrap() == 1 {
                1
            } else {
                0
            };
            assert_eq!(
                h.invoke_api(
                    "NtCreateFile",
                    &[
                        h.base,
                        0x100080,
                        h.attrs(),
                        h.base + 4096,
                        0,
                        0,
                        held_share,
                        1,
                        0,
                        0,
                        0
                    ]
                ),
                0
            );
            let held = h
                .process
                .state()
                .space
                .ptr(h.base, arch.ptr_size())
                .unwrap();
            let code = h.invoke_api(
                "NtCreateFile",
                &[
                    h.base,
                    hex(&case["access"]),
                    h.attrs(),
                    h.base + 4096,
                    0,
                    0,
                    0,
                    case["disposition"].as_u64().unwrap(),
                    0,
                    0,
                    0,
                ],
            );
            assert_eq!(
                u64::from(code),
                hex(&case["status"]),
                "{arch}/{}",
                case["index"]
            );
            if code == 0 {
                let handle = h
                    .process
                    .state()
                    .space
                    .ptr(h.base, arch.ptr_size())
                    .unwrap();
                drop(h.process.state_mut().objects.close(handle).unwrap());
            }
            drop(h.process.state_mut().objects.close(held).unwrap());
            let raw = case["data_hex"].as_str().unwrap();
            let expected: Vec<_> = (0..raw.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(
                std::fs::read(path).unwrap(),
                expected,
                "{arch}/{}",
                case["index"]
            );
        }
        // The documented reciprocal case: an attribute-only request can open
        // while a data handle denies data sharing. It requests no data access.
        let mut h = Harness::new(arch);
        h.name("\\??\\C:\\fixture.bin");
        assert_eq!(
            h.invoke_api(
                "NtCreateFile",
                &[
                    h.base,
                    0x80100080,
                    h.attrs(),
                    h.base + 4096,
                    0,
                    0,
                    0,
                    1,
                    0,
                    0,
                    0
                ]
            ),
            0
        );
        let data_handle = h
            .process
            .state()
            .space
            .ptr(h.base, arch.ptr_size())
            .unwrap();
        assert_eq!(
            h.invoke_api(
                "NtCreateFile",
                &[
                    h.base,
                    0x100080,
                    h.attrs(),
                    h.base + 4096,
                    0,
                    0,
                    0,
                    1,
                    0,
                    0,
                    0
                ]
            ),
            0
        );
        let metadata = h
            .process
            .state()
            .space
            .ptr(h.base, arch.ptr_size())
            .unwrap();
        drop(h.process.state_mut().objects.close(metadata).unwrap());
        drop(h.process.state_mut().objects.close(data_handle).unwrap());
    }
}
