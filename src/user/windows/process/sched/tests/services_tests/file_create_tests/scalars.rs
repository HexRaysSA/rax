//! Native scalar controls execute through the service dispatcher and real files.
use super::{Harness, Mem, WinArch, create};
use crate::user::windows::objects::Object;
use serde_json::Value;
use std::path::Path;

#[path = "storage.rs"]
mod storage;

fn number(v: &Value) -> u64 {
    v.as_u64().unwrap()
}
fn hex(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn close_result(h: &mut Harness) {
    let p = h.process.state_mut();
    let handle = p.space.ptr(h.base, p.arch.ptr_size()).unwrap();
    p.objects.close(handle).unwrap();
}

fn writable(path: &Path) {
    #[cfg(windows)]
    if let Ok(metadata) = path.metadata() {
        let mut permissions = metadata.permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(path, permissions).unwrap();
    }
    #[cfg(not(windows))]
    let _ = path;
}

#[test]
fn native_file_create_scalar_corpus_matches_grants_iosb_and_real_files_all_abis() {
    let mut failures = Vec::new();
    for (arch, corpus) in [
        (
            WinArch::Arm64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-file-create/scalar-arm64-v1.json"
            )),
        ),
        (
            WinArch::X64,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-file-create/scalar-x64-v1.json"
            )),
        ),
        (
            WinArch::X86,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-file-create/scalar-x86-v1.json"
            )),
        ),
    ] {
        let data: Value = serde_json::from_str(corpus).unwrap();
        let cases = data["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 492);
        let mut h = Harness::new(arch);
        let width = arch.ptr_size();
        for case in cases {
            let index = number(&case["index"]);
            let existing = number(&case["existing"]) != 0;
            let name = format!("case-{index:05}.dat");
            let path = h.directory.0.join(&name);
            h.name(&format!("\\??\\C:\\{name}"));
            if existing {
                assert_eq!(create(&mut h, 0xC0110080, 2), 0, "{arch}/{index}/seed");
                close_result(&mut h);
                std::fs::write(&path, b"original").unwrap();
            }
            let held = number(&case["held_mode"]);
            let held_handle = if held != 0 {
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
                            if held == 1 { 1 } else { 0 },
                            1,
                            0x60,
                            0,
                            0
                        ]
                    ),
                    0
                );
                Some(h.process.state().space.ptr(h.base, width).unwrap())
            } else {
                None
            };
            let mode = number(&case["allocation_mode"]);
            let allocation = h.base + 16384;
            h.process
                .state()
                .space
                .w64(
                    allocation,
                    match mode {
                        2 => u64::MAX,
                        3 => 1,
                        4 => 4096,
                        5 => 65536,
                        _ => 0,
                    },
                )
                .unwrap();
            let ea_mode = number(&case["ea_mode"]);
            let ea = h.base + 20480;
            let mut ea_raw = [0u8; 32];
            ea_raw[..14]
                .copy_from_slice(&[0, 0, 0, 0, 0, 3, 2, 0, b'O', b'n', b'e', 0, 0x12, 0x34]);
            h.process.state().space.wr(ea, &ea_raw).unwrap();
            h.process
                .state()
                .space
                .wptr(h.base, width, 0xa5a5a5a5)
                .unwrap();
            h.process
                .state()
                .space
                .wr(h.base + 4096, &vec![0xa5; (2 * width) as usize])
                .unwrap();
            let code = h.invoke_api(
                "NtCreateFile",
                &[
                    h.base,
                    hex(&case["access"]),
                    h.attrs(),
                    h.base + 4096,
                    if mode == 0 {
                        0
                    } else if mode == 6 {
                        1
                    } else {
                        allocation
                    },
                    hex(&case["attributes"]),
                    number(&case["share"]),
                    number(&case["disposition"]),
                    hex(&case["options"]),
                    if matches!(ea_mode, 0 | 4) { 0 } else { ea },
                    match ea_mode {
                        1 | 4 => 14,
                        2 => 1,
                        3 => 32,
                        _ => 0,
                    },
                ],
            );
            if code as u64 != hex(&case["status"]) {
                failures.push(format!(
                    "{arch}/{index}/status {code:#x}, expected {}",
                    case["status"]
                ));
            }
            let p = h.process.state();
            let actual_io = p.space.bytes(h.base + 4096, (2 * width) as usize).unwrap();
            if actual_io != bytes(&case["io_hex"]) {
                failures.push(format!(
                    "{arch}/{index}/IOSB {actual_io:02x?}, expected {}",
                    case["io_hex"]
                ));
            }
            let handle = p.space.ptr(h.base, width).unwrap();
            let valid = matches!(p.objects.get(handle), Some(Object::File(_)));
            if valid != (number(&case["handle_valid"]) != 0) {
                failures.push(format!("{arch}/{index}/handle validity {valid}"));
            }
            if valid {
                let Some(Object::File(file)) = p.objects.get(handle) else {
                    unreachable!()
                };
                let host = file.host.as_ref().unwrap();
                let disposition = number(&case["disposition"]);
                let changes_file = !existing || matches!(disposition, 0 | 4 | 5);
                if number(&case["group"]) == 4 {
                    let expected = if changes_file && matches!(ea_mode, 1 | 3) {
                        vec![0, 0, 0, 0, 0, 3, 2, 0, b'O', b'N', b'E', 0, 0x12, 0x34]
                    } else {
                        Vec::new()
                    };
                    assert_eq!(
                        storage::ea(host),
                        expected,
                        "{arch}/{index}/independent EA readback"
                    );
                }
                if number(&case["group"]) == 3 && changes_file && matches!(mode, 3..=5) {
                    let requested = match mode {
                        3 => 1,
                        4 => 4096,
                        5 => 65536,
                        _ => unreachable!(),
                    };
                    assert_eq!(
                        host.metadata().unwrap().len(),
                        0,
                        "{arch}/{index}/allocation EOF"
                    );
                    assert!(
                        storage::allocation(host) >= requested,
                        "{arch}/{index}/physical reservation"
                    );
                }
                if p.objects.access(handle).map(u64::from) != Some(hex(&case["granted"])) {
                    failures.push(format!(
                        "{arch}/{index}/grant {:?}, expected {}",
                        p.objects.access(handle),
                        case["granted"]
                    ));
                }
                h.process.state_mut().objects.close(handle).unwrap();
            } else if handle != hex(&case["handle"]) {
                failures.push(format!(
                    "{arch}/{index}/failed handle {handle:#x}, expected {}",
                    case["handle"]
                ));
            }
            if let Some(held) = held_handle {
                h.process.state_mut().objects.close(held).unwrap();
            }
            let exists = path.exists();
            if exists != (number(&case["exists_after_close"]) != 0) {
                failures.push(format!("{arch}/{index}/existence {exists}"));
            }
            if exists {
                if !path.is_dir() {
                    let actual = std::fs::read(&path).unwrap();
                    let expected = bytes(&case["data_hex"]);
                    if actual != expected {
                        failures.push(format!(
                            "{arch}/{index}/contents {actual:02x?}, expected {expected:02x?}"
                        ));
                    }
                }
                let output = h.base + 24576;
                assert_eq!(
                    h.invoke_api("NtQueryFullAttributesFile", &[h.attrs(), output]),
                    0,
                    "{arch}/{index}/attributes query"
                );
                let actual = h.process.state().space.u32(output + 48).unwrap();
                if u64::from(actual) != hex(&case["attributes_after"]) {
                    failures.push(format!(
                        "{arch}/{index}/attributes {actual:#x}, expected {}",
                        case["attributes_after"]
                    ));
                }
                writable(&path);
                if path.is_dir() {
                    std::fs::remove_dir(&path).unwrap();
                } else {
                    std::fs::remove_file(&path).unwrap();
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} scalar mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
