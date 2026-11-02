//! Complete class189 arena effects from independent native three-ABI calls.

use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct Header {
    required: u32,
    arena: u64,
    returned_page: u64,
}

#[derive(Deserialize)]
struct Case {
    index: u32,
    output: u32,
    returned: u32,
    length: u32,
    poison: u8,
    status: u32,
    exception: u32,
    protections: [u32; 6],
    copy_prefix: usize,
    arena_reconstruction_verified: bool,
    returned_bytes: String,
}

fn decode(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&value[at..at + 2], 16).unwrap())
        .collect()
}

fn prepare(p: &mut Proc, base: u64, head: &Header, case: &Case) -> (u64, u64, usize, usize) {
    p.vm.protect(base, head.arena, prot::READWRITE).unwrap();
    p.space
        .wr(base, &vec![case.poison; head.arena as usize])
        .unwrap();
    let (mut output_offset, mut returned_offset) = (0, head.returned_page);
    let mut output = base;
    let last_page = (u64::from(head.required) - 1) & !(PAGE_SIZE - 1);
    let tail_page = u64::from(head.required).div_ceil(PAGE_SIZE) * PAGE_SIZE;
    let mut protect = |offset, flags| {
        p.vm.protect(base + offset, PAGE_SIZE, flags).unwrap();
    };
    match case.output {
        0 => {}
        1 => output = 0,
        2 => output = 1,
        3 | 4 | 13 => {
            output_offset = match case.output {
                3 => 1,
                4 => 4,
                _ => 2,
            };
            output = base + output_offset;
        }
        5 => protect(0, prot::READONLY),
        6 => protect(0, prot::READWRITE | prot::GUARD),
        7 => protect(0, prot::NOACCESS),
        8..=10 => {
            output_offset = 4092;
            output = base + output_offset;
            protect(
                4096,
                match case.output {
                    8 => prot::NOACCESS,
                    9 => prot::READWRITE | prot::GUARD,
                    _ => prot::READONLY,
                },
            );
        }
        11 => protect(0, prot::READONLY | prot::GUARD),
        12 => {
            output = if p.arch.is64() {
                u64::MAX - 15
            } else {
                u64::from(u32::MAX - 15)
            }
        }
        14..=16 => protect(
            last_page,
            match case.output {
                14 => prot::NOACCESS,
                15 => prot::READWRITE | prot::GUARD,
                _ => prot::READONLY,
            },
        ),
        17 => protect(tail_page, prot::NOACCESS),
        _ => panic!("unknown independent output role"),
    }
    let mut returned = base + returned_offset;
    match case.returned {
        0 => {}
        1 => returned = 0,
        2 => returned = 1,
        3 => {
            returned_offset += 1;
            returned = base + returned_offset;
        }
        4 => protect(head.returned_page, prot::READONLY),
        5 => protect(head.returned_page, prot::READWRITE | prot::GUARD),
        6 => protect(head.returned_page, prot::NOACCESS),
        7..=10 => {
            returned_offset = output_offset
                + match case.returned {
                    7 => 0,
                    8 => 4,
                    9 => u64::from(head.required) - 4,
                    _ => u64::from(head.required),
                };
            returned = base + returned_offset;
        }
        11 => {
            returned_offset = head.returned_page + 4094;
            returned = base + returned_offset;
            protect(head.returned_page + PAGE_SIZE, prot::NOACCESS);
        }
        12 => protect(head.returned_page, prot::READONLY | prot::GUARD),
        _ => panic!("unknown independent ReturnLength role"),
    }
    (
        output,
        returned,
        output_offset as usize,
        returned_offset as usize,
    )
}

fn corpus(label: &str) -> (String, Vec<u8>) {
    if let Some(directory) = std::env::var_os("RAX_CODE_INTEGRITY_POLICIES_CORPUS") {
        let directory = std::path::PathBuf::from(directory);
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join("observations.json")).unwrap())
                .unwrap();
        let report = manifest["reports"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["architecture"] == label)
            .unwrap();
        return (
            std::fs::read_to_string(directory.join(format!("{label}.jsonl"))).unwrap(),
            std::fs::read(directory.join(report["snapshot"]["file"].as_str().unwrap())).unwrap(),
        );
    }
    let rows = match label {
        "arm64" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-code-integrity-policies/arm64.jsonl"
        )),
        "x64" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-code-integrity-policies/x64.jsonl"
        )),
        "x86" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-code-integrity-policies/x86.jsonl"
        )),
        _ => panic!("unknown native process ABI"),
    };
    (
        rows.into(),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-code-integrity-policies/policies.bin"
        ))
        .to_vec(),
    )
}

#[test]
fn code_integrity_policies_replays_every_native_arena_byte_and_guard() {
    let labels: Vec<String> = if let Some(directory) =
        std::env::var_os("RAX_CODE_INTEGRITY_POLICIES_CORPUS")
    {
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(std::path::PathBuf::from(directory).join("observations.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["schema"], "rax-native-code-integrity-policies-v1");
        assert_eq!(manifest["state"], "complete");
        manifest["reports"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["architecture"].as_str().unwrap().to_owned())
            .collect()
    } else {
        ["arm64", "x64", "x86"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    };
    let unique: std::collections::BTreeSet<_> = labels.iter().map(String::as_str).collect();
    assert_eq!(unique.len(), labels.len());
    assert!(unique.contains("x64") && unique.contains("x86") && unique.len() <= 3);
    let expected_count = labels.len() * 3280;
    let mut count = 0;
    for label in labels {
        let arch = match label.as_str() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => unreachable!(),
        };
        let (text, record) = corpus(&label);
        let mut lines = text.lines();
        let header: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(header["schema"], "rax-native-code-integrity-policies-v1");
        let head: Header = serde_json::from_value(header).unwrap();
        assert_eq!(record.len(), head.required as usize);
        assert!(head.required >= 4 && head.arena <= 32 << 20);
        let rows: Vec<Case> = lines
            .filter_map(|line| {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                (value["kind"] == "case").then(|| serde_json::from_value(value).unwrap())
            })
            .collect();
        assert_eq!(rows.len(), 3280);
        let (mut process, mut t, _) = query_fixture(arch);
        let p = process.state_mut();
        native_profile::kernel_profile(p, 29695, 0xAA64);
        p.native.as_mut().unwrap().code_integrity_policies =
            Ok(std::sync::Arc::from(record.clone()));
        let base =
            p.vm.allocate(
                None,
                head.arena + PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        p.vm.protect(base + head.arena, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        let sp = t.cpu.sp();
        let offsets = crate::user::windows::layout::offsets(arch);
        p.space
            .w32(t.teb + offsets.teb_last_error, 0x1234_5678)
            .unwrap();
        p.space
            .w32(t.teb + offsets.teb_last_status, 0xc123_abcd)
            .unwrap();
        for case in rows {
            assert!(case.arena_reconstruction_verified && case.copy_prefix <= record.len());
            let (output, returned, output_offset, returned_offset) = prepare(p, base, &head, &case);
            t.cpu.set_sp(sp);
            query_arguments(p, &mut t, 189, output, case.length, returned);
            let label = format!(
                "{arch}/{}/{}/{}/{}",
                case.index, case.output, case.returned, case.length
            );
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue, "{label}");
            assert_eq!(t.cpu.gpr(0), u64::from(case.status), "{label}");
            assert_eq!(case.exception, 0, "{label}");
            assert!(t.frames.is_empty(), "{label}");
            let watched = [
                0,
                4096,
                (u64::from(head.required) - 1) & !(PAGE_SIZE - 1),
                u64::from(head.required).div_ceil(PAGE_SIZE) * PAGE_SIZE,
                head.returned_page,
                head.returned_page + PAGE_SIZE,
            ];
            for (offset, expected) in watched.into_iter().zip(case.protections) {
                assert_eq!(
                    p.vm.query(base + offset).unwrap().protect,
                    expected,
                    "{label}/{offset}"
                );
            }
            assert_eq!(
                p.vm.query(base + head.arena).unwrap().protect,
                prot::NOACCESS
            );
            p.vm.protect(base, head.arena, prot::READWRITE).unwrap();
            let mut expected = vec![case.poison; head.arena as usize];
            expected[output_offset..output_offset + case.copy_prefix]
                .copy_from_slice(&record[..case.copy_prefix]);
            let returned_bytes = decode(&case.returned_bytes);
            assert_eq!(returned_bytes.len(), 8);
            expected[returned_offset..returned_offset + 8].copy_from_slice(&returned_bytes);
            let actual = p.space.bytes(base, head.arena as usize).unwrap();
            assert!(
                actual == expected,
                "{label}: complete arena differs at byte {:?}",
                actual.iter().zip(&expected).position(|(a, b)| a != b)
            );
            assert_eq!(
                p.space.u32(t.teb + offsets.teb_last_error).unwrap(),
                0x1234_5678
            );
            assert_eq!(
                p.space.u32(t.teb + offsets.teb_last_status).unwrap(),
                0xc123_abcd
            );
            count += 1;
        }
    }
    assert_eq!(count, expected_count);
}

#[test]
fn code_integrity_policies_missing_snapshot_remains_explicit() {
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = query_fixture(arch);
        let p = process.state_mut();
        query_arguments(p, &mut t, 189, 0, 0, scratch);
        assert!(
            matches!(dispatch_query(p, &mut t), Outcome::Fail(reason) if reason.contains("requires selected native inputs"))
        );
        native_profile::kernel_profile(p, 29695, 0xAA64);
        query_arguments(p, &mut t, 189, 0, 0, scratch);
        assert!(
            matches!(dispatch_query(p, &mut t), Outcome::Fail(reason) if reason.contains("policies not captured"))
        );
        assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xa5; 128]);
    }
}

#[test]
fn code_integrity_policies_preserves_opaque_bytes_without_layout_or_version_guesses() {
    for arch in WinArch::ALL {
        for size in [1, 3, 8, 33, 4097] {
            let record: Vec<_> = (0..size).map(|i| ((i * 37 + 19) % 256) as u8).collect();
            let (mut process, mut t, _) = query_fixture(arch);
            let p = process.state_mut();
            native_profile::kernel_profile(p, 29695, 0xAA64);
            p.native.as_mut().unwrap().code_integrity_policies =
                Ok(std::sync::Arc::from(record.clone()));
            std::sync::Arc::make_mut(&mut p.cfg).version.build = 1;
            let data =
                p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            p.space.wr(data, &[0xa5; 16384]).unwrap();
            query_arguments(p, &mut t, 189, data, size + 17, data + 8192);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), 0);
            assert_eq!(p.space.bytes(data, size as usize).unwrap(), record);
            assert_eq!(
                p.space.bytes(data + u64::from(size), 17).unwrap(),
                [0xa5; 17]
            );
            assert_eq!(p.space.u32(data + 8192).unwrap(), size);
        }
    }
}

#[cfg(windows)]
#[test]
fn code_integrity_policies_installed_ntdll_leaves_execute_selected_snapshot() {
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let arches = if host == WinArch::X86 {
        vec![host]
    } else {
        vec![host, WinArch::X86]
    };
    for arch in arches {
        let image: &[u8] = match arch {
            WinArch::X86 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
            WinArch::X64 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::Arm64 => include_bytes!(
                "../../../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe"
            ),
        };
        let mut config =
            WindowsConfig::embedded("C:\\native-policies.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let expected = p
            .native
            .as_ref()
            .unwrap()
            .code_integrity_policies
            .as_ref()
            .expect("qualified installed policies snapshot")
            .clone();
        let required = u32::try_from(expected.len()).unwrap();
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        let rounded = u64::from(required).div_ceil(PAGE_SIZE) * PAGE_SIZE;
        let size = rounded + 2 * PAGE_SIZE;
        let data =
            p.vm.allocate(None, size, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.space.wr(data, &vec![0xa5; size as usize]).unwrap();
        let returned = data + rounded + PAGE_SIZE;
        assert_eq!(
            super::secure_connect_tests::installed::leaf(
                p,
                &mut thread,
                "NtQuerySystemInformation",
                &[189, 0, 0, returned]
            ),
            STATUS_INFO_LENGTH_MISMATCH
        );
        assert_eq!(p.space.u32(returned).unwrap(), required);
        assert_eq!(
            super::secure_connect_tests::installed::leaf(
                p,
                &mut thread,
                "NtQuerySystemInformation",
                &[189, data, u64::from(required) + 17, returned]
            ),
            0
        );
        assert_eq!(
            p.space.bytes(data, expected.len()).unwrap(),
            expected.as_ref()
        );
        assert_eq!(
            p.space.bytes(data + u64::from(required), 17).unwrap(),
            [0xa5; 17]
        );
        assert_eq!(p.space.u32(returned).unwrap(), required);
    }
}
