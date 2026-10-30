//! Native class164 statuses, byte stores, aliasing and reached guard transitions.

use super::*;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Case {
    index: u32,
    output: u32,
    returned: u32,
    length: u32,
    poison: u8,
    status: u32,
    exception: u32,
    protections: [u32; 4],
    bytes: String,
    returned_bytes: String,
}

fn decode(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&value[at..at + 2], 16).unwrap())
        .collect()
}

fn prepare(p: &mut Proc, base: u64, case: &Case) -> (u64, u64, u64, u64) {
    p.vm.protect(base, 65536, prot::READWRITE).unwrap();
    p.space.wr(base, &vec![case.poison; 65536]).unwrap();
    let (mut output_offset, mut returned_offset) = (0, 8192);
    let mut output = base;
    let mut protect = |offset, value| {
        p.vm.protect(base + offset, PAGE_SIZE, value).unwrap();
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
            };
        }
        _ => panic!("unknown independent output role"),
    }
    let mut returned = base + returned_offset;
    match case.returned {
        0 => {}
        1 => returned = 0,
        2 => returned = 1,
        3 => {
            returned_offset = 8193;
            returned = base + returned_offset;
        }
        4 => protect(8192, prot::READONLY),
        5 => protect(8192, prot::READWRITE | prot::GUARD),
        6 => protect(8192, prot::NOACCESS),
        7..=10 => {
            returned_offset = output_offset
                + match case.returned {
                    7 => 0,
                    8 => 4,
                    9 => 28,
                    _ => 32,
                };
            returned = base + returned_offset;
        }
        11 => {
            returned_offset = 12286;
            returned = base + returned_offset;
            protect(12288, prot::NOACCESS);
        }
        12 => protect(8192, prot::READONLY | prot::GUARD),
        _ => panic!("unknown independent ReturnLength role"),
    }
    (
        output,
        returned,
        base + output_offset,
        base + returned_offset,
    )
}

fn corpus(label: &str) -> String {
    if let Some(directory) = std::env::var_os("RAX_CODE_INTEGRITY_POLICY_CORPUS") {
        return std::fs::read_to_string(
            std::path::PathBuf::from(directory).join(format!("{label}.jsonl")),
        )
        .expect("explicit fresh native observations");
    }
    match label {
        "arm64" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-code-integrity-policy/arm64.jsonl"
        )),
        "x64" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-code-integrity-policy/x64.jsonl"
        )),
        "x86" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-code-integrity-policy/x86.jsonl"
        )),
        _ => unreachable!(),
    }
    .into()
}

#[test]
fn code_integrity_policy_replays_native_queries() {
    let labels: Vec<String> = if let Some(directory) =
        std::env::var_os("RAX_CODE_INTEGRITY_POLICY_CORPUS")
    {
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(std::path::PathBuf::from(directory).join("observations.json"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["schema"], "rax-native-code-integrity-policy-v1");
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
    let expected_count = labels.len() * 2916;
    let mut count = 0;
    for label in labels {
        let arch = match label.as_str() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => panic!("unknown native process ABI"),
        };
        let contents = corpus(&label);
        let rows: Vec<Case> = contents
            .lines()
            .filter_map(|line| {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                (value["kind"] == "case").then(|| serde_json::from_value(value).unwrap())
            })
            .collect();
        assert_eq!(rows.len(), 2916, "{label}");
        let source = rows
            .iter()
            .find(|row| row.output == 0 && row.returned == 0 && row.length == 32)
            .unwrap();
        let record: [u8; 32] = decode(&source.bytes)[..32].try_into().unwrap();
        let (mut process, mut t, _) = query_fixture(arch);
        let p = process.state_mut();
        native_profile::kernel_profile(p, 29695, 0xAA64);
        p.native.as_mut().unwrap().code_integrity_policy = Ok(record);
        let base =
            p.vm.allocate(None, 65536, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let sp = t.cpu.sp();
        let offsets = crate::user::windows::layout::offsets(arch);
        p.space
            .w32(t.teb + offsets.teb_last_error, 0x1234_5678)
            .unwrap();
        p.space
            .w32(t.teb + offsets.teb_last_status, 0xc123_abcd)
            .unwrap();
        for case in rows {
            let (output, returned, output_watch, returned_watch) = prepare(p, base, &case);
            t.cpu.set_sp(sp);
            query_arguments(p, &mut t, 164, output, case.length, returned);
            let label = format!(
                "{arch}/{}/{}/{}/{}",
                case.index, case.output, case.returned, case.length
            );
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue, "{label}");
            assert_eq!(t.cpu.gpr(0), u64::from(case.status), "{label}");
            assert_eq!(case.exception, 0, "{label}");
            assert!(t.frames.is_empty(), "{label}");
            for (offset, expected) in [0, 4096, 8192, 12288].into_iter().zip(case.protections) {
                assert_eq!(
                    p.vm.query(base + offset).unwrap().protect,
                    expected,
                    "{label}/{offset}"
                );
            }
            p.vm.protect(base, 65536, prot::READWRITE).unwrap();
            assert_eq!(
                p.space.bytes(output_watch, 96).unwrap(),
                decode(&case.bytes),
                "{label}: output"
            );
            assert_eq!(
                p.space.bytes(returned_watch, 8).unwrap(),
                decode(&case.returned_bytes),
                "{label}: ReturnLength"
            );
            assert_eq!(
                p.space.u32(t.teb + offsets.teb_last_error).unwrap(),
                0x1234_5678,
                "{label}"
            );
            assert_eq!(
                p.space.u32(t.teb + offsets.teb_last_status).unwrap(),
                0xc123_abcd,
                "{label}"
            );
            count += 1;
        }
    }
    assert_eq!(count, expected_count);
}

#[test]
fn code_integrity_policy_requires_selected_snapshot_and_bounds_wow64_workspace() {
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = query_fixture(arch);
        let p = process.state_mut();
        query_arguments(p, &mut t, 164, scratch, 32, scratch + 96);
        assert!(
            matches!(dispatch_query(p, &mut t), Outcome::Fail(reason) if reason.contains("requires selected native inputs"))
        );
        native_profile::kernel_profile(p, 29695, 0xAA64);
        query_arguments(p, &mut t, 164, scratch, 32, scratch + 96);
        assert!(
            matches!(dispatch_query(p, &mut t), Outcome::Fail(reason) if reason.contains("policy not captured"))
        );
        assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xA5; 128]);
    }
    let (mut process, mut t, scratch) = query_fixture(WinArch::X86);
    let p = process.state_mut();
    let length = u32::try_from(p.cfg.arena_bytes).unwrap() + 1;
    query_arguments(p, &mut t, 164, scratch, length, scratch + 96);
    assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
    assert_eq!(t.cpu.gpr(0), u64::from(STATUS_NO_MEMORY));
    assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xA5; 128]);
}

#[test]
fn code_integrity_policy_preserves_arbitrary_record_bits_and_process_snapshot() {
    for arch in WinArch::ALL {
        for record in [[0; 32], [0xFF; 32], std::array::from_fn(|i| i as u8)] {
            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            native_profile::kernel_profile(p, 29695, 0xAA64);
            p.native.as_mut().unwrap().code_integrity_policy = Ok(record);
            std::sync::Arc::make_mut(&mut p.cfg).version.build = 1;
            query_arguments(p, &mut t, 164, scratch, 64, 0);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), 0);
            assert_eq!(p.space.bytes(scratch, 32).unwrap(), record);
            assert_eq!(p.space.bytes(scratch + 32, 96).unwrap(), [0xA5; 96]);
        }
    }
}

#[cfg(windows)]
#[test]
fn code_integrity_policy_installed_ntdll_leaves_execute_selected_snapshot_and_actual_returns() {
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
            WindowsConfig::embedded("C:\\native-policy.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let expected = *p
            .native
            .as_ref()
            .unwrap()
            .code_integrity_policy
            .as_ref()
            .expect("qualified installed policy snapshot");
        let tid = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&tid).unwrap();
        let data =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.space.wr(data, &[0xA5; 128]).unwrap();
        assert_eq!(
            super::secure_connect_tests::installed::leaf(
                p,
                &mut thread,
                "NtQuerySystemInformation",
                &[164, data, 32, data + 96]
            ),
            0
        );
        assert_eq!(p.space.bytes(data, 32).unwrap(), expected);
        assert_eq!(p.space.u32(data + 96).unwrap(), 32);
        if arch == WinArch::X86 {
            p.space.wr(data, &[0xA5; 128]).unwrap();
            assert_eq!(
                super::secure_connect_tests::installed::leaf(
                    p,
                    &mut thread,
                    "NtWow64GetNativeSystemInformation",
                    &[164, data, 32, data + 96]
                ),
                crate::user::windows::nt::status::STATUS_INVALID_INFO_CLASS
            );
            assert_eq!(p.space.bytes(data, 128).unwrap(), [0xA5; 128]);
        }
    }
}
