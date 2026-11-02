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

struct Corpus {
    build: u32,
    native_machine: u16,
    label: String,
    contents: String,
}

fn corpora() -> Vec<Corpus> {
    if let Some(directory) = std::env::var_os("RAX_CODE_INTEGRITY_POLICY_CORPUS") {
        let directory = std::path::PathBuf::from(directory);
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(directory.join("observations.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["schema"], "rax-native-code-integrity-policy-v1");
        assert_eq!(manifest["state"], "complete");
        assert_eq!(manifest["host"]["identity_source"], "IsWow64Process2");
        let native_machine =
            u16::try_from(manifest["host"]["native_machine"].as_u64().unwrap()).unwrap();
        assert!(matches!(native_machine, 0x8664 | 0xAA64));
        let reports = manifest["reports"].as_array().unwrap();
        let labels: std::collections::BTreeSet<_> = reports
            .iter()
            .map(|r| r["architecture"].as_str().unwrap())
            .collect();
        assert_eq!(labels.len(), reports.len());
        assert!(labels.contains("x64") && labels.contains("x86") && labels.len() <= 3);
        return reports
            .iter()
            .map(|report| {
                let label = report["architecture"].as_str().unwrap();
                assert!(matches!(label, "arm64" | "x64" | "x86"));
                assert_eq!(report["file"], format!("{label}.jsonl"));
                let kernel = report["kernel"].as_array().unwrap();
                assert_eq!(kernel.len(), 3);
                assert_eq!(kernel[0], 10);
                assert_eq!(kernel[1], 0);
                Corpus {
                    build: u32::try_from(kernel[2].as_u64().unwrap()).unwrap(),
                    native_machine,
                    label: label.into(),
                    contents: std::fs::read_to_string(directory.join(format!("{label}.jsonl")))
                        .expect("explicit fresh native observations"),
                }
            })
            .collect();
    }
    [
        (
            29695,
            0xAA64,
            "arm64",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-code-integrity-policy/arm64.jsonl"
            )),
        ),
        (
            29695,
            0xAA64,
            "x64",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-code-integrity-policy/x64.jsonl"
            )),
        ),
        (
            29695,
            0xAA64,
            "x86",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-code-integrity-policy/x86.jsonl"
            )),
        ),
        (
            20348,
            0x8664,
            "x64",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-code-integrity-policy/amd64-20348/x64.jsonl"
            )),
        ),
        (
            20348,
            0x8664,
            "x86",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/specifications/windows/native-code-integrity-policy/amd64-20348/x86.jsonl"
            )),
        ),
    ]
    .into_iter()
    .map(|(build, native_machine, label, contents)| Corpus {
        build,
        native_machine,
        label: label.into(),
        contents: contents.into(),
    })
    .collect()
}

#[test]
fn code_integrity_policy_replays_native_queries() {
    let corpora = corpora();
    let expected_count = corpora.len() * 2916;
    let mut count = 0;
    for corpus in corpora {
        let label = corpus.label;
        let arch = match label.as_str() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => panic!("unknown native process ABI"),
        };
        let contents = corpus.contents;
        let header: serde_json::Value =
            serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(header["kind"], "host");
        assert_eq!(header["kernel"], serde_json::json!([10, 0, corpus.build]));
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
        native_profile::kernel_profile(p, corpus.build, corpus.native_machine);
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
        for (build, machine) in [(20348, 0x8664), (29695, 0xAA64), (29698, 0xAA64)] {
            for record in [[0; 32], [0xFF; 32], std::array::from_fn(|i| i as u8)] {
                for length in [32, 64] {
                    let (mut process, mut t, scratch) = query_fixture(arch);
                    let p = process.state_mut();
                    native_profile::kernel_profile(p, build, machine);
                    p.native.as_mut().unwrap().code_integrity_policy = Ok(record);
                    // Advertising the opposite measured behavior must not
                    // change the selected kernel's copy contract.
                    std::sync::Arc::make_mut(&mut p.cfg).version.build =
                        if build == 20348 { 29695 } else { 20348 };
                    query_arguments(p, &mut t, 164, scratch, length, scratch + 96);
                    assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
                    let rejected = build == 20348 && length != 32;
                    assert_eq!(
                        t.cpu.gpr(0),
                        if rejected {
                            u64::from(STATUS_INFO_LENGTH_MISMATCH)
                        } else {
                            0
                        }
                    );
                    assert_eq!(
                        p.space.bytes(scratch, 32).unwrap(),
                        if rejected { [0xA5; 32] } else { record }
                    );
                    assert_eq!(p.space.bytes(scratch + 32, 64).unwrap(), [0xA5; 64]);
                    assert_eq!(p.space.u32(scratch + 96).unwrap(), 32);
                    assert_eq!(p.space.bytes(scratch + 100, 28).unwrap(), [0xA5; 28]);
                }
            }
        }
    }
}

#[test]
fn code_integrity_policy_unclassified_kernel_uses_exact_snapshot_and_rejects_unknown_sizes() {
    for arch in WinArch::ALL {
        for (major, minor, build, machine) in [
            (10, 0, 20348, Some(0xAA64)),
            (10, 0, 20349, Some(0x8664)),
            (10, 0, 26100, Some(0x8664)),
            (10, 0, 29695, Some(0x8664)),
            (10, 0, 29694, Some(0xAA64)),
            (10, 0, 29696, Some(0xAA64)),
            (10, 0, 29697, Some(0xAA64)),
            (10, 0, 29699, Some(0xAA64)),
            (10, 0, 29695, Some(0x14C)),
            (10, 0, 29695, None),
            (11, 0, 29695, Some(0xAA64)),
            (10, 1, 29695, Some(0xAA64)),
        ] {
            let (mut process, mut t, scratch) = query_fixture(arch);
            let p = process.state_mut();
            native_profile::kernel_profile(p, build, machine.unwrap_or(0));
            let native = p.native.as_mut().unwrap();
            native.version.major = major;
            native.version.minor = minor;
            native.object_namespace.native_machine = machine;
            native.code_integrity_policy = Ok([0x5A; 32]);
            std::sync::Arc::make_mut(&mut p.cfg).version.build = 29695;
            query_arguments(p, &mut t, 164, scratch, 64, scratch + 96);
            assert!(matches!(dispatch_query(p, &mut t), Outcome::Fail(reason)
                if reason.contains("copy profile is unmeasured")));
            assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xA5; 128]);
            assert!(t.frames.is_empty());
            query_arguments(p, &mut t, 164, scratch, 32, scratch + 96);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), 0);
            assert_eq!(p.space.bytes(scratch, 32).unwrap(), [0x5A; 32]);
            assert_eq!(p.space.bytes(scratch + 32, 64).unwrap(), [0xA5; 64]);
            assert_eq!(p.space.u32(scratch + 96).unwrap(), 32);
            assert_eq!(p.space.bytes(scratch + 100, 28).unwrap(), [0xA5; 28]);
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
