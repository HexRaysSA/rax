//! Replay every original byte and guard verdict from three native kernels.
use super::*;

fn decode(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&value[at..at + 2], 16).unwrap())
        .collect()
}

#[test]
fn system_flush_replays_all_2640_native_queries_without_output_rebasing() {
    let capture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-system-flush-information/replay.json"
    )))
    .unwrap();
    let mut count = 0;
    for profile in capture["profiles"].as_array().unwrap() {
        for sample in profile["samples"].as_array().unwrap() {
            let arch = match sample["arch"].as_str().unwrap() {
                "arm64" => WinArch::Arm64,
                "x64" => WinArch::X64,
                "x86" => WinArch::X86,
                _ => unreachable!(),
            };
            let source = sample["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row[0] == 0 && row[2] == 32 && row[3] == "valid")
                .unwrap();
            let record: [u8; 32] = decode(source[9].as_str().unwrap())[..32]
                .try_into()
                .unwrap();
            for native in [false, true] {
                if native && arch != WinArch::X86 {
                    continue;
                }
                let name = if native {
                    "NtWow64GetNativeSystemInformation"
                } else {
                    "NtQuerySystemInformation"
                };
                let (mut process, mut t) = fixture(arch, name, 0x36);
                let p = process.state_mut();
                p.flush_information = Ok(record);
                // Snapshot selection cannot be changed by a guest version field.
                std::sync::Arc::make_mut(&mut p.cfg).version.build = 1;
                let data =
                    p.vm.allocate(
                        None,
                        2 * PAGE_SIZE,
                        mem::RESERVE | mem::COMMIT,
                        prot::READWRITE,
                    )
                    .unwrap()
                    .0;
                let ret =
                    p.vm.allocate(
                        None,
                        2 * PAGE_SIZE,
                        mem::RESERVE | mem::COMMIT,
                        prot::READWRITE,
                    )
                    .unwrap()
                    .0;
                let sp = t.cpu.sp();
                for row in sample["rows"].as_array().unwrap() {
                    let cls = row[1].as_u64().unwrap() as u32;
                    if row[0].as_u64().unwrap() != u64::from(native) || cls != 192 {
                        continue;
                    }
                    let length = row[2].as_u64().unwrap() as u32;
                    let mode = row[3].as_str().unwrap();
                    p.vm.protect(data, 2 * PAGE_SIZE, prot::READWRITE).unwrap();
                    p.vm.protect(ret, 2 * PAGE_SIZE, prot::READWRITE).unwrap();
                    p.space
                        .wr(
                            data,
                            &[if mode == "alternate_output" {
                                0x5a
                            } else {
                                0xa5
                            }; 8192],
                        )
                        .unwrap();
                    p.space.wr(ret, &[0xcc; 8192]).unwrap();
                    let mut output = data + 128;
                    let mut returned = ret + 128;
                    match mode {
                        "valid" | "alternate_output" => {}
                        "null_output" => output = 0,
                        "misaligned_output" => output += 1,
                        "null_return" => returned = 0,
                        "misaligned_return" => returned += 1,
                        "bad_return" => {
                            returned = ret + PAGE_SIZE;
                            p.vm.protect(ret + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                                .unwrap();
                        }
                        "readonly_output" => {
                            p.vm.protect(data, PAGE_SIZE, prot::READONLY).unwrap();
                        }
                        "guard_output" => {
                            p.vm.protect(data, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                                .unwrap();
                        }
                        "readonly_guard_output" => {
                            p.vm.protect(data, PAGE_SIZE, prot::READONLY | prot::GUARD)
                                .unwrap();
                        }
                        "cross12" | "cross44" => {
                            output = data + PAGE_SIZE - if mode == "cross12" { 12 } else { 44 };
                            p.vm.protect(data + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                                .unwrap();
                        }
                        "alias_return" => returned = output,
                        "guard_return" => {
                            p.vm.protect(ret, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                                .unwrap();
                        }
                        "both_guard" => {
                            p.vm.protect(data, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                                .unwrap();
                            p.vm.protect(ret, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                                .unwrap();
                        }
                        "readonly_return" => {
                            p.vm.protect(ret, PAGE_SIZE, prot::READONLY).unwrap();
                        }
                        "return_cross2" => {
                            returned = ret + PAGE_SIZE - 2;
                            p.vm.protect(ret + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
                                .unwrap();
                        }
                        "readonly_output_bad_return" => {
                            p.vm.protect(data, PAGE_SIZE, prot::READONLY).unwrap();
                            returned = ret + PAGE_SIZE;
                            p.vm.protect(returned, PAGE_SIZE, prot::NOACCESS).unwrap();
                        }
                        "null_output_bad_return" => {
                            output = 0;
                            returned = ret + PAGE_SIZE;
                            p.vm.protect(returned, PAGE_SIZE, prot::NOACCESS).unwrap();
                        }
                        "misaligned_output_guard_return" => {
                            output += 1;
                            p.vm.protect(ret, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                                .unwrap();
                        }
                        "guard_output_bad_return" => {
                            p.vm.protect(data, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                                .unwrap();
                            returned = ret + PAGE_SIZE;
                            p.vm.protect(returned, PAGE_SIZE, prot::NOACCESS).unwrap();
                        }
                        "alias_return4" => returned = output + 4,
                        "alias_return28" => returned = output + 28,
                        "alias_return32" => returned = output + 32,
                        _ => panic!("unknown independent mode {mode}"),
                    }
                    t.cpu.set_sp(sp);
                    query_arguments(p, &mut t, cls, output, length, returned);
                    let label = format!("{arch}/{name}/{cls}/{length}/{mode}");
                    assert_eq!(dispatch_query(p, &mut t), Outcome::Continue, "{label}");
                    let status = row[4].as_u64().unwrap();
                    assert_eq!(t.cpu.gpr(0), status, "{label}");
                    assert_eq!(
                        row[5].as_u64().unwrap(),
                        0,
                        "{label}: no native raised exception"
                    );
                    assert!(t.frames.is_empty(), "{label}");
                    assert_eq!(
                        p.vm.query(data).unwrap().protect & prot::GUARD != 0,
                        row[7].as_bool().unwrap(),
                        "{label}"
                    );
                    assert_eq!(
                        p.vm.query(ret).unwrap().protect & prot::GUARD != 0,
                        row[8].as_bool().unwrap(),
                        "{label}"
                    );
                    p.vm.protect(data, 2 * PAGE_SIZE, prot::READWRITE).unwrap();
                    p.vm.protect(ret, 2 * PAGE_SIZE, prot::READWRITE).unwrap();
                    let expected = decode(row[9].as_str().unwrap());
                    if output != 0 {
                        assert_eq!(
                            p.space.bytes(output, 80).unwrap(),
                            expected,
                            "{label}: bytes"
                        );
                    } else {
                        assert!(expected.is_empty());
                    }
                    assert_eq!(
                        if returned == 0 {
                            0
                        } else {
                            p.space.u32(returned).unwrap()
                        },
                        row[6].as_u64().unwrap() as u32,
                        "{label}: returned"
                    );
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 2640);
}

#[test]
fn system_flush_requires_selected_metadata_and_respects_wow64_workspace_budget() {
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = query_fixture(arch);
        let p = process.state_mut();
        p.flush_information = Err("controlled unavailable snapshot".into());
        query_arguments(p, &mut t, 192, scratch, 32, scratch + 96);
        assert!(matches!(dispatch_query(p, &mut t), Outcome::Fail(reason)
            if reason.contains("SystemFlushInformation") && reason.contains("controlled unavailable snapshot")));
    }
    let (mut process, mut t, scratch) = query_fixture(WinArch::X86);
    let p = process.state_mut();
    p.flush_information = Ok([0; 32]);
    let length = u32::try_from(p.cfg.arena_bytes).unwrap() + 1;
    query_arguments(p, &mut t, 192, scratch, length, scratch + 96);
    assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
    assert_eq!(t.cpu.gpr(0), u64::from(STATUS_NO_MEMORY));
    assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xA5; 128]);
}

#[cfg(windows)]
#[test]
fn system_flush_installed_ntdll_leaves_execute_selected_snapshot_and_actual_returns() {
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
            WindowsConfig::embedded("C:\\native-flush.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let expected = *p
            .flush_information
            .as_ref()
            .expect("qualified installed flush snapshot");
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
                &[192, data, 32, data + 96]
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
                    &[192, data, 32, data + 96]
                ),
                crate::user::windows::nt::status::STATUS_INVALID_INFO_CLASS
            );
            assert_eq!(p.space.bytes(data, 128).unwrap(), [0xA5; 128]);
        }
    }
}
