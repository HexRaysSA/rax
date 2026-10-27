//! Independent permanent-NX setter corpus; no guest input changes policy.
use super::*;
use crate::error::MemoryAccessKind;
use crate::user::windows::nt::status::STATUS_INVALID_PARAMETER;

fn select(p: &mut Proc, name: &str, number: u32) {
    let module = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((module, table(p.arch, name, number)));
}

fn call(p: &mut Proc, t: &mut Thread, handle: u64, input: u64, length: u32) -> Outcome {
    select(p, "NtSetInformationProcess", 0x1c);
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    let args = [handle, 34, input, u64::from(length)];
    match p.arch {
        WinArch::Arm64 => {
            for (i, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr(i, value)
            }
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, 0x1c);
            t.cpu.set_gpr(1, 0x1234_0004);
            for (i, value) in args.into_iter().enumerate() {
                t.cpu.set_gpr([10, 2, 8, 9][i], value)
            }
        }
        WinArch::X86 => {
            p.space.w32(sp, 0x1234_0004).unwrap();
            p.space.w32(sp + 4, 0x1234_0000).unwrap();
            for (i, value) in args.into_iter().enumerate() {
                p.space.w32(sp + 8 + i as u64 * 4, value as u32).unwrap()
            }
            t.cpu.set_gpr(0, 0x1c);
        }
    }
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, 0x1c))
    };
    if result == Outcome::Continue {
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
        assert!(t.frames.is_empty());
    }
    t.cpu.set_sp(sp);
    result
}

fn flags(p: &mut Proc, t: &mut Thread, output: u64) -> u32 {
    select(p, "NtQueryInformationProcess", 0x19);
    let sp = t.cpu.sp();
    arguments(p, t, p.arch.ptr(u64::MAX), 34, output, 4, output + 8);
    assert_eq!(dispatch(p, t), Outcome::Continue);
    assert_eq!(t.cpu.gpr(0), 0);
    assert_eq!(p.space.u32(output + 8).unwrap(), 4);
    t.cpu.set_sp(sp);
    p.space.u32(output).unwrap()
}

fn pointer(base: u64, role: u64) -> u64 {
    match role {
        1 => 0,
        2 => 1,
        3 => base + 257,
        4 => base + 4352,
        5 => base + 8448,
        6 | 7 => base + 12544,
        8 => base + 4094,
        9 => base + 4092,
        10 => u64::MAX & !3,
        11 => u64::MAX & !7,
        12 => base + 8190,
        13 => base + 12286,
        _ => base + 256,
    }
}

#[test]
fn native_process_execute_flags_set_replays_all_5286_native_calls() {
    let data: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-process-execute-flags-set/local-29695-v1.json"
    )))
    .unwrap();
    let mut total = 0;
    assert_eq!(data.as_array().unwrap().len(), 9);
    for profile in data.as_array().unwrap() {
        let arch = match profile["arch"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => unreachable!(),
        };
        let (mut process, mut t) = fixture(arch, "NtSetInformationProcess", 0x1c);
        let p = process.state_mut();
        let query =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        assert_eq!(flags(p, &mut t, query), 0x0d);
        for row in profile["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["kind"] == "case")
        {
            total += 1;
            assert_eq!(row["exception"].as_u64().unwrap(), 0);
            assert_eq!(row["before"].as_u64().unwrap(), 0x0d);
            assert_eq!(row["after"].as_u64().unwrap(), 0x0d);
            let base =
                p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            p.space.wr(base, &[0xa5; 16384]).unwrap();
            let role = row["input_role"].as_u64().unwrap();
            let input = arch.ptr(pointer(base, role));
            if (base..=base + 16384 - 4).contains(&input) {
                p.space
                    .w32(input, row["flags"].as_u64().unwrap() as u32)
                    .unwrap();
            }
            let guard = if role == 7 {
                prot::READONLY
            } else {
                prot::READWRITE
            } | prot::GUARD;
            for (off, protect) in [
                (4096, prot::READONLY),
                (8192, prot::NOACCESS),
                (12288, guard),
            ] {
                p.vm.protect(base + off, 4096, protect).unwrap();
            }
            let (handle, owned) = match row["handle_kind"].as_u64().unwrap() {
                0 => (arch.ptr(u64::MAX), false),
                1 => (0, false),
                2 => (1, false),
                3 => (arch.ptr(u64::MAX - 1), false),
                4 => {
                    let id = p.objects.create(Object::Event {
                        manual: true,
                        signaled: 0,
                    });
                    (u64::from(p.objects.open(id, false)), true)
                }
                tag @ 5..=8 => {
                    let id = p.objects.create(Object::Process {
                        pid: p.pid,
                        exit_code: None,
                    });
                    (
                        u64::from(
                            p.objects
                                .open_access(id, false, row["grant"].as_u64().unwrap() as u32)
                                .unwrap(),
                        ) | (tag - 5),
                        true,
                    )
                }
                _ => unreachable!(),
            };
            assert_eq!(
                call(
                    p,
                    &mut t,
                    handle,
                    input,
                    row["length"].as_u64().unwrap() as u32
                ),
                Outcome::Continue,
                "{arch} {row}"
            );
            assert_eq!(
                t.cpu.gpr(0),
                row["status"].as_u64().unwrap(),
                "{arch} {row}"
            );
            assert_eq!(
                p.vm.query(base + 12288).unwrap().protect,
                row["guard_protection"].as_u64().unwrap() as u32,
                "{arch} {row}"
            );
            p.vm.protect(base, 16384, prot::READWRITE).unwrap();
            let start = if (base..=base + 16384 - 16).contains(&input) {
                input
            } else {
                base + 256
            };
            let bytes: String = p
                .space
                .bytes(start, 16)
                .unwrap()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(bytes, row["input"].as_str().unwrap(), "{arch} {row}");
            assert!(p.space.probe(base, 1, MemoryAccessKind::Fetch).is_err());
            assert_eq!(
                flags(p, &mut t, query),
                row["after"].as_u64().unwrap() as u32
            );
            if owned {
                p.objects.close(handle & !3).unwrap();
            }
            p.vm.free(base, 0, mem::RELEASE).unwrap();
        }
    }
    assert_eq!(total, 5286);
}

#[test]
fn native_process_execute_flags_set_original_packet_preserves_permanent_policy() {
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = setup(arch);
        let p = process.state_mut();
        p.space.w32(scratch, 0x0a).unwrap();
        assert_eq!(
            call(p, &mut t, arch.ptr(u64::MAX), scratch, 4),
            Outcome::Continue
        );
        assert_eq!(
            t.cpu.gpr(0),
            u64::from(if arch == WinArch::X86 {
                STATUS_ACCESS_DENIED
            } else {
                STATUS_INVALID_PARAMETER
            })
        );
        assert_eq!(p.space.u32(scratch).unwrap(), 0x0a);
        assert_eq!(flags(p, &mut t, scratch + 64), 0x0d);
        assert!(p.space.probe(scratch, 1, MemoryAccessKind::Fetch).is_err());
    }
}

#[cfg(windows)]
#[test]
fn installed_native_process_execute_flags_set_leaves_retain_policy_and_actual_ret16() {
    use super::super::secure_connect_tests::installed::leaf;
    use crate::user::windows::nt::status::STATUS_GUARD_PAGE_VIOLATION;
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    for arch in if host == WinArch::X86 {
        vec![host]
    } else {
        vec![host, WinArch::X86]
    } {
        let image: &[u8] = match arch {
            WinArch::Arm64 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/arm64/smoke.exe"
            )),
            WinArch::X64 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/x64/smoke.exe"
            )),
            WinArch::X86 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/x86/smoke.exe"
            )),
        };
        let mut config =
            WindowsConfig::embedded("C:\\native-execute-flags-set.exe", vec![], vec![], 4096)
                .unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process =
            crate::user::windows::WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let base =
            p.vm.allocate(
                None,
                PAGE_SIZE * 2,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        let query = base + PAGE_SIZE;
        let self_handle = arch.ptr(u64::MAX);
        assert_eq!(
            leaf(
                p,
                &mut t,
                "NtQueryInformationProcess",
                &[self_handle, 34, query, 4, query + 8]
            ),
            0
        );
        assert_eq!(p.space.u32(query).unwrap(), 0x0d);
        p.space.w32(base, 0x0a).unwrap();
        assert_eq!(
            leaf(
                p,
                &mut t,
                "NtSetInformationProcess",
                &[self_handle, 34, base, 4]
            ),
            if arch == WinArch::X86 {
                STATUS_ACCESS_DENIED
            } else {
                STATUS_INVALID_PARAMETER
            }
        );
        p.vm.protect(base, PAGE_SIZE, prot::READONLY | prot::GUARD)
            .unwrap();
        assert_eq!(
            leaf(
                p,
                &mut t,
                "NtSetInformationProcess",
                &[self_handle, 34, base, 4]
            ),
            if arch == WinArch::X86 {
                STATUS_ACCESS_DENIED
            } else {
                STATUS_GUARD_PAGE_VIOLATION
            }
        );
        assert_eq!(p.vm.query(base).unwrap().protect, prot::READONLY);
        assert_eq!(p.space.u32(base).unwrap(), 0x0a);
        assert_eq!(
            leaf(
                p,
                &mut t,
                "NtQueryInformationProcess",
                &[self_handle, 34, query, 4, query + 8]
            ),
            0
        );
        assert_eq!(p.space.u32(query).unwrap(), 0x0d);
        assert!(p.space.probe(base, 1, MemoryAccessKind::Fetch).is_err());
    }
}
