//! Replay fixed-NX profiles only; mutable and default no-NX DEP policies are
//! separate, unimplemented contracts. Native open-handle results are inputs to
//! these query checks, not coverage of NtOpenProcess.

use super::*;
use crate::error::MemoryAccessKind;

fn pointer(base: u64, role: u64, offset: u64) -> u64 {
    match role {
        1 => 0,
        2 => 1,
        3 => base + offset + 1,
        4 => base + 4096 + offset,
        5 => base + 8192 + offset,
        6 | 7 => base + 12288 + offset,
        8 => base + 4094,
        9 => base + 4092,
        _ => base + offset,
    }
}

fn projection(p: &Proc, base: u64, pointer: u64, fallback: u64) -> String {
    let at = if (base..=base + 16384 - 16).contains(&pointer) {
        pointer
    } else {
        base + fallback
    };
    p.space
        .bytes(at, 16)
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn native_process_execute_flags_replays_all_956_fixed_nx_native_queries() {
    let data: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-process-execute-flags/local-29683-v2.json"
    )))
    .unwrap();
    let mut profiles = 0;
    let mut queries = 0;
    for profile in data.as_array().unwrap() {
        if profile["kind"] != "observation" || profile["rows"][0]["dep_permanent"] != true {
            continue;
        }
        profiles += 1;
        let arch = match profile["arch"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => unreachable!(),
        };
        let (mut process, mut t) = fixture(arch, "NtQueryInformationProcess", 0x19);
        let p = process.state_mut();
        let sp = t.cpu.sp();
        for row in profile["rows"].as_array().unwrap().iter().skip(1).take(239) {
            queries += 1;
            let base =
                p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            p.space.wr(base, &[0xa5; 16384]).unwrap();
            let out_role = row["output_role"].as_u64().unwrap();
            let ret_role = row["return_role"].as_u64().unwrap();
            let guard = if out_role == 7 || ret_role == 7 {
                prot::READONLY
            } else {
                prot::READWRITE
            } | prot::GUARD;
            for (offset, protection) in [
                (4096, prot::READONLY),
                (8192, prot::NOACCESS),
                (12288, guard),
            ] {
                p.vm.protect(base + offset, 4096, protection).unwrap();
            }
            let output = pointer(base, out_role, 256);
            let alias = row["alias"].as_i64().unwrap();
            let returned = if alias >= 0 {
                base + 256 + alias as u64
            } else {
                pointer(base, ret_role, 512)
            };
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
                5 if row["opened"] == false => (0, false),
                5 => {
                    let id = p.objects.create(Object::Process {
                        pid: p.pid,
                        exit_code: None,
                    });
                    let access = row["access"].as_u64().unwrap() as u32;
                    (
                        u64::from(p.objects.open_access(id, false, access).unwrap()),
                        true,
                    )
                }
                _ => unreachable!(),
            };
            t.cpu.set_sp(sp);
            arguments(
                p,
                &mut t,
                handle,
                34,
                output,
                row["length"].as_u64().unwrap() as u32,
                returned,
            );
            assert_eq!(dispatch(p, &mut t), Outcome::Continue, "{arch} row={row}");
            assert_eq!(
                t.cpu.gpr(0),
                row["status"].as_u64().unwrap(),
                "{arch} row={row}"
            );
            assert_eq!(
                p.vm.query(base + 12288).unwrap().protect,
                row["guard_protection"].as_u64().unwrap() as u32,
                "{arch} row={row}"
            );
            p.vm.protect(base, 16384, prot::READWRITE).unwrap();
            assert_eq!(
                projection(p, base, output, 256),
                row["output"].as_str().unwrap(),
                "{arch} row={row}"
            );
            assert_eq!(
                projection(p, base, returned, 512),
                row["returned"].as_str().unwrap(),
                "{arch} row={row}"
            );
            assert_eq!(t.cpu.pc(), 0x1234_0004);
            assert_eq!(t.cpu.sp(), sp + if arch == WinArch::X86 { 4 } else { 0 });
            assert!(t.frames.is_empty());
            if owned {
                p.objects.close(handle).unwrap();
            }
            p.vm.free(base, 0, mem::RELEASE).unwrap();
        }
    }
    assert_eq!(profiles, 4);
    assert_eq!(queries, 956);
}

#[test]
fn native_process_execute_flags_reflects_existing_nx_mapping_and_rejects_peer_state() {
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = setup(arch);
        let p = process.state_mut();
        assert!(p.space.probe(scratch, 1, MemoryAccessKind::Fetch).is_err());
        let peer = p.objects.create(Object::Process {
            pid: p.pid + 4,
            exit_code: None,
        });
        let handle = p.objects.open_access(peer, false, 0x400).unwrap();
        arguments(p, &mut t, u64::from(handle), 34, scratch, 4, scratch + 64);
        assert!(
            matches!(dispatch(p, &mut t), Outcome::Fail(reason) if reason.contains("ProcessExecuteFlags for a process outside this personality"))
        );
        assert_eq!(p.space.bytes(scratch, 128).unwrap(), [0xa5; 128]);
    }
}

#[cfg(windows)]
#[test]
fn installed_native_execute_flags_query_leaf_matches_fixed_guest_nx_profile() {
    use crate::user::windows::loader::{self, SymRef};

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
            WinArch::X86 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/x86/smoke.exe"
            )),
            WinArch::X64 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/x64/smoke.exe"
            )),
            WinArch::Arm64 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/arm64/smoke.exe"
            )),
        };
        let mut config =
            WindowsConfig::embedded("C:\\native-execute-flags.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process =
            super::super::super::super::super::WindowsProcess::spawn_image(config, image.to_vec())
                .unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let entry = loader::lookup(
            p,
            module,
            &SymRef::Name(b"NtQueryInformationProcess".to_vec(), None),
        )
        .unwrap()
        .unwrap();
        let output =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.space.wr(output, &[0xa5; 40]).unwrap();
        let returned = output + 32;
        let resume = p.traps.callback_return();
        let sp = t.cpu.sp();
        match arch {
            WinArch::X86 => {
                for (i, value) in [resume, arch.ptr(u64::MAX), 34, output, 4, returned]
                    .into_iter()
                    .enumerate()
                {
                    p.space.w32(sp + i as u64 * 4, value as u32).unwrap();
                }
            }
            WinArch::X64 => {
                p.space.w64(sp, resume).unwrap();
                p.space.w64(sp + 40, returned).unwrap();
                for (register, value) in [(1, u64::MAX), (2, 34), (8, output), (9, 4)] {
                    t.cpu.set_gpr(register, value);
                }
            }
            WinArch::Arm64 => {
                for (register, value) in [
                    (0, u64::MAX),
                    (1, 34),
                    (2, output),
                    (3, 4),
                    (4, returned),
                    (30, resume),
                ] {
                    t.cpu.set_gpr(register, value);
                }
            }
        }
        t.cpu.set_pc(entry);
        assert_eq!(
            run_to_return(p, &mut t, resume, "NtQueryInformationProcess ExecuteFlags"),
            0
        );
        assert_eq!(p.space.u32(output).unwrap(), 0x0d);
        assert_eq!(p.space.u32(returned).unwrap(), 4);
        assert_eq!(p.space.bytes(output + 4, 28).unwrap(), [0xa5; 28]);
        assert_eq!(p.space.u32(returned + 4).unwrap(), 0xa5a5_a5a5);
        assert_eq!(
            t.cpu.sp(),
            sp + match arch {
                WinArch::X86 => 24,
                WinArch::X64 => 8,
                WinArch::Arm64 => 0,
            }
        );
        assert!(t.frames.is_empty());
    }
}
