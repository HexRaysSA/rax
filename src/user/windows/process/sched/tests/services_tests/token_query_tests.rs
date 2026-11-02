//! Native token-query records, not expected values copied from the adapter.
use super::*;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

#[path = "token_statistics_tests.rs"]
mod statistics;

#[path = "token_session_id_tests.rs"]
mod session_id;

#[path = "token_scalar_tests.rs"]
mod scalar_properties;

#[path = "token_bno_tests.rs"]
mod bno_isolation;

#[path = "token_user_tests.rs"]
mod user_identity;

fn setup(arch: WinArch, laa: bool) -> (WindowsProcess, Thread, u64, [u64; 3]) {
    setup_runtime(arch, laa, false)
}

fn setup_runtime(
    arch: WinArch,
    laa: bool,
    native: bool,
) -> (WindowsProcess, Thread, u64, [u64; 3]) {
    let mut image = match arch {
        WinArch::X86 => {
            include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
                .to_vec()
        }
        WinArch::X64 => {
            include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
                .to_vec()
        }
        WinArch::Arm64 => {
            include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
                .to_vec()
        }
    };
    if laa {
        let pe = u32::from_le_bytes(image[60..64].try_into().unwrap()) as usize;
        let flags = u16::from_le_bytes(image[pe + 22..pe + 24].try_into().unwrap()) | 0x20;
        image[pe + 22..pe + 24].copy_from_slice(&flags.to_le_bytes());
    }
    let mut cfg = WindowsConfig::embedded("C:\\token-query.exe", vec![], vec![], 4096).unwrap();
    cfg.arena_bytes = 64 << 20;
    cfg.native_libraries = native;
    let mut process = WindowsProcess::spawn_image(cfg, image).unwrap();
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut thread = p.threads.remove(&tid).unwrap();
    thread.attached = true;
    thread.main = false;
    if !native {
        let ntdll = p.modules.by_name("ntdll.dll").unwrap();
        p.modules.nt_services = Some((ntdll, table(arch, "NtQueryInformationToken", 0x21)));
        p.objects
            .select_wnf_catalog(crate::user::windows::wnf::tests::empty_subject_catalog(
                false,
            ));
    }
    let base =
        p.vm.allocate(
            None,
            PAGE_SIZE * 8,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    let event = p.objects.create(Object::Event {
        manual: false,
        signaled: 0,
    });
    let event = u64::from(p.objects.open(event, false));
    let token = p.objects.create(Object::PrimaryToken);
    let query = u64::from(p.objects.open_access(token, false, 8).unwrap());
    let denied = u64::from(p.objects.open_access(token, false, 0).unwrap());
    (process, thread, base, [event, query, denied])
}

fn invoke(p: &mut Proc, thread: &mut Thread, args: &[u64]) -> Outcome {
    super::nls_tests::arguments(p, thread, args);
    if p.arch != WinArch::Arm64 {
        thread.cpu.set_gpr(0, 0x21);
    }
    if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, thread, 0x1234_0000)
    } else {
        handle_stop(p, thread, stop(p.arch, 0x21))
    }
}

fn handle(p: &Proc, kind: &str, handles: [u64; 3]) -> u64 {
    match kind {
        "primary" => p.arch.ptr(u64::MAX - 3),
        "thread-token" => p.arch.ptr(u64::MAX - 4),
        "effective" => p.arch.ptr(u64::MAX - 5),
        "null" => 0,
        "process" => p.arch.ptr(u64::MAX),
        "thread" => p.arch.ptr(u64::MAX - 1),
        "invalid" => 0xDEAD,
        "event" => handles[0],
        "real" => handles[1],
        "no-access" => handles[2],
        _ => panic!("unknown native handle role"),
    }
}

fn destinations(p: &mut Proc, base: u64, role: u32) -> (u64, u64) {
    p.vm.protect(base, PAGE_SIZE * 8, prot::READWRITE).unwrap();
    p.space
        .wr(base, &vec![0xA5; (PAGE_SIZE * 8) as usize])
        .unwrap();
    let mut output = base + PAGE_SIZE;
    let mut returned = base + PAGE_SIZE * 5;
    let mut protection = None;
    match role {
        0 | 25..=40 => {}
        1 => output = 0,
        2..=4 => output += u64::from(role - 1),
        5 => returned = 0,
        6..=8 => returned += u64::from(role - 5),
        9..=12 => {
            protection = Some((
                output,
                [
                    prot::NOACCESS,
                    prot::READONLY,
                    prot::READWRITE | prot::GUARD,
                    prot::READONLY | prot::GUARD,
                ][(role - 9) as usize],
            ))
        }
        13..=16 => {
            protection = Some((
                returned,
                [
                    prot::NOACCESS,
                    prot::READONLY,
                    prot::READWRITE | prot::GUARD,
                    prot::READONLY | prot::GUARD,
                ][(role - 13) as usize],
            ))
        }
        17 => returned = output,
        18 => returned = output + 1,
        19 | 24 => {
            output += PAGE_SIZE - if role == 19 { 2 } else { 4 };
            protection = Some((base + PAGE_SIZE * 2, prot::NOACCESS));
        }
        20 => {
            returned += PAGE_SIZE - 2;
            protection = Some((base + PAGE_SIZE * 6, prot::NOACCESS));
        }
        21 => {
            output = 0;
            returned = 0;
        }
        22 => {
            output = 1;
            returned = 0;
        }
        23 => {
            output = 0;
            returned += 1;
        }
        41 | 42 => {
            output = 0;
            protection = Some((
                returned,
                if role == 41 {
                    prot::READWRITE | prot::GUARD
                } else {
                    prot::READONLY | prot::GUARD
                },
            ));
        }
        _ => panic!("unknown native pointer role"),
    }
    if (25..=40).contains(&role) {
        let protections = [
            prot::NOACCESS,
            prot::READONLY,
            prot::READWRITE | prot::GUARD,
            prot::READONLY | prot::GUARD,
        ];
        let pair = (role - 25) as usize;
        p.vm.protect(output, PAGE_SIZE, protections[pair / 4])
            .unwrap();
        p.vm.protect(returned, PAGE_SIZE, protections[pair % 4])
            .unwrap();
    }
    if let Some((address, protect)) = protection {
        p.vm.protect(address, PAGE_SIZE, protect).unwrap();
    }
    (output, returned)
}

fn cells(p: &Proc, address: u64, expected: &str) {
    assert_eq!(expected.len(), 8);
    for (index, hex) in expected.as_bytes().chunks_exact(2).enumerate() {
        if hex != b"??" {
            let expected = u8::from_str_radix(std::str::from_utf8(hex).unwrap(), 16).unwrap();
            assert_eq!(
                p.space.u8(address + index as u64).unwrap(),
                expected,
                "cell {index}"
            );
        }
    }
}

#[test]
fn native_token_query_replays_all_7320_native_profile_rows() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-token-query/cases.json"
    ))
    .unwrap();
    let rows = fixture["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 1830);
    for (arch, laa) in [
        (WinArch::Arm64, false),
        (WinArch::X64, false),
        (WinArch::X86, false),
        (WinArch::X86, true),
    ] {
        let (mut process, mut thread, base, handles) = setup(arch, laa);
        let p = process.state_mut();
        for (index, row) in rows.iter().enumerate() {
            let value = |name: &str| row[name].as_str().unwrap();
            let role: u32 = value("role").parse().unwrap();
            let (output, returned) = destinations(p, base, role);
            let token = handle(p, value("kind"), handles);
            let length = u32::from_str_radix(value("length"), 16).unwrap();
            let status = u32::from_str_radix(value("status"), 16).unwrap();
            let sp = thread.cpu.sp();
            let rng = p.rng;
            let count = p.objects.handle_count();
            assert_eq!(
                invoke(
                    p,
                    &mut thread,
                    &[token, 29, output, u64::from(length), returned]
                ),
                Outcome::Continue,
                "{arch}/{laa}/row{index}"
            );
            assert_eq!(
                thread.cpu.gpr(0),
                u64::from(status),
                "{arch}/{laa}/row{index}/{row}"
            );
            assert_eq!(
                thread.cpu.sp(),
                sp + if arch == WinArch::X86 { 4 } else { 0 }
            );
            thread.cpu.set_sp(sp);
            assert!(thread.frames.is_empty());
            assert_eq!(p.rng, rng);
            assert_eq!(p.objects.handle_count(), count);
            for (address, name) in [(output, "output-protect"), (returned, "returned-protect")] {
                if (base..base + PAGE_SIZE * 8).contains(&address) {
                    assert_eq!(
                        p.vm.query(address).unwrap().protect,
                        u32::from_str_radix(value(name), 16).unwrap(),
                        "{arch}/{laa}/row{index}/{name}"
                    );
                }
            }
            cells(p, output, value("output-bytes-cells"));
            cells(p, returned, value("return-bytes-cells"));
        }
    }
}

#[test]
fn native_token_query_reads_retained_false_true_and_missing_subject_state() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base, handles) = setup(arch, false);
        let p = process.state_mut();
        for flag in [false, true] {
            p.objects
                .select_wnf_catalog(crate::user::windows::wnf::tests::empty_subject_catalog(
                    flag,
                ));
            for kind in ["primary", "effective", "real"] {
                let (output, returned) = destinations(p, base, 0);
                let token = handle(p, kind, handles);
                let sp = thread.cpu.sp();
                assert_eq!(
                    invoke(p, &mut thread, &[token, 29, output, 8, returned]),
                    Outcome::Continue
                );
                thread.cpu.set_sp(sp);
                assert_eq!(thread.cpu.gpr(0), 0);
                assert_eq!(p.space.u32(output).unwrap(), u32::from(flag));
                assert_eq!(p.space.u32(returned).unwrap(), 4);
                assert_eq!(p.space.bytes(output + 4, 4).unwrap(), [0xA5; 4]);
            }
        }
        p.objects.select_wnf_catalog(Default::default());
        let (output, returned) = destinations(p, base, 0);
        let result = invoke(
            p,
            &mut thread,
            &[arch.ptr(u64::MAX - 3), 29, output, 4, returned],
        );
        assert_ne!(
            result,
            Outcome::Continue,
            "missing subject must not become a false flag"
        );
        assert_eq!(p.space.u32(output).unwrap(), 0xA5A5_A5A5);
        assert_eq!(p.space.u32(returned).unwrap(), 0xA5A5_A5A5);
    }
}

#[cfg(windows)]
#[test]
fn native_token_query_installed_leaves_replay_every_record_on_available_profiles() {
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let mut profiles = vec![(host, false)];
    if host != WinArch::X86 {
        profiles.push((WinArch::X86, false));
    }
    profiles.push((WinArch::X86, true));
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-token-query/cases.json"
    ))
    .unwrap();
    let rows = fixture["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 1830);
    for (arch, laa) in profiles {
        let (mut process, mut thread, base, handles) = setup_runtime(arch, laa, true);
        let p = process.state_mut();
        // The retained native corpus was measured with a non-AppContainer
        // primary subject. Do not silently impose that subject on the host.
        assert_eq!(p.objects.primary_token_app_container(), Some(false));
        let module = crate::user::windows::loader::load_dll(p, "ntdll.dll").unwrap();
        for (index, row) in rows.iter().enumerate() {
            let value = |name: &str| row[name].as_str().unwrap();
            let role: u32 = value("role").parse().unwrap();
            let (output, returned) = destinations(p, base, role);
            let token = handle(p, value("kind"), handles);
            let length = u32::from_str_radix(value("length"), 16).unwrap();
            let expected = u32::from_str_radix(value("status"), 16).unwrap();
            let rng = p.rng;
            let count = p.objects.handle_count();
            let actual = super::virtual_memory_tests::installed::invoke(
                p,
                &mut thread,
                module,
                "NtQueryInformationToken",
                &[token, 29, output, u64::from(length), returned],
            );
            assert_eq!(actual, expected, "{arch}/{laa}/installed row{index}/{row}");
            assert_eq!(p.rng, rng);
            assert_eq!(p.objects.handle_count(), count);
            for (address, name) in [(output, "output-protect"), (returned, "returned-protect")] {
                if (base..base + PAGE_SIZE * 8).contains(&address) {
                    assert_eq!(
                        p.vm.query(address).unwrap().protect,
                        u32::from_str_radix(value(name), 16).unwrap(),
                        "{arch}/{laa}/installed row{index}/{name}"
                    );
                }
            }
            cells(p, output, value("output-bytes-cells"));
            cells(p, returned, value("return-bytes-cells"));
        }
    }
}
