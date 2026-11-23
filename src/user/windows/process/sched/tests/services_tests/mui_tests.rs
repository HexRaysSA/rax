//! All native query rows, including aliases, undersized buffers and partial clears.
use super::nls_tests::{arguments, dispatch};
use super::*;
use crate::user::windows::memory::{mem, prot};

const CORPORA: [(WinArch, &str); 3] = [
    (
        WinArch::Arm64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-mui-query/native-mui-query-v2-arm64.log"
        ),
    ),
    (
        WinArch::X86,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-mui-query/native-mui-query-v2-x86.log"
        ),
    ),
    (
        WinArch::X64,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-mui-query/native-mui-query-v2-x64.log"
        ),
    ),
];

const AMD64_26100_CORPUS: &str = include_str!(
    "../../../../../../../docs/specifications/windows/native-mui-query/amd64-26100-native.log"
);

const AMD64_CORPORA: [(u32, &str); 2] = [
    (
        20348,
        include_str!(
            "../../../../../../../docs/specifications/windows/native-mui-query/amd64-20348-native.log"
        ),
    ),
    (26100, AMD64_26100_CORPUS),
];

// The native ARM64 capture has the same SHA-256 as both AMD64 query logs.
// Its independent provider and artifact identities are recorded in arm64-26200-inputs.json.
const ARM64_26200_CORPUS: &str = AMD64_26100_CORPUS;

fn field(line: &str, key: &str, radix: u32) -> u32 {
    let prefix = format!("{key}=");
    let text = line
        .split_whitespace()
        .find_map(|word| word.strip_prefix(&prefix))
        .unwrap();
    u32::from_str_radix(text, radix).unwrap()
}

#[test]
fn native_mui_commitment_returns_the_captured_wow64_status_without_stack_cleanup() {
    use crate::user::windows::memory::Mem;
    use crate::user::windows::nls::Nls;

    let profile: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-mui-query/commitment-29708-arm64.json"
    ))
    .unwrap();
    let service = profile["service"].as_u64().unwrap() as u32;
    let (mut process, mut thread) = fixture(WinArch::X86, "NtIsUILanguageComitted", service);
    let p = process.state_mut();
    let sp = thread.cpu.sp();
    let last_error =
        thread.teb + crate::user::windows::layout::offsets(WinArch::X86).teb_last_error;
    p.space.w32(last_error, 0x1234).unwrap();
    arguments(p, &mut thread, &[]);
    thread.cpu.set_gpr(0, u64::from(service));
    assert!(matches!(dispatch(p, &mut thread), Outcome::Fail(reason)
                     if reason.contains("commitment status is unavailable")));
    thread.cpu.set_sp(sp);
    let release: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-mui-query/wow64-release-ui-language.json"
    ))
    .unwrap();
    for row in [&profile, &release]
        .into_iter()
        .flat_map(|profile| profile["wow64_status"].as_array().unwrap())
    {
        let expected = row.as_u64().unwrap();
        let mut nls = Nls::new(vec![]).unwrap();
        nls.ui_language_commitment = Some(expected as u32);
        p.nls = Some(nls);
        arguments(p, &mut thread, &[]);
        thread.cpu.set_gpr(0, u64::from(service));
        assert_eq!(dispatch(p, &mut thread), Outcome::Continue);
        assert_eq!(thread.cpu.gpr(0), expected);
        assert_eq!(thread.cpu.sp(), sp + 4);
        assert_eq!(thread.cpu.pc(), 0x1234_0004);
        assert_eq!(p.space.u32(last_error).unwrap(), 0x1234);
        assert!(thread.frames.is_empty());
        thread.cpu.set_sp(sp);
    }
}

#[test]
fn native_mui_install_language_replays_wow64_word_and_guard_effects() {
    let preview: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-mui-query/installed-language-29708-arm64.json"
    ))
    .unwrap();
    let release: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-mui-query/wow64-release-ui-language.json"
    ))
    .unwrap();
    // Portable replay injects the service table. The installed leaf test
    // resolves each selected NTDLL's own service number and return sequence.
    let service = preview["guest_service"].as_u64().unwrap() as u32;
    assert_eq!(preview["argument_bytes"].as_u64().unwrap(), 4);
    replay_wow64_installed_ui_language(&preview, service, false);
    replay_wow64_installed_ui_language(&release, service, true);
}

fn replay_wow64_installed_ui_language(
    profile: &serde_json::Value,
    service: u32,
    guard_before_write_access: bool,
) {
    use crate::user::mm::PAGE_SIZE;
    use crate::user::windows::nls::{InstalledUiLanguage, Nls};

    let (mut process, mut thread) = fixture(WinArch::X86, "NtQueryInstallUILanguage", service);
    let p = process.state_mut();
    let sp = thread.cpu.sp();
    let error = thread.teb + crate::user::windows::layout::offsets(WinArch::X86).teb_last_error;
    let base =
        p.vm.allocate(
            None,
            PAGE_SIZE * 2,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    p.vm.protect(base + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
        .unwrap();
    let interior = base + 16;
    let edge = base + PAGE_SIZE - 1;

    arguments(p, &mut thread, &[interior]);
    thread.cpu.set_gpr(0, u64::from(service));
    assert!(matches!(dispatch(p, &mut thread), Outcome::Fail(reason)
                     if reason.contains("UI-language identifier is unavailable")));
    assert_eq!(p.space.u32(interior).unwrap(), 0);

    let mut nls = Nls::new(vec![]).unwrap();
    nls.installed_ui_language = Some(InstalledUiLanguage {
        id: profile["langid"].as_u64().unwrap().try_into().unwrap(),
        guard_before_write_access,
    });
    p.nls = Some(nls);
    let rows = profile["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 8);
    for row in rows {
        let case = row["case"].as_str().unwrap();
        if case != "write-guard-retry" {
            p.vm.protect(base, PAGE_SIZE, prot::READWRITE).unwrap();
            p.space.wr(interior, &[0xa5; 4]).unwrap();
            p.space.wr(edge - 3, &[0xa5; 4]).unwrap();
        }
        let (output, inspect, protection) = match case {
            "aligned" | "write-guard-retry" => (interior, interior, prot::READWRITE),
            "unaligned" => (interior + 1, interior, prot::READWRITE),
            "null" => (0, 0, 0),
            "readonly" => (interior, interior, prot::READONLY),
            "cross-page" => (edge, edge - 3, prot::READWRITE),
            "write-guard" => (interior, interior, prot::READWRITE | prot::GUARD),
            "readonly-guard" => (interior, interior, prot::READONLY | prot::GUARD),
            _ => panic!("unknown native pointer case {case}"),
        };
        if protection != 0 && case != "write-guard-retry" {
            p.vm.protect(base, PAGE_SIZE, protection).unwrap();
        }
        p.space
            .w32(
                error,
                row["last_error"].as_u64().unwrap().try_into().unwrap(),
            )
            .unwrap();
        thread.cpu.set_sp(sp);
        arguments(p, &mut thread, &[output]);
        thread.cpu.set_gpr(0, u64::from(service));
        assert_eq!(dispatch(p, &mut thread), Outcome::Continue, "{case}");
        assert_eq!(thread.cpu.gpr(0), row["status"].as_u64().unwrap(), "{case}");
        // This resumes inside NTDLL after the transition call. The installed
        // leaf subsequently executes RET 4 to pop its own argument.
        assert_eq!(thread.cpu.sp(), sp + 4, "{case}");
        assert_eq!(thread.cpu.pc(), 0x1234_0004, "{case}");
        assert_eq!(
            u64::from(p.space.u32(error).unwrap()),
            row["last_error"].as_u64().unwrap(),
            "{case}"
        );
        assert!(thread.frames.is_empty(), "{case}");
        if inspect != 0 {
            let after = p.vm.query(inspect).unwrap().protect;
            assert_eq!(
                u64::from(after),
                row["protection"].as_u64().unwrap(),
                "{case}"
            );
            if after & prot::GUARD == 0 {
                let expected: Vec<u8> = row["bytes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|byte| byte.as_u64().unwrap().try_into().unwrap())
                    .collect();
                assert_eq!(p.space.bytes(inspect, 4).unwrap(), expected, "{case}");
            }
        }
    }
}

#[cfg(all(windows, any(target_arch = "aarch64", target_arch = "x86_64")))]
#[test]
fn native_mui_installed_x86_leaves_use_selected_ui_language_snapshot() {
    use super::secure_connect_tests::installed::try_leaf;
    use crate::user::mm::PAGE_SIZE;
    use crate::user::windows::memory::Mem;
    use crate::user::windows::nt::status::*;
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDefaultUILanguage() -> u16;
    }

    let image =
        include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe");
    let mut config =
        WindowsConfig::embedded("C:\\native-wow64-mui.exe", vec![], vec![], 4096).unwrap();
    config.native_libraries = true;
    config.arena_bytes = 256 << 20;
    let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
    let p = process.state_mut();
    let state = p.wow64.as_ref().unwrap();
    let release = matches!(
        (state.machine, state.kernel),
        (0x8664, (10, 0, 20348 | 26100)) | (0xaa64, (10, 0, 26200))
    );
    let preview = (state.machine, state.kernel) == (0xaa64, (10, 0, 29708));
    let (commitment, language) = p.nls.as_ref().map_or((None, None), |nls| {
        (nls.ui_language_commitment, nls.installed_ui_language)
    });
    let (base, _) =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
    p.space.wr(base, &[0xa5; 4]).unwrap();
    let tid = *p.threads.keys().next().unwrap();
    let mut thread = p.threads.remove(&tid).unwrap();
    let commit = try_leaf(p, &mut thread, "NtIsUILanguageComitted", &[]);
    if !release && !preview {
        assert!(commitment.is_none() && language.is_none());
        assert!(commit.is_err());
        assert_eq!(p.space.bytes(base, 4).unwrap(), [0xa5; 4]);
        return;
    }
    assert_eq!(commit.unwrap(), commitment.unwrap());
    let language = language.unwrap();
    // SAFETY: this fixed system query takes no parameters and returns a LANGID.
    assert_eq!(language.id, unsafe { GetSystemDefaultUILanguage() });
    assert_eq!(language.guard_before_write_access, release);
    assert_eq!(
        try_leaf(p, &mut thread, "NtQueryInstallUILanguage", &[base + 1]).unwrap(),
        STATUS_SUCCESS
    );
    let [low, high] = language.id.to_le_bytes();
    assert_eq!(p.space.bytes(base, 4).unwrap(), [0xa5, low, high, 0xa5]);
    p.vm.protect(base, PAGE_SIZE, prot::READONLY | prot::GUARD)
        .unwrap();
    let (status, remaining) = if release {
        (STATUS_GUARD_PAGE_VIOLATION, prot::READONLY)
    } else {
        (STATUS_ACCESS_VIOLATION, prot::READONLY | prot::GUARD)
    };
    assert_eq!(
        try_leaf(p, &mut thread, "NtQueryInstallUILanguage", &[base + 1]).unwrap(),
        status
    );
    assert_eq!(p.vm.query(base).unwrap().protect, remaining);
    p.vm.protect(base, PAGE_SIZE, prot::READONLY).unwrap();
    assert_eq!(p.space.bytes(base, 4).unwrap(), [0xa5, low, high, 0xa5]);
}

#[test]
fn native_mui_query_replays_measured_builds_pointer_length_and_alias_rows() {
    let mut total = 0;
    let arm64_hosts = CORPORA.into_iter().flat_map(|(arch, raw)| {
        [29683, 29695, 29698, 29704, 29708].map(|build| (arch, raw, build, 0xAA64))
    });
    let amd64_hosts = AMD64_CORPORA
        .into_iter()
        .map(|(build, raw)| (WinArch::X64, raw, build, 0x8664));
    let arm64_26200 = [(WinArch::Arm64, ARM64_26200_CORPUS, 26200, 0xAA64)];
    for (arch, raw, build, machine) in arm64_hosts.chain(amd64_hosts).chain(arm64_26200) {
        let (mut process, mut thread) = fixture(arch, "NtGetMUIRegistryInfo", 0x12);
        let p = process.state_mut();
        p.object_namespace.native_machine = Some(machine);
        Arc::make_mut(&mut p.cfg).version.build = build;
        let base =
            p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        p.vm.protect(base + 4096, 4096, prot::NOACCESS).unwrap();
        p.vm.protect(base + 12288, 4096, prot::NOACCESS).unwrap();
        let output_base = base + 8192;
        // Payload contents are synthetic. Native rows independently determine
        // size, result, destination effects and ordering; no desktop data is used.
        let mut payload = vec![0x53; 1232];
        payload[..4].copy_from_slice(&1024u32.to_le_bytes());
        p.nls = Some(
            crate::user::windows::nls::Nls::new(vec![])
                .unwrap()
                .with_mui(payload.clone())
                .unwrap(),
        );
        let error = thread.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
        let mut count = 0;
        let call_sp = thread.cpu.sp();
        for line in raw.lines().filter(|line| line.starts_with("row ")) {
            let flags = field(line, "flags", 16);
            let size_kind = field(line, "size-kind", 10);
            let output_kind = field(line, "output-kind", 10);
            let length = field(line, "length", 10);
            p.vm.protect(base, 4096, prot::READWRITE).unwrap();
            p.vm.protect(output_base, 4096, prot::READWRITE).unwrap();
            p.space.wr(base, &[0xa5; 4096]).unwrap();
            p.space.wr(output_base, &[0xa5; 4096]).unwrap();
            let size = match size_kind {
                0 | 4 => base + 128,
                1 => 0,
                2 => 1,
                3 => base + 129,
                5 => base + 4096,
                6 => base + 4094,
                _ => panic!("unknown size pointer class"),
            };
            if matches!(size_kind, 0 | 3 | 4) {
                p.space.w32(size, length).unwrap();
            } else if size_kind == 6 {
                p.space.w16(size, length as u16).unwrap();
            }
            let output = match output_kind {
                0 | 7 => output_base + 64,
                1 => 0,
                2 => 1,
                3 => output_base + 65,
                4 => output_base + 4096,
                5 => output_base + 4080,
                6 => size,
                _ => panic!("unknown output pointer class"),
            };
            if size_kind == 4 {
                p.vm.protect(base, 4096, prot::READONLY).unwrap();
            }
            if output_kind == 7 {
                p.vm.protect(output_base, 4096, prot::READONLY).unwrap();
            }
            p.space.w32(error, 0x1234_5678).unwrap();
            // Each row is an independent call from the same native caller.
            // The synthetic WoW64 return consumes its supplied call frame.
            thread.cpu.set_sp(call_sp);
            arguments(p, &mut thread, &[u64::from(flags), size, output]);
            assert_eq!(
                dispatch(p, &mut thread),
                Outcome::Continue,
                "{arch} build {build}: {line}"
            );
            assert_eq!(
                thread.cpu.gpr(0),
                u64::from(field(line, "status", 16)),
                "{arch} build {build}: {line}"
            );
            let after = if matches!(size_kind, 0 | 3 | 4) {
                p.space.u32(size).unwrap()
            } else if size_kind == 6 {
                u32::from(p.space.u16(size).unwrap())
            } else {
                0
            };
            assert_eq!(
                after,
                field(line, "size-after", 10),
                "{arch} build {build}: {line}"
            );
            let output_page = p.space.bytes(output_base, 4096).unwrap();
            assert_eq!(
                output_page.iter().filter(|&&byte| byte != 0xa5).count(),
                field(line, "output-changed", 10) as usize,
                "{arch} build {build}: {line}"
            );
            assert_eq!(
                p.space.u32(error).unwrap(),
                field(line, "last-error", 16),
                "{arch} build {build}: {line}"
            );
            if thread.cpu.gpr(0) == 0 && output != 0 {
                assert_eq!(
                    p.space.bytes(output, payload.len()).unwrap(),
                    payload,
                    "{arch} build {build}: {line}"
                );
                assert!(
                    p.space
                        .bytes(
                            output + payload.len() as u64,
                            length as usize - payload.len()
                        )
                        .unwrap()
                        .iter()
                        .all(|&byte| byte == 0)
                );
            }
            count += 1;
        }
        assert_eq!(count, 1680);
        total += count;
    }
    assert_eq!(total, 30240);
}

#[test]
fn mui_cache_mutations_report_unavailable_without_query_argument_side_effects() {
    let legacy_hosts = WinArch::ALL
        .into_iter()
        .flat_map(|arch| [29683, 29695, 29698, 29704, 29708].map(|build| (arch, build, 0xAA64)));
    let probe_hosts = [
        (WinArch::X64, 20348, 0x8664),
        (WinArch::X64, 26100, 0x8664),
        (WinArch::Arm64, 26200, 0xAA64),
    ];
    for (arch, build, machine) in legacy_hosts.chain(probe_hosts) {
        let (mut process, mut thread) = fixture(arch, "NtGetMUIRegistryInfo", 0x12);
        let p = process.state_mut();
        p.object_namespace.native_machine = Some(machine);
        Arc::make_mut(&mut p.cfg).version.build = build;
        let sp = thread.cpu.sp();
        let before = p.vm.committed_bytes();
        for flags in [2, 3, 8, 9, 10, 11] {
            for size in [0, 1] {
                thread.cpu.set_sp(sp);
                arguments(p, &mut thread, &[flags, size, 1]);
                let result = dispatch(p, &mut thread);
                assert!(
                    matches!(result, Outcome::Fail(ref reason) if reason.contains("cache clear/commit is not implemented")),
                    "{arch}: {result:?}"
                );
                assert_eq!(p.vm.committed_bytes(), before);
            }
        }
    }
}

#[test]
fn mui_unmeasured_profiles_publish_no_size_or_payload() {
    for arch in WinArch::ALL {
        for (major, minor, build, machine) in [
            (10, 0, 29682, Some(0xAA64)),
            (10, 0, 29684, Some(0xAA64)),
            (10, 0, 29694, Some(0xAA64)),
            (10, 0, 29696, Some(0xAA64)),
            (10, 0, 29697, Some(0xAA64)),
            (10, 0, 29699, Some(0xAA64)),
            (10, 0, 29703, Some(0xAA64)),
            (10, 0, 29705, Some(0xAA64)),
            (10, 0, 29707, Some(0xAA64)),
            (10, 0, 29709, Some(0xAA64)),
            (10, 1, 29708, Some(0xAA64)),
            (11, 0, 29708, Some(0xAA64)),
            (10, 0, 29708, None),
            (10, 0, 29708, Some(0x8664)),
            (10, 0, 29708, Some(0x14C)),
            (10, 1, 29704, Some(0xAA64)),
            (11, 0, 29704, Some(0xAA64)),
            (10, 0, 29704, None),
            (10, 0, 29704, Some(0x8664)),
            (10, 0, 29704, Some(0x14C)),
            (10, 1, 29695, Some(0xAA64)),
            (11, 0, 29695, Some(0xAA64)),
            (10, 1, 29698, Some(0xAA64)),
            (11, 0, 29698, Some(0xAA64)),
            (10, 0, 29698, None),
            (10, 0, 29698, Some(0x8664)),
            (10, 0, 29698, Some(0x14C)),
        ] {
            let (mut process, mut thread) = fixture(arch, "NtGetMUIRegistryInfo", 0x12);
            let p = process.state_mut();
            p.object_namespace.native_machine = machine;
            let cfg = Arc::make_mut(&mut p.cfg);
            cfg.version.major = major;
            cfg.version.minor = minor;
            cfg.version.build = build;
            let base =
                p.vm.allocate(None, 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            p.space.wr(base, &[0xa5; 4096]).unwrap();
            p.space.w32(base + 128, 1232).unwrap();
            p.nls = Some(
                crate::user::windows::nls::Nls::new(vec![])
                    .unwrap()
                    .with_mui(vec![0x53; 1232])
                    .unwrap(),
            );
            let before = p.space.bytes(base, 4096).unwrap();
            let charge = p.vm.committed_bytes();
            arguments(p, &mut thread, &[0, base + 128, base + 256]);
            assert!(
                matches!(dispatch(p, &mut thread), Outcome::Fail(ref reason) if reason.contains("native build profile is unmeasured"))
            );
            assert_eq!(p.space.bytes(base, 4096).unwrap(), before);
            assert_eq!(p.vm.committed_bytes(), charge);
        }
    }
}
