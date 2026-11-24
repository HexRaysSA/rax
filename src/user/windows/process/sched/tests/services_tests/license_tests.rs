use super::{Outcome, Proc, Thread, handle_stop, native_profile, stop, terminal_fixture};
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::loader::services::tests::named_table;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::policy::{Catalog, DEVICE_FAMILY_NAME};
use std::sync::Arc;

const SERVICE: u32 = 0x160;

fn call(p: &mut Proc, t: &mut Thread, args: [u64; 5]) -> u32 {
    let stack = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    for (register, value) in args.into_iter().enumerate() {
        t.cpu.set_gpr(register, value);
    }
    assert_eq!(
        handle_stop(p, t, stop(WinArch::Arm64, SERVICE)),
        Outcome::Continue
    );
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), stack);
    assert!(t.frames.is_empty());
    t.cpu.gpr(0) as u32
}

#[test]
fn native_device_family_uses_the_captured_dword_and_native_output_lengths() {
    let (mut process, mut thread, module) = terminal_fixture(WinArch::Arm64);
    let p = process.state_mut();
    p.modules.nt_services = Some((
        module,
        named_table(WinArch::Arm64, "NtQueryLicenseValue", SERVICE),
    ));
    native_profile::kernel_profile(p, 29708, 0xaa64);
    let value = [0x78, 0x56, 0x34, 0x12];
    p.native.as_mut().unwrap().policy_catalog = Ok(Arc::new(Catalog::fixture([(
        DEVICE_FAMILY_NAME,
        4,
        value.to_vec(),
    )])));
    let (base, _) =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
    let (name, data, kind, required) = (base + 64, base + 128, base + 256, base + 264);
    let units: Vec<_> = DEVICE_FAMILY_NAME.encode_utf16().collect();
    let bytes = 2 * units.len() as u16;
    p.space.w16(base, bytes).unwrap();
    p.space.w16(base + 2, bytes + 2).unwrap();
    p.space.w64(base + 8, name).unwrap();
    p.space.put_wunits(name, &units).unwrap();

    for capacity in [0, 1, 3, 4, 8] {
        p.space.wr(data, &[0xa5; 8]).unwrap();
        p.space.w32(kind, 0xa5a5a5a5).unwrap();
        p.space.w32(required, 0x5a5a5a5a).unwrap();
        let status = call(
            p,
            &mut thread,
            [
                base,
                kind,
                if capacity == 0 { 0 } else { data },
                capacity,
                required,
            ],
        );
        let mut expected = [0xa5; 8];
        if capacity >= 4 {
            expected[..4].copy_from_slice(&value);
            assert_eq!(status, STATUS_SUCCESS);
        } else {
            assert_eq!(status, STATUS_BUFFER_TOO_SMALL);
        }
        assert_eq!(p.space.bytes(data, 8).unwrap(), expected);
        assert_eq!(p.space.u32(kind).unwrap(), 4);
        assert_eq!(p.space.u32(required).unwrap(), 4);
    }

    assert_eq!(
        call(p, &mut thread, [base, 0, required, 4, required]),
        STATUS_SUCCESS
    );
    assert_eq!(p.space.bytes(required, 4).unwrap(), value);

    for (output, length) in [(0, required), (data, 0)] {
        p.space.w32(kind, 0xa5a5a5a5).unwrap();
        p.space.w32(required, 0x5a5a5a5a).unwrap();
        assert_eq!(
            call(p, &mut thread, [base, kind, output, 4, length]),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(p.space.u32(kind).unwrap(), 0xa5a5a5a5);
        assert_eq!(p.space.u32(required).unwrap(), 0x5a5a5a5a);
    }

    p.space.w16(name, u16::from(b'k')).unwrap();
    p.space.wr(data, &[0xa5; 8]).unwrap();
    assert_eq!(
        call(p, &mut thread, [base, kind, data, 4, required]),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(p.space.u32(required).unwrap(), 0);
    assert_eq!(p.space.u32(kind).unwrap(), 0xa5a5a5a5);
    assert_eq!(p.space.bytes(data, 8).unwrap(), [0xa5; 8]);
}

#[test]
fn native_startup_license_replays_the_installed_remote_desktop_policy() {
    #[derive(serde::Deserialize)]
    struct Fixture {
        build: u32,
        machine: u16,
        observations: std::collections::BTreeMap<String, Observation>,
    }

    #[derive(serde::Deserialize)]
    struct Observation {
        status: u32,
        kind: u32,
        returned: u32,
        output: String,
    }

    use crate::user::windows::policy::APP_SERVER_MODE_NAME;

    let evidence: Fixture = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-startup-license/remote-desktop-policy-29708-arm64.json"
    ))
    .unwrap();
    assert_eq!(evidence.observations.len(), 9);
    let (mut process, mut thread, module) = terminal_fixture(WinArch::Arm64);
    let p = process.state_mut();
    p.modules.nt_services = Some((
        module,
        named_table(WinArch::Arm64, "NtQueryLicenseValue", SERVICE),
    ));
    native_profile::kernel_profile(p, evidence.build, evidence.machine);
    p.native.as_mut().unwrap().policy_catalog = Ok(Arc::new(Catalog::fixture([(
        APP_SERVER_MODE_NAME,
        4,
        [0; 4].to_vec(),
    )])));
    let (base, _) =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
    let (name, data, kind, required) = (base + 64, base + 192, base + 224, base + 232);
    for (case, row) in evidence.observations {
        let value = if case == "lower" {
            APP_SERVER_MODE_NAME.to_ascii_lowercase()
        } else {
            APP_SERVER_MODE_NAME.to_owned()
        };
        let units: Vec<_> = value.encode_utf16().collect();
        let length = 2 * units.len() as u16;
        p.space.w16(base, length).unwrap();
        p.space.w16(base + 2, length + 2).unwrap();
        p.space.w64(base + 8, name).unwrap();
        p.space.put_wunits(name, &units).unwrap();
        p.space.wr(data, &[0xA5; 16]).unwrap();
        p.space.w32(kind, 0xB6B6_B6B6).unwrap();
        p.space.w32(required, 0xC7C7_C7C7).unwrap();
        let status = call(
            p,
            &mut thread,
            [
                base,
                if case == "absent_kind" { 0 } else { kind },
                if matches!(case.as_str(), "0" | "absent_data") {
                    0
                } else {
                    data
                },
                case.parse().unwrap_or(4),
                if case == "absent_result" { 0 } else { required },
            ],
        );
        assert_eq!(status, row.status, "{case}");
        assert_eq!(p.space.u32(kind).unwrap(), row.kind, "{case}");
        assert_eq!(p.space.u32(required).unwrap(), row.returned, "{case}");
        let bytes = p.space.bytes(data, 16).unwrap();
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, row.output, "{case}");
    }
}

#[test]
fn amd64_startup_license_replays_the_native64_queries_on_windows_arm() {
    use crate::user::windows::policy::APP_SERVER_MODE_NAME;

    #[derive(serde::Deserialize)]
    struct Capture {
        build: u32,
        machine: u16,
        named_queries: Vec<String>,
        rows: Vec<[u32; 8]>,
    }

    let capture: Capture = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-startup-license/native64-29708-arm64.json"
    ))
    .unwrap();
    let names = [DEVICE_FAMILY_NAME, APP_SERVER_MODE_NAME];
    assert_eq!(capture.named_queries, names);
    assert_eq!(capture.rows.len(), 16);
    let (mut process, mut thread, module) = terminal_fixture(WinArch::X64);
    let p = process.state_mut();
    p.modules.nt_services = Some((
        module,
        named_table(WinArch::X64, "NtQueryLicenseValue", SERVICE),
    ));
    native_profile::kernel_profile(p, capture.build, capture.machine);
    let values = names.into_iter().enumerate().map(|(idx, name)| {
        let row = capture
            .rows
            .iter()
            .find(|row| row[..4] == [idx as u32, 4, 1, STATUS_SUCCESS])
            .unwrap();
        (name, 4, row[6].to_le_bytes().to_vec())
    });
    p.native.as_mut().unwrap().policy_catalog = Ok(Arc::new(Catalog::fixture(values)));

    let (base, _) =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
    let (name, data, kind, required) = (base + 16, base + 160, base + 192, base + 200);
    let stack = thread.cpu.sp();
    for [
        index,
        capacity,
        has_type,
        status,
        value_kind,
        size,
        first,
        second,
    ] in capture.rows
    {
        let units: Vec<_> = names[index as usize].encode_utf16().collect();
        let length = 2 * units.len() as u16;
        p.space.w16(base, length).unwrap();
        p.space.w16(base + 2, length + 2).unwrap();
        p.space.w64(base + 8, name).unwrap();
        p.space.put_wunits(name, &units).unwrap();
        p.space.w32(data, 0x1122_3344).unwrap();
        p.space.w32(data + 4, 0x5566_7788).unwrap();
        p.space.w32(kind, 0xA5A5_A5A5).unwrap();
        p.space.w32(required, 0x5A5A_5A5A).unwrap();

        thread.cpu.set_pc(0x1234_0004);
        thread.cpu.set_gpr(0, SERVICE.into());
        thread.cpu.set_gpr(1, 0x1234_0004);
        thread.cpu.set_gpr(10, base);
        thread.cpu.set_gpr(2, if has_type == 0 { 0 } else { kind });
        thread.cpu.set_gpr(8, if capacity == 0 { 0 } else { data });
        thread.cpu.set_gpr(9, capacity.into());
        p.space.w64(stack + 0x28, required).unwrap();
        assert_eq!(
            handle_stop(p, &mut thread, stop(WinArch::X64, SERVICE)),
            Outcome::Continue
        );
        assert_eq!(thread.cpu.pc(), 0x1234_0004);
        assert_eq!(thread.cpu.sp(), stack);
        assert!(thread.frames.is_empty());
        assert_eq!(thread.cpu.gpr(0) as u32, status);
        assert_eq!(p.space.u32(kind).unwrap(), value_kind);
        assert_eq!(p.space.u32(required).unwrap(), size);
        assert_eq!(p.space.u32(data).unwrap(), first);
        assert_eq!(p.space.u32(data + 4).unwrap(), second);
    }

    native_profile::kernel_profile(p, capture.build, 0x8664);
    thread.cpu.set_gpr(0, SERVICE.into());
    assert!(matches!(
        handle_stop(p, &mut thread, stop(WinArch::X64, SERVICE)),
        Outcome::Fail(reason) if reason.contains("unmeasured NtQueryLicenseValue profile")
    ));
}

#[test]
fn native_startup_license_replays_measured_release_builds() {
    use crate::user::windows::policy::APP_SERVER_MODE_NAME;

    #[derive(serde::Deserialize)]
    struct Capture {
        kernel: [u32; 3],
        machine: u16,
        rows: Vec<Query>,
    }

    #[derive(serde::Deserialize)]
    struct Query {
        name: String,
        length: u16,
        maximum: u16,
        capacity: u32,
        null_data: bool,
        has_type: bool,
        status: u32,
        kind: u32,
        required: u32,
        storage: String,
    }

    let captures = [
        (
            WinArch::X64,
            0x8664,
            20348,
            include_str!(
                "../../../../../../../docs/specifications/windows/native-startup-license/amd64-20348-native.json"
            ),
        ),
        (
            WinArch::X64,
            0x8664,
            26100,
            include_str!(
                "../../../../../../../docs/specifications/windows/native-startup-license/amd64-26100-native.json"
            ),
        ),
        (
            WinArch::Arm64,
            0xaa64,
            26200,
            include_str!(
                "../../../../../../../docs/specifications/windows/native-startup-license/arm64-26200-native.json"
            ),
        ),
    ];
    let decode_hex = |hex: &str| {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
    };

    for (arch, machine, build, source) in captures {
        let capture: Capture = serde_json::from_str(source).unwrap();
        assert_eq!(capture.kernel, [10, 0, build]);
        assert_eq!(capture.machine, machine);
        assert_eq!(capture.rows.len(), 80);
        let values = [DEVICE_FAMILY_NAME, APP_SERVER_MODE_NAME].map(|name| {
            let row = capture
                .rows
                .iter()
                .find(|row| row.name == name && row.capacity == 4 && row.has_type)
                .unwrap();
            assert_eq!(row.status, STATUS_SUCCESS);
            assert_eq!(row.kind, 4);
            assert_eq!(row.required, 4);
            (name, 4, decode_hex(&row.storage)[4..8].to_vec())
        });

        let (mut process, mut thread, module) = terminal_fixture(arch);
        let p = process.state_mut();
        p.modules.nt_services = Some((module, named_table(arch, "NtQueryLicenseValue", SERVICE)));
        native_profile::kernel_profile(p, build, capture.machine);
        p.native.as_mut().unwrap().policy_catalog = Ok(Arc::new(Catalog::fixture(values)));
        let (base, _) =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap();
        let (name, storage, kind, required) = (base + 16, base + 160, base + 192, base + 200);
        let stack = thread.cpu.sp();

        for row in capture.rows {
            let units: Vec<_> = row.name.encode_utf16().chain(Some(0)).collect();
            assert_eq!(row.length as usize, 2 * (units.len() - 1));
            p.space.w16(base, row.length).unwrap();
            p.space.w16(base + 2, row.maximum).unwrap();
            p.space.w64(base + 8, name).unwrap();
            p.space.put_wunits(name, &units).unwrap();
            p.space.wr(storage, b"ABCDEFGHIJKLMNOPQRSTUVWX").unwrap();
            p.space.w32(kind, 0xA5A5_A5A5).unwrap();
            p.space.w32(required, 0x5A5A_5A5A).unwrap();

            let args = [
                base,
                if row.has_type { kind } else { 0 },
                if row.null_data { 0 } else { storage + 4 },
                row.capacity.into(),
                required,
            ];
            let status = if arch == WinArch::Arm64 {
                call(p, &mut thread, args)
            } else {
                super::nls_tests::arguments(p, &mut thread, &args);
                thread.cpu.set_gpr(0, u64::from(SERVICE));
                assert_eq!(
                    handle_stop(p, &mut thread, stop(arch, SERVICE)),
                    Outcome::Continue
                );
                assert_eq!(thread.cpu.pc(), 0x1234_0004);
                assert_eq!(thread.cpu.sp(), stack);
                assert!(thread.frames.is_empty());
                thread.cpu.gpr(0) as u32
            };
            let case = (build, row.name.as_str(), row.maximum, row.capacity);
            assert_eq!(status, row.status, "{case:?}");
            assert_eq!(p.space.u32(kind).unwrap(), row.kind, "{case:?}");
            assert_eq!(p.space.u32(required).unwrap(), row.required, "{case:?}");
            assert_eq!(
                p.space.bytes(storage, 24).unwrap(),
                decode_hex(&row.storage),
                "{case:?}"
            );
        }
    }
}

#[test]
fn wow64_startup_license_replays_the_observed_stock_cmd_queries() {
    use crate::user::windows::policy::{APP_SERVER_MODE_NAME, WOW64_STARTUP_NAMES};
    use crate::user::windows::process::wow64;

    #[derive(serde::Deserialize)]
    struct Query {
        name: String,
        capacity: u32,
        status: u32,
        size: u32,
        kind: Option<u32>,
        data_hex: Option<String>,
    }

    let evidence: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-startup-license/wow64-cmd-29708-arm64.json"
    ))
    .unwrap();
    let queries: Vec<Query> = serde_json::from_value(evidence["queries"].clone()).unwrap();
    assert_eq!(queries.len(), 11);
    let decode = |raw: &str| {
        (0..raw.len())
            .step_by(2)
            .map(|start| u8::from_str_radix(&raw[start..start + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    let rows = queries.iter().filter_map(|row| {
        let data = decode(row.data_hex.as_deref()?);
        let name = WOW64_STARTUP_NAMES
            .iter()
            .map(|&(name, _)| name)
            .chain([APP_SERVER_MODE_NAME])
            .find(|&name| name == row.name)
            .unwrap();
        Some((name, row.kind.unwrap(), data))
    });
    let (mut process, mut thread) = super::fixture(WinArch::X86, "NtQueryLicenseValue", SERVICE);
    let p = process.state_mut();
    native_profile::kernel_profile(p, 29708, 0xaa64);
    Arc::make_mut(&mut p.cfg).version.build = 29708;
    wow64::initialize_test_profile(p, 0xaa64).unwrap();
    Arc::make_mut(&mut p.cfg).version.build = 12345;
    p.wow64.as_mut().unwrap().session = 1;
    p.native.as_mut().unwrap().policy_catalog = Ok(Arc::new(Catalog::fixture(rows)));
    let (base, _) =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
    let (name, data, kind, required) = (base, base + 128, base + 1024, base + 1028);
    let descriptor = base + PAGE_SIZE - 8;
    for row in queries {
        let units: Vec<_> = row.name.encode_utf16().collect();
        let length = 2 * units.len() as u16;
        p.space.w16(descriptor, length).unwrap();
        p.space.w16(descriptor + 2, length + 2).unwrap();
        p.space.w32(descriptor + 4, name as u32).unwrap();
        p.space.put_wunits(name, &units).unwrap();
        p.space.wr(data, &[0xa5; 800]).unwrap();
        p.space.w32(kind, u32::MAX).unwrap();
        p.space.w32(required, u32::MAX).unwrap();
        let args = [
            descriptor,
            kind,
            if row.capacity == 0 { 0 } else { data },
            row.capacity.into(),
            required,
        ];
        let sp = thread.cpu.sp();
        super::nls_tests::arguments(p, &mut thread, &args);
        thread.cpu.set_gpr(0, SERVICE.into());
        assert_eq!(
            super::nls_tests::dispatch(p, &mut thread),
            Outcome::Continue
        );
        assert_eq!(thread.cpu.pc(), 0x1234_0004);
        assert_eq!(thread.cpu.sp(), sp + 4);
        thread.cpu.set_sp(sp);
        assert_eq!(thread.cpu.gpr(0), u64::from(row.status), "{}", row.name);
        assert_eq!(p.space.u32(kind).unwrap(), row.kind.unwrap_or(u32::MAX));
        assert_eq!(p.space.u32(required).unwrap(), row.size);
        let expected = row.data_hex.as_deref().map_or_else(Vec::new, decode);
        assert_eq!(p.space.bytes(data, expected.len()).unwrap(), expected);
        assert_eq!(p.space.u8(data + expected.len() as u64).unwrap(), 0xa5);
    }
}

#[test]
fn wow64_startup_license_replays_measured_builds_and_sessions() {
    use crate::user::windows::policy::{APP_SERVER_MODE_NAME, WOW64_STARTUP_NAMES};
    use crate::user::windows::process::wow64;

    #[derive(serde::Deserialize)]
    struct Capture {
        build: u32,
        machine: u16,
        rows: usize,
        values: std::collections::BTreeMap<String, String>,
        #[serde(default)]
        clears_length_for_missing: Vec<String>,
    }

    #[derive(serde::Deserialize)]
    struct SessionCapture {
        #[serde(flatten)]
        profile: Capture,
        sessions: [u32; 2],
    }

    const GUARD: u64 = 8;
    const CAPACITY: u32 = 1024;
    const UNCHANGED_KIND: u32 = 0xA5A5_A5A5;
    const UNCHANGED_LENGTH: u32 = 0x5A5A_5A5A;
    let input = include_str!(
        "../../../../../../../docs/specifications/windows/native-startup-license/wow64-release-profiles.json"
    );
    let profiles: Vec<Capture> = serde_json::from_str(input).unwrap();
    assert_eq!(
        profiles
            .iter()
            .map(|row| (row.build, row.machine))
            .collect::<Vec<_>>(),
        [(20348, 0x8664), (26100, 0x8664), (26200, 0xaa64)]
    );
    let arm64_29708: SessionCapture = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-startup-license/wow64-29708-arm64-sessions.json"
    ))
    .unwrap();
    assert_eq!(
        (arm64_29708.profile.build, arm64_29708.profile.machine),
        (29708, 0xaa64)
    );
    assert_eq!(arm64_29708.sessions, [0, 1]);

    let initial: Vec<_> = (0..CAPACITY + 2 * GUARD as u32)
        .map(|index| b'A' + (index % 26) as u8)
        .collect();
    let names = [
        (DEVICE_FAMILY_NAME, Some(4)),
        (APP_SERVER_MODE_NAME, Some(4)),
    ]
    .into_iter()
    .chain(WOW64_STARTUP_NAMES);

    let profiles = profiles.iter().map(|profile| (profile, None)).chain(
        arm64_29708
            .sessions
            .into_iter()
            .map(|session| (&arm64_29708.profile, Some(session))),
    );
    for (profile, session) in profiles {
        let values: std::collections::BTreeMap<_, _> = names
            .clone()
            .filter_map(|(name, kind)| {
                let kind = kind?;
                let raw = &profile.values[name];
                let bytes = raw
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(bytes.len() * 2, raw.len());
                Some((name, (kind, bytes)))
            })
            .collect();
        assert_eq!(profile.values.len(), values.len());
        let (mut process, mut thread) =
            super::fixture(WinArch::X86, "NtQueryLicenseValue", SERVICE);
        let p = process.state_mut();
        native_profile::kernel_profile(p, profile.build, profile.machine);
        Arc::make_mut(&mut p.cfg).version.build = profile.build;
        wow64::initialize_test_profile(p, profile.machine).unwrap();
        if let Some(session) = session {
            p.wow64.as_mut().unwrap().session = session;
        }
        // The guest version can differ from the installed kernel captured by the loader.
        Arc::make_mut(&mut p.cfg).version.build = 12345;
        p.native.as_mut().unwrap().policy_catalog =
            Ok(Arc::new(Catalog::fixture(values.iter().map(
                |(&name, (kind, bytes))| (name, *kind, bytes.clone()),
            ))));
        let (base, _) =
            p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap();
        let (name, storage, kind, required) = (base, base + 128, base + 1280, base + 1284);
        let descriptor = base + PAGE_SIZE - 8;
        let stack = thread.cpu.sp();
        let mut count = 0;
        for (selected, value_kind) in names.clone() {
            let value = values.get(selected).map(|(_, bytes)| bytes.as_slice());
            let lowercase = selected.to_ascii_lowercase();
            for spelling in [selected, lowercase.as_str()] {
                let units: Vec<_> = spelling.encode_utf16().chain(Some(0)).collect();
                let length = 2 * (units.len() - 1) as u16;
                p.space.w16(descriptor, length).unwrap();
                p.space.w32(descriptor + 4, name as u32).unwrap();
                p.space.put_wunits(name, &units).unwrap();
                for maximum in [length, length + 2] {
                    p.space.w16(descriptor + 2, maximum).unwrap();
                    for (capacity, null_data) in [
                        (0, true),
                        (0, false),
                        (3, false),
                        (4, false),
                        (12, false),
                        (16, false),
                        (770, false),
                        (CAPACITY, false),
                    ] {
                        for has_type in [false, true] {
                            count += 1;
                            p.space.wr(storage, &initial).unwrap();
                            p.space.w32(kind, UNCHANGED_KIND).unwrap();
                            p.space.w32(required, UNCHANGED_LENGTH).unwrap();
                            let args = [
                                descriptor,
                                if has_type { kind } else { 0 },
                                if null_data { 0 } else { storage + GUARD },
                                capacity.into(),
                                required,
                            ];
                            super::nls_tests::arguments(p, &mut thread, &args);
                            thread.cpu.set_gpr(0, SERVICE.into());
                            assert_eq!(
                                super::nls_tests::dispatch(p, &mut thread),
                                Outcome::Continue
                            );
                            assert_eq!(thread.cpu.pc(), 0x1234_0004);
                            assert_eq!(thread.cpu.sp(), stack + 4);
                            thread.cpu.set_sp(stack);
                            let mut expected = initial.clone();
                            let (status, length, output_kind) = match value {
                                Some(value) if spelling == selected => {
                                    let kind = if has_type {
                                        value_kind.unwrap()
                                    } else {
                                        UNCHANGED_KIND
                                    };
                                    let size = value.len() as u32;
                                    let status = if capacity >= size {
                                        let start = GUARD as usize;
                                        expected[start..start + value.len()].copy_from_slice(value);
                                        STATUS_SUCCESS
                                    } else {
                                        STATUS_BUFFER_TOO_SMALL
                                    };
                                    (status, size, kind)
                                }
                                _ => (
                                    STATUS_OBJECT_NAME_NOT_FOUND,
                                    if profile
                                        .clears_length_for_missing
                                        .iter()
                                        .any(|name| name == spelling)
                                    {
                                        0
                                    } else {
                                        UNCHANGED_LENGTH
                                    },
                                    UNCHANGED_KIND,
                                ),
                            };
                            let case = (
                                profile.build,
                                session,
                                spelling,
                                maximum,
                                capacity,
                                null_data,
                                has_type,
                            );
                            assert_eq!(thread.cpu.gpr(0), u64::from(status), "{case:?}");
                            assert_eq!(p.space.u32(required).unwrap(), length, "{case:?}");
                            assert_eq!(p.space.u32(kind).unwrap(), output_kind, "{case:?}");
                            assert_eq!(
                                p.space.bytes(storage, initial.len()).unwrap(),
                                expected,
                                "{case:?}"
                            );
                        }
                    }
                }
            }
        }
        assert_eq!(count, profile.rows);

        // The installed catalog alone cannot qualify stale metadata or an unmeasured session.
        let reject = |p: &mut Proc, thread: &mut Thread| {
            p.space.wr(storage, &initial).unwrap();
            p.space.w32(kind, UNCHANGED_KIND).unwrap();
            p.space.w32(required, UNCHANGED_LENGTH).unwrap();
            super::nls_tests::arguments(
                p,
                thread,
                &[descriptor, kind, storage + GUARD, 4, required],
            );
            thread.cpu.set_gpr(0, SERVICE.into());
            assert!(matches!(
                super::nls_tests::dispatch(p, thread),
                Outcome::Fail(reason) if reason.contains("unmeasured NtQueryLicenseValue profile")
            ));
            assert_eq!(p.space.u32(required).unwrap(), UNCHANGED_LENGTH);
            assert_eq!(p.space.u32(kind).unwrap(), UNCHANGED_KIND);
            assert_eq!(p.space.bytes(storage, initial.len()).unwrap(), initial);
        };
        p.wow64.as_mut().unwrap().kernel.2 += 1;
        reject(p, &mut thread);
        if session.is_some() {
            let state = p.wow64.as_mut().unwrap();
            state.kernel.2 -= 1;
            state.session = 2;
            reject(p, &mut thread);
        }
    }
}
