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
