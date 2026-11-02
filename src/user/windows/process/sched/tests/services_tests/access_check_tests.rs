//! Replays captured native return values, outputs, aliases and protections.
use super::*;
use crate::user::windows::nt::status::*;
use crate::user::windows::process::{WindowsConfig, WindowsProcess};
use crate::user::windows::security::{Group, Privilege, Subject};
use std::sync::{Arc, OnceLock};

fn data() -> &'static serde_json::Value {
    static DATA: OnceLock<serde_json::Value> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../../../docs/specifications/windows/native-access-check/cases.json"
        ))
        .unwrap()
    })
}

fn hex(text: &str) -> Vec<u8> {
    crate::user::windows::wnf::tests::hex(text)
}

fn subject_fixture() -> Subject {
    let s = &data()["subject"];
    let groups = |name: &str| {
        s[name]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| Group {
                sid: hex(g["sid"].as_str().unwrap()),
                attributes: g["attributes"].as_u64().unwrap() as u32,
            })
            .collect()
    };
    Subject {
        statistics: None,
        attributes: None,
        user_attributes: 0,
        user: hex(s["user"]["sid"].as_str().unwrap()),
        groups: groups("groups"),
        restricted: groups("restricted"),
        app_container: s["app-container"].as_u64().unwrap() != 0,
        privileges: s["privileges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| Privilege {
                luid: p["luid"].as_u64().unwrap(),
                attributes: p["attributes"].as_u64().unwrap() as u32,
            })
            .collect(),
    }
}

fn setup(arch: WinArch, laa: bool, native: bool) -> (WindowsProcess, Thread, u64, [u64; 4]) {
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
    let mut cfg = WindowsConfig::embedded("C:\\access-check.exe", vec![], vec![], 4096).unwrap();
    cfg.arena_bytes = 64 << 20;
    cfg.native_libraries = native;
    let mut process = WindowsProcess::spawn_image(cfg, image).unwrap();
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut thread = p.threads.remove(&tid).unwrap();
    thread.attached = true;
    thread.main = false;
    // Eight x64 arguments occupy [SP+8, SP+72). Leave the caller's argument
    // storage inside its stack instead of overwriting an adjacent allocation.
    thread
        .cpu
        .set_sp(thread.cpu.sp().checked_sub(0x100).unwrap());
    if native {
        assert!(
            p.objects
                .primary_token_subject()
                .unwrap()
                .attributes
                .is_some()
        );
        #[cfg(windows)]
        {
            let actual = p.objects.primary_token_subject().unwrap();
            let mut expected = native_host_profile::primary_token_subject();
            // Attribute contents retain their separate byte/ownership suite;
            // compare all other live fields without printing private host SIDs.
            expected.attributes = actual.attributes.clone();
            assert!(
                actual.as_ref() == &expected,
                "captured token subject differs from independent typed Win32 controls"
            );
        }
    } else {
        let ntdll = p.modules.by_name("ntdll.dll").unwrap();
        p.modules.nt_services = Some((ntdll, table(arch, "NtAccessCheck", 0x21)));
    }
    // Both transports replay the same recorded subject. Installed DLL selection
    // does not imply the runner has the capture's SYSTEM identity. Attribute
    // capture retains its independent native byte and ownership suite.
    p.objects.select_wnf_catalog(
        crate::user::windows::wnf::Catalog::selected(Vec::new(), subject_fixture()).unwrap(),
    );
    let base =
        p.vm.allocate(
            None,
            PAGE_SIZE * 12,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    let primary = p.objects.create(Object::PrimaryToken);
    let query = u64::from(p.objects.open_access(primary, false, 8).unwrap());
    let denied = u64::from(p.objects.open_access(primary, false, 0).unwrap());
    let token = p
        .objects
        .create(Object::ImpersonationToken(Arc::new(subject_fixture())));
    let impersonation = u64::from(p.objects.open_access(token, false, 8).unwrap());
    let event = p.objects.create(Object::Event {
        manual: false,
        signaled: 0,
    });
    let event = u64::from(p.objects.open(event, false));
    (process, thread, base, [query, denied, impersonation, event])
}

fn token(p: &Proc, name: &str, handles: [u64; 4]) -> u64 {
    match name {
        "primary" => p.arch.ptr(u64::MAX - 3),
        "thread-token" => p.arch.ptr(u64::MAX - 4),
        "effective" => p.arch.ptr(u64::MAX - 5),
        "process" => p.arch.ptr(u64::MAX),
        "thread" => p.arch.ptr(u64::MAX - 1),
        "null" => 0,
        "invalid" => 0xDEAD,
        "real-primary" => handles[0],
        "no-access" => handles[1],
        "impersonation" => handles[2],
        "event" => handles[3],
        _ => panic!("unknown captured token role {name}"),
    }
}

fn invoke(p: &mut Proc, thread: &mut Thread, args: &[u64]) -> u32 {
    let sp = thread.cpu.sp();
    let rng = p.rng;
    let handles = p.objects.handle_count();
    super::nls_tests::arguments(p, thread, args);
    if p.arch != WinArch::Arm64 {
        thread.cpu.set_gpr(0, 0x21);
    }
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, thread, 0x1234_0000)
    } else {
        handle_stop(p, thread, stop(p.arch, 0x21))
    };
    assert_eq!(result, Outcome::Continue, "{} args={args:x?}", p.arch);
    assert_eq!(
        thread.cpu.sp(),
        sp + if p.arch == WinArch::X86 { 4 } else { 0 }
    );
    thread.cpu.set_sp(sp);
    assert!(thread.frames.is_empty());
    assert_eq!(p.rng, rng);
    assert_eq!(p.objects.handle_count(), handles);
    thread.cpu.gpr(0) as u32
}

fn unsupported(p: &mut Proc, thread: &mut Thread, args: &[u64], reason: &str) {
    super::nls_tests::arguments(p, thread, args);
    if p.arch != WinArch::Arm64 {
        thread.cpu.set_gpr(0, 0x21);
    }
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, thread, 0x1234_0000)
    } else {
        handle_stop(p, thread, stop(p.arch, 0x21))
    };
    assert!(
        matches!(&result, Outcome::Fail(message) if message.contains("NtAccessCheck") && message.contains(reason)),
        "expected {reason}: {result:?}"
    );
}

fn descriptor(name: &str) -> Vec<u8> {
    static VALUES: OnceLock<serde_json::Value> = OnceLock::new();
    let d = VALUES.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../../../docs/specifications/windows/native-access-check/descriptors.json"
        ))
        .unwrap()
    });
    hex(d[name].as_str().unwrap())
}

fn reset(p: &mut Proc, base: u64) {
    p.vm.protect(base, PAGE_SIZE * 12, prot::READWRITE).unwrap();
    p.space
        .wr(base, &vec![0xA5; (PAGE_SIZE * 12) as usize])
        .unwrap();
}

fn foreign_sid() -> Vec<u8> {
    hex("010900000000000520000000d27fa55fc16de51f257521c3ef0891da68770b1490c7cb81a02c8ba3b813e7aa")
}

fn logical_input(p: &mut Proc, base: u64, name: &str, length: u32) -> [u64; 6] {
    reset(p, base);
    let fields = [
        base,
        base + PAGE_SIZE * 2,
        base + PAGE_SIZE * 4,
        base + PAGE_SIZE * 6,
        base + PAGE_SIZE * 8,
        base + PAGE_SIZE * 10,
    ];
    let mapping = if name == "captured-absolute-nonmember" {
        let sid = foreign_sid();
        let sid_address = base + 512;
        let acl_address = base + 256;
        p.space.wr(sid_address, &sid).unwrap();
        let mut acl = vec![0; 236];
        acl[0] = 2;
        acl[2..4].copy_from_slice(&236u16.to_le_bytes());
        acl[4..6].copy_from_slice(&1u16.to_le_bytes());
        acl[10..12].copy_from_slice(&52u16.to_le_bytes());
        acl[12..16].copy_from_slice(&1u32.to_le_bytes());
        acl[16..60].copy_from_slice(&sid);
        p.space.wr(acl_address, &acl).unwrap();
        let mut header = vec![0; if p.arch == WinArch::X86 { 20 } else { 40 }];
        header[0] = 1;
        header[2..4].copy_from_slice(&4u16.to_le_bytes());
        let width = if p.arch == WinArch::X86 { 4 } else { 8 };
        for (index, address) in [sid_address, sid_address, 0, acl_address]
            .into_iter()
            .enumerate()
        {
            let at = width + index * width;
            header[at..at + width].copy_from_slice(&address.to_le_bytes()[..width]);
        }
        p.space.wr(base, &header).unwrap();
        [0x20001u32, 0x20000, 0x20000, 0x1F0001]
    } else {
        p.space.wr(base, &descriptor(name)).unwrap();
        [1u32, 2, 4, 7]
    };
    for (i, value) in mapping.into_iter().enumerate() {
        p.space.w32(fields[1] + i as u64 * 4, value).unwrap();
    }
    p.space.w32(fields[3], length).unwrap();
    fields
}

fn arguments(token: u64, desired: u32, f: [u64; 6]) -> [u64; 8] {
    [
        f[0],
        token,
        u64::from(desired),
        f[1],
        f[2],
        f[3],
        f[4],
        f[5],
    ]
}

fn check_logical(p: &Proc, f: [u64; 6], row: &serde_json::Value) {
    let number = |name: &str| u32::from_str_radix(row[name].as_str().unwrap(), 16).unwrap();
    assert_eq!(
        p.space.u32(f[3]).unwrap(),
        row["returned"].as_str().unwrap().parse::<u32>().unwrap()
    );
    assert_eq!(p.space.u32(f[4]).unwrap(), number("granted"));
    assert_eq!(p.space.u32(f[5]).unwrap(), number("access-status"));
    assert_eq!(
        p.space.bytes(f[2], 64).unwrap(),
        hex(row["privileges"].as_str().unwrap())
    );
}

#[test]
fn native_access_check_replays_all_17640_native_logical_rows() {
    let rows = data()["logical"].as_array().unwrap();
    assert_eq!(rows.len(), 4410);
    for (arch, laa) in [
        (WinArch::Arm64, false),
        (WinArch::X64, false),
        (WinArch::X86, false),
        (WinArch::X86, true),
    ] {
        let (mut process, mut thread, base, handles) = setup(arch, laa, false);
        let p = process.state_mut();
        for (i, row) in rows.iter().enumerate() {
            let f = logical_input(
                p,
                base,
                row["descriptor"].as_str().unwrap(),
                row["length"].as_str().unwrap().parse().unwrap(),
            );
            let t = token(p, row["token"].as_str().unwrap(), handles);
            let desired = u32::from_str_radix(row["desired"].as_str().unwrap(), 16).unwrap();
            let expected = u32::from_str_radix(row["return"].as_str().unwrap(), 16).unwrap();
            assert_eq!(
                invoke(p, &mut thread, &arguments(t, desired, f)),
                expected,
                "{arch}/{laa}/row{i}/{row}"
            );
            check_logical(p, f, row);
        }
    }
}

fn boundary_input(p: &mut Proc, base: u64, length: u32, role: u32) -> [u64; 6] {
    let mut f = logical_input(p, base, "allow-one", length);
    let mut moved = None;
    if (1..=12).contains(&role) {
        let field = ((role - 1) / 2) as usize;
        if role % 2 == 1 {
            f[field] = 0;
        } else {
            f[field] += 1;
            moved = Some(field);
        }
    } else if (37..=42).contains(&role) {
        let field = (role - 37) as usize;
        f[field] += PAGE_SIZE - 2;
        moved = Some(field);
    } else {
        match role {
            43 => f[5] = f[4],
            44 => f[4] = f[2],
            45 => f[5] = f[2],
            46 => f[3] = f[2],
            47 => {
                f[3] = f[2];
                f[4] = f[2];
                f[5] = f[2];
            }
            48 => f[3] = f[2] + 4,
            49 => f[0] = f[1],
            0 | 13..=36 => {}
            _ => panic!("unknown captured boundary role"),
        }
    }
    if moved == Some(0) {
        p.space.wr(f[0], &descriptor("allow-one")).unwrap();
    }
    if moved == Some(1) {
        for (i, value) in [1, 2, 4, 7].into_iter().enumerate() {
            p.space.w32(f[1] + i as u64 * 4, value).unwrap();
        }
    }
    if f[3] != 0 {
        p.space.w32(f[3], length).unwrap();
    }
    if (13..=36).contains(&role) {
        let index = (role - 13) as usize;
        let protections = [
            prot::NOACCESS,
            prot::READONLY,
            prot::READWRITE | prot::GUARD,
            prot::READONLY | prot::GUARD,
        ];
        p.vm.protect(f[index / 4], PAGE_SIZE, protections[index % 4])
            .unwrap();
    }
    if (37..=42).contains(&role) {
        p.vm.protect(
            base + PAGE_SIZE * (2 * u64::from(role - 37) + 1),
            PAGE_SIZE,
            prot::NOACCESS,
        )
        .unwrap();
    }
    f
}

fn check_boundary(p: &Proc, base: u64, f: [u64; 6], row: &serde_json::Value) {
    for (i, address) in f.into_iter().enumerate() {
        if (base..base + PAGE_SIZE * 12).contains(&address) {
            let protection =
                u32::from_str_radix(row[format!("p{i}-protect")].as_str().unwrap(), 16).unwrap();
            assert_eq!(
                p.vm.query(address).unwrap().protect,
                protection,
                "field{i} protection"
            );
        }
        let cells = row[format!("p{i}-cells")].as_str().unwrap();
        assert_eq!(cells.len(), 16);
        for (index, value) in cells.as_bytes().chunks_exact(2).enumerate() {
            if value != b"??" {
                let expected = u8::from_str_radix(std::str::from_utf8(value).unwrap(), 16).unwrap();
                assert_eq!(
                    p.space.u8(address + index as u64).unwrap(),
                    expected,
                    "field{i} byte{index}"
                );
            }
        }
    }
}

#[test]
fn native_access_check_replays_all_6000_native_pointer_rows() {
    for (arch, laa) in [
        (WinArch::Arm64, false),
        (WinArch::X64, false),
        (WinArch::X86, false),
        (WinArch::X86, true),
    ] {
        let key = if arch == WinArch::X86 {
            "wow64-boundaries"
        } else {
            "native64-boundaries"
        };
        let rows = data()[key].as_array().unwrap();
        assert_eq!(rows.len(), 1500);
        let (mut process, mut thread, base, handles) = setup(arch, laa, false);
        let p = process.state_mut();
        for (i, row) in rows.iter().enumerate() {
            let length = u32::from_str_radix(row["length"].as_str().unwrap(), 16).unwrap();
            let role = row["role"].as_str().unwrap().parse().unwrap();
            let f = boundary_input(p, base, length, role);
            let t = token(p, row["token"].as_str().unwrap(), handles);
            let expected = u32::from_str_radix(row["return"].as_str().unwrap(), 16).unwrap();
            assert_eq!(
                invoke(p, &mut thread, &arguments(t, 1, f)),
                expected,
                "{arch}/{laa}/row{i}/{row}"
            );
            check_boundary(p, base, f, row);
        }
    }
}

fn private_descriptor(name: &str) -> Vec<u8> {
    let owner = match name {
        "owned-empty" => hex("010100000000000512000000"),
        "world-empty" | "world-null" => hex("010100000000000100000000"),
        "foreign-empty" => foreign_sid(),
        _ => panic!("unknown private-token descriptor"),
    };
    let group = hex("010100000000000512000000");
    let mut bytes = vec![0; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    if name != "world-null" {
        bytes[16..20].copy_from_slice(&20u32.to_le_bytes());
        bytes.extend_from_slice(&[2, 0, 8, 0, 0, 0, 0, 0]);
    }
    let offset = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&offset.to_le_bytes());
    bytes.extend_from_slice(&owner);
    let offset = bytes.len() as u32;
    bytes[8..12].copy_from_slice(&offset.to_le_bytes());
    bytes.extend_from_slice(&group);
    bytes
}

#[test]
fn native_access_check_replays_private_token_privilege_records_all_guest_abis() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../../docs/specifications/windows/native-access-check/native-access-privileges-v2.json"
    )).unwrap();
    let rows = fixture["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1296);
    for (arch, laa) in [
        (WinArch::Arm64, false),
        (WinArch::X64, false),
        (WinArch::X86, false),
        (WinArch::X86, true),
    ] {
        let (mut process, mut thread, base, _) = setup(arch, laa, false);
        let p = process.state_mut();
        let mut tokens = std::collections::BTreeMap::new();
        for config in fixture["configurations"].as_array().unwrap() {
            let mut subject = subject_fixture();
            for privilege in &mut subject.privileges {
                privilege.attributes &= !2;
            }
            for enabled in config["enabled"].as_array().unwrap() {
                let luid = enabled["low"].as_u64().unwrap()
                    | ((enabled["high"].as_i64().unwrap() as u64) << 32);
                subject
                    .privileges
                    .iter_mut()
                    .find(|p| p.luid == luid)
                    .unwrap()
                    .attributes |= 2;
            }
            let object = p
                .objects
                .create(Object::ImpersonationToken(Arc::new(subject)));
            let handle = u64::from(p.objects.open_access(object, false, 8).unwrap());
            tokens.insert(config["label"].as_str().unwrap(), handle);
        }
        for (i, row) in rows.iter().enumerate() {
            let capacity = row["capacity"].as_u64().unwrap() as u32;
            let f = logical_input(p, base, "empty-dacl", capacity);
            p.space
                .wr(
                    base,
                    &private_descriptor(row["descriptor"].as_str().unwrap()),
                )
                .unwrap();
            let handle = tokens[row["token"].as_str().unwrap()];
            let desired = row["desired"].as_u64().unwrap() as u32;
            assert_eq!(
                invoke(p, &mut thread, &arguments(handle, desired, f)),
                row["return"].as_u64().unwrap() as u32,
                "{arch}/{laa}/private row{i}"
            );
            assert_eq!(
                p.space.u32(f[3]).unwrap(),
                row["returned"].as_u64().unwrap() as u32,
                "{arch}/{laa}/private row{i} length"
            );
            assert_eq!(
                p.space.u32(f[4]).unwrap(),
                row["granted"].as_u64().unwrap() as u32,
                "{arch}/{laa}/private row{i} granted"
            );
            assert_eq!(
                p.space.u32(f[5]).unwrap(),
                row["access-status"].as_u64().unwrap() as u32,
                "{arch}/{laa}/private row{i} status"
            );
            assert_eq!(
                p.space.bytes(f[2], 64).unwrap(),
                hex(row["privileges"].as_str().unwrap()),
                "{arch}/{laa}/private row{i} privileges"
            );
        }
    }
}

#[test]
fn native_access_check_unmodeled_subjects_and_aces_never_fabricate_access() {
    for arch in WinArch::ALL {
        for kind in ["missing", "app-container", "restricted", "callback-ace"] {
            let (mut process, mut thread, base, handles) = setup(arch, false, false);
            let p = process.state_mut();
            let f = logical_input(p, base, "allow-one", 56);
            let mut selected = handles[2];
            if kind == "missing" {
                p.objects.select_wnf_catalog(Default::default());
                selected = arch.ptr(u64::MAX - 3);
            } else if kind != "callback-ace" {
                let mut subject = subject_fixture();
                if kind == "app-container" {
                    subject.app_container = true;
                } else {
                    subject.restricted.push(Group {
                        sid: subject.user.clone(),
                        attributes: 4,
                    });
                }
                let object = p
                    .objects
                    .create(Object::ImpersonationToken(Arc::new(subject)));
                selected = u64::from(p.objects.open_access(object, false, 8).unwrap());
            } else {
                p.space.w8(base + 28, 9).unwrap();
            }
            let count = p.objects.handle_count();
            let rng = p.rng;
            let reason = match kind {
                "missing" => "primary access-check subject is not captured",
                "callback-ace" => "nonclassic or malformed access-check DACL",
                _ => "restricted or AppContainer access-check subject",
            };
            unsupported(p, &mut thread, &arguments(selected, 1, f), reason);
            assert_eq!(p.space.u32(f[2]).unwrap(), 0);
            assert_eq!(p.space.u32(f[3]).unwrap(), 56);
            assert_eq!(p.space.u32(f[4]).unwrap(), 0xA5A5_A5A5);
            assert_eq!(p.space.u32(f[5]).unwrap(), 0xA5A5_A5A5);
            assert_eq!(p.objects.handle_count(), count);
            assert_eq!(p.rng, rng);
        }
    }
}

#[test]
fn captured_impersonation_token_query_uses_its_subject_without_primary_capture() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base, _) = setup(arch, false, false);
        let p = process.state_mut();
        let mut subject = subject_fixture();
        subject.app_container = true;
        let token = p
            .objects
            .create(Object::ImpersonationToken(Arc::new(subject)));
        let query = u64::from(p.objects.open_access(token, false, 8).unwrap());
        let denied = u64::from(p.objects.open_access(token, false, 0).unwrap());
        p.objects.select_wnf_catalog(Default::default());
        let ntdll = p.modules.by_name("ntdll.dll").unwrap();
        p.modules.nt_services = Some((ntdll, table(arch, "NtQueryInformationToken", 0x21)));
        assert_eq!(invoke(p, &mut thread, &[query, 29, base, 8, base + 16]), 0);
        assert_eq!(p.space.u32(base).unwrap(), 1);
        assert_eq!(p.space.u32(base + 16).unwrap(), 4);
        assert_eq!(
            invoke(p, &mut thread, &[denied, 29, base, 8, base + 16]),
            STATUS_ACCESS_DENIED
        );
    }
}

#[test]
fn native_access_check_added_statuses_keep_win32_translation() {
    for (status, error) in [
        (STATUS_NO_IMPERSONATION_TOKEN, 1309),
        (STATUS_INVALID_SECURITY_DESCR, 1338),
        (STATUS_GENERIC_NOT_MAPPED, 1360),
    ] {
        assert_eq!(crate::user::windows::nt::status_to_error(status), error);
    }
}

#[cfg(windows)]
#[test]
fn native_access_check_installed_leaves_replay_both_complete_matrices() {
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
    for (arch, laa) in profiles {
        let (mut process, mut thread, base, handles) = setup(arch, laa, true);
        let p = process.state_mut();
        let module = crate::user::windows::loader::load_dll(p, "ntdll.dll").unwrap();
        for (i, row) in data()["logical"].as_array().unwrap().iter().enumerate() {
            let f = logical_input(
                p,
                base,
                row["descriptor"].as_str().unwrap(),
                row["length"].as_str().unwrap().parse().unwrap(),
            );
            let handle = token(p, row["token"].as_str().unwrap(), handles);
            let desired = u32::from_str_radix(row["desired"].as_str().unwrap(), 16).unwrap();
            let expected = u32::from_str_radix(row["return"].as_str().unwrap(), 16).unwrap();
            let actual = super::virtual_memory_tests::installed::invoke(
                p,
                &mut thread,
                module,
                "NtAccessCheck",
                &arguments(handle, desired, f),
            );
            assert_eq!(actual, expected, "{arch}/{laa}/installed logical{i}");
            check_logical(p, f, row);
        }
        let key = if arch == WinArch::X86 {
            "wow64-boundaries"
        } else {
            "native64-boundaries"
        };
        for (i, row) in data()[key].as_array().unwrap().iter().enumerate() {
            let length = u32::from_str_radix(row["length"].as_str().unwrap(), 16).unwrap();
            let role = row["role"].as_str().unwrap().parse().unwrap();
            let f = boundary_input(p, base, length, role);
            let handle = token(p, row["token"].as_str().unwrap(), handles);
            let expected = u32::from_str_radix(row["return"].as_str().unwrap(), 16).unwrap();
            let actual = super::virtual_memory_tests::installed::invoke(
                p,
                &mut thread,
                module,
                "NtAccessCheck",
                &arguments(handle, 1, f),
            );
            assert_eq!(actual, expected, "{arch}/{laa}/installed boundary{i}");
            check_boundary(p, base, f, row);
        }
    }
}
