use super::*;
use crate::user::windows::loader::apiset_schema::ApiSetSchema;
use crate::user::windows::memory::prot;
use crate::user::windows::native::NativeRuntime;
use crate::user::windows::process::{WinVersion, WindowsConfig, WindowsProcess};

fn fixture(arch: WinArch) -> WindowsProcess {
    let image: &[u8] = match arch {
        WinArch::X86 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
        }
        WinArch::X64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
        }
        WinArch::Arm64 => {
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
        }
    };
    let mut config = WindowsConfig::embedded("C:\\creation.exe", vec![], vec![], 4096).unwrap();
    config.arena_bytes = 64 << 20;
    WindowsProcess::spawn_image(config, image.to_vec()).unwrap()
}

fn runtime(machine: Option<u16>, kernel: (u32, u32, u32)) -> NativeRuntime {
    let schema: Vec<u8> = [6u32, 28, 0, 0, 28, 28, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let mut object_namespace = crate::user::windows::object_namespace::Namespace::default();
    object_namespace.native_machine = machine;
    NativeRuntime {
        directory: Default::default(),
        guest_root: "C:\\Windows".into(),
        guest_directory: "C:\\Windows\\System32".into(),
        version: WinVersion {
            major: kernel.0,
            minor: kernel.1,
            build: kernel.2,
            ..Default::default()
        },
        apisets: ApiSetSchema::parse(&schema).unwrap(),
        registry: Default::default(),
        object_namespace,
        nls: None,
        appcompat: Default::default(),
        wnf_catalog: Default::default(),
        startup: None,
        gui: Default::default(),
        code_integrity: Err("controlled absent metadata".into()),
        code_integrity_policy: Err("controlled absent metadata".into()),
        code_integrity_policies: Err("controlled absent metadata".into()),
        policy_catalog: Err("controlled absent metadata".into()),
    }
}

fn resources(p: &Proc) -> (usize, usize, u64) {
    (
        p.objects.handle_count(),
        p.objects.iter().count(),
        p.vm.committed_bytes(),
    )
}

#[test]
fn chpe_creation_replays_completed_native_record_without_other_publication() {
    let profile: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../docs/specifications/windows/native-chpe-creation/profile-29704-v1.json"
    ))
    .unwrap();
    assert_eq!(profile["kernel"], serde_json::json!([10, 0, 29704]));
    let children = profile["children"].as_array().unwrap();
    assert_eq!(children.len(), 3);
    assert!(
        children
            .iter()
            .all(|child| child["exit_code"] == 0 && child["resume_previous"] == 1)
    );
    let child = children
        .iter()
        .find(|child| child["architecture"] == "x64")
        .unwrap();
    let field = &child["fields"][0];
    assert_eq!(field["field_offset"], FIELD);
    assert_eq!(field["peb_relative"], RECORD);
    assert_eq!(child["reported_machine"], 0);
    assert_eq!(profile["input_pe_machines"]["x64"], 0x8664);
    let hex = field["payload_hex"].as_str().unwrap();
    let native: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect();
    let mut process = fixture(WinArch::X64);
    let p = process.state_mut();
    p.native = Some(runtime(Some(0xaa64), (10, 0, 29704)));
    std::sync::Arc::make_mut(&mut p.cfg).version.build = 1;
    let mut expected = p.space.bytes(p.peb, PAGE_SIZE as usize).unwrap();
    let counts = resources(p);
    initialize(p).unwrap();
    assert_eq!(p.space.u64(p.peb + FIELD).unwrap(), p.peb + RECORD);
    expected[FIELD as usize..FIELD as usize + 8].copy_from_slice(&(p.peb + RECORD).to_le_bytes());
    expected[RECORD as usize..RECORD as usize + BYTES].copy_from_slice(&native);
    assert_eq!(p.space.bytes(p.peb, PAGE_SIZE as usize).unwrap(), expected);
    assert_eq!(resources(p), counts);
    assert_eq!(initialize(p), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(p.space.bytes(p.peb, PAGE_SIZE as usize).unwrap(), expected);
    assert_eq!(resources(p), counts);
}

#[test]
fn chpe_creation_preserves_closed_other_guest_and_native_amd64_profiles() {
    for arch in WinArch::ALL {
        for native in [false, true] {
            let mut process = fixture(arch);
            let p = process.state_mut();
            if native {
                p.native = Some(runtime(
                    Some(if arch == WinArch::X64 { 0x8664 } else { 0xaa64 }),
                    (10, 0, 29704),
                ));
            }
            let before = p.space.bytes(p.peb, PAGE_SIZE as usize).unwrap();
            let counts = resources(p);
            initialize(p).unwrap();
            assert_eq!(p.space.bytes(p.peb, PAGE_SIZE as usize).unwrap(), before);
            assert_eq!(resources(p), counts);
        }
    }
}

#[test]
fn chpe_creation_rejects_unmeasured_native_identity_before_writing() {
    for (machine, kernel) in [
        (Some(0xaa64), (10, 0, 29703)),
        (Some(0xaa64), (10, 0, 29705)),
        (Some(0xaa64), (10, 1, 29704)),
        (Some(0xaa64), (11, 0, 29704)),
        (Some(0x014c), (10, 0, 29704)),
        (Some(0x9999), (10, 0, 29704)),
        (None, (10, 0, 29704)),
    ] {
        let mut process = fixture(WinArch::X64);
        let p = process.state_mut();
        p.native = Some(runtime(machine, kernel));
        std::sync::Arc::make_mut(&mut p.cfg).version.build = 29704;
        let before = p.space.bytes(p.peb, PAGE_SIZE as usize).unwrap();
        let counts = resources(p);
        assert_eq!(
            initialize(p),
            Err(STATUS_NOT_SUPPORTED),
            "{machine:?}/{kernel:?}"
        );
        assert_eq!(p.space.bytes(p.peb, PAGE_SIZE as usize).unwrap(), before);
        assert_eq!(resources(p), counts);
    }
}

#[test]
fn chpe_creation_rejects_modified_owned_storage_without_overwriting_it() {
    for variant in 0..3 {
        let mut process = fixture(WinArch::X64);
        let p = process.state_mut();
        p.native = Some(runtime(Some(0xaa64), (10, 0, 29704)));
        match variant {
            0 => p.space.w64(p.peb + FIELD, 0x1234_0000).unwrap(),
            1 => p.space.w64(p.peb + FIELD, p.peb + RECORD).unwrap(),
            _ => p.space.w64(p.peb + RECORD + 8, 0x1234_0000).unwrap(),
        }
        let before = p.space.bytes(p.peb, PAGE_SIZE as usize).unwrap();
        let counts = resources(p);
        assert_eq!(initialize(p), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(p.space.bytes(p.peb, PAGE_SIZE as usize).unwrap(), before);
        assert_eq!(resources(p), counts);
    }
}

#[test]
fn chpe_creation_preflights_owned_page_before_publishing_bytes() {
    let mut process = fixture(WinArch::X64);
    let p = process.state_mut();
    p.native = Some(runtime(Some(0xaa64), (10, 0, 29704)));
    let before = p.space.bytes(p.peb, PAGE_SIZE as usize).unwrap();
    p.vm.protect(p.peb, PAGE_SIZE, prot::READONLY).unwrap();
    let counts = resources(p);
    assert_eq!(initialize(p), Err(STATUS_ACCESS_VIOLATION));
    assert_eq!(p.space.bytes(p.peb, PAGE_SIZE as usize).unwrap(), before);
    assert_eq!(resources(p), counts);
}

#[path = "thread_tests.rs"]
mod thread_tests;
