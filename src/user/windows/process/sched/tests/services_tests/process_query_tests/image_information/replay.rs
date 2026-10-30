//! Replay address-free native metadata, destination bytes, guards and copy
//! predicates. Captured PE scalar fields are controlled inputs to synthetic PE
//! fixtures; they do not claim that the private native observer binary is loaded.

use super::{arguments, dispatch, setup};
use crate::user::image::pe::PeImage;
use crate::user::windows::arch::WinArch;
use crate::user::windows::loader::apiset_schema::ApiSetSchema;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::native::NativeRuntime;
use crate::user::windows::objects::Object;
use crate::user::windows::process::sched::Outcome;
use crate::user::windows::process::{Proc, image_information::ImageInformation};
use serde_json::Value;

const TRANSFER_ADDRESS: u64 = 0x1122_3344;

pub(super) fn fixture_bytes(arch: WinArch) -> Vec<u8> {
    let name = match arch {
        WinArch::Arm64 => "arm64",
        WinArch::X64 => "x64",
        WinArch::X86 => "x86",
    };
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/user/windows/bin")
            .join(name)
            .join("smoke.exe"),
    )
    .unwrap()
}

pub(super) fn kernel_profile(p: &mut Proc, build: u32, machine: u16) {
    let schema: Vec<u8> = [6u32, 28, 0, 0, 28, 28, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let mut native = NativeRuntime {
        directory: Default::default(),
        guest_root: "C:\\Windows".into(),
        guest_directory: "C:\\Windows\\System32".into(),
        version: Default::default(),
        apisets: ApiSetSchema::parse(&schema).unwrap(),
        registry: Default::default(),
        object_namespace: Default::default(),
        nls: None,
        appcompat: Default::default(),
        wnf_catalog: Default::default(),
        startup: None,
        gui: Default::default(),
        code_integrity: Err("controlled image query profile".into()),
        code_integrity_policy: Err("code integrity policy not captured in this fixture".into()),
    };
    native.version.build = build;
    native.object_namespace.native_machine = Some(machine);
    p.native = Some(native);
    // Reporting a different guest version cannot choose another kernel copy.
    std::sync::Arc::make_mut(&mut p.cfg).version.build = if build == 29683 { 26100 } else { 29683 };
}

fn install_metadata(p: &mut Proc, arch: WinArch, profile: &Value) {
    let h: Vec<u64> = profile["rows"][1]["pe"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    let mut bytes = fixture_bytes(arch);
    let pe = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
    let optional = pe + 24;
    for (offset, value) in [
        (pe + 4, h[0]),
        (pe + 22, h[10]),
        (optional + 68, h[5]),
        (optional + 50, h[6]),
        (optional + 48, h[7]),
        (optional + 40, h[8]),
        (optional + 42, h[9]),
        (optional + 70, h[11]),
    ] {
        bytes[offset..offset + 2].copy_from_slice(&(value as u16).to_le_bytes());
    }
    for (offset, value) in [
        (optional + 16, h[1]),
        (optional + 56, h[2]),
        (
            optional + if arch == WinArch::X86 { 88 } else { 104 },
            h[12],
        ),
        (optional + 64, h[13]),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
    }
    for (index, value) in [h[3], h[4]].into_iter().enumerate() {
        let offset = optional + 72 + index * arch.ptr_size() as usize;
        if arch == WinArch::X86 {
            bytes[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
        } else {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
    let file_size = profile["file_bytes"].as_u64().unwrap() as usize;
    assert!(file_size >= bytes.len());
    bytes.resize(file_size, 0);
    let image = PeImage::parse(bytes).unwrap();
    p.image_information = ImageInformation::capture(&image, TRANSFER_ADDRESS);
    assert!(p.image_information.is_ok(), "{}", profile["profile"]);
    let host = &profile["rows"][0];
    kernel_profile(
        p,
        host["build"].as_u64().unwrap() as u32,
        host["native_machine"].as_u64().unwrap() as u16,
    );
}

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
        10 => base + 4036,
        11 => base + 4032,
        12 => base + 4048,
        13 => base + 4080,
        14 => u64::MAX & !3,
        15 => u64::MAX & !7,
        16 => base + 4088,
        _ => base + offset,
    }
}

fn projection(p: &Proc, base: u64, address: u64, fallback: u64, mask: &str) -> String {
    let at = if (base..=base + 16384 - mask.len() as u64).contains(&address) {
        address
    } else {
        base + fallback
    };
    p.space
        .bytes(at, mask.len())
        .unwrap()
        .iter()
        .zip(mask.bytes())
        .map(|(byte, masked)| format!("{:02x}", if masked == b'1' { 0 } else { *byte }))
        .collect()
}

fn verify_metadata(
    p: &mut Proc,
    thread: &mut crate::user::windows::process::Thread,
    scratch: u64,
    arch: WinArch,
    profile: &Value,
) {
    let size = if arch == WinArch::X86 { 48 } else { 64 };
    arguments(
        p,
        thread,
        arch.ptr(u64::MAX),
        37,
        scratch,
        size,
        scratch + 96,
    );
    assert_eq!(
        dispatch(p, thread),
        Outcome::Continue,
        "{} {}",
        profile["arch"],
        profile["profile"]
    );
    assert_eq!(thread.cpu.gpr(0), 0);
    assert_eq!(
        p.space.ptr(scratch, arch.ptr_size()).unwrap(),
        TRANSFER_ADDRESS
    );
    assert_eq!(p.space.u32(scratch + 96).unwrap(), size);
    let expected = profile["rows"][1]["section"].as_array().unwrap();
    let offsets = if arch == WinArch::X86 {
        [4, 8, 12, 16, 20, 22, 24, 26, 28, 30, 32, 34, 35, 36, 40, 44]
    } else {
        [
            8, 16, 24, 32, 36, 38, 40, 42, 44, 46, 48, 50, 51, 52, 56, 60,
        ]
    };
    for (index, offset) in offsets.into_iter().enumerate() {
        let at = scratch + offset;
        let value = match index {
            1 | 2 => p.space.ptr(at, arch.ptr_size()).unwrap(),
            4..=10 => u64::from(p.space.u16(at).unwrap()),
            11 | 12 => u64::from(p.space.u8(at).unwrap()),
            _ => u64::from(p.space.u32(at).unwrap()),
        };
        assert_eq!(
            value,
            expected[index].as_u64().unwrap(),
            "{} {} metadata field {index}",
            profile["arch"],
            profile["profile"]
        );
    }
}

#[test]
fn native_process_image_information_replays_measured_kernel_queries_and_metadata_profiles() {
    let captures = [
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-process-image-information/local-29683-v9.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-process-image-information/hosted-20348-v9.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-process-image-information/hosted-26100-v9.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-process-image-information/local-29695-v1.json"
        )),
    ];
    let mut profiles = 0;
    let mut queries = 0;
    let mut pointer_bits = 0;
    let mut rejected = 0;
    for capture in captures {
        let records: Value = serde_json::from_str(capture).unwrap();
        for record in records
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["kind"] == "unavailable")
        {
            assert_eq!(record["windows_error"], 193);
            assert_eq!(record["query_calls"], 0);
            rejected += 1;
        }
        for profile in records
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["kind"] == "observation")
        {
            profiles += 1;
            let arch = match profile["arch"].as_str().unwrap() {
                "arm64" => WinArch::Arm64,
                "x64" => WinArch::X64,
                "x86" => WinArch::X86,
                _ => unreachable!(),
            };
            let (mut process, mut thread, scratch) = setup(arch);
            let p = process.state_mut();
            install_metadata(p, arch, profile);
            let sp = thread.cpu.sp();
            verify_metadata(p, &mut thread, scratch, arch, profile);
            for row in profile["rows"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| r["kind"] == "case")
            {
                queries += 1;
                let base =
                    p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                        .unwrap()
                        .0;
                p.space.wr(base, &[0xa5; 16384]).unwrap();
                let output_role = row["output_role"].as_u64().unwrap();
                let return_role = row["return_role"].as_u64().unwrap();
                let guard = if output_role == 7 || return_role == 7 {
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
                let output = arch.ptr(pointer(base, output_role, 256));
                let alias = row["alias"].as_i64().unwrap();
                let returned = if alias >= 0 {
                    base + 256 + alias as u64
                } else {
                    arch.ptr(pointer(base, return_role, 512))
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
                        // Use the measured grant, not the requested mask (0x400
                        // acquired 0x1400 in these owned native handle opens).
                        let access = row["granted_access"].as_u64().unwrap() as u32;
                        (
                            u64::from(p.objects.open_access(id, false, access).unwrap()),
                            true,
                        )
                    }
                    _ => unreachable!(),
                };
                thread.cpu.set_sp(sp);
                arguments(
                    p,
                    &mut thread,
                    handle,
                    37,
                    output,
                    row["length"].as_u64().unwrap() as u32,
                    returned,
                );
                assert_eq!(
                    dispatch(p, &mut thread),
                    Outcome::Continue,
                    "{} {} row={row}",
                    profile["arch"],
                    profile["profile"]
                );
                assert_eq!(
                    thread.cpu.gpr(0),
                    row["status"].as_u64().unwrap(),
                    "{} row={row}",
                    profile["rows"][0]
                );
                assert_eq!(
                    p.vm.query(base + 12288).unwrap().protect,
                    row["guard_protection"].as_u64().unwrap() as u32,
                    "{} row={row}",
                    profile["rows"][0]
                );
                p.vm.protect(base, 16384, prot::READWRITE).unwrap();
                for (address, fallback, name) in
                    [(output, 256, "output"), (returned, 512, "returned")]
                {
                    let mask = row[format!("{name}_mask")].as_str().unwrap();
                    assert_eq!(
                        projection(p, base, address, fallback, mask),
                        row[name].as_str().unwrap(),
                        "{} {name} row={row}",
                        profile["rows"][0]
                    );
                }
                let width = arch.ptr_size();
                let selected = if (base..=base + 16384 - width).contains(&output) {
                    output
                } else {
                    base + 256
                };
                let actual = p.space.bytes(selected, width as usize).unwrap();
                let reference = TRANSFER_ADDRESS.to_le_bytes();
                let mut changed = 0u64;
                let mut matches = 0u64;
                let mut compare = row["pointer_valid_mask"].as_u64().unwrap();
                for (index, byte) in actual.iter().enumerate() {
                    if *byte != 0xa5 {
                        changed |= 1 << index;
                    }
                    if *byte == reference[index] {
                        matches |= 1 << index;
                    }
                    if (returned..returned.saturating_add(4)).contains(&(selected + index as u64)) {
                        compare &= !(1 << index);
                    }
                }
                pointer_bits += compare.count_ones();
                assert_eq!(
                    changed & compare,
                    row["pointer_changed_mask"].as_u64().unwrap() & compare,
                    "{} pointer change row={row}",
                    profile["rows"][0]
                );
                assert_eq!(
                    matches & compare,
                    row["pointer_match_mask"].as_u64().unwrap() & compare,
                    "{} pointer match row={row}",
                    profile["rows"][0]
                );
                assert_eq!(thread.cpu.pc(), 0x1234_0004);
                assert_eq!(
                    thread.cpu.sp(),
                    sp + if arch == WinArch::X86 { 4 } else { 0 }
                );
                assert!(thread.frames.is_empty());
                if owned {
                    p.objects.close(handle).unwrap();
                }
                p.vm.free(base, 0, mem::RELEASE).unwrap();
            }
        }
    }
    assert_eq!(profiles, 126);
    assert_eq!(queries, 7708);
    assert_eq!(rejected, 6);
    assert!(
        pointer_bits > 25000,
        "nonzero validity-qualified pointer coverage"
    );
}

#[test]
fn native_process_image_information_replays_suspended_child_metadata_profiles() {
    let records: Value = serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/specifications/windows/native-process-image-information/local-relocation-directory-29683-v1.json"))).unwrap();
    let fresh: Value = serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/specifications/windows/native-process-image-information/local-relocation-directory-29695-v1.json"))).unwrap();
    let mut admitted = 0;
    let mut rejected = 0;
    for record in records
        .as_array()
        .unwrap()
        .iter()
        .chain(fresh.as_array().unwrap().iter())
        .filter(|r| r["kind"] == "section-metadata")
    {
        if record["available"] == false {
            rejected += 1;
            assert_eq!(record["windows_error"], 193);
            assert_eq!(record["query_calls"], 0);
            continue;
        }
        admitted += 1;
        let arch = match record["arch"].as_str().unwrap() {
            "arm64" => WinArch::Arm64,
            "x64" => WinArch::X64,
            "x86" => WinArch::X86,
            _ => unreachable!(),
        };
        let profile = serde_json::json!({"rows":[record["host"],{"pe":record["pe_fields"],"section":record["section"]}],"file_bytes":record["file_bytes"],"profile":record["profile"]});
        let (mut process, mut thread, scratch) = setup(arch);
        let p = process.state_mut();
        install_metadata(p, arch, &profile);
        verify_metadata(p, &mut thread, scratch, arch, &profile);
    }
    assert_eq!(admitted, 20);
    assert_eq!(rejected, 4);
}
