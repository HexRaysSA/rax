use super::*;
use crate::user::image::pe::hybrid::{CodeRange, EntryRange, Redirection};
use crate::user::windows::process::{WindowsConfig, WindowsProcess};

#[test]
fn oversized_supplied_image_metadata_does_not_expand_before_arena_admission() {
    let mut bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/user/windows/bin/x64/smoke.exe"
    ))
    .to_vec();
    let nt = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    bytes[nt + 80..nt + 84].copy_from_slice(&0xFFFF_F000u32.to_le_bytes());
    assert!(bytes.len() < 64 << 10);
    let pe = PeImage::parse(bytes.clone()).unwrap();
    assert!(decode(&pe).unwrap().is_none());
    let mut config = WindowsConfig::embedded("C:\\large-image.exe", vec![], vec![], 4096).unwrap();
    config.arena_bytes = 64 << 20;
    let error = WindowsProcess::spawn_image(config, bytes)
        .err()
        .expect("arena admission must fail");
    assert!(
        matches!(
            error,
            crate::user::windows::process::SpawnError::Load {
                status: STATUS_COMMITMENT_LIMIT,
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn module_code_ranges_admit_only_the_current_isa_and_ignore_unloaded_modules() {
    let input = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/user/windows/bin/x64/smoke.exe"
    ));
    let config = WindowsConfig::embedded("C:\\hybrid-range.exe", vec![], vec![], 4096).unwrap();
    let mut process = WindowsProcess::spawn_image(config, input.to_vec()).unwrap();
    let p = process.state_mut();
    let base = p.modules.list[0].base;
    p.modules.list[0].hybrid = Some(Arc::new(HybridMetadata {
        version: 2,
        code: vec![
            CodeRange {
                start: 0x1000,
                end: 0x1010,
                kind: CodeKind::Amd64,
            },
            CodeRange {
                start: 0x1010,
                end: 0x1020,
                kind: CodeKind::Arm64Ec,
            },
            CodeRange {
                start: 0x1020,
                end: 0x1030,
                kind: CodeKind::Arm64,
            },
        ],
        entries: Vec::<EntryRange>::new(),
        redirections: Vec::<Redirection>::new(),
        dispatch_slots: [0; 5],
        alternate_entry: 0,
    }));
    assert!(p.modules.has_hybrid_code());
    for (arch, offset, accepted) in [
        (WinArch::X64, 0x1000, true),
        (WinArch::X64, 0x100F, true),
        (WinArch::X64, 0x1010, false),
        (WinArch::X64, 0x1020, false),
        (WinArch::Arm64, 0x1020, true),
        (WinArch::Arm64, 0x102F, true),
        (WinArch::Arm64, 0x1010, false),
        (WinArch::Arm64, 0x1000, false),
        (WinArch::X86, 0x1000, false),
        (WinArch::X64, 0x1030, false),
    ] {
        assert_eq!(
            p.modules.check_instruction(arch, base + offset).is_ok(),
            accepted,
            "{arch} RVA {offset:#x}"
        );
    }
    p.modules.failed_indices.insert(
        0,
        LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "fixture unloaded"),
    );
    assert!(!p.modules.has_hybrid_code());
    assert!(
        p.modules
            .check_instruction(WinArch::X64, base + 0x1010)
            .is_ok()
    );
}
