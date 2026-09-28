//! Real ARM64 PE unwind metadata using the selected non-PAuth CPU profile.

use rax::user::image::pe::{PeImage, dir, imports};
use rax::user::windows::{ExitStatus, WinArch, WindowsConfig, WindowsProcess};

fn root() -> std::path::PathBuf {
    super::fixtures().join("arm64_pac_unwind")
}

fn fixture() -> Vec<u8> {
    std::fs::read(root().join("bin/arm64/pac.exe")).unwrap()
}

#[test]
fn pac_marked_arm64_frame_search_and_resume() {
    let bytes = fixture();
    for slice in [1, 4096] {
        let mut config = WindowsConfig::new(root().join("bin/arm64/pac.exe"), Vec::new());
        config.seed = Some(1);
        config.arena_bytes = 64 << 20;
        config.slice_insns = slice;
        let mut process = WindowsProcess::spawn_image(config, bytes.clone()).unwrap();
        assert_eq!(process.arch(), WinArch::Arm64);
        assert_eq!(process.run(), ExitStatus::Exited(0), "slice={slice}");
        assert_eq!(fixture(), bytes, "guest may not modify the fixture input");
    }
}

#[test]
fn pac_marked_arm64_fixture_identity_and_both_metadata_forms() {
    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(root().join("manifest.toml")).unwrap()).unwrap();
    let sources = manifest["source"].as_array().unwrap();
    assert_eq!(sources.len(), 3);
    for source in sources {
        let path = source["path"].as_str().unwrap();
        assert!(["build.sh", "src/kernel32.def", "src/pac.S"].contains(&path));
        assert_eq!(
            super::sha256::hex(&std::fs::read(root().join(path)).unwrap()),
            source["sha256"].as_str().unwrap(),
            "{path}"
        );
    }
    let fixtures = manifest["fixture"].as_array().unwrap();
    assert_eq!(fixtures.len(), 1);
    let entry = &fixtures[0];
    assert_eq!(entry["path"].as_str(), Some("bin/arm64/pac.exe"));
    assert_eq!(entry["expected_exit"].as_integer(), Some(0));
    let bytes = fixture();
    assert_eq!(bytes.len() as i64, entry["bytes"].as_integer().unwrap());
    assert_eq!(
        super::sha256::hex(&bytes),
        entry["sha256"].as_str().unwrap()
    );

    let pe = PeImage::parse(bytes).unwrap();
    assert_eq!(
        WinArch::from_machine(pe.headers().machine),
        Some(WinArch::Arm64)
    );
    assert_eq!(pe.headers().time_date_stamp, 0);
    let image = pe.memory_image();
    let imports = imports::descriptors(&image, pe.headers().directory(dir::IMPORT)).unwrap();
    assert_eq!(imports.len(), 1);
    assert_eq!(imports[0].dll_name(&image).unwrap(), b"KERNEL32.dll");
    let symbols: Vec<_> = imports[0]
        .thunks(&image, pe.headers().kind)
        .unwrap()
        .into_iter()
        .map(|thunk| thunk.symbol)
        .collect();
    assert_eq!(
        symbols,
        [
            imports::ImportRef::Name {
                hint: 0,
                name: b"ExitProcess".to_vec()
            },
            imports::ImportRef::Name {
                hint: 0,
                name: b"RaiseException".to_vec()
            },
        ]
    );

    let table = pe.headers().directory(dir::EXCEPTION);
    assert_eq!(table.size, 16, "exactly two ARM64 .pdata entries");
    let rva = table.rva as usize;
    let word = |at: usize| u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
    let full = word(rva + 4);
    let packed = word(rva + 12);
    assert_eq!(full & 3, 0, "handler-bearing frame has full .xdata");
    assert_eq!(
        &image[full as usize + 4..full as usize + 8],
        &[0xE1, 0x81, 0xFC, 0xE4]
    );
    assert_eq!(packed & 3, 1, "inner frame uses packed metadata");
    assert_eq!((packed >> 21) & 3, 2, "packed frame is PAC-signed CR=2");
}
