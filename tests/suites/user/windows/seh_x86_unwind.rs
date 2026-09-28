//! Freestanding PE32 x86 unwind continuation through the public import table.

use rax::user::windows::{ExitStatus, WindowsConfig, WindowsProcess};

fn fixture() -> std::path::PathBuf {
    super::fixtures().join("seh_x86")
}

#[test]
fn rtl_unwind_fixture_provenance() {
    let root = fixture();
    let metadata: toml::Value =
        toml::from_str(&std::fs::read_to_string(root.join("manifest.toml")).unwrap()).unwrap();
    let image = std::fs::read(root.join("bin/unwind.exe")).unwrap();
    assert_eq!(
        super::sha256::hex(&std::fs::read(root.join("src/unwind.S")).unwrap()),
        metadata["source_sha256"].as_str().unwrap()
    );
    assert_eq!(
        super::sha256::hex(&std::fs::read(root.join("src/kernel32.def")).unwrap()),
        metadata["def_sha256"].as_str().unwrap()
    );
    assert_eq!(
        super::sha256::hex(&image),
        metadata["image_sha256"].as_str().unwrap()
    );
    assert_eq!(
        image.len() as i64,
        metadata["image_bytes"].as_integer().unwrap()
    );
    assert_eq!(metadata["expected_status"].as_integer(), Some(0));
}

#[test]
fn rtl_unwind_inner_cleanup_and_target_continuation() {
    let image = fixture().join("bin/unwind.exe");
    for slice in [1, 4096] {
        let mut config = WindowsConfig::new(&image, Vec::new());
        config.seed = Some(1);
        config.arena_bytes = 64 << 20;
        config.slice_insns = slice;
        let mut process = WindowsProcess::spawn(config).unwrap();
        assert_eq!(process.run(), ExitStatus::Exited(0), "slice={slice}");
    }
}
