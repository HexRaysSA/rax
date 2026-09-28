//! Freestanding PE32+ witness for guest-owned x64 JIT function tables.

use rax::user::image::pe::{PeImage, dir, imports};
use rax::user::windows::{ExitStatus, WinArch, WindowsConfig, WindowsProcess};

fn root() -> std::path::PathBuf {
    super::fixtures().join("dynamic_unwind_x64")
}

fn image() -> Vec<u8> {
    std::fs::read(root().join("bin/dynamic_unwind.exe")).unwrap()
}

#[test]
fn x64_dynamic_unwind_fixture_identity_and_imports() {
    let root = root();
    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(root.join("manifest.toml")).unwrap()).unwrap();
    assert_eq!(
        manifest["machine"].as_str(),
        Some("IMAGE_FILE_MACHINE_AMD64")
    );
    assert_eq!(manifest["expected_exit"].as_integer(), Some(0));
    let sources = manifest["source"].as_array().unwrap();
    assert_eq!(sources.len(), 4);
    let mut source_names = std::collections::BTreeSet::new();
    for source in sources {
        let path = source["path"].as_str().unwrap();
        assert!(source_names.insert(path));
        assert_eq!(
            super::sha256::hex(&std::fs::read(root.join(path)).unwrap()),
            source["sha256"].as_str().unwrap(),
            "{path}"
        );
    }
    assert_eq!(
        source_names,
        [
            "build.sh",
            "src/dynamic.S",
            "src/kernel32.def",
            "src/probe.c"
        ]
        .into_iter()
        .collect()
    );

    let fixtures = manifest["fixture"].as_array().unwrap();
    assert_eq!(fixtures.len(), 1);
    let entry = &fixtures[0];
    assert_eq!(entry["path"].as_str(), Some("bin/dynamic_unwind.exe"));
    let bytes = image();
    assert_eq!(bytes.len() as i64, entry["bytes"].as_integer().unwrap());
    assert_eq!(
        super::sha256::hex(&bytes),
        entry["sha256"].as_str().unwrap()
    );

    let pe = PeImage::parse(bytes).unwrap();
    assert_eq!(
        WinArch::from_machine(pe.headers().machine),
        Some(WinArch::X64)
    );
    assert_eq!(pe.headers().time_date_stamp, 0);
    assert_eq!(pe.headers().directory(dir::EXCEPTION).size, 0);
    let mapped = pe.memory_image();
    let unwind_header = [
        0x09, 0x05, 0x02, 0x00, 0x05, 0x52, 0x01, 0x30, 0x60, 0x00, 0x00, 0x00,
    ];
    assert_eq!(
        mapped
            .windows(unwind_header.len())
            .filter(|window| *window == unwind_header)
            .count(),
        1,
        "fixture carries exactly one version-1 EHANDLER unwind header"
    );
    let descriptors = imports::descriptors(&mapped, pe.headers().directory(dir::IMPORT)).unwrap();
    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0].dll_name(&mapped).unwrap(), b"KERNEL32.dll");
    let symbols: std::collections::BTreeSet<_> = descriptors[0]
        .thunks(&mapped, pe.headers().kind)
        .unwrap()
        .into_iter()
        .map(|thunk| match thunk.symbol {
            imports::ImportRef::Name { name, .. } => String::from_utf8(name).unwrap(),
            imports::ImportRef::Ordinal(_) => panic!("unexpected ordinal import"),
        })
        .collect();
    let declared: std::collections::BTreeSet<_> = manifest["imports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(symbols, declared);
    assert_eq!(symbols.len(), 7);
}

#[test]
fn x64_dynamic_table_unwinds_guest_owned_jit_code() {
    let bytes = image();
    for slice in [1, 4096] {
        let mut config = WindowsConfig::new(root().join("bin/dynamic_unwind.exe"), Vec::new());
        config.seed = Some(1);
        config.arena_bytes = 64 << 20;
        config.slice_insns = slice;
        let mut process = WindowsProcess::spawn_image(config, bytes.clone()).unwrap();
        assert_eq!(process.arch(), WinArch::X64);
        assert_eq!(process.run(), ExitStatus::Exited(0), "slice={slice}");
        assert_eq!(image(), bytes, "guest may not modify the fixture input");
    }
}
