//! Compiler-produced ARM64 PE registering unwind metadata for anonymous code.

use rax::user::image::pe::{PeImage, dir, imports};
use rax::user::windows::{ExitStatus, WinArch, WindowsConfig, WindowsProcess};

fn root() -> std::path::PathBuf {
    super::fixtures().join("dynamic_unwind_arm64")
}

fn fixture() -> Vec<u8> {
    std::fs::read(root().join("bin/arm64/dynamic.exe")).unwrap()
}

#[test]
fn anonymous_arm64_full_xdata_handler_and_continuation() {
    let bytes = fixture();
    for slice in [1, 4096] {
        let mut config = WindowsConfig::new(root().join("bin/arm64/dynamic.exe"), Vec::new());
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
fn anonymous_arm64_fixture_provenance_and_metadata() {
    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(root().join("manifest.toml")).unwrap()).unwrap();
    let sources = manifest["source"].as_array().unwrap();
    assert_eq!(sources.len(), 4);
    let mut names = Vec::new();
    for source in sources {
        let path = source["path"].as_str().unwrap();
        names.push(path);
        assert_eq!(
            super::sha256::hex(&std::fs::read(root().join(path)).unwrap()),
            source["sha256"].as_str().unwrap(),
            "{path}"
        );
    }
    names.sort_unstable();
    assert_eq!(
        names,
        ["build.sh", "src/entry.c", "src/jit.S", "src/kernel32.def"]
    );
    let fixtures = manifest["fixture"].as_array().unwrap();
    assert_eq!(fixtures.len(), 1);
    let item = &fixtures[0];
    assert_eq!(item["path"].as_str(), Some("bin/arm64/dynamic.exe"));
    assert_eq!(item["expected_exit"].as_integer(), Some(0));
    let bytes = fixture();
    assert_eq!(bytes.len() as i64, item["bytes"].as_integer().unwrap());
    assert_eq!(super::sha256::hex(&bytes), item["sha256"].as_str().unwrap());

    let pe = PeImage::parse(bytes).unwrap();
    assert_eq!(
        WinArch::from_machine(pe.headers().machine),
        Some(WinArch::Arm64)
    );
    assert_eq!(pe.headers().time_date_stamp, 0);
    let image = pe.memory_image();
    let descriptors = imports::descriptors(&image, pe.headers().directory(dir::IMPORT)).unwrap();
    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0].dll_name(&image).unwrap(), b"KERNEL32.dll");
    let symbols: Vec<_> = descriptors[0]
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
            imports::ImportRef::Name {
                hint: 0,
                name: b"RtlAddFunctionTable".to_vec()
            },
            imports::ImportRef::Name {
                hint: 0,
                name: b"RtlDeleteFunctionTable".to_vec()
            },
            imports::ImportRef::Name {
                hint: 0,
                name: b"RtlLookupFunctionEntry".to_vec()
            },
            imports::ImportRef::Name {
                hint: 0,
                name: b"VirtualAlloc".to_vec()
            },
            imports::ImportRef::Name {
                hint: 0,
                name: b"VirtualProtect".to_vec()
            },
        ]
    );

    // The source PE's function supplies the full .xdata record copied by
    // the guest.  The actual registration table is built in anonymous memory.
    let pdata = pe.headers().directory(dir::EXCEPTION);
    assert_eq!(pdata.size, 8, "one 8-byte ARM64 function entry");
    let at = pdata.rva as usize;
    let word = |at: usize| u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
    let begin = word(at);
    let xdata = word(at + 4);
    assert_eq!(xdata & 3, 0, "full .xdata, not packed metadata");
    let header = word(xdata as usize);
    assert_eq!((header >> 18) & 3, 0, "version 0");
    assert_ne!(header & (1 << 20), 0, "handler-bearing record");
    assert_ne!(header & (1 << 21), 0, "single packed epilog");
    assert_eq!((header >> 27) & 31, 1, "one unwind-code word");
    assert_eq!(
        &image[xdata as usize + 4..xdata as usize + 8],
        &[0xE1, 0x81, 0xE4, 0xE3]
    );
    let handler = word(xdata as usize + 8);
    assert!(handler > begin && handler < begin + 0x100);
    assert_eq!(word(xdata as usize + 12), 0);
}
