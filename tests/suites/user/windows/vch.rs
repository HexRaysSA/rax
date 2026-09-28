//! Public VCH imports executed by freestanding PE32/PE32+ guests.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use rax::user::image::pe::{PeImage, dir, imports};
use rax::user::windows::WinArch;

fn root() -> PathBuf {
    super::fixtures().join("vch")
}

fn run(arch: &str) {
    let image = root().join(format!("bin/{arch}/vch.exe"));
    for slice in ["1", "4096"] {
        let output = super::cli_support::run(
            &[
                "--os",
                "windows",
                "--memory",
                "64M",
                "--slice",
                slice,
                "--seed",
                "1",
                image.to_str().unwrap(),
            ],
            &[("RAX_NO_JIT", "1")],
            None,
            Duration::from_secs(30),
        );
        assert_eq!(
            output.status,
            Some(0),
            "{arch} slice={slice}: stderr={:?}, stdout={:?}, signal={:?}",
            output.stderr,
            output.stdout,
            output.signal
        );
    }
}

#[test]
fn x86_public_vectored_continue_registration_removal() {
    run("x86");
}

#[test]
fn x64_public_vectored_continue_registration_removal() {
    run("x64");
}

#[test]
fn arm64_public_vectored_continue_registration_removal() {
    run("arm64");
}

#[test]
fn vch_source_tool_artifact_and_public_import_provenance() {
    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(root().join("manifest.toml")).unwrap()).unwrap();
    assert_eq!(manifest["expected_exit"].as_integer(), Some(0));
    assert!(
        manifest["oracle"]
            .as_str()
            .unwrap()
            .contains("no native Windows")
    );
    assert!(!manifest["clang"].as_str().unwrap().is_empty());
    assert!(!manifest["linker"].as_str().unwrap().is_empty());
    for key in ["clang_sha256", "linker_sha256", "dlltool_sha256"] {
        let hash = manifest[key].as_str().unwrap();
        assert_eq!(hash.len(), 64, "{key}");
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()), "{key}");
    }

    let sources = manifest["source"].as_array().unwrap();
    assert_eq!(sources.len(), 4);
    let mut found_sources = BTreeSet::new();
    for source in sources {
        let path = source["path"].as_str().unwrap();
        assert!(found_sources.insert(path), "duplicate source {path}");
        assert_eq!(
            super::sha256::hex(&std::fs::read(root().join(path)).unwrap()),
            source["sha256"].as_str().unwrap(),
            "{path}"
        );
    }
    assert_eq!(
        found_sources,
        BTreeSet::from([
            "build.sh",
            "src/vch.c",
            "src/kernel32.def",
            "src/kernel32-x86.def",
        ])
    );

    let entries = manifest["fixture"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    let mut found_arches = BTreeSet::new();
    for entry in entries {
        let arch = entry["arch"].as_str().unwrap();
        let expected_arch = match arch {
            "x86" => WinArch::X86,
            "x64" => WinArch::X64,
            "arm64" => WinArch::Arm64,
            _ => panic!("unknown fixture architecture {arch}"),
        };
        assert!(found_arches.insert(arch), "duplicate artifact for {arch}");
        let path = entry["path"].as_str().unwrap();
        assert_eq!(path, format!("bin/{arch}/vch.exe"));
        let bytes = std::fs::read(root().join(path)).unwrap();
        assert_eq!(bytes.len() as i64, entry["bytes"].as_integer().unwrap());
        assert_eq!(
            super::sha256::hex(&bytes),
            entry["sha256"].as_str().unwrap()
        );
        let pe = PeImage::parse(bytes).unwrap();
        assert_eq!(
            WinArch::from_machine(pe.headers().machine),
            Some(expected_arch)
        );
        assert_eq!(pe.headers().time_date_stamp, 0);
        assert_ne!(pe.headers().entry_rva, 0);
        let image = pe.memory_image();
        let descriptors =
            imports::descriptors(&image, pe.headers().directory(dir::IMPORT)).unwrap();
        assert_eq!(descriptors.len(), 1, "{path}: no CRT imports");
        assert_eq!(descriptors[0].dll_name(&image).unwrap(), b"kernel32.dll");
        let mut names = BTreeSet::new();
        for thunk in descriptors[0].thunks(&image, pe.headers().kind).unwrap() {
            if let imports::ImportRef::Name { name, .. } = thunk.symbol {
                names.insert(name);
            } else {
                panic!("{path}: ordinal-only import");
            }
        }
        assert_eq!(names.len(), 6, "{path}: exact public API surface");
        for name in [
            "ExitProcess",
            "RaiseException",
            "AddVectoredExceptionHandler",
            "RemoveVectoredExceptionHandler",
            "AddVectoredContinueHandler",
            "RemoveVectoredContinueHandler",
        ] {
            assert!(names.contains(name.as_bytes()), "{path}: missing {name}");
        }
    }
    assert_eq!(found_arches, BTreeSet::from(["x86", "x64", "arm64"]));
}
