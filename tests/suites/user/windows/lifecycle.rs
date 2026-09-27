//! Compiled native DLL lifecycle tests; no native Windows differential oracle.

use std::collections::BTreeSet;
use std::path::PathBuf;

use rax::user::image::pe::{
    IMAGE_FILE_DLL, IMAGE_SCN_MEM_EXECUTE, PeImage, RvaSource, dir, exports, imports, reloc,
    relocs, tls,
};
use rax::user::windows::layout::offsets;
use rax::user::windows::memory::Mem;
use rax::user::windows::{WinArch, WindowsProcess};

const ARTIFACTS: [&str; 10] = [
    "observer.dll",
    "leaf.dll",
    "root.dll",
    "fail.dll",
    "fail-ok.dll",
    "forward.dll",
    "data.exe",
    "dynamic.exe",
    "startup.exe",
    "forward-miss.exe",
];

fn root() -> PathBuf {
    super::fixtures().join("lifecycle")
}

struct Bundle {
    directory: PathBuf,
}

impl Bundle {
    fn new(arch: &str, program: &str, slice: &str) -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "rax-windows-lifecycle-{}-{arch}-{program}-{slice}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        for name in ARTIFACTS {
            std::fs::copy(
                root().join(format!("bin/{arch}/{name}")),
                directory.join(name),
            )
            .unwrap();
        }
        Self { directory }
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        for name in ARTIFACTS {
            let _ = std::fs::remove_file(self.directory.join(name));
        }
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn run(arch: &str, program: &str) {
    for slice in ["1", "4096"] {
        let bundle = Bundle::new(arch, program, slice);
        let image = bundle.directory.join(format!("{program}.exe"));
        let drive = format!("C={}", bundle.directory.display());
        let output = super::cli_support::run(
            &[
                "--os",
                "windows",
                "--memory",
                "64M",
                "--drive",
                &drive,
                "--cwd",
                "C:\\",
                "--slice",
                slice,
                "--seed",
                "1",
                image.to_str().unwrap(),
            ],
            &[("RAX_NO_JIT", "1")],
            None,
            std::time::Duration::from_secs(30),
        );
        assert_eq!(
            output.status,
            Some(0),
            "{arch} {program} slice={slice}: stderr={:?}, stdout={:?}, signal={:?}",
            output.stderr,
            output.stdout,
            output.signal
        );
        for name in ARTIFACTS {
            let expected = if program == "dynamic" && name == "fail.dll" {
                "fail-ok.dll"
            } else {
                name
            };
            assert_eq!(
                std::fs::read(bundle.directory.join(name)).unwrap(),
                std::fs::read(root().join(format!("bin/{arch}/{expected}"))).unwrap(),
                "{arch} {program} must only replace its temporary failed DLL"
            );
        }
    }
}

#[test]
fn x86_dynamic_native_dll_lifecycle() {
    run("x86", "dynamic");
}
#[test]
fn x64_dynamic_native_dll_lifecycle() {
    run("x64", "dynamic");
}
#[test]
fn arm64_dynamic_native_dll_lifecycle() {
    run("arm64", "dynamic");
}
#[test]
fn x86_missing_forwarder_export_rolls_back_fresh_target() {
    run("x86", "forward-miss");
}
#[test]
fn x64_missing_forwarder_export_rolls_back_fresh_target() {
    run("x64", "forward-miss");
}
#[test]
fn arm64_missing_forwarder_export_rolls_back_fresh_target() {
    run("arm64", "forward-miss");
}
#[test]
fn x86_compiled_dll_static_startup_and_process_detach() {
    run("x86", "startup");
}
#[test]
fn x64_compiled_dll_static_startup_and_process_detach() {
    run("x64", "startup");
}
#[test]
fn arm64_compiled_dll_static_startup_and_process_detach() {
    run("arm64", "startup");
}

fn import_names(pe: &PeImage) -> BTreeSet<Vec<u8>> {
    let image = pe.memory_image();
    imports::descriptors(&image, pe.headers().directory(dir::IMPORT))
        .unwrap()
        .into_iter()
        .map(|descriptor| descriptor.dll_name(&image).unwrap())
        .collect()
}

#[test]
fn lifecycle_sources_artifact_hashes_and_graph_are_verified() {
    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(root().join("manifest.toml")).unwrap()).unwrap();
    let sources = manifest["source"].as_array().unwrap();
    assert_eq!(sources.len(), 18);
    let mut paths = BTreeSet::new();
    for source in sources {
        let path = source["path"].as_str().unwrap();
        assert!(paths.insert(path), "duplicate source {path}");
        assert_eq!(
            super::sha256::hex(&std::fs::read(root().join(path)).unwrap()),
            source["sha256"].as_str().unwrap(),
            "{path}"
        );
    }
    assert!(paths.contains("build.sh") && paths.contains("src/common.h"));
    let fixtures = manifest["fixture"].as_array().unwrap();
    assert_eq!(fixtures.len(), 30);
    let mut found = BTreeSet::new();
    for fixture in fixtures {
        let path = fixture["path"].as_str().unwrap();
        let arch = fixture["arch"].as_str().unwrap();
        let expected_arch = match arch {
            "x86" => WinArch::X86,
            "x64" => WinArch::X64,
            "arm64" => WinArch::Arm64,
            _ => panic!("unknown fixture architecture {arch}"),
        };
        let name = path.strip_prefix(&format!("bin/{arch}/")).unwrap();
        assert!(ARTIFACTS.contains(&name));
        assert!(found.insert((arch, name)), "duplicate artifact {path}");
        let bytes = std::fs::read(root().join(path)).unwrap();
        assert_eq!(bytes.len() as i64, fixture["bytes"].as_integer().unwrap());
        assert_eq!(
            super::sha256::hex(&bytes),
            fixture["sha256"].as_str().unwrap()
        );
        let pe = PeImage::parse(bytes).unwrap();
        assert_eq!(
            WinArch::from_machine(pe.headers().machine),
            Some(expected_arch)
        );
        assert_eq!(pe.headers().time_date_stamp, 0);
        assert_eq!(
            pe.headers().characteristics & IMAGE_FILE_DLL != 0,
            name.ends_with(".dll")
        );
        let names = import_names(&pe);
        let expected: BTreeSet<Vec<u8>> = match name {
            "observer.dll" | "forward.dll" => BTreeSet::new(),
            "leaf.dll" | "dynamic.exe" | "forward-miss.exe" => {
                [b"KERNEL32.dll".to_vec(), b"observer.dll".to_vec()].into()
            }
            "root.dll" | "fail.dll" | "fail-ok.dll" => [
                b"KERNEL32.dll".to_vec(),
                b"observer.dll".to_vec(),
                b"leaf.dll".to_vec(),
            ]
            .into(),
            "startup.exe" => [
                b"KERNEL32.dll".to_vec(),
                b"observer.dll".to_vec(),
                b"root.dll".to_vec(),
            ]
            .into(),
            "data.exe" => [
                b"KERNEL32.dll".to_vec(),
                b"observer.dll".to_vec(),
                b"absent-lifecycle.dll".to_vec(),
            ]
            .into(),
            _ => unreachable!(),
        };
        assert_eq!(names, expected, "{path} imports");
        let image = pe.memory_image();
        if name == "forward.dll" {
            assert_eq!(pe.headers().entry_rva, 0);
            let exports =
                exports::ExportDirectory::read(&image, pe.headers().directory(dir::EXPORT))
                    .unwrap()
                    .unwrap();
            assert!(matches!(
                exports.by_name(&image, b"Probe", None).unwrap(),
                Some((_, exports::ExportTarget::Forwarder(target))) if target == b"leaf.Probe"
            ));
            assert!(matches!(
                exports.by_name(&image, b"Missing", None).unwrap(),
                Some((_, exports::ExportTarget::Forwarder(target))) if target == b"leaf.NoSuchExport"
            ));
        }
        if ["leaf.dll", "root.dll", "fail.dll", "fail-ok.dll"].contains(&name) {
            let h = pe.headers();
            assert_ne!(h.entry_rva, 0);
            let directory = tls::TlsDirectory::read(&image, h.kind, h.directory(dir::TLS))
                .unwrap()
                .unwrap();
            assert_eq!(directory.raw_size(), 4);
            assert_eq!(directory.size_of_zero_fill, 12);
            assert_eq!(directory.block_size(), 16);
            assert_eq!(directory.alignment(), Some(4));
            let callback_rva = directory
                .address_of_callbacks
                .checked_sub(h.image_base)
                .unwrap();
            let callbacks = tls::callbacks(&image, h.kind, callback_rva).unwrap();
            assert_eq!(callbacks.len(), 2);
            assert_ne!(callbacks[0], callbacks[1]);
            for callback in &callbacks {
                let rva = u32::try_from(callback.checked_sub(h.image_base).unwrap()).unwrap();
                assert_ne!(
                    pe.section_at(rva).unwrap().characteristics & IMAGE_SCN_MEM_EXECUTE,
                    0
                );
            }
            let fixups = relocs::fixups(&image, h.directory(dir::BASERELOC)).unwrap();
            let expected_kind = if expected_arch == WinArch::X86 {
                reloc::HIGHLOW
            } else {
                reloc::DIR64
            };
            let tls_rva = u64::from(h.directory(dir::TLS).rva);
            let width = expected_arch.ptr_size();
            for rva in (0..4)
                .map(|i| tls_rva + i * width)
                .chain((0..2).map(|i| callback_rva + i * width))
            {
                assert!(
                    fixups
                        .iter()
                        .any(|f| f.rva == rva && f.kind == expected_kind),
                    "{path} missing TLS VA relocation at {rva:#x}"
                );
            }
            let template_rva = directory.raw_data_start.checked_sub(h.image_base).unwrap();
            let id = if name == "leaf.dll" {
                1
            } else if name == "root.dll" {
                2
            } else {
                3
            };
            assert_eq!(image.u32_at(template_rva).unwrap(), 0x1357_0000 + id);
        } else {
            assert!(!pe.headers().directory(dir::TLS).is_present(), "{path}");
        }
    }
}

#[test]
fn compiled_static_tls_templates_are_installed_before_guest_startup() {
    for (arch, expected_arch) in [
        ("x86", WinArch::X86),
        ("x64", WinArch::X64),
        ("arm64", WinArch::Arm64),
    ] {
        let bundle = Bundle::new(arch, "startup-layout", "embedding");
        let process =
            WindowsProcess::spawn(super::config(bundle.directory.join("startup.exe"))).unwrap();
        assert_eq!(process.arch(), expected_arch);
        let p = process.state();
        let thread = p.threads.values().find(|thread| thread.main).unwrap();
        let o = offsets(expected_arch);
        assert_eq!(
            p.space.ptr(thread.teb + o.teb_tls_pointer, o.ptr).unwrap(),
            thread.tls_array
        );
        assert_eq!(p.modules.next_tls_index, 2);
        let mut indices = BTreeSet::new();
        for (name, id) in [("leaf.dll", 1), ("root.dll", 2)] {
            let index = p.modules.by_name(name).unwrap();
            let module = &p.modules.list[index];
            let tls = module.tls.unwrap();
            assert!(indices.insert(tls.index));
            let block = p
                .space
                .ptr(thread.tls_array + o.ptr * u64::from(tls.index), o.ptr)
                .unwrap();
            assert!(thread.tls_blocks.contains(&block));
            assert_eq!(p.space.u32(block).unwrap(), 0x1357_0000 + id);
            for offset in [4, 8, 12] {
                assert_eq!(p.space.u32(block + offset).unwrap(), 0);
            }
            let bytes = std::fs::read(bundle.directory.join(name)).unwrap();
            assert_ne!(
                module.base,
                PeImage::parse(bytes).unwrap().headers().image_base,
                "observer's shared preferred base forces relocation"
            );
        }
    }
}
