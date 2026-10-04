//! Windows PE process, calling-convention, and memory integration tests.
#![cfg(unix)]

use std::path::PathBuf;

use rax::user::image::pe::{PeImage, dir, imports};
use rax::user::windows::nt::status::{
    STATUS_COMMITMENT_LIMIT, STATUS_INVALID_IMAGE_FORMAT, STATUS_NO_MEMORY, STATUS_NOT_IMPLEMENTED,
};
use rax::user::windows::{ExitStatus, SpawnError, WinArch, WindowsConfig, WindowsProcess};

#[path = "../linux/support.rs"]
mod cli_support;
#[path = "../linux/sha256.rs"]
mod sha256;

#[path = "lifecycle.rs"]
mod lifecycle;

#[path = "fibers.rs"]
mod fibers;

#[path = "crt.rs"]
mod crt;

#[path = "crt_init.rs"]
mod crt_init;

#[path = "crt_startup.rs"]
mod crt_startup;

#[path = "crt_onexit.rs"]
mod crt_onexit;

#[path = "crt_stdio.rs"]
mod crt_stdio;

#[path = "crt_termination.rs"]
mod crt_termination;

#[path = "crt_exit.rs"]
mod crt_exit;

#[path = "crt_bootstrap.rs"]
mod crt_bootstrap;

#[path = "crt_normal_exit.rs"]
mod crt_normal_exit;

#[path = "seh_x86_unwind.rs"]
mod seh_x86_unwind;

#[path = "arm64_pac_unwind.rs"]
mod arm64_pac_unwind;

#[path = "dynamic_unwind_x64.rs"]
mod dynamic_unwind_x64;

#[path = "arm64_dynamic_unwind.rs"]
mod arm64_dynamic_unwind;

#[path = "vch.rs"]
mod vch;

#[path = "slist.rs"]
mod slist;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/user/windows")
}

fn binary(arch: &str) -> PathBuf {
    fixtures().join(format!("bin/{arch}/smoke.exe"))
}

fn config(path: PathBuf) -> WindowsConfig {
    let mut config = WindowsConfig::new(path, Vec::new());
    config.seed = Some(0xD159_6475_1FCE_4921);
    config.arena_bytes = 64 << 20;
    config
}

struct TemporaryImage {
    directory: PathBuf,
    path: PathBuf,
}

impl TemporaryImage {
    fn new(case: &str, bytes: &[u8]) -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("rax-windows-{}-{case}-{stamp}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("image.exe");
        std::fs::write(&path, bytes).unwrap();
        Self { directory, path }
    }
}

impl Drop for TemporaryImage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.directory.join("rax-services.dat"));
        let _ = std::fs::remove_file(self.directory.join("rax-services-exit.dat"));
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn smoke(name: &str, expected_arch: WinArch) {
    let mut process = WindowsProcess::spawn(config(binary(name)))
        .unwrap_or_else(|error| panic!("{name} process construction: {error}"));
    assert_eq!(process.arch(), expected_arch);
    assert_eq!(process.run(), ExitStatus::Exited(0), "{name} smoke fixture");
}

#[test]
fn freestanding_x86_windows_process_and_memory() {
    smoke("x86", WinArch::X86);
}

#[test]
fn freestanding_x64_windows_process_and_memory() {
    smoke("x64", WinArch::X64);
}

#[test]
fn freestanding_arm64_windows_process_and_memory() {
    smoke("arm64", WinArch::Arm64);
}

fn services(arch: &str) {
    let bytes = std::fs::read(fixtures().join(format!("bin/{arch}/services.exe"))).unwrap();
    let temp = TemporaryImage::new(&format!("services-{arch}"), &bytes);
    let drive = format!("C={}", temp.directory.display());
    let image = temp.path.to_str().unwrap();
    for slice in ["1", "4096"] {
        let output = cli_support::run(
            &[
                "--os", "windows", "--memory", "64M", "--drive", &drive, "--cwd", "C:\\",
                "--slice", slice, "--seed", "1", image,
            ],
            &[("RAX_NO_JIT", "1")],
            None,
            std::time::Duration::from_secs(30),
        );
        assert_eq!(
            output.status,
            Some(0),
            "{arch} slice={slice}: stderr={:?}, stdout={:?}, signal={:?}",
            output.stderr,
            output.stdout,
            output.signal
        );
        assert!(
            !temp.directory.join("rax-services.dat").exists(),
            "final independent file close must complete deferred deletion"
        );
        assert!(
            !temp.directory.join("rax-services-exit.dat").exists(),
            "ExitProcess must close file handles and complete delete-on-close"
        );
        assert_eq!(
            std::fs::read(&temp.path).unwrap(),
            bytes,
            "input image is unchanged"
        );
    }
}

#[test]
fn x86_guest_threads_locks_apcs_and_files() {
    services("x86");
}
#[test]
fn x64_guest_threads_locks_apcs_and_files() {
    services("x64");
}
#[test]
fn arm64_guest_threads_locks_apcs_and_files() {
    services("arm64");
}

#[test]
fn service_fixture_sources_hashes_and_single_import_dll_are_verified() {
    let text = std::fs::read_to_string(fixtures().join("services-manifest.toml")).unwrap();
    let manifest: toml::Value = toml::from_str(&text).unwrap();
    let sources = manifest["source"].as_array().unwrap();
    assert_eq!(sources.len(), 4);
    for source in sources {
        let path = source["path"].as_str().unwrap();
        assert_eq!(
            sha256::hex(&std::fs::read(fixtures().join(path)).unwrap()),
            source["sha256"].as_str().unwrap(),
            "{path}"
        );
    }
    let entries = manifest["fixture"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    for entry in entries {
        let path = entry["path"].as_str().unwrap();
        let bytes = std::fs::read(fixtures().join(path)).unwrap();
        assert_eq!(
            sha256::hex(&bytes),
            entry["sha256"].as_str().unwrap(),
            "{path}"
        );
        assert_eq!(bytes.len() as i64, entry["bytes"].as_integer().unwrap());
        let pe = PeImage::parse(bytes).unwrap();
        let image = pe.memory_image();
        let descriptors =
            imports::descriptors(&image, pe.headers().directory(dir::IMPORT)).unwrap();
        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].dll_name(&image).unwrap(), b"KERNEL32.dll");
        let thunks = descriptors[0].thunks(&image, pe.headers().kind).unwrap();
        assert!(
            thunks.len() >= 50,
            "services must not be optimized out of the fixture"
        );
    }
}

#[test]
fn retained_service_primary_sources_match_their_provenance_hashes() {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/specifications/windows/services");
    for group in ["thread-sync", "locks", "file", "dll-lifecycle", "fibers"] {
        let folder = root.join(group);
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(folder.join("sources.json")).unwrap()).unwrap();
        let entries = manifest["sources"]
            .as_array()
            .or_else(|| manifest["files"].as_array())
            .unwrap();
        assert!(!entries.is_empty(), "{group} primary sources are required");
        for entry in entries {
            let path = entry["path"]
                .as_str()
                .or_else(|| entry["file"].as_str())
                .unwrap();
            let content = std::fs::read(folder.join(path)).unwrap();
            assert_eq!(
                sha256::hex(&content),
                entry["sha256"].as_str().unwrap(),
                "{group}/{path}"
            );
        }
    }
}

#[test]
fn retained_crt_primary_contracts_and_auxiliary_hashes_are_verified() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("docs/specifications/windows/crt-foundation");
    for (name, primary_count) in [("manifest-alloc.json", 21), ("manifest-memory.json", 19)] {
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join(name)).unwrap()).unwrap();
        assert_eq!(manifest["sources"].as_array().unwrap().len(), primary_count);
        let mut paths = std::collections::HashSet::new();
        for entry in manifest["sources"]
            .as_array()
            .unwrap()
            .iter()
            .chain(manifest["auxiliary"].as_array().into_iter().flatten())
        {
            let path = entry["path"].as_str().unwrap();
            assert!(paths.insert(path), "{name}: duplicate retained path {path}");
            assert_eq!(
                sha256::hex(&std::fs::read(root.join(path)).unwrap()),
                entry["sha256"].as_str().unwrap(),
                "{name}: {path}"
            );
        }
    }
}

fn cli_smoke(arch: &str) {
    let path = binary(arch);
    let program = path.to_str().expect("fixture path is UTF-8");
    for personality in ["auto", "windows"] {
        let output = cli_support::run(
            &[
                "--os",
                personality,
                "--memory",
                "64M",
                "--seed",
                "123",
                program,
            ],
            &[],
            None,
            std::time::Duration::from_secs(30),
        );
        assert_eq!(
            output.status,
            Some(0),
            "{arch} --os {personality}: stderr={:?}, stdout={:?}, signal={:?}",
            output.stderr,
            output.stdout,
            output.signal
        );
    }
}

#[test]
fn cli_auto_detects_and_explicitly_selects_x86_windows() {
    cli_smoke("x86");
}

#[test]
fn cli_auto_detects_and_explicitly_selects_x64_windows() {
    cli_smoke("x64");
}

#[test]
fn cli_auto_detects_and_explicitly_selects_arm64_windows() {
    cli_smoke("arm64");
}

#[test]
fn cli_rejects_invalid_drive_and_linux_personality_for_pe() {
    let path = binary("x64");
    let program = path.to_str().expect("fixture path is UTF-8");
    for (options, diagnostic) in [
        (vec!["--drive", "invalid"], "invalid drive mapping"),
        (vec!["--os", "linux"], "ELF"),
    ] {
        let mut args = options;
        args.push(program);
        let output = cli_support::run(&args, &[], None, std::time::Duration::from_secs(30));
        assert_eq!(output.status, Some(126), "{args:?}: {output:?}");
        assert!(
            output.stderr.contains(diagnostic),
            "{args:?}: expected {diagnostic:?}, stderr={:?}",
            output.stderr
        );
    }
}

#[test]
fn supplied_image_bytes_are_not_reread_from_the_executable_path() {
    // A different on-disk architecture proves spawn_image uses the supplied
    // bytes rather than reading the configured x64 executable a second time.
    let bytes = std::fs::read(binary("x86")).unwrap();
    let mut process = WindowsProcess::spawn_image(config(binary("x64")), bytes)
        .unwrap_or_else(|error| panic!("supplied image process construction: {error}"));
    assert_eq!(process.arch(), WinArch::X86);
    assert_eq!(process.run(), ExitStatus::Exited(0));
}

#[test]
fn hostile_stack_sizes_and_small_arenas_fail_without_panicking() {
    fn rejected(config: WindowsConfig, bytes: Vec<u8>, case: &str) {
        let error = WindowsProcess::spawn_image(config, bytes)
            .err()
            .unwrap_or_else(|| panic!("{case} must not construct a process"));
        assert!(
            matches!(
                &error,
                SpawnError::BadImage(_) | SpawnError::Load { .. } | SpawnError::Memory(_)
            ),
            "{case}: unexpected startup error: {error}"
        );
    }
    let source = std::fs::read(binary("x64")).unwrap();
    let nt = u32::from_le_bytes(source[0x3C..0x40].try_into().unwrap()) as usize;
    let mut hostile = source.clone();
    // PE32+: COFF header is 20 bytes; SizeOfStackReserve is optional+72.
    let reserve = nt + 4 + 20 + 72;
    hostile[reserve..reserve + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    rejected(config(binary("x64")), hostile, "u64::MAX stack reservation");
    let mut small = config(binary("x64"));
    small.arena_bytes = 0x1000;
    rejected(small, source, "4096-byte arena");
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn optional_header(bytes: &[u8]) -> usize {
    u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize + 24
}

fn rejected_invalid_image(bytes: Vec<u8>, case: &str) {
    let error = WindowsProcess::spawn_image(config(binary("x64")), bytes)
        .err()
        .unwrap_or_else(|| panic!("{case}: malformed-present image metadata was ignored"));
    assert!(
        matches!(&error, SpawnError::Load { status, .. } if *status == STATUS_INVALID_IMAGE_FORMAT),
        "{case}: expected invalid image, got {error}"
    );
}

#[test]
fn malformed_present_tls_is_rejected_before_thread_start() {
    let source = std::fs::read(binary("x64")).unwrap();
    let pe = PeImage::parse(source.clone()).unwrap();
    let base = pe.headers().image_base;
    let size = pe.headers().size_of_image;
    let directory = optional_header(&source) + 112 + 8 * dir::TLS;
    for case in [
        "unreadable-directory",
        "short-directory",
        "invalid-index",
        "foreign-index",
        "reversed-template",
        "foreign-template",
        "invalid-callback-array",
    ] {
        let mut bytes = source.clone();
        // TLS64 fits in unused header padding, as does its valid index.
        put32(&mut bytes, directory, 0x340);
        put32(&mut bytes, directory + 4, 40);
        put64(&mut bytes, 0x350, base + 0x368);
        match case {
            "unreadable-directory" => put32(&mut bytes, directory, size),
            "short-directory" => put32(&mut bytes, directory + 4, 1),
            "invalid-index" => put64(&mut bytes, 0x350, u64::MAX),
            "foreign-index" => put64(&mut bytes, 0x350, 0x7FFD_F000),
            "reversed-template" => {
                put64(&mut bytes, 0x340, base + 0x380);
                put64(&mut bytes, 0x348, base + 0x370);
            }
            "foreign-template" => {
                put64(&mut bytes, 0x340, 0x7FFD_F000);
                put64(&mut bytes, 0x348, 0x7FFD_F001);
            }
            "invalid-callback-array" => put64(&mut bytes, 0x358, u64::MAX),
            _ => unreachable!(),
        }
        rejected_invalid_image(bytes, case);
    }
}

#[test]
fn malformed_present_load_configuration_is_rejected() {
    let source = std::fs::read(binary("x64")).unwrap();
    let pe = PeImage::parse(source.clone()).unwrap();
    let directory = optional_header(&source) + 112 + 8 * dir::LOAD_CONFIG;
    for case in [
        "unreadable-directory",
        "short-directory",
        "invalid-cookie",
        "foreign-cookie",
    ] {
        let mut bytes = source.clone();
        put32(&mut bytes, directory, 0x300);
        put32(&mut bytes, directory + 4, 96);
        put32(&mut bytes, 0x300, 96);
        match case {
            "unreadable-directory" => put32(&mut bytes, directory, pe.headers().size_of_image),
            "short-directory" => put32(&mut bytes, directory + 4, 1),
            "invalid-cookie" => put64(&mut bytes, 0x358, u64::MAX),
            "foreign-cookie" => put64(&mut bytes, 0x358, 0x7FFD_F000),
            _ => unreachable!(),
        }
        rejected_invalid_image(bytes, case);
    }
}

#[test]
fn valid_empty_tls_and_default_security_cookie_are_initialized() {
    let mut bytes = std::fs::read(binary("x64")).unwrap();
    let base = PeImage::parse(bytes.clone()).unwrap().headers().image_base;
    let optional = optional_header(&bytes);
    put32(&mut bytes, optional + 112 + 8 * dir::TLS, 0x340);
    put32(&mut bytes, optional + 116 + 8 * dir::TLS, 40);
    put64(&mut bytes, 0x350, base + 0x368);
    let mut process = WindowsProcess::spawn_image(config(binary("x64")), bytes).unwrap();
    assert_eq!(process.state().modules.exe().tls.unwrap().index, 0);
    assert_eq!(process.run(), ExitStatus::Exited(0));

    let mut bytes = std::fs::read(binary("x64")).unwrap();
    put32(&mut bytes, optional + 112 + 8 * dir::LOAD_CONFIG, 0x300);
    put32(&mut bytes, optional + 116 + 8 * dir::LOAD_CONFIG, 96);
    put32(&mut bytes, 0x300, 96);
    put64(&mut bytes, 0x358, base + 0x380);
    put64(&mut bytes, 0x380, 0x0000_2B99_2DDF_A232);
    let mut process = WindowsProcess::spawn_image(config(binary("x64")), bytes).unwrap();
    use rax::user::windows::memory::Mem;
    let cookie = process.state().space.u64(base + 0x380).unwrap();
    assert_ne!(cookie, 0);
    assert_ne!(cookie, 0x0000_2B99_2DDF_A232);
    assert_eq!(cookie >> 48, 0);
    assert_eq!(process.run(), ExitStatus::Exited(0));
}

#[test]
fn exhausted_loader_allocator_returns_an_error_without_host_panic() {
    let mut small = config(binary("x64"));
    small.arena_bytes = 4 << 20;
    let mut process = WindowsProcess::spawn(small).unwrap();
    let state = process.state_mut();
    let heap = state.process_heap;
    // Drain all usable fragments without allocating millions of tiny blocks.
    for size in [1 << 20, 4096, 256, 16] {
        while state
            .heaps
            .alloc(&mut state.vm, heap, size, false)
            .is_some()
        {}
    }
    let error = rax::user::windows::loader::ldr::init(state).unwrap_err();
    assert_eq!(error.status, STATUS_NO_MEMORY);
}

#[test]
fn loader_names_cannot_truncate_their_unicode_string_lengths() {
    let mut process = WindowsProcess::spawn(config(binary("x64"))).unwrap();
    let state = process.state_mut();
    state.modules.list[0].path = "A".repeat(0x8000);
    let error = rax::user::windows::loader::ldr::add_entry(state, 0).unwrap_err();
    assert_eq!(error.status, STATUS_INVALID_IMAGE_FORMAT);
}

#[test]
fn mandatory_loader_peb_write_failure_is_reported() {
    use rax::user::windows::memory::prot;
    let mut process = WindowsProcess::spawn(config(binary("x64"))).unwrap();
    let state = process.state_mut();
    state.vm.protect(state.peb, 0x1000, prot::NOACCESS).unwrap();
    let error = rax::user::windows::loader::ldr::init(state).unwrap_err();
    assert_eq!(error.status, STATUS_NO_MEMORY);
}

#[test]
fn iat_slots_cannot_write_another_guest_allocation() {
    let mut bytes = std::fs::read(binary("x64")).unwrap();
    let pe = PeImage::parse(bytes.clone()).unwrap();
    let descriptor = pe
        .rva_to_file_offset(pe.headers().directory(dir::IMPORT).rva)
        .unwrap() as usize;
    // This position-independent fixture remains executable at a low base.
    // The hostile IAT RVA then addresses the already mapped PEB instead
    // of unmapped memory: a global mapping check alone would accept it.
    let optional = optional_header(&bytes);
    put64(&mut bytes, optional + 24, 0x0040_0000);
    put32(&mut bytes, descriptor + 16, 0x7FFD_F000 - 0x0040_0000);
    rejected_invalid_image(bytes, "foreign IAT");
}

fn allocation_ranges(process: &WindowsProcess) -> Vec<(u64, u64)> {
    process
        .state()
        .vm
        .allocations()
        .map(|a| (a.base, a.size))
        .collect()
}

#[test]
fn failed_relocation_releases_its_image_reservation() {
    let mut process = WindowsProcess::spawn(config(binary("x64"))).unwrap();
    let mut bytes = std::fs::read(binary("x64")).unwrap();
    let optional = optional_header(&bytes);
    put32(&mut bytes, optional + 112 + 8 * dir::BASERELOC, 0x300);
    put32(&mut bytes, optional + 116 + 8 * dir::BASERELOC, 8);
    put32(&mut bytes, 0x304, 7); // Block cannot be shorter than its header.
    let pe = PeImage::parse(bytes).unwrap();
    let before = allocation_ranges(&process);
    let error = rax::user::windows::loader::load_exe(
        process.state_mut(),
        &pe,
        &binary("x64"),
        "bad-relocations.exe".into(),
    )
    .unwrap_err();
    assert_eq!(error.status, STATUS_INVALID_IMAGE_FORMAT);
    assert_eq!(allocation_ranges(&process), before);
}

#[test]
fn failed_image_commit_releases_its_reservation() {
    let mut small = config(binary("x64"));
    small.arena_bytes = 4 << 20;
    let mut process = WindowsProcess::spawn(small).unwrap();
    let mut bytes = std::fs::read(binary("x64")).unwrap();
    let optional = optional_header(&bytes);
    put64(&mut bytes, optional + 24, 0x0000_0001_5000_0000);
    put32(&mut bytes, optional + 56, 4 << 20);
    let pe = PeImage::parse(bytes).unwrap();
    let before = allocation_ranges(&process);
    let error = rax::user::windows::loader::load_exe(
        process.state_mut(),
        &pe,
        &binary("x64"),
        "over-budget.exe".into(),
    )
    .unwrap_err();
    assert_eq!(error.status, STATUS_COMMITMENT_LIMIT);
    assert_eq!(allocation_ranges(&process), before);
}

#[test]
fn x86_allocation_ceiling_depends_on_large_address_aware_flag() {
    use rax::user::windows::memory::{AllocKind, prot};
    let source = std::fs::read(binary("x86")).unwrap();
    let nt = u32::from_le_bytes(source[0x3C..0x40].try_into().unwrap()) as usize;
    for large_address_aware in [false, true] {
        let mut bytes = source.clone();
        let flags = u16::from_le_bytes(bytes[nt + 22..nt + 24].try_into().unwrap());
        let flags = if large_address_aware {
            flags | 0x20
        } else {
            flags & !0x20
        };
        bytes[nt + 22..nt + 24].copy_from_slice(&flags.to_le_bytes());
        let mut process = WindowsProcess::spawn_image(config(binary("x86")), bytes).unwrap();
        let result = process.state_mut().vm.reserve(
            Some(0x7FFF_0000),
            0x1000,
            prot::READWRITE,
            AllocKind::Private,
            false,
            None,
        );
        if large_address_aware {
            assert_eq!(result.unwrap(), 0x7FFF_0000);
        } else {
            assert!(
                result.is_err(),
                "non-LAA allocation cannot begin at its 0x7FFF0000 ceiling"
            );
        }
    }
}

#[test]
fn unsupported_or_reserved_tls_alignment_is_not_silently_ignored() {
    let source = std::fs::read(binary("x64")).unwrap();
    let base = PeImage::parse(source.clone()).unwrap().headers().image_base;
    let optional = optional_header(&source);
    for (characteristics, expected) in [
        (3, STATUS_INVALID_IMAGE_FORMAT), // Unsupported cannot hide reserved bits.
        ((15 << 20) | 1, STATUS_INVALID_IMAGE_FORMAT),
        (7 << 20, STATUS_NOT_IMPLEMENTED), // 2^(7-1) = 64-byte alignment.
        (15 << 20, STATUS_INVALID_IMAGE_FORMAT), // No IMAGE_SCN_ALIGN_16384BYTES value.
        (1, STATUS_NOT_IMPLEMENTED),       // SDK IMAGE_SCN_SCALE_INDEX, unsupported.
        (2, STATUS_INVALID_IMAGE_FORMAT),  // Neither SDK flag nor bits23:20.
    ] {
        let mut bytes = source.clone();
        put32(&mut bytes, optional + 112 + 8 * dir::TLS, 0x340);
        put32(&mut bytes, optional + 116 + 8 * dir::TLS, 40);
        put64(&mut bytes, 0x350, base + 0x368);
        put32(&mut bytes, 0x364, characteristics);
        let error = WindowsProcess::spawn_image(config(binary("x64")), bytes)
            .err()
            .unwrap();
        assert!(
            matches!(&error, SpawnError::Load {status, ..} if *status == expected),
            "TLS characteristics {characteristics:#x}: {error}"
        );
    }
}

#[test]
fn export_targets_are_bounded_by_their_image_without_rejecting_data_exports() {
    use rax::user::windows::loader::{SymRef, lookup};
    let source = std::fs::read(binary("x64")).unwrap();
    let size = PeImage::parse(source.clone())
        .unwrap()
        .headers()
        .size_of_image;
    for rva in [0x380, size, 0x7FFD_F000 - 0x0040_0000] {
        let mut bytes = source.clone();
        let optional = optional_header(&bytes);
        put64(&mut bytes, optional + 24, 0x0040_0000);
        put32(&mut bytes, optional + 112 + 8 * dir::EXPORT, 0x300);
        put32(&mut bytes, optional + 116 + 8 * dir::EXPORT, 0x80);
        put32(&mut bytes, 0x310, 1); // Ordinal base.
        put32(&mut bytes, 0x314, 1); // One EAT entry, no name entries.
        put32(&mut bytes, 0x31C, 0x340);
        put32(&mut bytes, 0x340, rva);
        let mut process = WindowsProcess::spawn_image(config(binary("x64")), bytes).unwrap();
        let result = lookup(process.state_mut(), 0, &SymRef::Ordinal(1));
        if rva == 0x380 {
            assert_eq!(result.unwrap(), Some(0x0040_0380));
        } else {
            assert_eq!(result.unwrap_err().status, STATUS_INVALID_IMAGE_FORMAT);
        }
    }
}

#[test]
fn failed_native_dll_load_is_not_reused_as_a_successful_partial_module() {
    use rax::user::windows::loader::load_dll;
    let source = std::fs::read(binary("x64")).unwrap();
    for case in ["malformed-tls", "missing-import"] {
        let mut bytes = source.clone();
        let optional = optional_header(&bytes);
        let flags = u16::from_le_bytes(bytes[optional - 2..optional].try_into().unwrap()) | 0x2000;
        bytes[optional - 2..optional].copy_from_slice(&flags.to_le_bytes());
        put64(&mut bytes, optional + 24, 0x0000_0001_5000_0000);
        match case {
            "malformed-tls" => {
                put32(&mut bytes, optional + 112 + 8 * dir::TLS, 0x340);
                put32(&mut bytes, optional + 116 + 8 * dir::TLS, 1);
            }
            "missing-import" => {
                let pe = PeImage::parse(bytes.clone()).unwrap();
                let descriptor = pe
                    .rva_to_file_offset(pe.headers().directory(dir::IMPORT).rva)
                    .unwrap() as usize;
                put32(&mut bytes, descriptor + 12, 0x3A0);
                let name = b"missing_loader_test.dll\0";
                bytes[0x3A0..0x3A0 + name.len()].copy_from_slice(name);
            }
            _ => unreachable!(),
        }
        let temp = TemporaryImage::new(case, &bytes);
        let mut process = WindowsProcess::spawn(config(binary("x64"))).unwrap();
        let path = process.state().cfg.drives.to_windows(&temp.path);
        let first = load_dll(process.state_mut(), &path).unwrap_err();
        let count = process.state().modules.list.len();
        let failed_idx = count - 1;
        let failed = &process.state().modules.list[failed_idx];
        assert_eq!(process.state().modules.by_name(&failed.name), None);
        assert_eq!(process.state().modules.by_base(failed.base), None);
        assert!(process.state().modules.by_address(failed.base).is_none());
        let direct = rax::user::windows::loader::lookup(
            process.state_mut(),
            failed_idx,
            &rax::user::windows::loader::SymRef::Ordinal(1),
        )
        .unwrap_err();
        assert_eq!(
            direct, first,
            "{case}: direct lookup must preserve the failure"
        );
        let second = load_dll(process.state_mut(), &path).unwrap_err();
        assert_eq!(
            first, second,
            "{case}: failed load must retain its original error"
        );
        assert_eq!(process.state().modules.list.len(), count);
    }
}

#[test]
fn fixture_hashes_and_import_provenance() {
    let text = std::fs::read_to_string(fixtures().join("manifest.toml")).unwrap();
    let manifest: toml::Value = toml::from_str(&text).unwrap();
    let source = std::fs::read(fixtures().join(manifest["source"].as_str().unwrap())).unwrap();
    assert_eq!(
        sha256::hex(&source),
        manifest["source_sha256"].as_str().unwrap()
    );
    let entries = manifest["fixture"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    for entry in entries {
        let path = entry["path"].as_str().unwrap();
        let bytes = std::fs::read(fixtures().join(path)).unwrap();
        assert_eq!(
            sha256::hex(&bytes),
            entry["sha256"].as_str().unwrap(),
            "{path}"
        );
        assert_eq!(bytes.len() as i64, entry["bytes"].as_integer().unwrap());
        let pe = PeImage::parse(bytes).unwrap();
        let image = pe.memory_image();
        let descriptors =
            imports::descriptors(&image, pe.headers().directory(dir::IMPORT)).unwrap();
        assert_eq!(descriptors.len(), 1, "fixture imports only kernel32");
        assert_eq!(descriptors[0].dll_name(&image).unwrap(), b"KERNEL32.dll");
        assert_eq!(
            descriptors[0]
                .thunks(&image, pe.headers().kind)
                .unwrap()
                .len(),
            12
        );
    }
}

#[test]
fn malformed_and_unsupported_process_images_are_rejected() {
    let source = std::fs::read(binary("x64")).unwrap();
    let nt = u32::from_le_bytes(source[0x3C..0x40].try_into().unwrap()) as usize;
    for case in ["truncated", "unsupported-machine", "dll"] {
        let mut bytes = source.clone();
        match case {
            "truncated" => bytes.truncate(20),
            "unsupported-machine" => {
                bytes[nt + 4..nt + 6].copy_from_slice(&0xFFFFu16.to_le_bytes())
            }
            "dll" => {
                let flags =
                    u16::from_le_bytes(bytes[nt + 22..nt + 24].try_into().unwrap()) | 0x2000;
                bytes[nt + 22..nt + 24].copy_from_slice(&flags.to_le_bytes());
            }
            _ => unreachable!(),
        }
        let temp = TemporaryImage::new(case, &bytes);
        assert!(
            matches!(
                WindowsProcess::spawn(config(temp.path.clone())),
                Err(SpawnError::BadImage(_))
            ),
            "{case}"
        );
    }
}
