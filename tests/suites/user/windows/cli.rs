//! Actual CLI execution on Unix and Windows, including installed-DLL oracles.
#![cfg(any(unix, windows))]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const GUEST_EXIT: u32 = 0x8765_4321;

fn fixture(arch: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/user/windows/native_cli/bin")
        .join(arch)
        .join("probe.exe")
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rax-user"))
}

fn run(mut command: Command) -> Output {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn CLI or native oracle");
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let err = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break (status, false);
        }
        if Instant::now() >= deadline {
            child
                .kill()
                .expect("terminate only this timed-out test child");
            break (child.wait().unwrap(), true);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = Output {
        status,
        stdout: out.join().unwrap(),
        stderr: err.join().unwrap(),
    };
    assert!(!timed_out, "test child exceeded 60 s: {output:?}");
    output
}

fn expected_exit() -> i32 {
    if cfg!(windows) {
        GUEST_EXIT as i32
    } else {
        (GUEST_EXIT & 0xFF) as i32
    }
}

#[test]
fn builtin_cli_executes_each_pe_abi_and_preserves_host_exit_width() {
    for arch in ["x86", "x64", "arm64"] {
        let mut command = cli();
        command
            .args(["--windows-libraries", "builtin", "--memory", "256M"])
            .arg(fixture(arch));
        let output = run(command);
        assert_eq!(
            output.status.code(),
            Some(expected_exit()),
            "{arch}: {output:?}"
        );
        assert_eq!(
            &output.stdout[..output.stdout.len().min(7)],
            b"RAXCLI\n",
            "{arch}: {output:?}"
        );
        assert_eq!(output.stdout.len(), 15, "{arch}: {output:?}");
    }
}

#[test]
fn missing_program_reports_127() {
    let mut command = cli();
    command.arg(fixture("missing-architecture"));
    let output = run(command);
    assert_eq!(output.status.code(), Some(127), "{output:?}");
}

#[test]
fn non_executable_reports_126() {
    let mut command = cli();
    command.arg(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/user/windows/native_cli/README.md"),
    );
    let output = run(command);
    assert_eq!(output.status.code(), Some(126), "{output:?}");
}

#[test]
fn malformed_drive_mapping_is_rejected() {
    let mut command = cli();
    command
        .args(["--windows-libraries", "builtin", "--drive", "CC=invalid"])
        .arg(fixture("x86"));
    let output = run(command);
    assert_eq!(output.status.code(), Some(126), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid drive mapping"));
}

#[cfg(unix)]
#[test]
fn native_windows_libraries_require_a_windows_host() {
    let mut command = cli();
    command
        .args(["--windows-libraries", "native"])
        .arg(fixture("x86"));
    let output = run(command);
    assert_eq!(output.status.code(), Some(125), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("require a Windows host"));
}

#[cfg(windows)]
#[test]
fn installed_libraries_match_native_status_and_selected_system_image() {
    let host = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "x86",
        other => panic!("native CLI oracle requires a supported Windows architecture: {other}"),
    };
    for arch in [host, "x86"] {
        let path = fixture(arch);
        let native = run(Command::new(&path));
        assert_eq!(
            native.status.code(),
            Some(GUEST_EXIT as i32),
            "{arch}: {native:?}"
        );
        assert_eq!(native.stdout.len(), 15, "{arch}: {native:?}");
        let mut expected = native.stdout.clone();
        if arch == "x86" && cfg!(target_arch = "aarch64") {
            // Windows ARM64 may run native x86 controls with CHPE modules.
            // The existing RAX x86 profile deliberately selects pure x86
            // SysWOW64 DLLs. Verify their actual disk bytes independently.
            let windows = windows_directory();
            let bytes = std::fs::read(windows.join("SysWOW64").join("kernel32.dll")).unwrap();
            let nt = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
            assert_eq!(&bytes[nt..nt + 4], b"PE\0\0");
            assert_eq!(
                u16::from_le_bytes(bytes[nt + 4..nt + 6].try_into().unwrap()),
                0x14c
            );
            expected[7..11].copy_from_slice(&bytes[nt + 8..nt + 12]);
            expected[11..15].copy_from_slice(&bytes[nt + 80..nt + 84]);
        }
        for provider in ["auto", "native"] {
            let mut command = cli();
            command.args(["--windows-libraries", provider]).arg(&path);
            let emulated = run(command);
            assert_eq!(
                emulated.status.code(),
                native.status.code(),
                "{arch}/{provider}: {emulated:?}"
            );
            assert_eq!(emulated.stdout, expected, "{arch}/{provider}: {emulated:?}");
        }
    }
}

#[test]
fn program_paths_preserve_unicode_spaces_and_relative_resolution() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("rax-cli-{}-{stamp}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let name = "program Ω with spaces.exe";
    let path = directory.join(name);
    std::fs::copy(fixture("arm64"), &path).unwrap();
    let mut command = cli();
    command
        .current_dir(&directory)
        .args(["--windows-libraries", "builtin"])
        .arg(name);
    let output = run(command);
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(directory).unwrap();
    assert_eq!(output.status.code(), Some(expected_exit()), "{output:?}");
    assert!(output.stdout.starts_with(b"RAXCLI\n"), "{output:?}");
}

#[path = "../linux/sha256.rs"]
mod sha256;

#[test]
fn fixture_binaries_and_source_match_recorded_provenance() {
    for name in ["native_cli", "native_mapped_filename"] {
        verify_fixture_provenance(name);
    }
}

fn verify_fixture_provenance(name: &str) {
    let folder = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/user/windows")
        .join(name);
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(folder.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(
        sha256::hex(&std::fs::read(folder.join("src/probe.c")).unwrap()),
        manifest["source_sha256"].as_str().unwrap()
    );
    let fixtures = manifest["fixtures"].as_array().unwrap();
    assert_eq!(fixtures.len(), 3);
    for fixture in fixtures {
        let bytes = std::fs::read(folder.join(fixture["path"].as_str().unwrap())).unwrap();
        assert_eq!(bytes.len() as u64, fixture["bytes"].as_u64().unwrap());
        assert_eq!(sha256::hex(&bytes), fixture["sha256"].as_str().unwrap());
    }
}

#[cfg(windows)]
#[test]
fn installed_cli_preserves_the_executable_backing_filename() {
    let host = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "x64"
    } else {
        "x86"
    };
    let archs = if host == "x86" {
        vec![host]
    } else {
        vec![host, "x86"]
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "rax-cli-mapped-name-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    for arch in archs {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/user/windows/native_mapped_filename/bin")
            .join(arch)
            .join("probe.exe");
        let path = directory.join(format!("mapped executable λ {arch}.exe"));
        std::fs::copy(source, &path).unwrap();
        let before = sha256::hex(&std::fs::read(&path).unwrap());
        let native = run(Command::new(&path));
        assert_eq!(native.status.code(), Some(0), "{arch}: {native:?}");
        assert!(
            native.stdout.starts_with(b"RAX-MAPPED-NAME\n"),
            "{arch}: {native:?}"
        );
        for provider in ["auto", "native"] {
            let mut command = cli();
            // Bound this filename fixture's commit charge while the separate
            // installed-library oracle continues exercising the CLI default.
            command
                .args(["--windows-libraries", provider, "--memory", "256M"])
                .arg(&path);
            let actual = run(command);
            assert_eq!(
                actual.status.code(),
                Some(0),
                "{arch}/{provider}: {actual:?}"
            );
            assert_eq!(
                actual.stdout, native.stdout,
                "{arch}/{provider}: {actual:?}"
            );
        }
        assert_eq!(sha256::hex(&std::fs::read(&path).unwrap()), before);
        std::fs::remove_file(path).unwrap();
    }
    std::fs::remove_dir(directory).unwrap();
}

#[cfg(windows)]
#[test]
fn linux_personality_reports_its_unavailable_host_requirement() {
    let mut command = cli();
    command.args(["--os", "linux"]).arg(fixture("x86"));
    let output = run(command);
    assert_eq!(output.status.code(), Some(125), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires a Unix host"));
}

#[cfg(windows)]
fn windows_directory() -> PathBuf {
    use std::os::windows::ffi::OsStringExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetWindowsDirectoryW(buffer: *mut u16, length: u32) -> u32;
    }
    let mut buffer = vec![0u16; 32768];
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    assert!(length > 0 && (length as usize) < buffer.len());
    PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length as usize]))
}
