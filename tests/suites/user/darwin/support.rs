//! Building fixtures, running them natively and under `rax-user`, and
//! comparing the runs.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Emulated programs run for seconds in a debug build (dyld and libSystem
/// initialization); this bounds a hang.
pub const TIMEOUT: Duration = Duration::from_secs(600);

/// The fixture sources.
pub fn sources() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/user/darwin/src")
}

/// Where fixtures are built.
pub fn build_dir() -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("user-darwin");
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Why the native oracle is unavailable, or `None` when it is.
pub fn oracle_missing() -> Option<&'static str> {
    static WHY: OnceLock<Option<&'static str>> = OnceLock::new();
    *WHY.get_or_init(|| {
        if !cfg!(target_os = "macos") {
            return Some("not a macOS host");
        }
        if sdk().is_none() {
            return Some("no macOS SDK (xcrun --show-sdk-path failed)");
        }
        None
    })
}

fn sdk() -> Option<String> {
    static SDK: OnceLock<Option<String>> = OnceLock::new();
    SDK.get_or_init(|| {
        let out = Command::new("xcrun").arg("--show-sdk-path").output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    })
    .clone()
}

/// Whether x86_64 programs run natively (Rosetta on Apple silicon).
pub fn x86_64_native() -> bool {
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| {
        Command::new("arch")
            .args(["-x86_64", "/usr/bin/true"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

/// Compiles fixture `name` for `arch` (`arm64` or `x86_64`).
pub fn build(name: &str, arch: &str) -> PathBuf {
    build_as(name, arch, name)
}

/// Compiles fixture `name` for `arch` into a file of its own named after
/// `output` (so tests building the same fixture do not race).
pub fn build_as(name: &str, arch: &str, output: &str) -> PathBuf {
    let src = sources().join(format!("{name}.c"));
    let out = build_dir().join(format!("{output}.{arch}"));
    let status = Command::new("xcrun")
        .args(["clang", "-isysroot"])
        .arg(sdk().expect("oracle checked"))
        .args([
            "-arch",
            arch,
            "-O1",
            "-Wall",
            "-Wno-deprecated-declarations",
            "-o",
        ])
        .arg(&out)
        .arg(&src)
        .status()
        .expect("run clang");
    assert!(status.success(), "compiling {name} for {arch}");
    out
}

/// One run's observable result.
#[derive(Debug, PartialEq, Eq)]
pub struct Run {
    /// Standard output.
    pub stdout: Vec<u8>,
    /// The exit status as a shell reports it (`128 + N` for signal N).
    pub status: Option<i32>,
}

fn wait(mut cmd: Command, stdin: Option<&Path>) -> (Run, String) {
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(match stdin {
            Some(p) => Stdio::from(std::fs::File::open(p).expect("stdin file")),
            None => Stdio::null(),
        });
    let mut child = cmd.spawn().expect("spawn");
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let out_t = std::thread::spawn(move || {
        let mut v = Vec::new();
        out.read_to_end(&mut v).ok();
        v
    });
    let err_t = std::thread::spawn(move || {
        let mut v = Vec::new();
        err.read_to_end(&mut v).ok();
        v
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().expect("wait") {
            use std::os::unix::process::ExitStatusExt;
            break s.code().or_else(|| s.signal().map(|n| 128 + n));
        }
        if start.elapsed() > TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let stdout = out_t.join().unwrap();
    let stderr = String::from_utf8_lossy(&err_t.join().unwrap()).into_owned();
    (Run { stdout, status }, stderr)
}

/// Runs `program` natively as `arch`.
pub fn native(
    program: &Path,
    arch: &str,
    args: &[&str],
    env: &[(&str, &str)],
    cwd: Option<&Path>,
) -> Run {
    let mut cmd = Command::new("arch");
    cmd.arg(format!("-{arch}")).arg(program).args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    wait(cmd, None).0
}

/// Runs `program` under `rax-user` as `arch`; returns the run and the
/// emulator's diagnostics.
pub fn emulated(
    program: &Path,
    arch: &str,
    args: &[&str],
    env: &[(&str, &str)],
    cwd: Option<&Path>,
) -> (Run, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rax-user"));
    cmd.args(["--arch", arch]).arg(program).args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    wait(cmd, None)
}

/// Whether `arch` can be compared on this host; prints the reason when not.
pub fn comparable(what: &str, arch: &str) -> bool {
    if let Some(why) = oracle_missing() {
        eprintln!("skipped {what} ({arch}): {why}");
        return false;
    }
    if arch == "x86_64" && !x86_64_native() {
        eprintln!("skipped {what} ({arch}): x86_64 programs do not run natively (no Rosetta)");
        return false;
    }
    if arch == "arm64" && std::env::consts::ARCH != "aarch64" {
        eprintln!("skipped {what} ({arch}): arm64 programs do not run on this host");
        return false;
    }
    true
}

/// Runs `program` both ways and asserts the runs agree.
pub fn compare(
    what: &str,
    program: &Path,
    arch: &str,
    args: &[&str],
    env: &[(&str, &str)],
    cwd: Option<&Path>,
) {
    let expected = native(program, arch, args, env, cwd);
    let (got, diag) = emulated(program, arch, args, env, cwd);
    assert!(
        expected.status.is_some(),
        "{what} ({arch}): the native run timed out"
    );
    if got != expected {
        panic!(
            "{what} ({arch}) differs from the native run\n--- native (status {:?})\n{}\n--- rax-user (status {:?})\n{}\n--- rax-user stderr\n{}",
            expected.status,
            String::from_utf8_lossy(&expected.stdout),
            got.status,
            String::from_utf8_lossy(&got.stdout),
            diag
        );
    }
}
