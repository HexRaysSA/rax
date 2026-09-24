//! Shared helpers: fixture paths and running `rax-user` with a timeout.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The fixture root.
pub fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/user/linux")
}

/// The `rax-user` binary Cargo built for this test.
pub fn rax_user() -> &'static str {
    env!("CARGO_BIN_EXE_rax-user")
}

/// One run's observable result.
#[derive(Debug)]
pub struct Run {
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Standard error.
    pub stderr: String,
    /// Exit status (`None` if killed by a host signal or timed out).
    pub status: Option<i32>,
}

/// Runs `rax-user` with `args`, extra environment, and `stdin`, killing it
/// after `timeout`.
pub fn run(args: &[&str], env: &[(&str, &str)], stdin: Option<&Path>, timeout: Duration) -> Run {
    let mut cmd = Command::new(rax_user());
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(match stdin {
            Some(p) => Stdio::from(std::fs::File::open(p).expect("stdin fixture")),
            None => Stdio::null(),
        });
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn rax-user");
    let out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    let out_t = std::thread::spawn(move || {
        let mut v = Vec::new();
        std::io::Read::read_to_end(&mut { out }, &mut v).ok();
        v
    });
    let err_t = std::thread::spawn(move || {
        let mut v = Vec::new();
        std::io::Read::read_to_end(&mut { err }, &mut v).ok();
        v
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().expect("wait") {
            break s.code();
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let stdout = out_t.join().unwrap();
    let stderr = String::from_utf8_lossy(&err_t.join().unwrap()).into_owned();
    Run {
        stdout,
        stderr,
        status,
    }
}

/// Writes `bytes` to a fresh temporary file and returns its path.
pub fn temp_file(name: &str, bytes: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rax-user-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::File::create(&path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
    path
}
