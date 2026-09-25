//! Static Linux programs produce the output a real kernel produced.
//!
//! Fixtures, sources, and the case table live in `tests/fixtures/user/linux`
//! (see its README). `expected/<arch>/<case>.{stdout,status}` were recorded
//! on Linux by `record-expected.sh`; every case must match them byte for
//! byte under `rax-user`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::sha256;
use super::support::{fixtures, run};

const ARCHES: [&str; 3] = ["x86_64", "aarch64", "riscv64"];

struct Case {
    name: String,
    program: String,
    stdin: Option<String>,
    args: Vec<String>,
}

fn cases() -> Vec<Case> {
    let text = std::fs::read_to_string(fixtures().join("cases.txt")).unwrap();
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut it = l.split_whitespace().map(str::to_string);
            let name = it.next().unwrap();
            let program = it.next().unwrap();
            let stdin = it.next().filter(|s| s != "-");
            Case {
                name,
                program,
                stdin,
                args: it.collect(),
            }
        })
        .collect()
}

/// Parses `manifest.toml` into `path -> sha256`.
fn manifest() -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(fixtures().join("manifest.toml")).unwrap();
    let mut out = BTreeMap::new();
    let mut path = None;
    for line in text.lines() {
        let Some((k, v)) = line.split_once(" = ") else {
            continue;
        };
        let v = v.trim_matches('"').to_string();
        match k {
            "path" => path = Some(v),
            "sha256" => {
                out.insert(path.take().expect("path before sha256"), v);
            }
            _ => {}
        }
    }
    out
}

/// Parses `oracle-overrides.txt` into `(arch, case) -> source`: another
/// architecture, or `qemu-<arch>` for a run under QEMU user mode.
fn overrides() -> BTreeMap<(String, String), String> {
    let text = std::fs::read_to_string(fixtures().join("oracle-overrides.txt")).unwrap();
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut it = l.split_whitespace().map(str::to_string);
            let arch = it.next().unwrap();
            let case = it.next().unwrap();
            let source = it.next().unwrap();
            assert!(it.next().is_some(), "override {arch}/{case} needs a reason");
            ((arch, case), source)
        })
        .collect()
}

#[test]
fn fixture_binaries_match_manifest() {
    // Every binary is listed with its hash, and every case's program exists
    // for every architecture (hostsig, driven by the CLI tests, has no
    // recorded case).
    let m = manifest();
    for (path, want) in &m {
        let bytes = std::fs::read(fixtures().join(path)).unwrap();
        assert_eq!(
            &sha256::hex(&bytes),
            want,
            "{path} does not match manifest.toml"
        );
    }
    for case in cases() {
        for arch in ARCHES {
            let path = format!("bin/{arch}/{}", case.program);
            assert!(m.contains_key(&path), "{path} is not in manifest.toml");
        }
    }
    assert_eq!(
        m.len() % ARCHES.len(),
        0,
        "every program is built for every architecture"
    );
}

#[test]
fn oracle_overrides_are_consistent() {
    // A copied expectation is the source architecture's recording; a QEMU
    // run uses the emulator for the case's own architecture and its version
    // is recorded.
    let root = fixtures().join("expected");
    let oracle = std::fs::read_to_string(root.join("ORACLE")).unwrap();
    for ((arch, case), source) in overrides() {
        assert!(
            ARCHES.contains(&arch.as_str()),
            "unknown architecture {arch}"
        );
        assert!(
            cases().iter().any(|c| c.name == case),
            "unknown case {case}"
        );
        if let Some(qemu_arch) = source.strip_prefix("qemu-") {
            assert_eq!(qemu_arch, arch, "{arch}/{case} must run under its own QEMU");
            assert!(
                oracle.contains(&format!(
                    "override: {arch}/{case} run under {source} version"
                )),
                "expected/ORACLE records the QEMU version for {arch}/{case}"
            );
            continue;
        }
        assert!(ARCHES.contains(&source.as_str()), "unknown source {source}");
        for ext in ["stdout", "status"] {
            let file = format!("{case}.{ext}");
            assert_eq!(
                std::fs::read(root.join(&arch).join(&file)).unwrap(),
                std::fs::read(root.join(&source).join(&file)).unwrap(),
                "{arch}/{file} must equal {source}/{file}"
            );
        }
    }
}

/// A temporary directory of its own for one run. `rax-user` keeps the
/// objects the host user's emulated processes share (System V and POSIX
/// IPC, abstract socket names, the emulated inotify hub) under `TMPDIR`,
/// and each expected result was recorded in a fresh container, so runs in
/// parallel must not see each other's objects: a fixture may rely on a
/// fresh namespace, as `sysvmsg` does in naming the identifier after its
/// queue's. The name is short to leave room for socket paths.
fn private_tmpdir() -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("rxf{:x}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn check_case(arch: &str, case: &Case, extra: &[&str], env: &[(&str, &str)]) {
    let root = fixtures();
    let exe = root.join("bin").join(arch).join(&case.program);
    let exe = exe.to_str().unwrap().to_string();
    let mut args: Vec<&str> = extra.to_vec();
    args.push(&exe);
    args.extend(case.args.iter().map(String::as_str));
    let tmp = private_tmpdir();
    let mut env_all = vec![
        ("RAX_FIXTURE_VAR", "set"),
        ("TMPDIR", tmp.to_str().unwrap()),
    ];
    env_all.extend_from_slice(env);
    let stdin = case.stdin.as_ref().map(|p| root.join(p));
    let r = run(&args, &env_all, stdin.as_deref(), Duration::from_secs(120));
    let _ = std::fs::remove_dir_all(&tmp);
    let dir = root.join("expected").join(arch);
    let want_out = std::fs::read(dir.join(format!("{}.stdout", case.name))).unwrap();
    let want_status: i32 = std::fs::read_to_string(dir.join(format!("{}.status", case.name)))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let label = format!("{arch}/{} {extra:?}", case.name);
    assert_eq!(
        String::from_utf8_lossy(&r.stdout),
        String::from_utf8_lossy(&want_out),
        "{label}: stdout differs\nstderr:\n{}",
        r.stderr
    );
    assert_eq!(
        r.status,
        Some(want_status),
        "{label}: status\nstderr:\n{}",
        r.stderr
    );
}

#[test]
fn x86_64_fixtures_match_linux() {
    for case in cases() {
        check_case("x86_64", &case, &[], &[]);
    }
}

#[test]
fn x86_64_fixtures_match_linux_without_jit() {
    for case in cases() {
        check_case("x86_64", &case, &[], &[("RAX_NO_JIT", "1")]);
    }
}

#[test]
fn aarch64_fixtures_match_linux() {
    for case in cases() {
        check_case("aarch64", &case, &[], &[]);
    }
}

#[test]
fn riscv64_fixtures_match_linux() {
    for case in cases() {
        check_case("riscv64", &case, &[], &[]);
    }
}

#[test]
fn riscv64_fixtures_match_linux_with_jit() {
    for case in cases() {
        check_case("riscv64", &case, &["--riscv-jit"], &[]);
    }
}

#[test]
fn small_slices_do_not_change_results() {
    // Preemption boundaries (every 64 instructions) must be invisible.
    for arch in ["aarch64", "riscv64"] {
        for case in cases()
            .iter()
            .filter(|c| c.name == "memory" || c.name == "fileio")
        {
            check_case(arch, case, &["--slice", "64"], &[]);
        }
    }
}

/// Live differential against Docker. Requires a Docker daemon able to run
/// all three architectures and `RAX_USER_DOCKER_ORACLE=1`; without the
/// variable the test reports that it did not run (CI runs ignored tests, and
/// its runners cannot execute foreign-architecture containers).
#[test]
#[ignore = "requires Docker with binfmt support for x86_64, aarch64, and riscv64"]
fn live_docker_oracle() {
    use std::process::Command;
    if std::env::var_os("RAX_USER_DOCKER_ORACLE").is_none() {
        eprintln!("live_docker_oracle: NOT RUN (set RAX_USER_DOCKER_ORACLE=1)");
        return;
    }
    let root = fixtures();
    let ok = Command::new("docker")
        .args(["info"])
        .output()
        .is_ok_and(|o| o.status.success());
    assert!(ok, "docker is not available");
    let overrides = overrides();
    for arch in ARCHES {
        for case in cases() {
            // Same container setup and oracle substitutions as
            // record-expected.sh.
            let source = overrides.get(&(arch.to_string(), case.name.clone()));
            let oracle_arch = match source {
                Some(s) if !s.starts_with("qemu-") => s.as_str(),
                _ => arch,
            };
            let program = format!("/w/{oracle_arch}/{}", case.program);
            let mut cmd = Command::new("docker");
            cmd.args([
                "run",
                "--rm",
                "--init",
                "--security-opt",
                "seccomp=unconfined",
                "-i",
                "-e",
                "RAX_FIXTURE_VAR=set",
                "-v",
            ])
            .arg(format!("{}:/w:ro", root.join("bin").display()))
            .arg("alpine:latest");
            match source {
                Some(qemu) if qemu.starts_with("qemu-") => {
                    cmd.args([
                        "sh",
                        "-c",
                        "apk add -q \"$0\" >/dev/null 2>&1 && exec \"$@\"",
                    ])
                    .args([qemu.as_str(), qemu.as_str(), &program]);
                }
                _ => {
                    cmd.arg(&program);
                }
            }
            cmd.args(&case.args);
            cmd.stdin(match &case.stdin {
                Some(p) => std::process::Stdio::from(std::fs::File::open(root.join(p)).unwrap()),
                None => std::process::Stdio::null(),
            });
            let o = cmd.output().unwrap();
            let exe = root.join("bin").join(arch).join(&case.program);
            let mut args = vec![exe.to_str().unwrap()];
            args.extend(case.args.iter().map(String::as_str));
            let stdin = case.stdin.as_ref().map(|p| root.join(p));
            let r = run(
                &args,
                &[("RAX_FIXTURE_VAR", "set")],
                stdin.as_deref(),
                Duration::from_secs(120),
            );
            assert_eq!(r.stdout, o.stdout, "{arch}/{}: stdout", case.name);
            assert_eq!(r.status, o.status.code(), "{arch}/{}: status", case.name);
        }
    }
}
