//! Building fixtures, running them natively and under `rax-user`, and
//! comparing the runs.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

/// Emulated programs run for seconds in a debug build (dyld and libSystem
/// initialization); this bounds a hang, the output pipes included.
pub const TIMEOUT: Duration = Duration::from_secs(600);

/// How long output may take to end once a run's process group is killed.
const DRAIN: Duration = Duration::from_secs(10);

/// The macOS release whose kernel the Darwin personality reproduces
/// (`docs/architecture/user-mode/darwin.md`, "Behavior references"). A
/// native run on another release shows another kernel (and its SDK may lack
/// calls the fixtures make), so it is no oracle.
pub const MODELED_MACOS: u32 = 27;

/// When set, a comparison or probe that cannot run fails instead of
/// skipping: CI sets it on a host of the modeled release, where a missing
/// oracle must not pass as a skip.
pub const REQUIRE_ORACLE: &str = "RAX_USER_DARWIN_REQUIRE_ORACLE";

/// Reports why `what` (`arch`) does not run: a skip, or a failure under
/// [`REQUIRE_ORACLE`].
pub fn skip(what: &str, arch: &str, why: &str) {
    if std::env::var_os(REQUIRE_ORACLE).is_some() {
        panic!("{what} ({arch}) did not run and {REQUIRE_ORACLE} is set: {why}");
    }
    eprintln!("skipped {what} ({arch}): {why}");
}

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

/// Why the host's kernel is not the one the personality reproduces, or
/// `None` when it is.
fn release_mismatch() -> Option<&'static str> {
    static WHY: OnceLock<Option<String>> = OnceLock::new();
    WHY.get_or_init(|| {
        let version = Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
        let major = version
            .as_deref()
            .and_then(|v| v.split('.').next()?.parse::<u32>().ok());
        match (major, version) {
            (Some(major), _) if major == MODELED_MACOS => None,
            (_, Some(v)) => Some(format!(
                "the host runs macOS {v}, not the macOS {MODELED_MACOS} kernel the personality reproduces"
            )),
            (_, None) => Some("the host's macOS release is unknown (sw_vers failed)".to_owned()),
        }
    })
    .as_deref()
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
/// `output` (so tests building the same fixture do not race). A source
/// line `// link: FLAGS` adds linker flags (frameworks, libraries).
pub fn build_as(name: &str, arch: &str, output: &str) -> PathBuf {
    let src = sources().join(format!("{name}.c"));
    let out = build_dir().join(format!("{output}.{arch}"));
    let text = std::fs::read_to_string(&src).expect("fixture source");
    let link: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("// link:"))
        .flat_map(str::split_whitespace)
        .collect();
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
        .args(&link)
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

/// One past the highest descriptor a run is spawned with open.
fn descriptor_limit() -> i32 {
    // SAFETY: sysconf takes no pointers and only reads a limit (-1 when it
    // is indeterminate).
    let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    if max < 0 {
        1 << 16
    } else {
        max.clamp(3, 1 << 16) as i32
    }
}

/// Kills process group `pgid`.
fn kill_group(pgid: libc::pid_t) {
    // SAFETY: kill takes no pointers. A group that has ended fails with
    // ESRCH, and its ID is not reused while a member remains.
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
}

/// The stacks of the processes in group `pgid` (`sample`'s call graphs,
/// on macOS), so that a run killed at its limit shows where it waited.
fn group_stacks(pgid: libc::pid_t) -> String {
    if !cfg!(target_os = "macos") {
        return String::new();
    }
    let Ok(pids) = Command::new("pgrep")
        .args(["-g", &pgid.to_string()])
        .output()
    else {
        return String::new();
    };
    let mut text = String::new();
    for pid in String::from_utf8_lossy(&pids.stdout).split_whitespace() {
        let Ok(report) = Command::new("/usr/bin/sample").args([pid, "1"]).output() else {
            continue;
        };
        let report = String::from_utf8_lossy(&report.stdout);
        let graph: Vec<&str> = report
            .lines()
            .skip_while(|l| !l.starts_with("Call graph:"))
            .take(150)
            .collect();
        text.push_str(&format!(
            "--- stacks of process {pid}\n{}\n",
            graph.join("\n")
        ));
    }
    text
}

fn wait(cmd: Command, stdin: Option<&Path>) -> (Run, String) {
    wait_within(cmd, stdin, TIMEOUT)
}

/// Runs `cmd` to completion or for `limit`, whichever is first; returns the
/// run and its standard error.
fn wait_within(mut cmd: Command, stdin: Option<&Path>, limit: Duration) -> (Run, String) {
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(match stdin {
            Some(p) => Stdio::from(std::fs::File::open(p).expect("stdin file")),
            None => Stdio::null(),
        });
    // A guest starts with the emulator's standard input, output, and error
    // alone, so descriptors this process inherited (a CI runner leaves some
    // open) would reach only the native run; every run drops them at exec.
    let open_max = descriptor_limit();
    // SAFETY: the closure runs in the forked child before exec. It calls only
    // fcntl, which is async-signal-safe and allocates nothing; a descriptor
    // that is not open fails with EBADF and is left alone.
    unsafe {
        cmd.pre_exec(move || {
            for fd in 3..open_max {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
            Ok(())
        });
    }
    // A process group of its own, so a hang ends with the processes it made.
    cmd.process_group(0);
    let mut child = cmd.spawn().expect("spawn");
    let pgid = child.id() as libc::pid_t;
    let (tx, rx) = mpsc::channel();
    let pipes: [Box<dyn Read + Send>; 2] = [
        Box::new(child.stdout.take().unwrap()),
        Box::new(child.stderr.take().unwrap()),
    ];
    for (i, mut pipe) in pipes.into_iter().enumerate() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut v = Vec::new();
            pipe.read_to_end(&mut v).ok();
            let _ = tx.send((i, v));
        });
    }
    drop(tx);
    let deadline = Instant::now() + limit;
    let mut stacks = None;
    let mut status = loop {
        if let Some(s) = child.try_wait().expect("wait") {
            break s.code().or_else(|| s.signal().map(|n| 128 + n));
        }
        if Instant::now() > deadline {
            stacks = Some(group_stacks(pgid));
            kill_group(pgid);
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    // The output ends once every process holding the pipes has closed them,
    // the program's descendants included. Those still holding them at the
    // deadline are killed with the group, and the run counts as timed out;
    // output a process outside the group keeps open is abandoned.
    let mut output: [Option<Vec<u8>>; 2] = [None, None];
    let mut killed = false;
    while output.iter().any(Option::is_none) {
        let left = if killed {
            DRAIN
        } else {
            deadline.saturating_duration_since(Instant::now())
        };
        match rx.recv_timeout(left) {
            Ok((i, v)) => output[i] = Some(v),
            Err(RecvTimeoutError::Timeout) if !killed => {
                stacks.get_or_insert_with(|| group_stacks(pgid));
                kill_group(pgid);
                killed = true;
                status = None;
            }
            Err(_) => break,
        }
    }
    let [stdout, stderr] = output.map(Option::unwrap_or_default);
    let mut stderr = String::from_utf8_lossy(&stderr).into_owned();
    if status.is_none() {
        stderr.push_str(&format!(
            "(the run or a process holding its output outlived {limit:?})\n"
        ));
        stderr.push_str(&stacks.unwrap_or_default());
    }
    (Run { stdout, status }, stderr)
}

/// The command running `program` natively as `arch`.
fn native_cmd(
    program: &Path,
    arch: &str,
    args: &[&str],
    env: &[(&str, &str)],
    cwd: Option<&Path>,
) -> Command {
    let mut cmd = Command::new("arch");
    cmd.arg(format!("-{arch}")).arg(program).args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    cmd
}

/// The command running `program` under `rax-user` as `arch`.
fn emulated_cmd(
    program: &Path,
    arch: &str,
    args: &[&str],
    env: &[(&str, &str)],
    cwd: Option<&Path>,
) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rax-user"));
    cmd.args(["--arch", arch]).arg(program).args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    cmd
}

/// `cmd` under the QoS clamp `qos` (`taskpolicy -c`), which its process
/// and every process it starts inherit, or `cmd` itself.
fn clamped(cmd: Command, qos: Option<&str>) -> Command {
    let Some(qos) = qos else {
        return cmd;
    };
    let mut c = Command::new("/usr/sbin/taskpolicy");
    c.args(["-c", qos])
        .arg(cmd.get_program())
        .args(cmd.get_args());
    for (k, v) in cmd.get_envs() {
        match v {
            Some(v) => c.env(k, v),
            None => c.env_remove(k),
        };
    }
    if let Some(d) = cmd.get_current_dir() {
        c.current_dir(d);
    }
    c
}

/// Runs `program` natively as `arch`.
pub fn native(
    program: &Path,
    arch: &str,
    args: &[&str],
    env: &[(&str, &str)],
    cwd: Option<&Path>,
) -> Run {
    wait(native_cmd(program, arch, args, env, cwd), None).0
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
    wait(emulated_cmd(program, arch, args, env, cwd), None)
}

/// Whether `arch` can be compared on this host; reports the reason when not
/// (see [`skip`]).
pub fn comparable(what: &str, arch: &str) -> bool {
    let why = oracle_missing()
        .or_else(release_mismatch)
        .or_else(|| {
            (arch == "x86_64" && !x86_64_native())
                .then_some("x86_64 programs do not run natively (no Rosetta)")
        })
        .or_else(|| {
            (arch == "arm64" && std::env::consts::ARCH != "aarch64")
                .then_some("arm64 programs do not run on this host")
        });
    match why {
        Some(why) => {
            skip(what, arch, why);
            false
        }
        None => true,
    }
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
    compare_in(None, what, program, arch, args, env, cwd);
}

/// Runs `program` both ways under the QoS clamp `qos`, as a host that
/// starts its jobs clamped does (GitHub's macOS runners run them at
/// utility QoS), and asserts the runs agree.
pub fn compare_clamped(qos: &str, what: &str, program: &Path, arch: &str) {
    compare_in(Some(qos), what, program, arch, &[], &[], None);
}

fn compare_in(
    qos: Option<&str>,
    what: &str,
    program: &Path,
    arch: &str,
    args: &[&str],
    env: &[(&str, &str)],
    cwd: Option<&Path>,
) {
    let expected = wait(
        clamped(native_cmd(program, arch, args, env, cwd), qos),
        None,
    )
    .0;
    let (got, diag) = wait(
        clamped(emulated_cmd(program, arch, args, env, cwd), qos),
        None,
    );
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

/// A process the run leaves holding its output cannot outlast the limit,
/// which a hung `rax-user` descendant once did for the whole CI job.
#[test]
fn a_descendant_holding_the_output_is_ended_at_the_limit() {
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "echo early; sleep 120 & exit 0"]);
    let start = Instant::now();
    let (run, diag) = wait_within(cmd, None, Duration::from_secs(2));
    assert!(start.elapsed() < Duration::from_secs(60), "{diag}");
    assert_eq!(run.status, None, "{diag}");
    assert_eq!(run.stdout, b"early\n");
    // The descendant's stacks come with the diagnostics.
    if cfg!(target_os = "macos") {
        assert!(diag.contains("--- stacks of process"), "{diag}");
    }
}

/// A descriptor this process inherited does not reach a run, as it does not
/// reach an emulated guest.
#[test]
fn a_run_starts_without_inherited_descriptors() {
    // SAFETY: F_DUPFD takes no pointers; the duplicate of standard error is
    // inheritable (not close-on-exec) and closed below.
    let fd = unsafe { libc::fcntl(2, libc::F_DUPFD, 20) };
    assert!(fd >= 20, "dup: {}", std::io::Error::last_os_error());
    let probe = format!("[ -e /dev/fd/{fd} ] && echo open || echo closed");
    let plain = Command::new("/bin/sh").args(["-c", &probe]).output();
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", &probe]);
    let (run, diag) = wait_within(cmd, None, TIMEOUT);
    // SAFETY: `fd` is the descriptor duplicated above, closed once.
    unsafe { libc::close(fd) };
    assert_eq!(
        plain.expect("probe").stdout,
        b"open\n",
        "the probe sees inherited descriptors"
    );
    assert_eq!(run.status, Some(0), "{diag}");
    assert_eq!(run.stdout, b"closed\n");
}
