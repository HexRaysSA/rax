//! The host test driver launches two independent engines. A guest fork would
//! accidentally validate the older family transport instead of discovery.

use super::support::*;
use std::io::BufRead;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;

struct Target(Child, bool);
impl Drop for Target {
    fn drop(&mut self) {
        if self.1 {
            return;
        }
        // Darwin can report a continued status even to WNOHANG. Do not
        // let Child::try_wait cache that nonterminal status as a reap.
        let mut status = 0;
        let pid = self.0.id() as i32;
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == 0 || (result == pid && !libc::WIFEXITED(status) && !libc::WIFSIGNALED(status))
        {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &mut status, 0);
            }
        }
        // ECHILD after the native tracer reaped its target is expected.
    }
}

fn host_stopped(pid: i32) -> bool {
    #[cfg(target_vendor = "apple")]
    {
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
        let got = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        got == size && unsafe { info.assume_init() }.pbi_status == 4
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        let _ = pid;
        false
    }
}

fn independent(target: &Path, tracer: &Path, arch: &str, mode: &str, emulated_run: bool) -> Run {
    let target_mode = match mode {
        "detach" => "target-detach",
        "stopped" => "target-stopped",
        "stopped-catch" => "target-stopped-catch",
        "external-stopped-catch" => "target-spin-catch",
        "external-stopped" => "target-spin",
        _ => "target",
    };
    let mut command: Command = if emulated_run {
        emulated_cmd(target, arch, &[target_mode], &[], None)
    } else {
        native_cmd(target, arch, &[target_mode], &[], None)
    };
    let mut target = Target(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
        false,
    );
    let stdout = target.0.stdout.take().unwrap();
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = std::io::BufReader::new(stdout).read_line(&mut line);
        let _ = send.send((result, line));
    });
    let (result, line) = receive
        .recv_timeout(TIMEOUT)
        .expect("independent target readiness");
    assert!(result.is_ok());
    assert_eq!(line, "ready\n");
    if mode.starts_with("external-stopped") {
        assert_eq!(
            unsafe { libc::kill(target.0.id() as i32, libc::SIGSTOP) },
            0
        );
    }
    if mode.starts_with("stopped") || mode.starts_with("external-stopped") {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let mut status = 0;
            let result = unsafe {
                libc::waitpid(
                    target.0.id() as i32,
                    &mut status,
                    libc::WNOHANG | libc::WUNTRACED,
                )
            };
            assert!(
                result >= 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            );
            if result > 0 && libc::WIFSTOPPED(status) {
                assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
                break;
            }
            assert!(
                result == 0 || result < 0 || libc::WIFCONTINUED(status),
                "target ended before initial stop"
            );
            assert!(
                std::time::Instant::now() < until,
                "initial kernel stop event"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
    let pid = target.0.id().to_string();
    let result = if emulated_run {
        let (result, diagnostics) = emulated(tracer, arch, &[mode, &pid], &[], None);
        assert_eq!(
            result.status,
            Some(0),
            "{diagnostics}\nstdout: {}",
            String::from_utf8_lossy(&result.stdout)
        );
        result
    } else {
        native(tracer, arch, &[mode, &pid], &[], None)
    };
    if matches!(mode, "detach" | "tracer-exit") && result.status == Some(0) {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let status = loop {
            if mode == "detach" && host_stopped(target.0.id() as i32) {
                // The retained stop may already be marked waited. Query
                // SSTOP directly before the original parent continues it.
                unsafe {
                    libc::kill(target.0.id() as i32, libc::SIGCONT);
                    libc::kill(target.0.id() as i32, libc::SIGUSR1);
                }
            }
            let mut status = 0;
            let result = unsafe { libc::waitpid(target.0.id() as i32, &mut status, libc::WNOHANG) };
            assert!(
                result >= 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR),
                "original parent wait: {}",
                std::io::Error::last_os_error()
            );
            if result > 0 && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                use std::os::unix::process::ExitStatusExt;
                break std::process::ExitStatus::from_raw(status);
            }
            assert!(
                std::time::Instant::now() < until,
                "target exit after {mode}: arch={arch}, emulated={emulated_run}"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        };
        target.1 = true;
        use std::os::unix::process::ExitStatusExt;
        if mode == "detach" {
            assert_eq!(
                status.code(),
                Some(42),
                "restored original parent: arch={arch}, emulated={emulated_run}, status={status:?}"
            );
        } else {
            assert_eq!(
                status.signal(),
                Some(libc::SIGKILL),
                "tracer exit kills target"
            );
        }
    }
    result
}

fn registry(arch: &str, mode: &str) {
    if !comparable("ptrace_registry", arch) {
        return;
    }
    let target = build_as(
        "ptrace_registry",
        arch,
        &format!("ptrace_registry_target_{mode}"),
    );
    let tracer = build_as(
        "ptrace_registry",
        arch,
        &format!("ptrace_registry_tracer_{mode}"),
    );
    let signed = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(sources().join("ptrace_get_task_allow.plist"))
        .arg(&target)
        .status()
        .unwrap();
    assert!(signed.success());
    // Rosetta exposes ARM thread state for these independently launched
    // translated tasks. Keep its host state outside the x86 guest oracle;
    // RAX must still complete the x86 state query in its own run.
    let translated = arch == "x86_64"
        && Command::new("/usr/sbin/sysctl")
            .args(["-n", "hw.optional.arm64"])
            .output()
            .is_ok_and(|output| output.status.success() && output.stdout == b"1\n");
    let native_mode = if mode.starts_with("mach") && translated {
        if mode == "mach-pre" {
            "mach-pre-no-state"
        } else {
            "mach-no-state"
        }
    } else {
        mode
    };
    let native = independent(&target, &tracer, arch, native_mode, false);
    assert_eq!(
        native.status,
        Some(0),
        "native output: {}",
        String::from_utf8_lossy(&native.stdout)
    );
    let state = if native_mode.ends_with("no-state") {
        ""
    } else {
        "state=0\n"
    };
    let extra = if mode.starts_with("mach") {
        format!(
            "task=0 live=1\nthreads=0 nonempty=1\n{state}suspend=0\nresume=0\nsuspend2=0 live=1\nresume2=0\nallocate=0\nmemory=0 equal=1\ncache=0 value=6\ndeallocate=0\n"
        )
    } else if mode == "codesign" {
        let output = String::from_utf8_lossy(&native.stdout);
        let line = output
            .lines()
            .find(|line| line.starts_with("codesign=0 errno=0 flags="))
            .expect("native signing status");
        let value = line.strip_prefix("codesign=0 errno=0 flags=").unwrap();
        assert_eq!(value.len(), 8);
        assert!(u32::from_str_radix(value, 16).is_ok());
        format!("{line}\n")
    } else {
        String::new()
    };
    let attach = "attach=0 errno=0\nstop=1 signal=17\n";
    let tail = match mode {
        "detach" => "detach=0 errno=0\nnochild=1\n",
        "exit" | "stopped" | "stopped-catch" | "external-stopped" | "external-stopped-catch" => {
            "continue=0 errno=0\nexited=1 status=42\n"
        }
        "waitid" => {
            "nohang=1\ncontinue=0 errno=0\npeek=0 pid=1 status=42\npeek=0 pid=1 status=42\nexited=1 status=42\n"
        }
        "tracer-exit" => "continue=0 errno=0\n",
        _ => "kill=0 errno=0\nterm=1 signal=9\n",
    };
    let expected = if mode == "mach-pre" {
        format!("{extra}{attach}{tail}")
    } else {
        format!("{attach}{extra}{tail}")
    };
    assert_eq!(String::from_utf8_lossy(&native.stdout), expected);
    let mut emulated = independent(&target, &tracer, arch, mode, true);
    if native_mode.ends_with("no-state") {
        let output = String::from_utf8(emulated.stdout).unwrap();
        assert_eq!(
            output.lines().filter(|line| *line == "state=0").count(),
            1,
            "RAX x86 architectural state query"
        );
        emulated.stdout = output
            .lines()
            .filter(|line| *line != "state=0")
            .map(|line| format!("{line}\n"))
            .collect::<String>()
            .into_bytes();
    }
    assert_eq!(emulated, native);
}

#[test]
fn independent_arm64() {
    registry("arm64", "tracer");
}
#[test]
fn independent_x86_64() {
    registry("x86_64", "tracer");
}

#[test]
fn independent_mach_arm64() {
    registry("arm64", "mach");
}
#[test]
fn independent_mach_x86_64() {
    registry("x86_64", "mach");
}

#[test]
fn independent_waitid_arm64() {
    registry("arm64", "waitid");
}
#[test]
fn independent_waitid_x86_64() {
    registry("x86_64", "waitid");
}
#[test]
fn independent_exit_arm64() {
    registry("arm64", "exit");
}
#[test]
fn independent_exit_x86_64() {
    registry("x86_64", "exit");
}
#[test]
fn independent_detach_arm64() {
    registry("arm64", "detach");
}
#[test]
fn independent_detach_x86_64() {
    registry("x86_64", "detach");
}
#[test]
fn independent_tracer_exit_arm64() {
    registry("arm64", "tracer-exit");
}
#[test]
fn independent_tracer_exit_x86_64() {
    registry("x86_64", "tracer-exit");
}
#[test]
fn independent_task_before_attach_arm64() {
    registry("arm64", "mach-pre");
}
#[test]
fn independent_task_before_attach_x86_64() {
    registry("x86_64", "mach-pre");
}

#[test]
fn independent_stopped_arm64() {
    registry("arm64", "stopped");
}
#[test]
fn independent_stopped_x86_64() {
    registry("x86_64", "stopped");
}
#[test]
fn independent_stopped_catch_arm64() {
    registry("arm64", "stopped-catch");
}
#[test]
fn independent_stopped_catch_x86_64() {
    registry("x86_64", "stopped-catch");
}

#[test]
fn independent_external_stopped_arm64() {
    registry("arm64", "external-stopped");
}
#[test]
fn independent_external_stopped_x86_64() {
    registry("x86_64", "external-stopped");
}
#[test]
fn independent_external_stopped_catch_arm64() {
    registry("arm64", "external-stopped-catch");
}
#[test]
fn independent_external_stopped_catch_x86_64() {
    registry("x86_64", "external-stopped-catch");
}

fn native_job_control(arch: &str) {
    if !comparable("ptrace_registry_native_job_control", arch) {
        return;
    }
    let program = build_as(
        "ptrace_registry",
        arch,
        &format!("ptrace_registry_native_job_{arch}"),
    );
    for emulated_run in [false, true] {
        let mut command = if emulated_run {
            emulated_cmd(&program, arch, &["target-native-continue"], &[], None)
        } else {
            native_cmd(&program, arch, &["target-native-continue"], &[], None)
        };
        let mut target = Target(
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
            false,
        );
        let stdout = target.0.stdout.take().unwrap();
        let (send, receive) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut line = String::new();
            let read = std::io::BufReader::new(stdout).read_line(&mut line);
            let _ = send.send((read, line));
        });
        let (read, line) = receive.recv_timeout(TIMEOUT).unwrap();
        assert!(read.is_ok());
        assert_eq!(line, "ready\n");
        let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !host_stopped(target.0.id() as i32) {
            assert!(std::time::Instant::now() < until);
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert_eq!(
            unsafe { libc::kill(target.0.id() as i32, libc::SIGCONT) },
            0
        );
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(target.0.id() as i32, &mut status, libc::WNOHANG) };
            assert!(
                result >= 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            );
            if result > 0 && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                target.1 = true;
                assert!(libc::WIFEXITED(status));
                assert_eq!(
                    libc::WEXITSTATUS(status),
                    42,
                    "arch={arch}, emulated={emulated_run}"
                );
                break;
            }
            assert!(std::time::Instant::now() < until, "ordinary native SIGCONT");
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
}

#[test]
fn native_job_control_arm64() {
    native_job_control("arm64");
}
#[test]
fn native_job_control_x86_64() {
    native_job_control("x86_64");
}

#[test]
fn traced_reap_copyout_and_double_wait_arm64() {
    family_reap("arm64", false);
}
#[test]
fn traced_reap_copyout_and_double_wait_x86_64() {
    family_reap("x86_64", false);
}
#[test]
fn traced_reparent_original_parent_arm64() {
    family_reap("arm64", true);
}
#[test]
fn traced_reparent_original_parent_x86_64() {
    family_reap("x86_64", true);
}

fn family_reap(arch: &str, reparent: bool) {
    let name = if reparent {
        "ptrace_reparent"
    } else {
        "ptrace_reap"
    };
    if !comparable(name, arch) {
        return;
    }
    let program = build(name, arch);
    if reparent {
        assert!(
            Command::new("/usr/bin/codesign")
                .args(["--force", "--sign", "-", "--entitlements"])
                .arg(sources().join("ptrace_get_task_allow.plist"))
                .arg(&program)
                .status()
                .unwrap()
                .success()
        );
    }
    compare(name, &program, arch, &[], &[], None);
}

#[test]
fn independent_signing_status_arm64() {
    registry("arm64", "codesign");
}
#[test]
fn independent_signing_status_x86_64() {
    registry("x86_64", "codesign");
}
#[test]
fn original_parent_signal_arm64() {
    parent_signal("arm64", "signal");
}
#[test]
fn original_parent_signal_x86_64() {
    parent_signal("x86_64", "signal");
}
#[test]
fn original_parent_retained_job_event_arm64() {
    parent_signal("arm64", "job");
}
#[test]
fn original_parent_retained_job_event_x86_64() {
    parent_signal("x86_64", "job");
}

fn parent_signal(arch: &str, mode: &str) {
    let name = "ptrace_reparent";
    if !comparable(name, arch) {
        return;
    }
    let program = build_as(name, arch, &format!("ptrace_reparent_{mode}"));
    assert!(
        Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--entitlements"])
            .arg(sources().join("ptrace_get_task_allow.plist"))
            .arg(&program)
            .status()
            .unwrap()
            .success()
    );
    compare(name, &program, arch, &[mode], &[], None);
}

#[test]
fn cache_attributes_arm64() {
    cache_attributes("arm64");
}
#[test]
fn cache_attributes_x86_64() {
    cache_attributes("x86_64");
}
fn cache_attributes(arch: &str) {
    if !comparable("vm_attribute", arch) {
        return;
    }
    let program = build("vm_attribute", arch);
    compare("vm_attribute", &program, arch, &[], &[], None);
}

#[test]
fn process_exit_notifications_arm64() {
    process_exit_notifications("arm64");
}
#[test]
fn process_exit_notifications_x86_64() {
    process_exit_notifications("x86_64");
}
fn process_exit_notifications(arch: &str) {
    let name = "ptrace_registry_event";
    if !comparable(name, arch) {
        return;
    }
    let target = build_as(name, arch, "ptrace_registry_event_target");
    let tracer = build_as(name, arch, "ptrace_registry_event_tracer");
    assert!(
        Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--entitlements"])
            .arg(sources().join("ptrace_get_task_allow.plist"))
            .arg(&target)
            .status()
            .unwrap()
            .success()
    );
    for mode in ["event", "event-reap"] {
        let native = independent(&target, &tracer, arch, mode, false);
        assert_eq!(native.status, Some(0));
        assert_eq!(
            String::from_utf8_lossy(&native.stdout),
            "event=1 identity=1 flags=1 terminal=1 status=1\ntask-dead=1\ntoken-dead=1\nreacquire=5 null=1\nempty=1\nlate=-1 errno=3\nexited=1 status=42\n"
        );
        assert_eq!(independent(&target, &tracer, arch, mode, true), native);
    }
}
