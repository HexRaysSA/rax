//! The C fixtures behave under `rax-user` as they do natively.

use super::support::{
    build, build_as, comparable, compare, compare_clamped, emulated, emulated_cmd, native,
    native_cmd, while_ready,
};

fn fixture(name: &str, arch: &str, args: &[&str], env: &[(&str, &str)]) {
    if !comparable(name, arch) {
        return;
    }
    let program = build(name, arch);
    compare(name, &program, arch, args, env, None);
}

/// `name` with both runs at utility QoS, as GitHub's macOS runners start
/// jobs: thread and task priorities follow the clamp's ceiling, and the
/// host coalesces timers and sleeps far more.
fn fixture_at_utility(name: &str, arch: &str) {
    let what = format!("{name} at utility QoS");
    if !comparable(&what, arch) {
        return;
    }
    let program = build_as(name, arch, &format!("{name}_utility"));
    compare_clamped("utility", &what, &program, arch);
}

#[test]
fn hello_arm64() {
    fixture(
        "hello",
        "arm64",
        &["one", "two words", ""],
        &[("RAX_FIXTURE_VAR", "set")],
    );
}

#[test]
fn ptrace_self_arm64() {
    fixture("ptrace", "arm64", &[], &[]);
}

#[test]
fn ptrace_self_x86_64() {
    fixture("ptrace", "x86_64", &[], &[]);
}

#[test]
fn ptrace_trace_arm64() {
    fixture("ptrace_trace", "arm64", &[], &[]);
}

#[test]
fn ptrace_trace_x86_64() {
    fixture("ptrace_trace", "x86_64", &[], &[]);
}

#[test]
fn ptrace_restrict_arm64() {
    fixture("ptrace_restrict", "arm64", &[], &[]);
}

#[test]
fn ptrace_restrict_x86_64() {
    fixture("ptrace_restrict", "x86_64", &[], &[]);
}

fn ptrace_restrict_signed(arch: &str) {
    if !comparable("ptrace_restrict_signed", arch) {
        return;
    }
    let program = build_as("ptrace_restrict", arch, "ptrace_restrict_signed");
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--options", "restrict"])
        .arg(&program)
        .status()
        .expect("sign restricted tracing fixture");
    assert!(status.success(), "signing restricted fixture for {arch}");
    compare(
        "ptrace_restrict_signed",
        &program,
        arch,
        &["initial"],
        &[],
        None,
    );
}

#[test]
fn ptrace_restrict_signed_arm64() {
    ptrace_restrict_signed("arm64");
}

#[test]
fn ptrace_restrict_signed_x86_64() {
    ptrace_restrict_signed("x86_64");
}

fn ptrace_restrict_entitled(arch: &str, initial: bool) {
    let what = if initial {
        "ptrace_restrict_entitled_initial"
    } else {
        "ptrace_restrict_entitled_mark"
    };
    if !comparable(what, arch) {
        return;
    }
    let program = build_as("ptrace_restrict", arch, what);
    let mut sign = std::process::Command::new("/usr/bin/codesign");
    sign.args(["--force", "--sign", "-"]);
    if initial {
        sign.args(["--options", "restrict"]);
    }
    let status = sign
        .arg("--entitlements")
        .arg(super::support::sources().join("ptrace_get_task_allow.plist"))
        .arg(&program)
        .status()
        .expect("sign entitled restricted fixture");
    assert!(status.success(), "signing {what} for {arch}");
    let args = if initial { &["initial"][..] } else { &[][..] };
    compare(what, &program, arch, args, &[], None);
}

#[test]
fn ptrace_restrict_entitled_mark_arm64() {
    ptrace_restrict_entitled("arm64", false);
}
#[test]
fn ptrace_restrict_entitled_mark_x86_64() {
    ptrace_restrict_entitled("x86_64", false);
}
#[test]
fn ptrace_restrict_entitled_initial_arm64() {
    ptrace_restrict_entitled("arm64", true);
}
#[test]
fn ptrace_restrict_entitled_initial_x86_64() {
    ptrace_restrict_entitled("x86_64", true);
}

#[test]
fn ptrace_signals_arm64() {
    fixture("ptrace_signals", "arm64", &[], &[]);
}

#[test]
fn ptrace_signals_x86_64() {
    fixture("ptrace_signals", "x86_64", &[], &[]);
}

#[test]
fn ptrace_pending_signal_arm64() {
    fixture("ptrace_pending_signal", "arm64", &[], &[]);
}

#[test]
fn ptrace_pending_signal_x86_64() {
    fixture("ptrace_pending_signal", "x86_64", &[], &[]);
}

#[test]
fn ptrace_signal_coalesce_arm64() {
    fixture("ptrace_signal_coalesce", "arm64", &[], &[]);
}

#[test]
fn ptrace_signal_coalesce_x86_64() {
    fixture("ptrace_signal_coalesce", "x86_64", &[], &[]);
}

#[test]
fn ptrace_signal_kevent_arm64() {
    fixture("ptrace_signal_kevent", "arm64", &[], &[]);
}

#[test]
fn ptrace_signal_kevent_x86_64() {
    fixture("ptrace_signal_kevent", "x86_64", &[], &[]);
}

#[test]
fn ptrace_waitid_arm64() {
    fixture("ptrace_waitid", "arm64", &[], &[]);
}

#[test]
fn ptrace_waitid_x86_64() {
    fixture("ptrace_waitid", "x86_64", &[], &[]);
}

#[test]
fn ptrace_sigchld_arm64() {
    fixture("ptrace_sigchld", "arm64", &[], &[]);
}

#[test]
fn ptrace_sigchld_x86_64() {
    fixture("ptrace_sigchld", "x86_64", &[], &[]);
}

#[test]
fn ptrace_continue_stop_arm64() {
    fixture("ptrace_continue_stop", "arm64", &[], &[]);
}

#[test]
fn ptrace_continue_stop_x86_64() {
    fixture("ptrace_continue_stop", "x86_64", &[], &[]);
}

#[test]
fn ptrace_continue_clears_stop_arm64() {
    fixture("ptrace_continue_clears_stop", "arm64", &[], &[]);
}

#[test]
fn ptrace_continue_clears_stop_x86_64() {
    fixture("ptrace_continue_clears_stop", "x86_64", &[], &[]);
}

#[test]
fn ptrace_continue_waitid_arm64() {
    fixture("ptrace_continue_waitid", "arm64", &[], &[]);
}

#[test]
fn ptrace_continue_waitid_x86_64() {
    fixture("ptrace_continue_waitid", "x86_64", &[], &[]);
}

#[test]
fn ptrace_requests_arm64() {
    fixture("ptrace_requests", "arm64", &[], &[]);
}

#[test]
fn ptrace_requests_x86_64() {
    fixture("ptrace_requests", "x86_64", &[], &[]);
}

#[test]
fn ptrace_procinfo_arm64() {
    fixture("ptrace_procinfo", "arm64", &[], &[]);
}

#[test]
fn ptrace_procinfo_x86_64() {
    fixture("ptrace_procinfo", "x86_64", &[], &[]);
}

#[test]
fn ptrace_procinfo_zombie_arm64() {
    fixture("ptrace_procinfo_zombie", "arm64", &[], &[]);
}

#[test]
fn ptrace_procinfo_zombie_x86_64() {
    fixture("ptrace_procinfo_zombie", "x86_64", &[], &[]);
}

#[test]
fn ptrace_thupdate_self_arm64() {
    fixture("ptrace_thupdate_self", "arm64", &[], &[]);
}

#[test]
fn ptrace_thupdate_self_x86_64() {
    fixture("ptrace_thupdate_self", "x86_64", &[], &[]);
}

#[test]
fn ptrace_thupdate_thread_arm64() {
    fixture("ptrace_thupdate_thread", "arm64", &[], &[]);
}

#[test]
fn ptrace_thupdate_thread_x86_64() {
    fixture("ptrace_thupdate_thread", "x86_64", &[], &[]);
}

#[test]
fn ptrace_thupdate_zero_arm64() {
    ptrace_thupdate_zero("arm64");
}

#[test]
fn ptrace_thupdate_zero_x86_64() {
    ptrace_thupdate_zero("x86_64");
}

fn ptrace_thupdate_zero(arch: &str) {
    if !comparable("ptrace_thupdate_zero", arch) {
        return;
    }
    let program = build_as("ptrace_thupdate_self", arch, "ptrace_thupdate_zero");
    compare("ptrace_thupdate_zero", &program, arch, &["zero"], &[], None);
}

#[test]
fn ptrace_detach_signal_arm64() {
    fixture(
        "ptrace_detach_signal",
        "arm64",
        &["detach", "usr2", "usr1"],
        &[],
    );
}

#[test]
fn ptrace_detach_signal_x86_64() {
    fixture(
        "ptrace_detach_signal",
        "x86_64",
        &["detach", "usr2", "usr1"],
        &[],
    );
}

#[test]
fn ptrace_detach_trap_arm64() {
    ptrace_detach_trap("arm64");
}

#[test]
fn ptrace_detach_trap_x86_64() {
    ptrace_detach_trap("x86_64");
}

fn ptrace_detach_trap(arch: &str) {
    if !comparable("ptrace_detach_trap", arch) {
        return;
    }
    let program = build_as("ptrace_detach_signal", arch, "ptrace_detach_trap");
    compare(
        "ptrace_detach_trap",
        &program,
        arch,
        &["detach", "0", "trap"],
        &[],
        None,
    );
}

#[test]
fn ptrace_continue_signal_arm64() {
    ptrace_continue_signal("arm64");
}

#[test]
fn ptrace_continue_signal_x86_64() {
    ptrace_continue_signal("x86_64");
}

fn ptrace_continue_signal(arch: &str) {
    if !comparable("ptrace_continue_signal", arch) {
        return;
    }
    let program = build_as("ptrace_detach_signal", arch, "ptrace_continue_signal");
    compare(
        "ptrace_continue_signal",
        &program,
        arch,
        &["continue", "usr1", "trap"],
        &[],
        None,
    );
}

#[test]
fn ptrace_deny_trace_arm64() {
    fixture("ptrace_deny_trace", "arm64", &[], &[]);
}

#[test]
fn ptrace_deny_trace_x86_64() {
    fixture("ptrace_deny_trace", "x86_64", &[], &[]);
}

#[test]
fn ptrace_deny_traced_arm64() {
    fixture("ptrace_deny_traced", "arm64", &[], &[]);
}

#[test]
fn ptrace_deny_traced_x86_64() {
    fixture("ptrace_deny_traced", "x86_64", &[], &[]);
}

#[test]
fn ptrace_sigexc_nohandler_arm64() {
    fixture("ptrace_sigexc_nohandler", "arm64", &[], &[]);
}

#[test]
fn ptrace_sigexc_nohandler_x86_64() {
    fixture("ptrace_sigexc_nohandler", "x86_64", &[], &[]);
}

#[test]
fn ptrace_sigexc_handler_arm64() {
    fixture("ptrace_sigexc_handler", "arm64", &[], &[]);
}

#[test]
fn ptrace_sigexc_handler_x86_64() {
    fixture("ptrace_sigexc_handler", "x86_64", &[], &[]);
}

#[test]
fn ptrace_sigexc_state_arm64() {
    fixture("ptrace_sigexc_state", "arm64", &[], &[]);
}

#[test]
fn ptrace_sigexc_state_x86_64() {
    fixture("ptrace_sigexc_state", "x86_64", &[], &[]);
}

#[test]
fn ptrace_sigexc_control_arm64() {
    fixture("ptrace_sigexc_control", "arm64", &[], &[]);
}

#[test]
fn ptrace_sigexc_control_x86_64() {
    if std::env::consts::ARCH != "aarch64" {
        fixture("ptrace_sigexc_control", "x86_64", &[], &[]);
        return;
    }
    if !comparable("ptrace_sigexc_control", "x86_64") {
        return;
    }
    // Rosetta delivers the original signal here despite p_xstat being
    // cleared. Check XNU's signal path instead of using that run as an
    // Intel-host oracle; keep the observed difference in the Darwin guide.
    let program = build("ptrace_sigexc_control", "x86_64");
    let (got, diag) = emulated(&program, "x86_64", &[], &[], None);
    assert_eq!(got.status, Some(0), "{diag}");
    assert_eq!(got.stdout, b"exception type=5 count=2 code=65539 signal=30\nstop=1 signal=30\ncontinue=0\nreceived 0\nexit 42\n", "{diag}");
}

#[test]
fn ptrace_sigexc_original_kill_arm64() {
    ptrace_sigexc_original_kill("arm64");
}

#[test]
fn ptrace_sigexc_original_kill_x86_64() {
    ptrace_sigexc_original_kill("x86_64");
}

fn ptrace_sigexc_original_kill(arch: &str) {
    if !comparable("ptrace_sigexc_original_kill", arch) {
        return;
    }
    let program = build_as("ptrace_sigexc_control", arch, "ptrace_sigexc_original_kill");
    if arch == "x86_64" && std::env::consts::ARCH == "aarch64" {
        let (got, diag) = emulated(&program, arch, &["original-kill"], &[], None);
        assert_eq!(got.status, Some(0), "{diag}");
        assert_eq!(got.stdout, b"exception type=5 count=2 code=65539 signal=9\nstop=1 signal=9\ncontinue=0\nsignal 9\n", "{diag}");
    } else {
        compare(
            "ptrace_sigexc_original_kill",
            &program,
            arch,
            &["original-kill"],
            &[],
            None,
        );
    }
}

#[test]
fn ptrace_thupdate_sigexc_arm64() {
    ptrace_thupdate_sigexc("arm64");
}

#[test]
fn ptrace_thupdate_sigexc_x86_64() {
    ptrace_thupdate_sigexc("x86_64");
}

#[test]
fn ptrace_thupdate_sigexc_nohandler_arm64() {
    fixture("ptrace_thupdate_sigexc_nohandler", "arm64", &[], &[]);
}

#[test]
fn ptrace_thupdate_sigexc_nohandler_x86_64() {
    fixture("ptrace_thupdate_sigexc_nohandler", "x86_64", &[], &[]);
}

#[test]
fn ptrace_thupdate_sigexc_signal_arm64() {
    ptrace_thupdate_sigexc_signal("arm64");
}

#[test]
fn ptrace_thupdate_sigexc_signal_x86_64() {
    ptrace_thupdate_sigexc_signal("x86_64");
}

#[test]
fn ptrace_thupdate_sigexc_kill_arm64() {
    ptrace_thupdate_sigexc_kill("arm64");
}

#[test]
fn ptrace_thupdate_sigexc_kill_x86_64() {
    ptrace_thupdate_sigexc_kill("x86_64");
}

fn ptrace_thupdate_sigexc_kill(arch: &str) {
    if !comparable("ptrace_thupdate_sigexc_kill", arch) {
        return;
    }
    let program = build_as(
        "ptrace_sigexc_kill_signal",
        arch,
        "ptrace_thupdate_sigexc_kill",
    );
    if arch == "x86_64" && std::env::consts::ARCH == "aarch64" {
        // One Rosetta run reported a nonzero wait result; its value and
        // cause are unknown. Check the XNU signal path on this host.
        let (got, diag) = emulated(&program, arch, &["update"], &[], None);
        assert_eq!(got.status, Some(0), "{diag}");
        assert_eq!(got.stdout, b"exception type=5 count=2 code=65539 signal=30\nstop=1 signal=30\nupdate=0\nkill=0\npending=1\nsignal 9\n", "{diag}");
    } else {
        compare(
            "ptrace_thupdate_sigexc_kill",
            &program,
            arch,
            &["update"],
            &[],
            None,
        );
    }
}

fn ptrace_thupdate_sigexc_signal(arch: &str) {
    if !comparable("ptrace_thupdate_sigexc_signal", arch) {
        return;
    }
    let program = build_as(
        "ptrace_sigexc_control",
        arch,
        "ptrace_thupdate_sigexc_signal",
    );
    compare(
        "ptrace_thupdate_sigexc_signal",
        &program,
        arch,
        &["update-usr1"],
        &[],
        None,
    );
}

fn ptrace_thupdate_sigexc(arch: &str) {
    if !comparable("ptrace_thupdate_sigexc", arch) {
        return;
    }
    let program = build_as("ptrace_sigexc_control", arch, "ptrace_thupdate_sigexc");
    if arch == "x86_64" && std::env::consts::ARCH == "aarch64" {
        let (got, diag) = emulated(&program, arch, &["update"], &[], None);
        assert_eq!(got.status, Some(0), "{diag}");
        assert_eq!(got.stdout, b"exception type=5 count=2 code=65539 signal=30\nstop=1 signal=30\nupdate=0\nreceived 0\nexit 42\n", "{diag}");
    } else {
        compare(
            "ptrace_thupdate_sigexc",
            &program,
            arch,
            &["update"],
            &[],
            None,
        );
    }
}

#[test]
fn ptrace_sigexc_kill_arm64() {
    fixture("ptrace_sigexc_kill", "arm64", &[], &[]);
}

#[test]
fn ptrace_sigexc_kill_x86_64() {
    fixture("ptrace_sigexc_kill", "x86_64", &[], &[]);
}

#[test]
fn ptrace_sigexc_kill_signal_arm64() {
    fixture("ptrace_sigexc_kill_signal", "arm64", &[], &[]);
}

#[test]
fn ptrace_sigexc_kill_signal_x86_64() {
    fixture("ptrace_sigexc_kill_signal", "x86_64", &[], &[]);
}

#[test]
fn ptrace_tracer_exit_arm64() {
    fixture("ptrace_tracer_exit", "arm64", &[], &[]);
}

#[test]
fn ptrace_tracer_exit_x86_64() {
    if std::env::consts::ARCH != "aarch64" {
        fixture("ptrace_tracer_exit", "x86_64", &[], &[]);
        return;
    }
    if !comparable("ptrace_tracer_exit", "x86_64") {
        return;
    }
    let program = build("ptrace_tracer_exit", "x86_64");
    let (got, diag) = emulated(&program, "x86_64", &[], &[], None);
    assert_eq!(got.status, Some(0), "{diag}");
    assert_eq!(got.stdout, b"tracer-exit=0 tracee-pipe-eof=1\n", "{diag}");
}

#[test]
fn ptrace_deny_attach_arm64() {
    fixture("ptrace_deny_attach", "arm64", &[], &[]);
}

#[test]
fn ptrace_deny_attach_x86_64() {
    fixture("ptrace_deny_attach", "x86_64", &[], &[]);
}

#[test]
fn ptrace_deny_routing_arm64() {
    fixture("ptrace_deny_routing", "arm64", &[], &[]);
}

#[test]
fn ptrace_deny_routing_x86_64() {
    fixture("ptrace_deny_routing", "x86_64", &[], &[]);
}

#[test]
fn ptrace_step_arm64() {
    fixture("ptrace_step", "arm64", &[], &[]);
}

#[test]
fn ptrace_step_x86_64() {
    fixture("ptrace_step", "x86_64", &[], &[]);
}

#[test]
fn ptrace_step_boundary_arm64() {
    if !comparable("ptrace_step_boundary", "arm64") {
        return;
    }
    // The explicit SVC; NOP; MOV; STR sequence must advance one
    // instruction per step. Native stop timing varies in this probe.
    let program = build("ptrace_step_boundary", "arm64");
    let (got, diag) = emulated(&program, "arm64", &[], &[], None);
    assert_eq!(got.status, Some(0), "{diag}");
    assert_eq!(got.stdout, b"initial=17 marker=0\nstep=1 signal=5 marker=0\nstep=2 signal=5 marker=0\nstep=3 signal=5 marker=1\nexit=42\n", "{diag}");
}

#[test]
fn ptrace_step_boundary_x86_64() {
    if std::env::consts::ARCH != "aarch64" {
        fixture("ptrace_step_boundary", "x86_64", &[], &[]);
        return;
    }
    if !comparable("ptrace_step_boundary", "x86_64") {
        return;
    }
    // Rosetta's host-level stepping is not an Intel instruction oracle.
    // The inline sequence is SYSCALL; NOP; one 32-bit MOV to shared memory.
    let program = build("ptrace_step_boundary", "x86_64");
    let (got, diag) = emulated(&program, "x86_64", &[], &[], None);
    assert_eq!(got.status, Some(0), "{diag}");
    assert_eq!(
        got.stdout,
        b"initial=17 marker=0\nstep=1 signal=5 marker=0\nstep=2 signal=5 marker=1\nexit=42\n",
        "{diag}"
    );
}

#[test]
fn ptrace_exec_arm64() {
    fixture("ptrace_exec", "arm64", &[], &[]);
}

#[test]
fn ptrace_exec_x86_64() {
    fixture("ptrace_exec", "x86_64", &[], &[]);
}

#[test]
fn ptrace_kill_arm64() {
    fixture("ptrace_kill", "arm64", &[], &[]);
}

#[test]
fn ptrace_kill_x86_64() {
    fixture("ptrace_kill", "x86_64", &[], &[]);
}

#[test]
fn ptrace_kill_signal_arm64() {
    fixture("ptrace_kill_signal", "arm64", &[], &[]);
}

#[test]
fn ptrace_kill_signal_x86_64() {
    fixture("ptrace_kill_signal", "x86_64", &[], &[]);
}

#[test]
fn ptrace_kill_running_arm64() {
    fixture("ptrace_kill_running", "arm64", &[], &[]);
}

#[test]
fn ptrace_kill_running_x86_64() {
    fixture("ptrace_kill_running", "x86_64", &[], &[]);
}

#[test]
fn ptrace_kill_xstatus_arm64() {
    ptrace_kill_xstatus("arm64");
}

#[test]
fn ptrace_kill_xstatus_x86_64() {
    ptrace_kill_xstatus("x86_64");
}

fn ptrace_kill_xstatus(arch: &str) {
    if !comparable("ptrace_kill_xstatus", arch) {
        return;
    }
    let program = build_as("ptrace_sigexc_kill", arch, "ptrace_kill_xstatus");
    compare(
        "ptrace_kill_xstatus",
        &program,
        arch,
        &["status"],
        &[],
        None,
    );
}

#[test]
fn ptrace_lifecycle_arm64() {
    fixture("ptrace_lifecycle", "arm64", &[], &[]);
}

#[test]
fn ptrace_lifecycle_x86_64() {
    fixture("ptrace_lifecycle", "x86_64", &[], &[]);
}

fn ptrace_cs_trace(arch: &str, variant: &str) {
    let what = format!("ptrace_cs_trace_{variant}");
    if !comparable(&what, arch) {
        return;
    }
    let program = build_as("ptrace_cs_trace", arch, &what);
    if variant != "linker" {
        let mut sign = std::process::Command::new("/usr/bin/codesign");
        sign.args(["--force", "--sign", "-"]);
        if variant != "adhoc" {
            sign.args(["--options", "runtime"]);
        }
        if variant == "entitled" {
            sign.arg("--entitlements")
                .arg(super::support::sources().join("ptrace_get_task_allow.plist"));
        }
        let status = sign.arg(&program).status().expect("sign tracing fixture");
        assert!(status.success(), "signing {what} for {arch}");
    }
    compare(&what, &program, arch, &[], &[], None);
}

#[test]
fn ptrace_cs_trace_linker_arm64() {
    ptrace_cs_trace("arm64", "linker");
}
#[test]
fn ptrace_cs_trace_linker_x86_64() {
    ptrace_cs_trace("x86_64", "linker");
}
#[test]
fn ptrace_cs_trace_adhoc_arm64() {
    ptrace_cs_trace("arm64", "adhoc");
}
#[test]
fn ptrace_cs_trace_adhoc_x86_64() {
    ptrace_cs_trace("x86_64", "adhoc");
}
#[test]
fn ptrace_cs_trace_runtime_arm64() {
    ptrace_cs_trace("arm64", "runtime");
}
#[test]
fn ptrace_cs_trace_runtime_x86_64() {
    ptrace_cs_trace("x86_64", "runtime");
}
#[test]
fn ptrace_cs_trace_entitled_arm64() {
    ptrace_cs_trace("arm64", "entitled");
}
#[test]
fn ptrace_cs_trace_entitled_x86_64() {
    ptrace_cs_trace("x86_64", "entitled");
}

fn ptrace_cs_trace_lazy(arch: &str) {
    if !comparable("ptrace_cs_trace_lazy", arch) {
        return;
    }
    let program = build_as("ptrace_cs_trace", arch, "ptrace_cs_trace_lazy");
    compare("ptrace_cs_trace_lazy", &program, arch, &["lazy"], &[], None);
}

#[test]
fn ptrace_cs_trace_lazy_arm64() {
    ptrace_cs_trace_lazy("arm64");
}

#[test]
fn ptrace_cs_trace_lazy_x86_64() {
    ptrace_cs_trace_lazy("x86_64");
}

fn ptrace_cs_trace_markhard(arch: &str) {
    if !comparable("ptrace_cs_trace_markhard", arch) {
        return;
    }
    let program = build_as("ptrace_cs_trace", arch, "ptrace_cs_trace_markhard");
    compare(
        "ptrace_cs_trace_markhard",
        &program,
        arch,
        &["markhard"],
        &[],
        None,
    );
}

#[test]
fn ptrace_cs_trace_markhard_arm64() {
    ptrace_cs_trace_markhard("arm64");
}

#[test]
fn ptrace_cs_trace_markhard_x86_64() {
    ptrace_cs_trace_markhard("x86_64");
}

fn ptrace_attach(arch: &str) {
    if !comparable("ptrace_attach", arch) {
        return;
    }
    let program = build("ptrace_attach", arch);
    let entitlements = super::support::sources().join("ptrace_get_task_allow.plist");
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(entitlements)
        .arg(&program)
        .status()
        .expect("codesign ptrace fixture");
    assert!(status.success(), "signing ptrace fixture for {arch}");
    compare("ptrace_attach", &program, arch, &[], &[], None);
}

fn ptrace_attach_basic(arch: &str, mode: &str) {
    let what = match mode {
        "restrict" => "ptrace_attach_restricted",
        "sigexc" => "ptrace_attachexc_basic",
        _ => "ptrace_attach_basic",
    };
    if !comparable(what, arch) {
        return;
    }
    let program = build_as("ptrace_attach_basic", arch, what);
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(super::support::sources().join("ptrace_get_task_allow.plist"))
        .arg(&program)
        .status()
        .expect("sign attach fixture");
    assert!(status.success(), "signing {what} for {arch}");
    let args = if mode.is_empty() {
        &[][..]
    } else {
        &[mode][..]
    };
    compare(what, &program, arch, args, &[], None);
}

fn ptrace_attach_thread_state(arch: &str) {
    if !comparable("ptrace_attach_thread_state", arch) {
        return;
    }
    let program = build("ptrace_attach_thread_state", arch);
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(super::support::sources().join("ptrace_get_task_allow.plist"))
        .arg(&program)
        .status()
        .expect("sign thread-state attach fixture");
    assert!(status.success(), "signing thread-state fixture for {arch}");
    if arch == "x86_64" && std::env::consts::ARCH == "aarch64" {
        let (got, diag) = emulated(&program, arch, &[], &[], None);
        assert_eq!(got.status, Some(0), "{diag}");
        assert_eq!(
            got.stdout, b"get=0 set=0\nregister=1122334455667788 exit=42\n",
            "{diag}"
        );
    } else {
        compare("ptrace_attach_thread_state", &program, arch, &[], &[], None);
    }
}

#[test]
fn ptrace_attach_thread_state_arm64() {
    ptrace_attach_thread_state("arm64");
}

#[test]
fn ptrace_attach_thread_state_x86_64() {
    ptrace_attach_thread_state("x86_64");
}

fn ptrace_attach_thread_suspend(arch: &str, mode: &str) {
    let what = match mode {
        "" => "ptrace_attach_thread_suspend",
        "kill" => "ptrace_attach_suspended_kill",
        "signal" => "ptrace_attach_suspended_signal",
        "running" => "ptrace_attach_suspended_running_kill",
        "pending" => "ptrace_attach_suspended_pending_kill",
        _ => unreachable!(),
    };
    if !comparable(what, arch) {
        return;
    }
    let program = build_as("ptrace_attach_thread_suspend", arch, what);
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(super::support::sources().join("ptrace_get_task_allow.plist"))
        .arg(&program)
        .status()
        .expect("sign thread-suspend attach fixture");
    assert!(
        status.success(),
        "signing thread-suspend fixture for {arch}"
    );
    let args = if mode.is_empty() {
        &[][..]
    } else {
        &[mode][..]
    };
    if mode == "running" {
        let host = native(&program, arch, args, &[], None);
        let (got, diag) = emulated(&program, arch, args, &[], None);
        for (label, run) in [("native", host), ("emulated", got)] {
            assert_eq!(run.status, Some(0), "{label}: {diag}");
            assert!(
                run.stdout == b"prestop=0\nextra=5 suspend=0,0 kill=0 signal=9\n"
                    || run.stdout == b"prestop=9\nextra=5 suspend=0,0 kill=0 signal=9\n",
                "{label}: {:?}\n{diag}",
                String::from_utf8_lossy(&run.stdout)
            );
        }
    } else {
        compare(what, &program, arch, args, &[], None);
    }
}

#[test]
fn ptrace_attach_thread_suspend_arm64() {
    ptrace_attach_thread_suspend("arm64", "");
}

#[test]
fn ptrace_attach_thread_suspend_x86_64() {
    ptrace_attach_thread_suspend("x86_64", "");
}

#[test]
fn ptrace_attach_suspended_kill_arm64() {
    ptrace_attach_thread_suspend("arm64", "kill");
}

#[test]
fn ptrace_attach_suspended_kill_x86_64() {
    ptrace_attach_thread_suspend("x86_64", "kill");
}

#[test]
fn ptrace_attach_suspended_signal_arm64() {
    ptrace_attach_thread_suspend("arm64", "signal");
}

#[test]
fn ptrace_attach_suspended_signal_x86_64() {
    ptrace_attach_thread_suspend("x86_64", "signal");
}

#[test]
fn ptrace_attach_suspended_running_kill_arm64() {
    ptrace_attach_thread_suspend("arm64", "running");
}

#[test]
fn ptrace_attach_suspended_running_kill_x86_64() {
    ptrace_attach_thread_suspend("x86_64", "running");
}

#[test]
fn ptrace_attach_suspended_pending_kill_arm64() {
    ptrace_attach_thread_suspend("arm64", "pending");
}

#[test]
fn ptrace_attach_suspended_pending_kill_x86_64() {
    ptrace_attach_thread_suspend("x86_64", "pending");
}

fn ptrace_attach_task_exec(arch: &str) {
    if !comparable("ptrace_attach_task_exec", arch) {
        return;
    }
    let program = build("ptrace_attach_task_exec", arch);
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(super::support::sources().join("ptrace_get_task_allow.plist"))
        .arg(&program)
        .status()
        .expect("sign task-exec attach fixture");
    assert!(status.success(), "signing task-exec fixture for {arch}");
    if arch == "x86_64" && std::env::consts::ARCH == "aarch64" {
        let (got, diag) = emulated(&program, arch, &[], &[], None);
        assert_eq!(got.status, Some(0), "{diag}");
        assert_eq!(
            got.stdout,
            b"old-task-unusable=1 old-thread-unusable=1\nfresh=0 threads=0 nonempty=1\nexit=42\n",
            "{diag}"
        );
    } else {
        compare("ptrace_attach_task_exec", &program, arch, &[], &[], None);
    }
}

#[test]
fn ptrace_attach_task_exec_arm64() {
    ptrace_attach_task_exec("arm64");
}

#[test]
fn ptrace_attach_task_exec_x86_64() {
    ptrace_attach_task_exec("x86_64");
}

fn ptrace_thupdate_remote(arch: &str) {
    if !comparable("ptrace_thupdate_remote", arch) {
        return;
    }
    let program = build("ptrace_thupdate_remote", arch);
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(super::support::sources().join("ptrace_get_task_allow.plist"))
        .arg(&program)
        .status()
        .expect("sign remote thread-update fixture");
    assert!(
        status.success(),
        "signing remote thread-update fixture for {arch}"
    );
    compare("ptrace_thupdate_remote", &program, arch, &[], &[], None);
}

#[test]
fn ptrace_thupdate_remote_arm64() {
    ptrace_thupdate_remote("arm64");
}

#[test]
fn ptrace_thupdate_remote_x86_64() {
    ptrace_thupdate_remote("x86_64");
}

fn ptrace_attach_memory(arch: &str) {
    if !comparable("ptrace_attach_memory", arch) {
        return;
    }
    let program = build("ptrace_attach_memory", arch);
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(super::support::sources().join("ptrace_get_task_allow.plist"))
        .arg(&program)
        .status()
        .expect("sign remote memory fixture");
    assert!(status.success(), "signing remote memory fixture for {arch}");
    compare("ptrace_attach_memory", &program, arch, &[], &[], None);
}

#[test]
fn ptrace_attach_memory_arm64() {
    ptrace_attach_memory("arm64");
}

#[test]
fn ptrace_attach_memory_x86_64() {
    ptrace_attach_memory("x86_64");
}

fn ptrace_attach_large_memory(arch: &str) {
    if !comparable("ptrace_attach_large_memory", arch) {
        return;
    }
    let program = build("ptrace_attach_large_memory", arch);
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(super::support::sources().join("ptrace_get_task_allow.plist"))
        .arg(&program)
        .status()
        .expect("sign large remote memory fixture");
    assert!(
        status.success(),
        "signing large remote memory fixture for {arch}"
    );
    compare("ptrace_attach_large_memory", &program, arch, &[], &[], None);
}

#[test]
fn ptrace_attach_large_memory_arm64() {
    ptrace_attach_large_memory("arm64");
}

#[test]
fn ptrace_attach_large_memory_x86_64() {
    ptrace_attach_large_memory("x86_64");
}

fn ptrace_attach_vm(arch: &str) {
    if !comparable("ptrace_attach_vm", arch) {
        return;
    }
    let program = build("ptrace_attach_vm", arch);
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(super::support::sources().join("ptrace_get_task_allow.plist"))
        .arg(&program)
        .status()
        .expect("sign remote VM fixture");
    assert!(status.success(), "signing remote VM fixture for {arch}");
    compare("ptrace_attach_vm", &program, arch, &[], &[], None);
}

#[test]
fn ptrace_attach_vm_arm64() {
    ptrace_attach_vm("arm64");
}

#[test]
fn ptrace_attach_vm_x86_64() {
    ptrace_attach_vm("x86_64");
}

fn ptrace_attach_exception_clear(arch: &str) {
    if !comparable("ptrace_attach_exception_clear", arch) {
        return;
    }
    let program = build("ptrace_attach_exception_clear", arch);
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(super::support::sources().join("ptrace_get_task_allow.plist"))
        .arg(&program)
        .status()
        .expect("sign exception-port attach fixture");
    assert!(
        status.success(),
        "signing exception-port fixture for {arch}"
    );
    if arch == "x86_64" && std::env::consts::ARCH == "aarch64" {
        let (got, diag) = emulated(&program, arch, &[], &[], None);
        assert_eq!(got.status, Some(0), "{diag}");
        assert_eq!(
            got.stdout, b"exception-info=0 live=1\nexception-invalid=4 clear=0\nexception-query=0 null=1\nexception-cleared=1\nexit=42\n",
            "{diag}"
        );
    } else {
        compare(
            "ptrace_attach_exception_clear",
            &program,
            arch,
            &[],
            &[],
            None,
        );
    }
}

#[test]
fn ptrace_attach_exception_clear_arm64() {
    ptrace_attach_exception_clear("arm64");
}

#[test]
fn ptrace_attach_exception_clear_x86_64() {
    ptrace_attach_exception_clear("x86_64");
}

fn ptrace_attach_stopped(arch: &str, mode: &str) {
    let what = match mode {
        "self" => "ptrace_attach_stopped_self",
        "sigexc" => "ptrace_attachexc_stopped",
        _ => "ptrace_attach_stopped",
    };
    if !comparable(what, arch) {
        return;
    }
    let program = build_as("ptrace_attach_stopped", arch, what);
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(super::support::sources().join("ptrace_get_task_allow.plist"))
        .arg(&program)
        .status()
        .expect("sign stopped-child fixture");
    assert!(status.success(), "signing stopped-child fixture for {arch}");
    let args = if mode.is_empty() {
        &[][..]
    } else {
        &[mode][..]
    };
    compare(what, &program, arch, args, &[], None);
}

#[test]
fn ptrace_attach_stopped_arm64() {
    ptrace_attach_stopped("arm64", "");
}

#[test]
fn ptrace_attach_stopped_x86_64() {
    ptrace_attach_stopped("x86_64", "");
}

#[test]
fn ptrace_attach_stopped_self_arm64() {
    ptrace_attach_stopped("arm64", "self");
}

#[test]
fn ptrace_attach_stopped_self_x86_64() {
    ptrace_attach_stopped("x86_64", "self");
}

#[test]
fn ptrace_attachexc_stopped_arm64() {
    ptrace_attach_stopped("arm64", "sigexc");
}

#[test]
fn ptrace_attachexc_stopped_x86_64() {
    ptrace_attach_stopped("x86_64", "sigexc");
}

fn ptrace_job_control(arch: &str, mode: &str) {
    let what = match mode {
        "self" => "ptrace_job_control_self",
        "external" => "ptrace_job_control_external",
        "hoststop" => "ptrace_job_control_hoststop",
        "hoststop_unwaited" => "ptrace_job_control_hoststop_unwaited",
        "double" => "ptrace_job_control_double",
        _ => "ptrace_job_control",
    };
    if !comparable(what, arch) {
        return;
    }
    let program = build_as("ptrace_job_control", arch, what);
    let args = if mode.is_empty() {
        &[][..]
    } else {
        &[mode][..]
    };
    compare(what, &program, arch, args, &[], None);
}

#[test]
fn ptrace_job_control_arm64() {
    ptrace_job_control("arm64", "");
}

#[test]
fn ptrace_job_control_x86_64() {
    ptrace_job_control("x86_64", "");
}

#[test]
fn ptrace_job_control_self_arm64() {
    ptrace_job_control("arm64", "self");
}

#[test]
fn ptrace_job_control_self_x86_64() {
    ptrace_job_control("x86_64", "self");
}

#[test]
fn ptrace_job_control_external_arm64() {
    ptrace_job_control("arm64", "external");
}

#[test]
fn ptrace_job_control_external_x86_64() {
    ptrace_job_control("x86_64", "external");
}

#[test]
fn ptrace_job_control_hoststop_arm64() {
    ptrace_job_control("arm64", "hoststop");
}

#[test]
fn ptrace_job_control_hoststop_x86_64() {
    ptrace_job_control("x86_64", "hoststop");
}

#[test]
fn ptrace_job_control_hoststop_unwaited_arm64() {
    ptrace_job_control("arm64", "hoststop_unwaited");
}

#[test]
fn ptrace_job_control_hoststop_unwaited_x86_64() {
    ptrace_job_control("x86_64", "hoststop_unwaited");
}

#[test]
fn ptrace_job_control_double_arm64() {
    ptrace_job_control("arm64", "double");
}

#[test]
fn ptrace_job_control_double_x86_64() {
    ptrace_job_control("x86_64", "double");
}

#[test]
fn ptrace_job_race_arm64() {
    fixture("ptrace_job_race", "arm64", &[], &[]);
}

#[test]
fn ptrace_job_race_x86_64() {
    fixture("ptrace_job_race", "x86_64", &[], &[]);
}

fn ptrace_traceme_task(arch: &str) {
    if !comparable("ptrace_traceme_task", arch) {
        return;
    }
    let program = build("ptrace_traceme_task", arch);
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(super::support::sources().join("ptrace_get_task_allow.plist"))
        .arg(&program)
        .status()
        .expect("sign trace-me task fixture");
    assert!(status.success(), "signing trace-me task fixture for {arch}");
    compare("ptrace_traceme_task", &program, arch, &[], &[], None);
}

#[test]
fn ptrace_traceme_task_arm64() {
    ptrace_traceme_task("arm64");
}

#[test]
fn ptrace_traceme_task_x86_64() {
    ptrace_traceme_task("x86_64");
}

#[test]
fn ptrace_attach_basic_arm64() {
    ptrace_attach_basic("arm64", "");
}
#[test]
fn ptrace_attach_basic_x86_64() {
    ptrace_attach_basic("x86_64", "");
}
#[test]
fn ptrace_attach_restricted_arm64() {
    ptrace_attach_basic("arm64", "restrict");
}
#[test]
fn ptrace_attach_restricted_x86_64() {
    ptrace_attach_basic("x86_64", "restrict");
}

#[test]
fn ptrace_attachexc_basic_arm64() {
    ptrace_attach_basic("arm64", "sigexc");
}

#[test]
fn ptrace_attachexc_basic_x86_64() {
    ptrace_attach_basic("x86_64", "sigexc");
}

fn ptrace_attachexc_handler(arch: &str, suspended: bool) {
    let what = if suspended {
        "ptrace_attachexc_suspended_kill"
    } else {
        "ptrace_attachexc_handler"
    };
    if !comparable(what, arch) {
        return;
    }
    let program = build_as("ptrace_attachexc_handler", arch, what);
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(super::support::sources().join("ptrace_get_task_allow.plist"))
        .arg(&program)
        .status()
        .expect("sign exception attach fixture");
    assert!(
        status.success(),
        "signing exception attach fixture for {arch}"
    );
    let args = if suspended {
        &["suspendkill"][..]
    } else {
        &[][..]
    };
    if arch == "x86_64" && std::env::consts::ARCH == "aarch64" {
        let (got, diag) = emulated(&program, arch, args, &[], None);
        assert_eq!(got.status, Some(0), "{diag}");
        let expected = if suspended {
            &b"attach=0 errno=0\nexception=5 count=2 code=65539 signal=17\nstop=1 signal=17\nkill=0 errno=0 early=0\nsignal=9\n"[..]
        } else {
            &b"attach=0 errno=0\nexception=5 count=2 code=65539 signal=17\nstop=1 signal=17\ncontinue=0 errno=0\nexit=42\n"[..]
        };
        assert_eq!(got.stdout, expected, "{diag}");
    } else {
        compare(what, &program, arch, args, &[], None);
    }
}

#[test]
fn ptrace_attachexc_handler_arm64() {
    ptrace_attachexc_handler("arm64", false);
}

#[test]
fn ptrace_attachexc_handler_x86_64() {
    ptrace_attachexc_handler("x86_64", false);
}

#[test]
fn ptrace_attachexc_suspended_kill_arm64() {
    ptrace_attachexc_handler("arm64", true);
}

#[test]
fn ptrace_attachexc_suspended_kill_x86_64() {
    ptrace_attachexc_handler("x86_64", true);
}

#[test]
fn ptrace_attach_arm64() {
    ptrace_attach("arm64");
}

#[test]
fn ptrace_attach_x86_64() {
    ptrace_attach("x86_64");
}

#[test]
fn pauth_arm64e() {
    fixture("pauth", "arm64e", &[], &[]);
}

#[test]
fn hello_x86_64() {
    fixture(
        "hello",
        "x86_64",
        &["one", "two words", ""],
        &[("RAX_FIXTURE_VAR", "set")],
    );
}

#[test]
fn mach_ipc_arm64() {
    fixture("mach_ipc", "arm64", &[], &[]);
}

#[test]
fn mach_ipc_x86_64() {
    fixture("mach_ipc", "x86_64", &[], &[]);
}

#[test]
fn mach_sync_arm64() {
    fixture("mach_sync", "arm64", &[], &[]);
}

#[test]
fn mach_sync_x86_64() {
    fixture("mach_sync", "x86_64", &[], &[]);
}

#[test]
fn mach_info_arm64() {
    fixture("mach_info", "arm64", &[], &[]);
}

#[test]
fn mach_info_x86_64() {
    fixture("mach_info", "x86_64", &[], &[]);
}

#[test]
fn guard_fatal_arm64() {
    fixture("guard_fatal", "arm64", &[], &[]);
}

#[test]
fn guard_fatal_x86_64() {
    fixture("guard_fatal", "x86_64", &[], &[]);
}

#[test]
fn signals_arm64() {
    fixture("signals", "arm64", &[], &[]);
}

#[test]
fn signals_x86_64() {
    fixture("signals", "x86_64", &[], &[]);
}

#[test]
fn threads_arm64() {
    fixture("threads", "arm64", &[], &[]);
}

#[test]
fn threads_x86_64() {
    fixture("threads", "x86_64", &[], &[]);
}

#[test]
fn threads_sync_arm64() {
    fixture("threads_sync", "arm64", &[], &[]);
}

#[test]
fn threads_sync_x86_64() {
    fixture("threads_sync", "x86_64", &[], &[]);
}

#[test]
fn kqueue_arm64() {
    fixture("kqueue", "arm64", &[], &[]);
}

#[test]
fn kqueue_x86_64() {
    fixture("kqueue", "x86_64", &[], &[]);
}

#[test]
fn kqueue_at_utility_arm64() {
    fixture_at_utility("kqueue", "arm64");
}

#[test]
fn kqueue_at_utility_x86_64() {
    fixture_at_utility("kqueue", "x86_64");
}

#[test]
fn workq_arm64() {
    fixture("workq", "arm64", &[], &[]);
}

#[test]
fn workq_x86_64() {
    fixture("workq", "x86_64", &[], &[]);
}

#[test]
fn dispatch_arm64() {
    fixture("dispatch", "arm64", &[], &[]);
}

#[test]
fn dispatch_x86_64() {
    fixture("dispatch", "x86_64", &[], &[]);
}

#[test]
fn fork_arm64() {
    fixture("fork", "arm64", &[], &[]);
}

#[test]
fn fork_x86_64() {
    fixture("fork", "x86_64", &[], &[]);
}

#[test]
fn exec_arm64() {
    fixture("exec", "arm64", &[], &[]);
}

#[test]
fn exec_x86_64() {
    fixture("exec", "x86_64", &[], &[]);
}

/// arm64 execs the x86_64 build of the fixture (translated), thin and in
/// fat files beside x86_64h slices.
#[test]
fn exec_translated_arm64() {
    if !comparable("exec_translated", "arm64") || !comparable("exec_translated", "x86_64") {
        return;
    }
    let x86 = build_as("exec", "x86_64", "exec_translated");
    let program = build_as("exec", "arm64", "exec_translated");
    let x86 = x86.to_str().expect("UTF-8 build path");
    compare(
        "exec_translated",
        &program,
        "arm64",
        &["translate", x86],
        &[],
        None,
    );
}

#[test]
fn spawn_arm64() {
    fixture("spawn", "arm64", &[], &[]);
}

#[test]
fn spawn_x86_64() {
    fixture("spawn", "x86_64", &[], &[]);
}

#[test]
fn spawn_bridge_arm64() {
    if !comparable("spawn bridge", "arm64") {
        return;
    }
    let program = build_as("spawn", "arm64", "spawn_bridge_smoke");
    compare(
        "spawn bridge",
        &program,
        "arm64",
        &["bridge-smoke"],
        &[],
        None,
    );
}

#[test]
fn spawn_bridge_x86_64() {
    if !comparable("spawn bridge", "x86_64") {
        return;
    }
    let program = build_as("spawn", "x86_64", "spawn_bridge_smoke");
    compare(
        "spawn bridge",
        &program,
        "x86_64",
        &["bridge-smoke"],
        &[],
        None,
    );
}

#[test]
fn csr_arm64() {
    fixture("csr", "arm64", &[], &[]);
}

#[test]
fn csr_x86_64() {
    fixture("csr", "x86_64", &[], &[]);
}

#[test]
fn volumes_arm64() {
    fixture("volumes", "arm64", &[], &[]);
}

#[test]
fn volumes_x86_64() {
    fixture("volumes", "x86_64", &[], &[]);
}

#[test]
fn identity_arm64() {
    fixture("identity", "arm64", &[], &[]);
}

#[test]
fn identity_x86_64() {
    fixture("identity", "x86_64", &[], &[]);
}

#[test]
fn shm_arm64() {
    fixture("shm", "arm64", &[], &[]);
}

#[test]
fn shm_x86_64() {
    fixture("shm", "x86_64", &[], &[]);
}

#[test]
fn xattr_arm64() {
    fixture("xattr", "arm64", &[], &[]);
}

#[test]
fn xattr_x86_64() {
    fixture("xattr", "x86_64", &[], &[]);
}

#[test]
fn acl_arm64() {
    fixture("acl", "arm64", &[], &[]);
}

#[test]
fn acl_x86_64() {
    fixture("acl", "x86_64", &[], &[]);
}

#[test]
fn procinfo_arm64() {
    fixture("procinfo", "arm64", &[], &[]);
}

#[test]
fn procinfo_x86_64() {
    fixture("procinfo", "x86_64", &[], &[]);
}

#[test]
fn procinfo_at_utility_arm64() {
    fixture_at_utility("procinfo", "arm64");
}

#[test]
fn procinfo_at_utility_x86_64() {
    fixture_at_utility("procinfo", "x86_64");
}

#[test]
fn sockets_arm64() {
    fixture("sockets", "arm64", &[], &[]);
}

#[test]
fn sockets_x86_64() {
    fixture("sockets", "x86_64", &[], &[]);
}

#[test]
fn reclaim_arm64() {
    fixture("reclaim", "arm64", &[], &[]);
}

#[test]
fn reclaim_x86_64() {
    fixture("reclaim", "x86_64", &[], &[]);
}

#[test]
fn attrs_arm64() {
    fixture("attrs", "arm64", &[], &[]);
}

#[test]
fn attrs_x86_64() {
    fixture("attrs", "x86_64", &[], &[]);
}

#[test]
fn tbi_arm64() {
    fixture("tbi", "arm64", &[], &[]);
}

#[test]
fn mk_timer_arm64() {
    fixture("mk_timer", "arm64", &[], &[]);
}

#[test]
fn mk_timer_x86_64() {
    fixture("mk_timer", "x86_64", &[], &[]);
}

#[test]
fn mk_timer_at_utility_arm64() {
    fixture_at_utility("mk_timer", "arm64");
}

#[test]
fn mk_timer_at_utility_x86_64() {
    fixture_at_utility("mk_timer", "x86_64");
}

#[test]
fn kevent_data_arm64() {
    fixture("kevent_data", "arm64", &[], &[]);
}

#[test]
fn kevent_data_x86_64() {
    fixture("kevent_data", "x86_64", &[], &[]);
}

#[test]
fn vouchers_arm64() {
    fixture("vouchers", "arm64", &[], &[]);
}

#[test]
fn vouchers_x86_64() {
    fixture("vouchers", "x86_64", &[], &[]);
}

#[test]
fn exc_ports_arm64() {
    fixture("exc_ports", "arm64", &[], &[]);
}

#[test]
fn exc_ports_x86_64() {
    fixture("exc_ports", "x86_64", &[], &[]);
}

#[test]
fn busy_wait_arm64() {
    fixture("busy_wait", "arm64", &[], &[]);
}

#[test]
fn busy_wait_x86_64() {
    fixture("busy_wait", "x86_64", &[], &[]);
}

#[test]
fn thread_state_arm64() {
    fixture("thread_state", "arm64", &[], &[]);
}

#[test]
fn thread_state_x86_64() {
    fixture("thread_state", "x86_64", &[], &[]);
}

#[test]
fn mach_exc_arm64() {
    fixture("mach_exc", "arm64", &[], &[]);
}

#[test]
fn mach_exc_x86_64() {
    fixture("mach_exc", "x86_64", &[], &[]);
}

#[test]
fn sysctl_arm64() {
    fixture("sysctl", "arm64", &[], &[]);
}

#[test]
fn sysctl_x86_64() {
    fixture("sysctl", "x86_64", &[], &[]);
}

#[test]
fn audit_arm64() {
    fixture("audit", "arm64", &[], &[]);
}

#[test]
fn audit_x86_64() {
    fixture("audit", "x86_64", &[], &[]);
}

#[test]
fn protected_open_arm64() {
    fixture("protected_open", "arm64", &[], &[]);
}

#[test]
fn protected_open_x86_64() {
    fixture("protected_open", "x86_64", &[], &[]);
}

#[test]
fn registered_ports_arm64() {
    fixture("registered_ports", "arm64", &[], &[]);
}

#[test]
fn registered_ports_x86_64() {
    fixture("registered_ports", "x86_64", &[], &[]);
}

#[test]
fn fd_flags_arm64() {
    fixture("fd_flags", "arm64", &[], &[]);
}

#[test]
fn fd_flags_x86_64() {
    fixture("fd_flags", "x86_64", &[], &[]);
}

#[test]
fn host_services_arm64() {
    fixture("host_services", "arm64", &[], &[]);
}

#[test]
fn host_services_x86_64() {
    fixture("host_services", "x86_64", &[], &[]);
}

#[test]
fn iokit_arm64() {
    fixture("iokit", "arm64", &[], &[]);
}

#[test]
fn iokit_x86_64() {
    fixture("iokit", "x86_64", &[], &[]);
}

#[test]
fn remap_arm64() {
    fixture("remap", "arm64", &[], &[]);
}

#[test]
fn remap_x86_64() {
    fixture("remap", "x86_64", &[], &[]);
}

#[test]
fn coreservices_arm64() {
    fixture("coreservices", "arm64", &[], &[]);
}

#[test]
fn coreservices_x86_64() {
    fixture("coreservices", "x86_64", &[], &[]);
}

#[test]
fn workloop_ctl_arm64() {
    fixture("workloop_ctl", "arm64", &[], &[]);
}

#[test]
fn workloop_ctl_x86_64() {
    fixture("workloop_ctl", "x86_64", &[], &[]);
}

#[test]
fn workloop_bound_arm64() {
    fixture("workloop_bound", "arm64", &[], &[]);
}

#[test]
fn workloop_bound_x86_64() {
    fixture("workloop_bound", "x86_64", &[], &[]);
}

#[test]
fn codesign_arm64() {
    fixture("codesign", "arm64", &[], &[]);
}

#[test]
fn codesign_x86_64() {
    fixture("codesign", "x86_64", &[], &[]);
}

#[test]
fn procargs_arm64() {
    fixture("procargs", "arm64", &["one", "two words"], &[]);
}

#[test]
fn procargs_x86_64() {
    fixture("procargs", "x86_64", &["one", "two words"], &[]);
}

#[test]
fn psem_arm64() {
    fixture("psem", "arm64", &[], &[]);
}

#[test]
fn psem_x86_64() {
    fixture("psem", "x86_64", &[], &[]);
}

#[test]
fn shared_wait_arm64() {
    fixture("shared_wait", "arm64", &[], &[]);
}

#[test]
fn shared_wait_x86_64() {
    fixture("shared_wait", "x86_64", &[], &[]);
}

/// The process a guest runs in catches SIGCONT on the host only while the
/// guest catches it, as a native process does: a kernel need not report the
/// continue of a process that catches SIGCONT to its parent's
/// `waitid(WCONTINUED)` (macOS 27.0 reports none), so a host handler the
/// guest never installed would hide its continues.
fn sigcont_caught_only_with_the_guest(arch: &str) {
    let what = "sigcont_catch";
    if !comparable(what, arch) {
        return;
    }
    let program = build(what, arch);
    let caught = |pid: u32| {
        let r = native(&program, arch, &["query", &pid.to_string()], &[], None);
        assert_eq!(r.status, Some(0), "query {pid}");
        r.stdout == b"1\n"
    };
    for (mode, catches) in [("default", false), ("catch", true)] {
        let native = while_ready(native_cmd(&program, arch, &[mode], &[], None), caught);
        let emulated = while_ready(emulated_cmd(&program, arch, &[mode], &[], None), caught);
        assert_eq!(
            (native, emulated),
            (catches, catches),
            "{arch} {mode}: native, emulated"
        );
    }
}

#[test]
fn sigcont_caught_only_with_the_guest_arm64() {
    sigcont_caught_only_with_the_guest("arm64");
}

#[test]
fn sigcont_caught_only_with_the_guest_x86_64() {
    sigcont_caught_only_with_the_guest("x86_64");
}
