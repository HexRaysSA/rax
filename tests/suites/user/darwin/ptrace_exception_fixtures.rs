//! Native comparisons for remote task exception ports and suspension.

use super::support::{build, comparable, compare, sources};

#[test]
fn x86_tf() {
    if !comparable("x86_tf", "x86_64") {
        return;
    }
    let program = build("x86_tf", "x86_64");
    compare("x86_tf", &program, "x86_64", &[], &[], None);
}

fn handler_fixture(name: &str, arch: &str) {
    if !comparable(name, arch) {
        return;
    }
    let program = build(name, arch);
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(sources().join("ptrace_get_task_allow.plist"))
        .arg(&program)
        .status()
        .expect("sign exception-port fixture");
    assert!(status.success(), "signing {name} for {arch}");
    compare(name, &program, arch, &[], &[], None);
}

#[test]
fn arm_mach_step() {
    handler_fixture("arm_mach_step", "arm64");
}

#[test]
fn arm_mach_step_exclusive_load() {
    handler_fixture("arm_mach_step_exclusive_load", "arm64");
}

#[test]
fn arm_mach_step_exclusive_store() {
    handler_fixture("arm_mach_step_exclusive_store", "arm64");
}

#[test]
fn arm_mach_step_syscall() {
    handler_fixture("arm_mach_step_syscall", "arm64");
}

#[test]
fn arm_mach_step_read() {
    handler_fixture("arm_mach_step_read", "arm64");
}

#[test]
fn arm_mach_step_read_ready() {
    handler_fixture("arm_mach_step_read_ready", "arm64");
}

#[test]
fn arm_mach_step_read_state() {
    handler_fixture("arm_mach_step_read_state", "arm64");
}

#[test]
fn arm_mach_step_read_argument() {
    handler_fixture("arm_mach_step_read_argument", "arm64");
}

#[test]
fn arm_mach_step_read_pc() {
    handler_fixture("arm_mach_step_read_pc", "arm64");
}

#[test]
fn arm_mach_step_fault() {
    handler_fixture("arm_mach_step_fault", "arm64");
}

#[test]
fn ptrace_oob_job_attach_arm64() {
    handler_fixture("ptrace_oob_job_attach", "arm64");
}

#[test]
fn ptrace_oob_job_attach_x86_64() {
    handler_fixture("ptrace_oob_job_attach", "x86_64");
}

#[test]
fn ptrace_oob_job_attach_held_arm64() {
    handler_fixture("ptrace_oob_job_attach_held", "arm64");
}

#[test]
fn ptrace_oob_job_attach_held_x86_64() {
    handler_fixture("ptrace_oob_job_attach_held", "x86_64");
}

#[test]
fn ptrace_attach_exception_dead_arm64() {
    handler_fixture("ptrace_attach_exception_dead", "arm64");
}

#[test]
fn ptrace_attach_exception_dead_x86_64() {
    handler_fixture("ptrace_attach_exception_dead", "x86_64");
}

#[test]
fn ptrace_attach_exception_live_arm64() {
    handler_fixture("ptrace_attach_exception_live", "arm64");
}

#[test]
fn ptrace_attach_exception_live_x86_64() {
    handler_fixture("ptrace_attach_exception_live", "x86_64");
}

#[test]
fn ptrace_attach_exception_live_ports_arm64() {
    handler_fixture("ptrace_attach_exception_live_ports", "arm64");
}

#[test]
fn ptrace_attach_exception_live_ports_x86_64() {
    handler_fixture("ptrace_attach_exception_live_ports", "x86_64");
}

#[test]
fn ptrace_inherited_state_arm64() {
    // Rosetta clears this inherited action in the native probe; that does
    // not establish physical Intel inheritance behavior.
    handler_fixture("ptrace_inherited_state", "arm64");
}

#[test]
fn ptrace_inherited_state_exec_arm64() {
    handler_fixture("ptrace_inherited_state_exec", "arm64");
}

#[test]
fn ptrace_task_suspend_arm64() {
    handler_fixture("ptrace_task_suspend", "arm64");
}

#[test]
fn ptrace_task_suspend_x86_64() {
    handler_fixture("ptrace_task_suspend", "x86_64");
}

#[test]
fn ptrace_task_suspend_exec_arm64() {
    handler_fixture("ptrace_task_suspend_exec", "arm64");
}

#[test]
fn ptrace_task_suspend_exec_x86_64() {
    handler_fixture("ptrace_task_suspend_exec", "x86_64");
}

#[test]
fn ptrace_task_suspend_trace_arm64() {
    handler_fixture("ptrace_task_suspend_trace", "arm64");
}

#[test]
fn ptrace_task_suspend_trace_x86_64() {
    handler_fixture("ptrace_task_suspend_trace", "x86_64");
}

#[test]
fn ptrace_task_resume_registered_exec_arm64() {
    handler_fixture("ptrace_task_resume_registered_exec", "arm64");
}

#[test]
fn ptrace_task_resume_registered_exec_x86_64() {
    handler_fixture("ptrace_task_resume_registered_exec", "x86_64");
}

#[test]
fn ptrace_pre_attach_arm64() {
    handler_fixture("ptrace_pre_attach", "arm64");
}

#[test]
fn ptrace_pre_attach_x86_64() {
    handler_fixture("ptrace_pre_attach", "x86_64");
}

#[test]
fn ptrace_task_suspend2_arm64() {
    handler_fixture("ptrace_task_suspend2", "arm64");
}

#[test]
fn ptrace_task_suspend2_x86_64() {
    handler_fixture("ptrace_task_suspend2", "x86_64");
}

#[test]
fn ptrace_task_suspend2_exec_arm64() {
    handler_fixture("ptrace_task_suspend2_exec", "arm64");
}

#[test]
fn ptrace_task_suspend2_exec_x86_64() {
    handler_fixture("ptrace_task_suspend2_exec", "x86_64");
}

#[test]
fn ptrace_resume_port_arm64() {
    handler_fixture("ptrace_resume_port", "arm64");
}

#[test]
fn ptrace_resume_port_x86_64() {
    handler_fixture("ptrace_resume_port", "x86_64");
}

#[test]
fn ptrace_resume_port_move_arm64() {
    handler_fixture("ptrace_resume_port_move", "arm64");
}

#[test]
fn ptrace_resume_port_move_x86_64() {
    handler_fixture("ptrace_resume_port_move", "x86_64");
}

#[test]
fn ptrace_oob_resume_arm64() {
    handler_fixture("ptrace_oob_resume", "arm64");
}

#[test]
fn ptrace_oob_resume_x86_64() {
    handler_fixture("ptrace_oob_resume", "x86_64");
}

#[test]
fn ptrace_oob_resume_signal_arm64() {
    handler_fixture("ptrace_oob_resume_signal", "arm64");
}

#[test]
fn ptrace_oob_resume_signal_x86_64() {
    handler_fixture("ptrace_oob_resume_signal", "x86_64");
}

#[test]
fn ptrace_oob_resume_sigexc_arm64() {
    handler_fixture("ptrace_oob_resume_sigexc", "arm64");
}

#[test]
fn ptrace_oob_resume_sigexc_x86_64() {
    handler_fixture("ptrace_oob_resume_sigexc", "x86_64");
}

#[test]
fn ptrace_oob_job_arm64() {
    handler_fixture("ptrace_oob_job", "arm64");
}

#[test]
fn ptrace_oob_job_x86_64() {
    handler_fixture("ptrace_oob_job", "x86_64");
}

#[test]
fn ptrace_oob_job_status_arm64() {
    handler_fixture("ptrace_oob_job_status", "arm64");
}

#[test]
fn ptrace_oob_job_status_x86_64() {
    handler_fixture("ptrace_oob_job_status", "x86_64");
}

#[test]
fn ptrace_oob_job_extra_arm64() {
    handler_fixture("ptrace_oob_job_extra", "arm64");
}

#[test]
fn ptrace_oob_job_extra_x86_64() {
    handler_fixture("ptrace_oob_job_extra", "x86_64");
}

#[test]
fn ptrace_task_hold_state_arm64() {
    handler_fixture("ptrace_task_hold_state", "arm64");
}

#[test]
fn ptrace_task_hold_state_x86_64() {
    handler_fixture("ptrace_task_hold_state", "x86_64");
}

#[test]
fn ptrace_thread_hold_state_arm64() {
    handler_fixture("ptrace_thread_hold_state", "arm64");
}

#[test]
fn ptrace_thread_hold_state_x86_64() {
    handler_fixture("ptrace_thread_hold_state", "x86_64");
}

#[test]
fn ptrace_oob_job_repeat_arm64() {
    handler_fixture("ptrace_oob_job_repeat", "arm64");
}

#[test]
fn ptrace_oob_job_repeat_x86_64() {
    handler_fixture("ptrace_oob_job_repeat", "x86_64");
}
