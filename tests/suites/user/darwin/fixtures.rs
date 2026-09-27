//! The C fixtures behave under `rax-user` as they do natively.

use super::support::{build, comparable, compare};

fn fixture(name: &str, arch: &str, args: &[&str], env: &[(&str, &str)]) {
    if !comparable(name, arch) {
        return;
    }
    let program = build(name, arch);
    compare(name, &program, arch, args, env, None);
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
