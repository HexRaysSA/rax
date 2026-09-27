//! The C fixtures behave under `rax-user` as they do natively.

use super::support::{build, build_as, comparable, compare};

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

#[test]
fn kqueue_arm64() {
    fixture("kqueue", "arm64", &[], &[]);
}

#[test]
fn kqueue_x86_64() {
    fixture("kqueue", "x86_64", &[], &[]);
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
