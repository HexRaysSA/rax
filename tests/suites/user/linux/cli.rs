//! The `rax-user` command-line contract.

use std::time::Duration;

use super::support::{fixtures, run, temp_file};

fn hello(arch: &str) -> String {
    fixtures()
        .join("bin")
        .join(arch)
        .join("hello")
        .to_str()
        .unwrap()
        .to_string()
}

const T: Duration = Duration::from_secs(60);

#[test]
fn missing_program_is_status_127() {
    let r = run(&["/nonexistent/rax-user-program"], &[], None, T);
    assert_eq!(r.status, Some(127));
    assert!(
        r.stderr.contains("/nonexistent/rax-user-program"),
        "{}",
        r.stderr
    );
}

#[test]
fn non_elf_file_is_status_126() {
    let p = temp_file("not-elf", b"#!/bin/sh\necho hi\n");
    let r = run(&[p.to_str().unwrap()], &[], None, T);
    assert_eq!(r.status, Some(126));
    assert!(r.stderr.contains("bad magic"), "{}", r.stderr);
}

#[test]
fn unsupported_machine_is_status_126() {
    // A minimal ELF64 header for EM_HEXAGON (164).
    let mut elf = vec![0u8; 64];
    elf[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf[18..20].copy_from_slice(&164u16.to_le_bytes());
    let p = temp_file("hexagon.elf", &elf);
    let r = run(&[p.to_str().unwrap()], &[], None, T);
    assert_eq!(r.status, Some(126));
    assert!(
        r.stderr.contains("not a supported Linux ABI"),
        "{}",
        r.stderr
    );
}

#[test]
fn exit_status_and_arguments_pass_through() {
    let h = hello("x86_64");
    let r = run(&[&h, "a", "b c", "-d"], &[], None, T);
    assert_eq!(r.status, Some(44), "{}", r.stderr);
    let out = String::from_utf8(r.stdout).unwrap();
    assert!(
        out.contains("argc=4\nargv[1]=a\nargv[2]=b c\nargv[3]=-d\n"),
        "{out}"
    );
}

#[test]
fn environment_options_edit_the_guest_environment() {
    let h = hello("aarch64");
    let r = run(
        &["--clear-env", "-E", "RAX_FIXTURE_VAR=from-cli", &h],
        &[("RAX_FIXTURE_VAR", "from-host")],
        None,
        T,
    );
    let out = String::from_utf8(r.stdout).unwrap();
    assert!(out.contains("RAX_FIXTURE_VAR=from-cli\n"), "{out}");
    let r = run(
        &["-U", "RAX_FIXTURE_VAR", &h],
        &[("RAX_FIXTURE_VAR", "x")],
        None,
        T,
    );
    let out = String::from_utf8(r.stdout).unwrap();
    assert!(out.contains("RAX_FIXTURE_VAR=(unset)\n"), "{out}");
}

#[test]
fn strace_logs_system_calls() {
    let h = hello("riscv64");
    let r = run(&["--strace", &h], &[], None, T);
    assert_eq!(r.status, Some(41));
    assert!(r.stderr.contains("] exit_group(0x29"), "{}", r.stderr);
    assert!(r.stderr.contains("] writev(0x1"), "{}", r.stderr);
    assert!(r.stderr.contains(") = -1 ENOTTY"), "{}", r.stderr);
}

#[test]
fn fatal_signals_are_reported() {
    let segv = fixtures().join("bin/x86_64/segv");
    let r = run(&[segv.to_str().unwrap()], &[], None, T);
    assert_eq!(r.status, Some(139));
    assert!(
        r.stderr
            .contains("killed by SIGSEGV (si_code 1, address 0x8)"),
        "{}",
        r.stderr
    );
}

#[test]
fn size_options_are_validated() {
    let h = hello("x86_64");
    let r = run(&["--stack-size", "12Q", &h], &[], None, T);
    assert_eq!(r.status, Some(2), "{}", r.stderr);
    let r = run(&["--stack-size", "16M", "--memory", "1G", &h], &[], None, T);
    assert_eq!(r.status, Some(41), "{}", r.stderr);
}
