//! The signal-frame layouts the Darwin personality writes are the SDK's.

use rax::user::darwin::signal::frame;
use rax::user::darwin::thread_state as ts;

use super::support::{build, native, oracle_missing, skip};

fn check(arch: &str, expected: &[(&str, usize)]) {
    if let Some(why) = oracle_missing() {
        skip("layouts", arch, why);
        return;
    }
    let program = build("layouts", arch);
    // Only the compiler matters here: the probe runs natively on the host
    // (x86_64 through Rosetta when present, else it is not run).
    if arch == "x86_64" && !super::support::x86_64_native() {
        skip("layouts", arch, "x86_64 programs do not run natively");
        return;
    }
    if arch == "arm64" && std::env::consts::ARCH != "aarch64" {
        skip("layouts", arch, "arm64 programs do not run on this host");
        return;
    }
    let run = native(&program, arch, &[], &[], None);
    assert_eq!(run.status, Some(0), "layout probe ({arch}) failed");
    let text = String::from_utf8(run.stdout).expect("text");
    let sdk: Vec<(String, usize)> = text
        .lines()
        .map(|l| {
            let (k, v) = l.split_once(' ').expect("name value");
            (k.to_owned(), v.parse().expect("number"))
        })
        .collect();
    let ours: Vec<(String, usize)> = expected.iter().map(|&(k, v)| (k.to_owned(), v)).collect();
    assert_eq!(sdk, ours, "{arch}: SDK layouts (left) and RAX's (right)");
}

fn common() -> Vec<(&'static str, usize)> {
    vec![
        ("siginfo", frame::SIGINFO_SIZE as usize),
        ("ucontext", frame::UCONTEXT_SIZE as usize),
        ("ucontext.uc_mcsize", 40),
        ("ucontext.uc_mcontext", 48),
    ]
}

#[test]
fn arm64_signal_frame_layouts() {
    let mut e = common();
    e.extend([
        ("mcontext", frame::ARM64_MCONTEXT_SIZE as usize),
        ("mcontext.ss", ts::ARM_EXCEPTION_STATE64_SIZE),
        (
            "mcontext.fs",
            ts::ARM_EXCEPTION_STATE64_SIZE + ts::ARM_THREAD_STATE64_SIZE,
        ),
        ("thread_state", ts::ARM_THREAD_STATE64_SIZE),
        ("exception_state", ts::ARM_EXCEPTION_STATE64_SIZE),
        ("float_state", ts::ARM_NEON_STATE64_SIZE),
    ]);
    check("arm64", &e);
}

#[test]
fn x86_64_signal_frame_layouts() {
    let mut e = common();
    e.extend([
        ("mcontext", frame::X86_MCONTEXT_SIZE as usize),
        ("mcontext.ss", ts::X86_EXCEPTION_STATE64_SIZE),
        (
            "mcontext.fs",
            ts::X86_EXCEPTION_STATE64_SIZE + ts::X86_THREAD_STATE64_SIZE,
        ),
        ("thread_state", ts::X86_THREAD_STATE64_SIZE),
        ("exception_state", ts::X86_EXCEPTION_STATE64_SIZE),
        ("float_state", ts::X86_AVX_STATE64_SIZE),
    ]);
    check("x86_64", &e);
}
