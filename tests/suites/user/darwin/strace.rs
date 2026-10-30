//! `--strace` detail: the Mach messages a program sends and receives, and
//! where each call came from.
//!
//! The fixture's own bytes are the oracle for the dumps: a 64-byte complex
//! message (`MACH_MSG_TYPE_MAKE_SEND` to a port of its own, one 64-byte
//! out-of-line region) whose inline marker and out-of-line pattern it
//! chose, and a `task_info` call (routine 3405 of `osfmk/mach/task.defs`,
//! reply 3505). The native run is the oracle for the program's output,
//! which tracing must leave alone.

use super::support::{build, comparable, emulated_with, native};

/// The fixture's message as sent: `MACH_MSGH_BITS_COMPLEX` (0x80000000)
/// with `MACH_MSG_TYPE_MAKE_SEND` (20) as the remote disposition, 64 bytes.
const SENT: &str = "send bits=0x80000014 size=64 ";
/// The message's ID, 0x5241.
const ID: &str = " id=21057";
/// The inline marker, bytes 0x30-0x3f of the message.
const MARKER: &str = "|RAX-INLINE-MARK!|";
/// One 16-byte line of the out-of-line pattern.
const PATTERN: &str = "52 41 58 2d 4f 4f 4c 2d  50 41 54 54 45 52 4e 21  |RAX-OOL-PATTERN!|";

/// Builds the fixture and runs it with `options`, checking its output
/// against the native run; returns the emulator's diagnostics, or `None`
/// when the host has no oracle.
fn run(arch: &str, options: &[&str]) -> Option<(String, std::path::PathBuf)> {
    let what = format!("strace_msg {}", options.join(" "));
    if !comparable(&what, arch) {
        return None;
    }
    let program = build("strace_msg", arch);
    let expected = native(&program, arch, &[], &[], None);
    let (got, stderr) = emulated_with(&program, arch, options);
    assert_eq!(
        got, expected,
        "{what} ({arch}) differs from the native run\n--- rax-user stderr\n{stderr}"
    );
    Some((stderr, program))
}

/// The index of the first line containing every one of `parts`.
fn find(lines: &[&str], from: usize, parts: &[&str]) -> Option<usize> {
    (from..lines.len()).find(|&i| parts.iter().all(|p| lines[i].contains(p)))
}

/// The detail lines after line `at` (indented past the event lines).
fn detail<'a>(lines: &[&'a str], at: usize) -> Vec<&'a str> {
    lines[at + 1..]
        .iter()
        .take_while(|l| {
            l.split_once("] ")
                .is_some_and(|(_, rest)| rest.starts_with("    "))
        })
        .copied()
        .collect()
}

fn count(lines: &[&str], part: &str) -> usize {
    lines.iter().filter(|l| l.contains(part)).count()
}

fn dumps_messages_and_call_sites(arch: &str, pc: &str) {
    let options = ["--strace-mach-msg", "--strace-pc", "--strace-stack"];
    let Some((stderr, program)) = run(arch, &options) else {
        return;
    };
    let lines: Vec<&str> = stderr.lines().collect();
    let context = || format!("({arch}) trace:\n{stderr}");

    // The request as the sender laid it out: its inline bytes and its
    // out-of-line region read from the sender's memory.
    let sent = find(&lines, 0, &[SENT, ID]).unwrap_or_else(|| panic!("no send {}", context()));
    let block = detail(&lines, sent);
    assert!(
        block
            .iter()
            .any(|l| l.contains("0030 ") && l.contains(MARKER)),
        "inline marker {}",
        context()
    );
    assert_eq!(
        count(&block, "descriptor 0: ool address=0x"),
        1,
        "{}",
        context()
    );
    assert_eq!(
        count(&block, "size=64 copy=physical deallocate=0"),
        1,
        "{}",
        context()
    );
    assert_eq!(
        count(&block, PATTERN),
        4,
        "out-of-line region {}",
        context()
    );

    // The send's trap line carries its PC, then the backtrace: the stub in
    // the shared cache first, the fixture's `main` further out.
    let trap = find(&lines, sent, &["mach_msg", "_trap("])
        .unwrap_or_else(|| panic!("no trap line {}", context()));
    assert!(
        lines[trap].contains(&format!("] {pc}=0x")),
        "PC prefix {}",
        context()
    );
    let frames: Vec<&str> = lines[trap + 1..]
        .iter()
        .take_while(|l| l.contains("]  > 0x"))
        .copied()
        .collect();
    assert!(frames.len() >= 2, "backtrace {}", context());
    assert!(
        frames[0].ends_with(" [shared region]"),
        "the trap stub {}",
        context()
    );
    let name = program.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        frames.iter().any(|f| f.ends_with(&name)),
        "a frame in {name} {}",
        context()
    );

    // The message as the receiver gets it, trailer (8 bytes) included,
    // with the out-of-line region at the address the receive gave it.
    let received = find(
        &lines,
        trap,
        &["received bits=", " size=64 ", ID, "(72 bytes with trailer)"],
    )
    .unwrap_or_else(|| panic!("no receive {}", context()));
    let block = detail(&lines, received);
    assert!(
        block
            .iter()
            .any(|l| l.contains("0030 ") && l.contains(MARKER)),
        "received marker {}",
        context()
    );
    assert_eq!(
        count(&block, "descriptor 0: ool address=0x"),
        1,
        "{}",
        context()
    );
    assert_eq!(count(&block, PATTERN), 4, "received region {}", context());

    // A kernel call: the request names its routine, the reply its origin.
    assert!(
        find(
            &lines,
            received,
            &["] ", "send ", " id=3405 to task (task_info)"]
        )
        .is_some(),
        "task_info request {}",
        context()
    );
    assert!(
        find(
            &lines,
            received,
            &[
                "received ",
                " id=3505 ",
                "from the kernel (task_info reply)"
            ]
        )
        .is_some(),
        "task_info reply {}",
        context()
    );

    // BSD calls carry their PC too.
    assert!(
        lines
            .iter()
            .any(|l| l.contains(&format!("] {pc}=0x")) && l.contains("write")),
        "a write with its PC {}",
        context()
    );
}

#[test]
fn strace_dumps_messages_and_call_sites_arm64() {
    dumps_messages_and_call_sites("arm64", "pc");
}

#[test]
fn strace_dumps_messages_and_call_sites_x86_64() {
    dumps_messages_and_call_sites("x86_64", "rip");
}

#[test]
fn strace_message_limits_and_plain_strace_arm64() {
    // A limit of 16 bytes: the first line of each region, and the count
    // of the rest; no PC or backtrace unless asked for.
    if let Some((stderr, _)) = run("arm64", &["--strace-mach-msg=16"]) {
        let lines: Vec<&str> = stderr.lines().collect();
        let sent = find(&lines, 0, &[SENT, ID]).expect(&stderr);
        let block = detail(&lines, sent);
        assert_eq!(count(&block, "... 48 more bytes"), 2, "{stderr}");
        assert_eq!(count(&block, PATTERN), 1, "{stderr}");
        assert_eq!(count(&block, MARKER), 0, "{stderr}");
        assert_eq!(count(&lines, "]  > 0x"), 0, "{stderr}");
        assert_eq!(count(&lines, "] pc=0x"), 0, "{stderr}");
    }
    // A limit of 0: headers and descriptors, no contents.
    if let Some((stderr, _)) = run("arm64", &["--strace-mach-msg=0"]) {
        let lines: Vec<&str> = stderr.lines().collect();
        let sent = find(&lines, 0, &[SENT, ID]).expect(&stderr);
        let block = detail(&lines, sent);
        assert_eq!(
            block.len(),
            1,
            "the descriptor alone after the header\n{stderr}"
        );
        assert!(
            block[0].contains("descriptor 0: ool address=0x"),
            "{stderr}"
        );
        assert_eq!(count(&lines, "more bytes"), 0, "{stderr}");
    }
    // Plain `--strace` keeps its lines: the receive's summary, no dumps.
    if let Some((stderr, _)) = run("arm64", &["--strace"]) {
        let lines: Vec<&str> = stderr.lines().collect();
        assert!(
            find(
                &lines,
                0,
                &["received bits=", ID, "(72 bytes with trailer)"]
            )
            .is_some(),
            "{stderr}"
        );
        assert_eq!(count(&lines, "send bits="), 0, "{stderr}");
        assert_eq!(count(&lines, "from the kernel"), 0, "{stderr}");
        assert_eq!(count(&lines, MARKER), 0, "{stderr}");
        assert_eq!(count(&lines, "] pc=0x"), 0, "{stderr}");
    }
}
