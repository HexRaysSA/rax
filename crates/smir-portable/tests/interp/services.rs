//! Runtime services, on `programs/services.smo`, and the order of a module's
//! initializers and finalizers, on `programs/lifecycle.smo`.
//!
//! The Python reference machine performs no services, so these programs are
//! not compared with it. Each expectation is what the linking chapter and the
//! service catalog say the service does, observed through a host that records
//! what the program wrote.

use super::{checked, crate_dir, python};
use rax_smir_portable::Limits;
use rax_smir_portable::interp::{
    Clock, Errno, Exit, Host, NoHost, Policy, StandardStreams, run, run_program, run_with,
};
use rax_smir_portable::ir::{Module, Value};
use serde_json::Value as Json;
use std::io::Write;
use std::process::{Command, Stdio};

const WRITE_TEXT: u32 = 301;
const WRITE_NULL: u32 = 302;
const WRITE_LOCAL: u32 = 303;
const WRITE_POISON_HANDLE: u32 = 304;
const ECHO: u32 = 305;
const READ_FROM: u32 = 306;
const READ_INTO_TEXT: u32 = 307;
const QUIT: u32 = 308;
const GIVE_UP: u32 = 309;
const FLOOD: u32 = 310;

const EBADF: u128 = 9;

fn object() -> std::path::PathBuf {
    crate_dir().join("tests/interp/programs/services.smo")
}

fn module() -> Module {
    Module::load(
        &std::fs::read(object()).expect("services.smo"),
        Limits::default(),
    )
    .expect("services.smo verifies and lowers")
}

/// What one run did: how it ended and what reached each stream.
struct Ran {
    exit: Exit,
    output: Vec<u8>,
    error: Vec<u8>,
    /// Input the program did not consume.
    unread: Vec<u8>,
}

/// Run a function on both engines, which must do the same, and return what
/// it did.
fn call_with(function: u32, arguments: &[u128], input: &[u8], policy: Policy) -> Ran {
    let ran = super::native::on_both(&module(), function, arguments, input, policy, true);
    Ran {
        exit: ran.outcome.exit,
        output: ran.output,
        error: ran.error,
        unread: ran.unread,
    }
}

fn call(function: u32, arguments: &[u128], input: &[u8]) -> Ran {
    call_with(function, arguments, input, Policy::default())
}

/// The value of a function that returns `status * 65536 + count`.
fn packed(status: u128, count: u128) -> Exit {
    Exit::Return(vec![Value::Int(status << 16 | count)])
}

fn fault(exit: &Exit) -> (&'static str, &str) {
    match exit {
        Exit::Trap(fault) => ("trap", &fault.code),
        Exit::LanguageUb(fault) => ("language_ub", &fault.code),
        other => panic!("expected a fault, got {other:?}"),
    }
}

#[test]
fn the_committed_object_is_the_assembled_builder_output() {
    let directory = crate_dir().join("tests/interp/programs");
    let mut build = python();
    build
        .arg(directory.join("build_services.py"))
        .arg("--check");
    checked(build, None, "programs/build_services.py --check");
    for name in ["services", "lifecycle", "mapping", "files"] {
        let mut assemble = python();
        assemble
            .arg(crate_dir().join("tests/interp/oracle.py"))
            .arg("assemble")
            .arg(directory.join(format!("{name}.json")))
            .arg(directory.join(format!("{name}.smo")));
        checked(assemble, None, "oracle.py assemble");
    }
}

fn lifecycle_module() -> Module {
    Module::load(
        &std::fs::read(crate_dir().join("tests/interp/programs/lifecycle.smo"))
            .expect("lifecycle.smo"),
        Limits::default(),
    )
    .expect("lifecycle.smo verifies and lowers")
}

/// Run a function of the lifecycle object and return how it ended and what
/// the hooks and the function wrote.
fn lifecycle(function: u32, arguments: &[u128]) -> (Exit, String) {
    let ran = super::native::on_both(
        &lifecycle_module(),
        function,
        arguments,
        b"",
        Policy::default(),
        true,
    );
    (
        ran.outcome.exit,
        String::from_utf8(ran.output).expect("letters"),
    )
}

#[test]
fn initializers_run_before_the_entry_and_finalizers_after_a_normal_end() {
    const MAIN: u32 = 300;
    const QUIT: u32 = 301;
    const FAIL: u32 = 302;
    // Initializers by ascending priority, then position: c, b, a. The entry
    // writes m. Finalizers in the reverse of that order: e, d.
    assert_eq!(
        lifecycle(MAIN, &[]),
        (Exit::Return(vec![Value::Int(7)]), "cbamed".to_owned())
    );
    // A clean exit runs the finalizers; a quick or immediate one does not.
    assert_eq!(
        lifecycle(QUIT, &[3, 0]),
        (Exit::Exited(3), "cbamed".to_owned())
    );
    assert_eq!(
        lifecycle(QUIT, &[3, 1]),
        (Exit::Exited(3), "cbam".to_owned())
    );
    assert_eq!(
        lifecycle(QUIT, &[3, 2]),
        (Exit::Exited(3), "cbam".to_owned())
    );
    // Nor does a program that stops on a fault.
    let (exit, output) = lifecycle(FAIL, &[]);
    assert_eq!(
        (fault(&exit), output.as_str()),
        (("trap", "failed"), "cbam")
    );
}

#[test]
fn writes_reach_the_stream_the_handle_names() {
    let ran = call(WRITE_TEXT, &[1, 6], b"");
    assert_eq!(ran.exit, packed(0, 6));
    assert_eq!(
        (ran.output.as_slice(), ran.error.as_slice()),
        (&b"hello\n"[..], &b""[..])
    );

    let ran = call(WRITE_TEXT, &[2, 4], b"");
    assert_eq!(ran.exit, packed(0, 4));
    assert_eq!(
        (ran.output.as_slice(), ran.error.as_slice()),
        (&b""[..], &b"hell"[..])
    );

    // Standard input cannot be written, and no other handle is open. The
    // failure is a status, not a fault, and its value is zero.
    for handle in [0, 3, u128::from(u64::MAX)] {
        let ran = call(WRITE_TEXT, &[handle, 6], b"");
        assert_eq!(ran.exit, packed(EBADF, 0), "handle {handle}");
        assert!(ran.output.is_empty() && ran.error.is_empty());
    }
    assert_eq!(Errno::EBADF.code(), EBADF as u32);
}

#[test]
fn a_buffer_is_guarded_before_the_host_sees_anything() {
    // One byte more than the object holds.
    let ran = call(WRITE_TEXT, &[1, 7], b"");
    assert_eq!(fault(&ran.exit), ("trap", "memory_bounds"));
    assert!(ran.output.is_empty());
    // The guard comes before the handle is looked at.
    let ran = call(WRITE_TEXT, &[9, 7], b"");
    assert_eq!(fault(&ran.exit), ("trap", "memory_bounds"));

    // A span of no bytes is not dereferenced, even at the null pointer; one
    // byte there is an access with no provenance.
    assert_eq!(call(WRITE_NULL, &[0], b"").exit, packed(0, 0));
    let ran = call(WRITE_NULL, &[1], b"");
    assert_eq!(fault(&ran.exit), ("language_ub", "pointer_provenance"));

    // Reading into constant data is refused before any input is consumed.
    let ran = call(READ_INTO_TEXT, &[], b"z");
    assert_eq!(fault(&ran.exit), ("trap", "memory_permission"));
    assert_eq!(ran.unread, b"z");
}

#[test]
fn undef_bytes_are_written_as_zero_and_poison_is_undefined() {
    let ran = call(WRITE_LOCAL, &[0], b"");
    assert_eq!(
        (ran.exit, ran.output.as_slice()),
        (packed(0, 4), &b"abcd"[..])
    );
    // A stack object nothing was stored to.
    let ran = call(WRITE_LOCAL, &[1], b"");
    assert_eq!(
        (ran.exit, ran.output.as_slice()),
        (packed(0, 4), &[0_u8; 4][..])
    );
    // One poison byte among the four.
    let ran = call(WRITE_LOCAL, &[2], b"");
    assert_eq!(fault(&ran.exit), ("language_ub", "ub_service_argument"));
    assert!(ran.output.is_empty());

    let ran = call(WRITE_POISON_HANDLE, &[], b"");
    assert_eq!(fault(&ran.exit), ("language_ub", "ub_service_argument"));
    assert!(ran.output.is_empty());
}

#[test]
fn reads_fill_guest_memory_with_what_the_host_supplied() {
    let ran = call(ECHO, &[4], b"abcdef");
    assert_eq!(ran.exit, packed(0, 4));
    assert_eq!(
        (ran.output.as_slice(), ran.unread.as_slice()),
        (&b"abcd"[..], &b"ef"[..])
    );

    // Fewer bytes than asked for is a short read, and none is end of input.
    let ran = call(ECHO, &[16], b"xyz");
    assert_eq!(
        (ran.exit, ran.output.as_slice()),
        (packed(0, 3), &b"xyz"[..])
    );
    let ran = call(ECHO, &[16], b"");
    assert_eq!((ran.exit, ran.output.as_slice()), (packed(0, 0), &b""[..]));
    let ran = call(ECHO, &[0], b"abc");
    assert_eq!(
        (ran.exit, ran.unread.as_slice()),
        (packed(0, 0), &b"abc"[..])
    );

    // The stack object holds 16 bytes.
    let ran = call(ECHO, &[17], b"abc");
    assert_eq!(fault(&ran.exit), ("trap", "memory_bounds"));
    assert_eq!(ran.unread, b"abc");

    // Only standard input can be read.
    assert_eq!(call(READ_FROM, &[0], b"q").exit, packed(0, 1));
    for handle in [1, 2, 3] {
        let ran = call(READ_FROM, &[handle], b"q");
        assert_eq!(ran.exit, packed(EBADF, 0), "handle {handle}");
        assert_eq!(ran.unread, b"q");
    }
}

#[test]
fn one_transfer_moves_at_most_65536_bytes() {
    let policy = Policy {
        max_memory_bytes: 1 << 20,
        ..Policy::default()
    };
    for (asked, moved) in [
        (70_000_u128, 65_536_usize),
        (65_536, 65_536),
        (65_535, 65_535),
    ] {
        let ran = call_with(FLOOD, &[asked], b"", policy);
        assert_eq!(
            ran.exit,
            Exit::Return(vec![Value::Int(moved as u128)]),
            "asked {asked}"
        );
        assert_eq!(ran.output, vec![b'x'; moved]);
    }
    // The whole span is guarded, not only the part that is transferred.
    let ran = call_with(FLOOD, &[70_001], b"", policy);
    assert_eq!(fault(&ran.exit), ("trap", "memory_bounds"));
    assert!(ran.output.is_empty());
}

#[test]
fn a_program_can_end_itself() {
    assert_eq!(call(QUIT, &[0, 0], b"").exit, Exit::Exited(0));
    assert_eq!(call(QUIT, &[3, 1], b"").exit, Exit::Exited(3));
    // The status is a signed 32-bit value.
    assert_eq!(call(QUIT, &[0xffff_ffff, 2], b"").exit, Exit::Exited(-1));
    assert_eq!(call(QUIT, &[300, 0], b"").exit, Exit::Exited(300));
    // The mode is one of clean, quick and immediate.
    let ran = call(QUIT, &[0, 3], b"");
    assert_eq!(fault(&ran.exit), ("trap", "service_argument"));
    assert_eq!(call(GIVE_UP, &[], b"").exit, Exit::Aborted);
}

/// Grants one capability and performs nothing.
struct Only(&'static str);

impl Host for Only {
    fn grants(&self, capability: &str) -> bool {
        capability == self.0
    }

    fn read(&mut self, _handle: u64, _buffer: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EIO)
    }

    fn write(&mut self, _handle: u64, _bytes: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EIO)
    }

    fn now(&mut self, _clock: Clock) -> Result<u64, Errno> {
        Err(Errno::EIO)
    }
}

#[test]
fn every_declared_capability_must_be_granted() {
    let module = module();
    assert_eq!(
        module.capabilities().collect::<Vec<_>>(),
        ["file", "process"]
    );
    let entry = module.function(GIVE_UP).unwrap();
    // The function needs no capability itself; the module declares them.
    let refused = run(&module, entry, &[], Policy::default()).unwrap_err();
    assert_eq!(
        (refused.code(), refused.context()),
        ("EXEC_CAPABILITY", "file")
    );
    let refused = run_with(&module, entry, &[], Policy::default(), &mut NoHost).unwrap_err();
    assert_eq!(refused.code(), "EXEC_CAPABILITY");
    for (granted, missing) in [("file", "process"), ("process", "file")] {
        let refused =
            run_with(&module, entry, &[], Policy::default(), &mut Only(granted)).unwrap_err();
        assert_eq!(
            (refused.code(), refused.context()),
            ("EXEC_CAPABILITY", missing)
        );
    }
}

#[test]
fn a_host_failure_is_the_status_of_the_call() {
    // A host that grants everything and fails every transfer.
    struct Failing;
    impl Host for Failing {
        fn grants(&self, _capability: &str) -> bool {
            true
        }
        fn read(&mut self, _handle: u64, _buffer: &mut [u8]) -> Result<usize, Errno> {
            Err(Errno::EIO)
        }
        fn write(&mut self, _handle: u64, _bytes: &[u8]) -> Result<usize, Errno> {
            Err(Errno::EPIPE)
        }
        fn now(&mut self, _clock: Clock) -> Result<u64, Errno> {
            Err(Errno::EIO)
        }
    }
    let module = module();
    let outcome = run_with(
        &module,
        module.function(WRITE_TEXT).unwrap(),
        &[Value::Int(1), Value::Int(6)],
        Policy::default(),
        &mut Failing,
    )
    .unwrap();
    assert_eq!(outcome.exit, packed(u128::from(Errno::EPIPE.code()), 0));
    let outcome = run_with(
        &module,
        module.function(READ_FROM).unwrap(),
        &[Value::Int(0)],
        Policy::default(),
        &mut Failing,
    )
    .unwrap();
    assert_eq!(outcome.exit, packed(u128::from(Errno::EIO.code()), 0));
}

#[test]
fn main_receives_the_argument_vector() {
    let module = module();
    assert!(module.export("main").is_some());
    assert_eq!(module.export("program_quit"), module.function(QUIT));
    assert_eq!(module.export("no_such_function"), None);
    let run_main = |arguments: &[&str]| {
        let mut host = StandardStreams {
            input: &b""[..],
            output: Vec::new(),
            error: Vec::new(),
        };
        let arguments: Vec<Vec<u8>> = arguments
            .iter()
            .map(|text| text.as_bytes().to_vec())
            .collect();
        let outcome = run_program(&module, &arguments, Policy::default(), &mut host);
        (outcome.map(|outcome| outcome.exit), host.output)
    };
    // main writes five bytes of its second argument and returns the count
    // of arguments plus 100 when the vector ends with a null pointer.
    let (exit, output) = run_main(&["program", "portable"]);
    assert_eq!(exit.unwrap(), Exit::Return(vec![Value::Int(102)]));
    assert_eq!(output, b"porta");
    let (exit, output) = run_main(&["program", "first", "second", "third"]);
    assert_eq!(exit.unwrap(), Exit::Return(vec![Value::Int(104)]));
    assert_eq!(output, b"first");
    // A shorter argument ends before five bytes do: the write runs past the
    // end of the vector's object.
    let (exit, _) = run_main(&["program", "ab"]);
    assert_eq!(fault(&exit.unwrap()), ("trap", "memory_bounds"));
    // With one argument, the second slot is the terminating null pointer.
    let (exit, _) = run_main(&["program"]);
    assert_eq!(fault(&exit.unwrap()), ("language_ub", "pointer_provenance"));
    // An argument cannot hold the byte that ends it.
    let (exit, _) = run_main(&["program", "a\0b"]);
    assert_eq!(exit.unwrap_err().code(), "EXEC_ENTRY");
}

/// Run `smir-run` on the service object with `input` on its standard input.
fn runner(arguments: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_smir-run"))
        .arg(object())
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start smir-run");
    child
        .stdin
        .take()
        .expect("piped input")
        .write_all(input)
        .expect("write input");
    child.wait_with_output().expect("smir-run output")
}

#[test]
fn the_command_line_runs_the_program_with_the_process_streams() {
    let ran = runner(&["--program", "--", "portable", "smir"], b"");
    assert_eq!(ran.stdout, b"porta");
    assert!(
        ran.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    // main returns 3 + 100: the object's path and the two arguments.
    assert_eq!(ran.status.code(), Some(103));

    // A program that faults: nothing on standard output, one line of JSON on
    // standard error, and the status that says it did not complete.
    let ran = runner(&["--program"], b"");
    assert!(ran.stdout.is_empty());
    let report: Json = serde_json::from_slice(&ran.stderr).expect("the report is JSON");
    assert_eq!(
        (report["status"].as_str(), report["code"].as_str()),
        (Some("language_ub"), Some("pointer_provenance"))
    );
    assert_eq!(report["function"], 300);
    assert_eq!(ran.status.code(), Some(125));

    // A limit that the run exhausts is reported the same way.
    let ran = runner(&["--program", "--fuel", "3", "--", "portable"], b"");
    let report: Json = serde_json::from_slice(&ran.stderr).expect("the report is JSON");
    assert_eq!(
        (report["status"].as_str(), report["code"].as_str()),
        (Some("resource"), Some("fuel"))
    );
    assert_eq!(ran.status.code(), Some(125));

    // Functions of an object that needs capabilities cannot be run one by one.
    let ran = runner(&["--entry-function", "309"], b"");
    let report: Json = serde_json::from_slice(&ran.stdout).expect("the rejection is JSON");
    assert_eq!(
        (
            report["status"].as_str(),
            report["code"].as_str(),
            report["detail"].as_str()
        ),
        (Some("rejected"), Some("EXEC_CAPABILITY"), Some("file"))
    );
    assert_eq!(ran.status.code(), Some(1));

    // Program arguments belong to program mode only.
    assert_eq!(
        runner(&["--batch", "--", "x"], b"[]").status.code(),
        Some(2)
    );
    assert_eq!(
        runner(&["--program", "--batch"], b"").status.code(),
        Some(2)
    );
}

/// A host whose clocks read fixed values, and whose thread clock fails.
struct Clocks;

impl Host for Clocks {
    fn grants(&self, _capability: &str) -> bool {
        true
    }

    fn read(&mut self, _handle: u64, _buffer: &mut [u8]) -> Result<usize, Errno> {
        Ok(0)
    }

    fn write(&mut self, _handle: u64, bytes: &[u8]) -> Result<usize, Errno> {
        Ok(bytes.len())
    }

    fn now(&mut self, clock: Clock) -> Result<u64, Errno> {
        match clock {
            Clock::Monotonic => Ok(1_000),
            Clock::Utc => Ok(1_800_000_000_123_456_789),
            Clock::ProcessCpu => Ok(u64::MAX),
            Clock::ThreadCpu => Err(Errno::EIO),
        }
    }
}

#[test]
fn a_clock_reading_is_the_host_s_or_a_status() {
    const NOW: u32 = 303;
    let module = lifecycle_module();
    let read = |clock: u128, host: &mut dyn Host| {
        let entry = module.function(NOW).unwrap();
        run_with(
            &module,
            entry,
            &[Value::Int(clock)],
            Policy::default(),
            host,
        )
        .unwrap()
        .exit
    };
    let reading = |status: u32, nanoseconds: u64| {
        Exit::Return(vec![
            Value::Int(u128::from(status)),
            Value::Int(u128::from(nanoseconds)),
        ])
    };
    assert_eq!(read(0, &mut Clocks), reading(0, 1_000));
    assert_eq!(read(1, &mut Clocks), reading(0, 1_800_000_000_123_456_789));
    assert_eq!(read(2, &mut Clocks), reading(0, u64::MAX));
    // A clock the host cannot read, and an identifier that names no clock.
    assert_eq!(read(3, &mut Clocks), reading(Errno::EIO.code(), 0));
    assert_eq!(read(4, &mut Clocks), reading(Errno::EINVAL.code(), 0));
    assert_eq!(
        read(0xffff_ffff, &mut Clocks),
        reading(Errno::EINVAL.code(), 0)
    );

    // The host's own clocks: the epoch clock is past 2020, and the monotonic
    // clock does not go back.
    let mut host = StandardStreams {
        input: &b""[..],
        output: Vec::new(),
        error: Vec::new(),
    };
    let nanoseconds = |exit: Exit| match exit {
        Exit::Return(values) => match values.as_slice() {
            [Value::Int(0), Value::Int(nanoseconds)] => *nanoseconds,
            other => panic!("clock failed: {other:?}"),
        },
        other => panic!("clock did not return: {other:?}"),
    };
    assert!(nanoseconds(read(1, &mut host)) > 1_577_836_800_000_000_000);
    let first = nanoseconds(read(0, &mut host));
    assert!(nanoseconds(read(0, &mut host)) >= first);
    assert!(nanoseconds(read(2, &mut host)) >= first);
}
