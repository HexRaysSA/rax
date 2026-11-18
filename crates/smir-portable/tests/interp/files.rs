//! Files, on `programs/files.smo`.
//!
//! The Python reference machine performs no services, so these programs are
//! not compared with it. Each expectation is what the service catalog says
//! the `file` services do, for a host whose files are those of a directory.

use super::crate_dir;
use rax_smir_portable::Limits;
use rax_smir_portable::interp::{
    Code, Directory, Engine, Exit, NoHost, Policy, StandardStreams, run_on, run_with,
};
use rax_smir_portable::ir::{Module, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

const ROUND_TRIP: u32 = 300;
const POSITIONS: u32 = 301;
const REFUSED: u32 = 302;
const NAMES: u32 = 303;
const APPEND: u32 = 304;
const NO_SPAN: u32 = 305;
const AFTER_CLOSE: u32 = 306;
const NOWHERE: u32 = 307;

const ENOENT: u128 = 2;
const EBADF: u128 = 9;
const EINVAL: u128 = 22;
const ESPIPE: u128 = 29;
const EROFS: u128 = 30;
const ENAMETOOLONG: u128 = 36;
const EILSEQ: u128 = 84;

fn module() -> Module {
    Module::load(
        &std::fs::read(crate_dir().join("tests/interp/programs/files.smo")).expect("files.smo"),
        Limits::default(),
    )
    .expect("files.smo verifies and lowers")
}

/// A fresh directory, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static COUNT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "smir-files-{}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

type Streams = StandardStreams<&'static [u8], Vec<u8>, Vec<u8>>;

fn streams() -> Streams {
    StandardStreams {
        input: b"",
        output: Vec::new(),
        error: Vec::new(),
    }
}

/// Run a function on both engines, each with a directory of its own, and
/// return how it ended and the directory the interpreter left. The two runs
/// must end the same, after the same number of steps.
fn call(function: u32) -> (Exit, Scratch) {
    let module = module();
    let entry = module.function(function).expect("function exists");
    let code = Code::compile(&module).expect("the module compiles for this host");
    let run = |engine| {
        let scratch = Scratch::new();
        let mut host = Directory::new(streams(), &scratch.0).expect("the directory is there");
        let outcome = run_on(engine, &module, entry, &[], Policy::default(), &mut host)
            .expect("the request is valid");
        (outcome, scratch)
    };
    let (interpreted, scratch) = run(Engine::Interpreter);
    let (native, _) = run(Engine::Native(&code));
    assert_eq!(native, interpreted, "function {function}");
    (interpreted.exit, scratch)
}

fn returned(values: &[u128]) -> Exit {
    Exit::Return(values.iter().map(|bits| Value::Int(*bits)).collect())
}

#[test]
fn files_need_the_file_capability() {
    let module = module();
    let entry = module.function(ROUND_TRIP).unwrap();
    let refused = run_with(&module, entry, &[], Policy::default(), &mut NoHost).unwrap_err();
    assert_eq!(refused.code(), "EXEC_CAPABILITY");
}

#[test]
fn a_file_holds_what_was_written_to_it() {
    let (exit, scratch) = call(ROUND_TRIP);
    let first = u128::from(u64::from_le_bytes(*b"hello, f"));
    assert_eq!(exit, returned(&[0, 12, 0, 0, 12, first, 0]));
    // It is a file of the machine, in the directory the host was given.
    assert_eq!(
        std::fs::read(scratch.0.join("notes.txt")).unwrap(),
        b"hello, file\n"
    );
}

#[test]
fn the_position_moves_from_the_start_the_end_or_itself() {
    let word = u128::from(u32::from_le_bytes(*b"file"));
    assert_eq!(
        call(POSITIONS).0,
        returned(&[7, word, 7, 8, EINVAL, EINVAL, ESPIPE])
    );
}

#[test]
fn requests_that_name_no_file_are_refused_with_a_status() {
    assert_eq!(
        call(REFUSED).0,
        returned(&[
            ENOENT,
            EINVAL,
            EINVAL,
            EINVAL,
            EINVAL,
            EILSEQ,
            EINVAL,
            ENAMETOOLONG,
            EINVAL,
            EBADF,
            EBADF,
            ENOENT,
            ENOENT
        ])
    );
}

#[test]
fn a_name_is_changed_and_removed() {
    let (exit, scratch) = call(NAMES);
    assert_eq!(exit, returned(&[0, ENOENT, 0, 0, 0, ENOENT]));
    assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
}

#[test]
fn appended_bytes_go_to_the_end() {
    let word = u128::from(u32::from_le_bytes(*b"hell"));
    let (exit, scratch) = call(APPEND);
    assert_eq!(exit, returned(&[12, word]));
    assert_eq!(
        std::fs::read(scratch.0.join("notes.txt")).unwrap(),
        b"hellohello, "
    );
}

#[test]
fn a_name_the_program_may_not_read_is_a_fault() {
    // The fault a load of the same bytes would raise.
    match call(NO_SPAN).0 {
        Exit::LanguageUb(fault) => assert_eq!(fault.code, "pointer_provenance"),
        other => panic!("expected a fault, got {other:?}"),
    }
}

#[test]
fn a_closed_handle_is_no_handle() {
    assert_eq!(call(AFTER_CLOSE).0, returned(&[EBADF, EBADF, EBADF]));
}

#[test]
fn a_host_without_a_directory_has_no_files() {
    let module = module();
    let entry = module.function(NOWHERE).unwrap();
    let outcome = run_with(&module, entry, &[], Policy::default(), &mut streams()).unwrap();
    assert_eq!(outcome.exit, returned(&[EROFS, ENOENT]));
}
