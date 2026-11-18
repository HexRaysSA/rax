//! Mapping memory, on `programs/mapping.smo`.
//!
//! The Python reference machine performs no services, so these programs are
//! not compared with it. Each expectation is what the service catalog says
//! the `memory` services do.

use super::crate_dir;
use rax_smir_portable::Limits;
use rax_smir_portable::interp::{Exit, NoHost, Outcome, Policy, run_with};
use rax_smir_portable::ir::{Module, Value};

const USE: u32 = 300;
const AFTER_UNMAP: u32 = 301;
const WRITE_READ_ONLY: u32 = 302;
const READ_WRITE_ONLY: u32 = 303;
const READ_NO_ACCESS: u32 = 304;
const PROTECT: u32 = 305;
const SEALED: u32 = 306;
const REFUSED: u32 = 307;
const TOO_MUCH: u32 = 308;
const AGAIN: u32 = 309;

const ENOMEM: u128 = 12;
const EINVAL: u128 = 22;

fn module() -> Module {
    Module::load(
        &std::fs::read(crate_dir().join("tests/interp/programs/mapping.smo")).expect("mapping.smo"),
        Limits::default(),
    )
    .expect("mapping.smo verifies and lowers")
}

/// Run a function on both engines, which must do the same.
fn run(function: u32, arguments: &[u128], policy: Policy) -> Outcome {
    super::native::on_both(&module(), function, arguments, b"", policy, true).outcome
}

fn call(function: u32, arguments: &[u128]) -> Exit {
    run(function, arguments, Policy::default()).exit
}

fn returned(values: &[u128]) -> Exit {
    Exit::Return(values.iter().map(|bits| Value::Int(*bits)).collect())
}

fn trap(exit: &Exit) -> &str {
    match exit {
        Exit::Trap(fault) => &fault.code,
        other => panic!("expected a trap, got {other:?}"),
    }
}

#[test]
fn mapping_needs_the_memory_capability() {
    let module = module();
    let entry = module.function(USE).unwrap();
    let refused = run_with(
        &module,
        entry,
        &[Value::Int(1)],
        Policy::default(),
        &mut NoHost,
    )
    .unwrap_err();
    assert_eq!(refused.code(), "EXEC_CAPABILITY");
}

#[test]
fn mapped_memory_is_zero_and_holds_what_is_written() {
    // The last eight bytes read as zero, so the sum is the value written.
    for value in [0_u128, 1, 0x1122_3344_5566_7788] {
        assert_eq!(call(USE, &[value]), returned(&[0, value, 0]));
    }
}

#[test]
fn a_mapping_ends_when_it_is_unmapped() {
    assert_eq!(trap(&call(AFTER_UNMAP, &[])), "memory_lifetime");
}

#[test]
fn a_mapping_permits_what_it_was_mapped_for() {
    // Reading a read-only mapping works; the write after it does not.
    assert_eq!(trap(&call(WRITE_READ_ONLY, &[])), "memory_permission");
    assert_eq!(trap(&call(READ_WRITE_ONLY, &[])), "memory_permission");
    assert_eq!(trap(&call(READ_NO_ACCESS, &[])), "memory_permission");
}

#[test]
fn permissions_change_and_the_contents_stay() {
    assert_eq!(call(PROTECT, &[]), returned(&[0, 5, 0, 6]));
    assert_eq!(trap(&call(SEALED, &[])), "memory_permission");
}

#[test]
fn requests_that_name_no_mapping_are_refused_with_a_status() {
    // Nothing to map, a bad alignment, an unknown permission, part of a
    // mapping, an object that is no mapping, a mapping already unmapped, and
    // an unknown permission to change to.
    assert_eq!(call(REFUSED, &[]), returned(&[EINVAL; 7]));
}

#[test]
fn mapped_bytes_count_against_the_memory_limit_until_unmapped() {
    let policy = Policy {
        max_memory_bytes: 4 << 20,
        ..Policy::default()
    };
    // More than the limit: a status and a null base, not a fault.
    assert_eq!(
        run(TOO_MUCH, &[5 << 20], policy).exit,
        returned(&[ENOMEM, 1])
    );
    assert_eq!(run(TOO_MUCH, &[1 << 20], policy).exit, returned(&[0, 0]));
    // A megabyte mapped and unmapped twenty times fits a limit of four.
    assert_eq!(run(AGAIN, &[20], policy).exit, returned(&[0]));
}
