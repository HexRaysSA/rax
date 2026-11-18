//! Guest threads and waiting, on `programs/threads.smo`.
//!
//! The Python reference machine has one thread, so these programs are not
//! compared with it. Each expectation is what the service catalog says the
//! `thread` and `sync` services do. A program's threads run in parallel on
//! host threads, so only what every interleaving produces is asserted.

use super::{checked, crate_dir, python};
use rax_smir_portable::Limits;
use rax_smir_portable::interp::{Exit, NoHost, Outcome, Policy, StandardStreams, run_with};
use rax_smir_portable::ir::{Module, Value};
use std::time::{Duration, Instant};

const COUNT: u32 = 300;
const IDENTITY: u32 = 301;
const JOINS: u32 = 302;
const DETACHED: u32 = 303;
const EXIT_VALUE: u32 = 304;
const WAITS: u32 = 305;
const HANDOFF: u32 = 306;
const STUCK: u32 = 307;
const JOIN_SLEEPER: u32 = 308;
const JOIN_FAILING: u32 = 309;
const JOIN_QUITTING: u32 = 320;
const LEAVE_SPINNER: u32 = 321;
const BAD_ENTRY: u32 = 322;
const MISALIGNED: u32 = 323;
const OUTSIDE: u32 = 324;
const FIRST_LEAVES: u32 = 325;
const JOIN_SPINNER: u32 = 326;
const ROUSE: u32 = 327;
const OWN_COPIES: u32 = 341;
const OUTLIVED: u32 = 343;
const BEYOND: u32 = 344;
/// The function the failing thread runs.
const FAIL: u32 = 315;

const EAGAIN: u128 = 11;
const EINVAL: u128 = 22;
const EDEADLK: u128 = 35;
const ETIMEDOUT: u128 = 110;

fn module() -> Module {
    Module::load(
        &std::fs::read(crate_dir().join("tests/interp/programs/threads.smo")).expect("threads.smo"),
        Limits::default(),
    )
    .expect("threads.smo verifies and lowers")
}

fn run(function: u32, arguments: &[u128], policy: Policy) -> Outcome {
    let module = module();
    let mut host = StandardStreams {
        input: &b""[..],
        output: Vec::new(),
        error: Vec::new(),
    };
    let values: Vec<Value> = arguments.iter().map(|bits| Value::Int(*bits)).collect();
    let entry = module.function(function).expect("function exists");
    run_with(&module, entry, &values, policy, &mut host).expect("the request is valid")
}

/// How a function that takes nothing ends, under the default limits.
fn call(function: u32) -> Exit {
    run(function, &[], Policy::default()).exit
}

fn returned(values: &[u128]) -> Exit {
    Exit::Return(values.iter().map(|bits| Value::Int(*bits)).collect())
}

#[test]
fn the_committed_object_is_the_assembled_builder_output() {
    let directory = crate_dir().join("tests/interp/programs");
    let mut build = python();
    build.arg(directory.join("build_threads.py")).arg("--check");
    checked(build, None, "programs/build_threads.py --check");
    let mut assemble = python();
    assemble
        .arg(crate_dir().join("tests/interp/oracle.py"))
        .arg("assemble")
        .arg(directory.join("threads.json"))
        .arg(directory.join("threads.smo"));
    checked(assemble, None, "oracle.py assemble");
}

#[test]
fn threads_need_the_thread_and_sync_capabilities() {
    let module = module();
    let entry = module.function(IDENTITY).unwrap();
    let error = run_with(&module, entry, &[], Policy::default(), &mut NoHost).unwrap_err();
    assert_eq!(error.code(), "EXEC_CAPABILITY");
}

#[test]
fn threads_add_to_one_word_without_losing_an_update() {
    // Four threads, each adding one a number of times with an atomic
    // read-modify-write. A lost update would leave the word short.
    for each in [0_u128, 1, 1000, 50_000] {
        let policy = Policy {
            fuel: u64::MAX,
            ..Policy::default()
        };
        let outcome = run(COUNT, &[each], policy);
        assert_eq!(outcome.exit, returned(&[4 * each, 4 * each, 0]), "{each}");
        // Each addition is at least three steps of its thread, and the steps
        // of all threads are counted together.
        assert!(outcome.steps >= 12 * each as u64, "{} steps", outcome.steps);
    }
}

#[test]
fn a_thread_knows_its_identity_and_the_first_thread_is_one() {
    // The first thread is 1; the first thread it starts has handle 2 and
    // says so itself.
    assert_eq!(call(IDENTITY), returned(&[1, 2, 2]));
}

#[test]
fn a_thread_is_joined_once_and_not_by_itself() {
    assert_eq!(call(JOINS), returned(&[0, EINVAL, EDEADLK, EINVAL]));
    // A detached thread cannot be joined, nor detached again.
    assert_eq!(call(DETACHED), returned(&[0, EINVAL, EINVAL]));
}

#[test]
fn a_thread_that_ends_itself_leaves_its_result() {
    assert_eq!(call(EXIT_VALUE), returned(&[0, 77]));
    // The first thread ending itself ends the program normally.
    assert_eq!(call(FIRST_LEAVES), Exit::Exited(0));
}

#[test]
fn a_wait_returns_at_once_unless_the_word_holds_the_expected_value() {
    // The word is zero. Expecting one: EAGAIN. Expecting zero with no time,
    // or with a millisecond and nobody to wake: ETIMEDOUT. Nobody waits, so a
    // wake wakes nobody.
    assert_eq!(call(WAITS), returned(&[EAGAIN, ETIMEDOUT, ETIMEDOUT, 0, 0]));
}

#[test]
fn a_wake_after_a_store_is_never_lost() {
    // The second thread waits while the word is zero; the first stores nine
    // and wakes. Whichever gets there first, the waiter sees the nine: a
    // lost wake would leave it waiting, and the join with it.
    for _ in 0..200 {
        assert_eq!(call(HANDOFF), returned(&[0, 9]));
    }
}

#[test]
fn a_woken_thread_runs_again_and_may_wait_again() {
    // The first thread wakes until it has woken the waiter, without changing
    // the word, so the waiter was really waiting and goes back to waiting.
    // Only then does the first thread store and wake for good.
    let policy = Policy {
        fuel: u64::MAX,
        ..Policy::default()
    };
    for _ in 0..50 {
        assert_eq!(run(ROUSE, &[], policy).exit, returned(&[0, 9]));
    }
}

#[test]
fn a_program_whose_threads_all_wait_is_stopped() {
    // Nothing can wake the only thread.
    assert_eq!(call(STUCK), Exit::Deadlock);
    // One thread joins another that sleeps for good.
    assert_eq!(call(JOIN_SLEEPER), Exit::Deadlock);
}

#[test]
fn what_ends_one_thread_abnormally_ends_the_program() {
    // The first thread is waiting in a join when the other one faults; the
    // fault is located in the function that thread ran.
    let Exit::Trap(fault) = call(JOIN_FAILING) else {
        panic!("expected the thread's trap");
    };
    assert_eq!(
        (fault.code.as_str(), fault.function),
        ("worker_failed", FAIL)
    );
    assert_eq!(call(JOIN_QUITTING), Exit::Exited(3));
}

#[test]
fn the_program_ends_when_its_first_thread_returns() {
    // The other thread spins for ever; it is stopped, not waited for. It
    // must not run out of steps before the first thread gets to return,
    // however busy the host is.
    let started = Instant::now();
    let policy = Policy {
        fuel: u64::MAX,
        ..Policy::default()
    };
    assert_eq!(run(LEAVE_SPINNER, &[], policy).exit, returned(&[0]));
    assert!(started.elapsed() < Duration::from_secs(20));
}

#[test]
fn the_step_limit_covers_all_threads() {
    // The first thread waits in a join for a thread that spins until the
    // steps run out. No more steps are counted than the limit allows.
    let policy = Policy {
        fuel: 100_000,
        ..Policy::default()
    };
    let outcome = run(JOIN_SPINNER, &[], policy);
    assert_eq!(outcome.exit, Exit::Resource("fuel"));
    assert!(outcome.steps <= 100_000, "{} steps", outcome.steps);
    assert!(outcome.steps >= 90_000, "{} steps", outcome.steps);
}

#[test]
fn every_thread_has_its_own_copy_of_thread_local_storage() {
    // The segment holds 5 and 7. Each of the two threads adds 100 to its
    // first word and sees 112 in all; the first thread's own word, which it
    // set to 9 before, is untouched.
    for _ in 0..20 {
        assert_eq!(call(OWN_COPIES), returned(&[112, 112, 9]));
    }
}

#[test]
fn thread_local_storage_ends_with_its_thread() {
    let Exit::Trap(fault) = call(OUTLIVED) else {
        panic!("expected a trap");
    };
    assert_eq!(fault.code, "memory_lifetime");
    // An address past the segment's end is representable, and is checked
    // like any other when it is used.
    let Exit::Trap(fault) = call(BEYOND) else {
        panic!("expected a trap");
    };
    assert_eq!(fault.code, "memory_bounds");
}

#[test]
fn a_thread_starts_only_at_a_function_of_the_entry_shape() {
    assert_eq!(call(BAD_ENTRY), returned(&[EINVAL]));
}

#[test]
fn the_waited_word_is_guarded_like_any_access() {
    let Exit::Trap(fault) = call(MISALIGNED) else {
        panic!("expected a trap");
    };
    assert_eq!(fault.code, "service_argument");
    // The null pointer has no object behind it.
    assert!(matches!(call(OUTSIDE), Exit::LanguageUb(_) | Exit::Trap(_)));
}
