//! Processes that last: `interp::Instance`, on the authored programs.
//!
//! An instance runs a module's initializers once, each call on the state
//! the earlier calls left, and the finalizers when it is finished. Both
//! engines must do the same.

use super::crate_dir;
use rax_smir_portable::Limits;
use rax_smir_portable::interp::{
    Called, Clock, Code, Errno, Exit, Host, Instance, NoHost, Policy, run,
};
use rax_smir_portable::ir::{Module, Value};
use std::sync::{Arc, Mutex};

fn load(name: &str) -> Arc<Module> {
    let bytes = std::fs::read(crate_dir().join(format!("tests/interp/programs/{name}.smo")))
        .expect("the object is there");
    Arc::new(Module::load(&bytes, Limits::default()).expect("the object verifies and lowers"))
}

/// The module with no code, and with code for this host.
fn engines(module: &Arc<Module>) -> [Option<Arc<Code>>; 2] {
    [
        None,
        Some(Arc::new(
            Code::compile(module).expect("the module compiles for this host"),
        )),
    ]
}

fn returned(values: &[u128]) -> Called {
    Called::Returned(values.iter().map(|bits| Value::Int(*bits)).collect())
}

/// A host that grants everything and keeps what is written to it, where
/// the test can read it while the instance has the host.
#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Shared {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Host for Shared {
    fn grants(&self, _capability: &str) -> bool {
        true
    }
    fn read(&mut self, _handle: u64, _buffer: &mut [u8]) -> Result<usize, Errno> {
        Ok(0)
    }
    fn write(&mut self, _handle: u64, bytes: &[u8]) -> Result<usize, Errno> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn now(&mut self, _clock: Clock) -> Result<u64, Errno> {
        Ok(0)
    }
}

/// `bump_counter(x)` of the authored programs: adds `x` to a global that
/// starts at 100 and returns the new value xor the old.
const BUMP_COUNTER: u32 = 161;
/// `through_pointer(x)`: reads a read-only table through a pointer, and
/// writes to it, which faults, when `x` is odd.
const THROUGH_POINTER: u32 = 162;

#[test]
fn what_a_call_leaves_the_next_call_finds() {
    let module = load("programs");
    let entry = module.function(BUMP_COUNTER).unwrap();
    // In a process of its own every call finds the counter at 100.
    for _ in 0..2 {
        let alone = run(&module, entry, &[Value::Int(3)], Policy::default()).unwrap();
        assert_eq!(alone.exit, Exit::Return(vec![Value::Int(103 ^ 100)]));
    }
    // An instance's call finds it where the call before left it.
    for code in engines(&module) {
        let instance = Instance::start(
            Arc::clone(&module),
            code,
            Policy::default(),
            Box::new(NoHost),
        )
        .unwrap();
        let mut counter = 100_u128;
        for x in [3_u128, 3, 40, 0, 1000] {
            assert_eq!(
                instance.call(entry, &[Value::Int(x)]).unwrap(),
                returned(&[(counter + x) ^ counter])
            );
            counter += x;
        }
        let outcome = instance.finish().unwrap();
        assert_eq!(outcome.exit, Exit::Return(Vec::new()));
        assert!(outcome.steps > 0);
    }
}

#[test]
fn a_call_with_other_arguments_than_the_function_takes_changes_nothing() {
    let module = load("programs");
    let entry = module.function(BUMP_COUNTER).unwrap();
    let instance = Instance::start(
        Arc::clone(&module),
        None,
        Policy::default(),
        Box::new(NoHost),
    )
    .unwrap();
    let before = instance.call(entry, &[Value::Int(0)]).unwrap();
    assert_eq!(instance.call(entry, &[]).unwrap_err().code(), "EXEC_ENTRY");
    assert_eq!(
        instance
            .call(entry, &[Value::Int(1), Value::Int(2)])
            .unwrap_err()
            .code(),
        "EXEC_ENTRY"
    );
    assert_eq!(instance.call(entry, &[Value::Int(0)]).unwrap(), before);
}

#[test]
fn a_fault_ends_the_instance_for_every_later_call() {
    let module = load("programs");
    let (faulting, bump) = (
        module.function(THROUGH_POINTER).unwrap(),
        module.function(BUMP_COUNTER).unwrap(),
    );
    for code in engines(&module) {
        let instance = Instance::start(
            Arc::clone(&module),
            code,
            Policy::default(),
            Box::new(NoHost),
        )
        .unwrap();
        assert!(matches!(
            instance.call(faulting, &[Value::Int(0)]).unwrap(),
            Called::Returned(_)
        ));
        let Called::Ended(exit) = instance.call(faulting, &[Value::Int(1)]).unwrap() else {
            panic!("writing to a read-only table faults")
        };
        assert!(
            matches!(&exit, Exit::Trap(fault) if fault.code == "memory_permission"),
            "{exit:?}"
        );
        // The program has ended; nothing more runs in it.
        assert_eq!(
            instance.call(bump, &[Value::Int(1)]).unwrap(),
            Called::Ended(exit.clone())
        );
        assert_eq!(instance.finish().unwrap().exit, exit);
    }
}

#[test]
fn initializers_run_once_and_finalizers_at_the_end() {
    const MAIN: u32 = 300;
    const QUIT: u32 = 301;
    let module = load("lifecycle");
    for code in engines(&module) {
        // Initializers write c, b, a; `main` writes m and returns 7;
        // finalizers write e, d.
        let host = Shared::default();
        let instance = Instance::start(
            Arc::clone(&module),
            code.clone(),
            Policy::default(),
            Box::new(host.clone()),
        )
        .unwrap();
        let main = module.function(MAIN).unwrap();
        assert_eq!(instance.call(main, &[]).unwrap(), returned(&[7]));
        assert_eq!(host.text(), "cbam");
        assert_eq!(instance.call(main, &[]).unwrap(), returned(&[7]));
        assert_eq!(host.text(), "cbamm");
        assert_eq!(instance.finish().unwrap().exit, Exit::Return(Vec::new()));
        assert_eq!(host.text(), "cbammed");

        // A call that ends the program in good order runs the finalizers
        // then; finishing does not run them again.
        let host = Shared::default();
        let instance = Instance::start(
            Arc::clone(&module),
            code.clone(),
            Policy::default(),
            Box::new(host.clone()),
        )
        .unwrap();
        let quit = module.function(QUIT).unwrap();
        assert_eq!(
            instance
                .call(quit, &[Value::Int(3), Value::Int(0)])
                .unwrap(),
            Called::Ended(Exit::Exited(3))
        );
        assert_eq!(host.text(), "cbamed");
        assert_eq!(
            instance.call(main, &[]).unwrap(),
            Called::Ended(Exit::Exited(3))
        );
        assert_eq!(instance.finish().unwrap().exit, Exit::Exited(3));
        assert_eq!(host.text(), "cbamed");

        // An instance that is dropped is finished.
        let host = Shared::default();
        drop(
            Instance::start(
                Arc::clone(&module),
                code,
                Policy::default(),
                Box::new(host.clone()),
            )
            .unwrap(),
        );
        assert_eq!(host.text(), "cbaed");
    }
}

#[test]
fn a_thread_a_call_started_runs_on_and_ends_with_the_instance() {
    // `leave_spinner` starts a thread that spins for ever, and returns;
    // `identity` starts and joins a thread of its own.
    const LEAVE_SPINNER: u32 = 321;
    const IDENTITY: u32 = 301;
    let module = load("threads");
    let policy = Policy {
        fuel: u64::MAX,
        ..Policy::default()
    };
    for code in engines(&module) {
        let instance = Instance::start(
            Arc::clone(&module),
            code,
            policy,
            Box::new(Shared::default()),
        )
        .unwrap();
        let spinner = module.function(LEAVE_SPINNER).unwrap();
        assert_eq!(instance.call(spinner, &[]).unwrap(), returned(&[0]));
        // The spinner is the program's second thread; the next call's
        // thread is its third, while the spinner spins on.
        let identity = module.function(IDENTITY).unwrap();
        assert_eq!(instance.call(identity, &[]).unwrap(), returned(&[1, 3, 3]));
        assert_eq!(instance.call(identity, &[]).unwrap(), returned(&[1, 4, 4]));
        // Finishing stops the spinner, which would never stop by itself.
        assert_eq!(instance.finish().unwrap().exit, Exit::Return(Vec::new()));
    }
}

#[test]
fn an_instance_needs_what_its_module_declares() {
    let module = load("lifecycle");
    let refused = Instance::start(module, None, Policy::default(), Box::new(NoHost));
    assert_eq!(
        refused.err().map(|error| error.code().to_owned()),
        Some("EXEC_CAPABILITY".into())
    );
}
