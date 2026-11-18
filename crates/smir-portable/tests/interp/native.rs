//! Native code against the interpreter.
//!
//! Code compiled for the host must end every run the way the interpreter
//! ends it: the same values, or the same fault at the same place, after the
//! same number of steps, and the same bytes on every stream. These tests run
//! the authored programs on both engines and require exactly that. The
//! tests of the services, of threads and of mapped memory do the same for
//! their own programs, through [`on_both`].

use super::{POLICY, Sequence, crate_dir, programs, vectors};
use rax_smir_portable::Limits;
use rax_smir_portable::interp::{
    Code, Engine, Host, NoHost, Outcome, Policy, StandardStreams, run_on,
};
use rax_smir_portable::ir::{Module, Value};

/// What one run did: how it ended, and what reached the two output streams.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Ran {
    pub(crate) outcome: Outcome,
    pub(crate) output: Vec<u8>,
    pub(crate) error: Vec<u8>,
    /// Input the program did not consume.
    pub(crate) unread: Vec<u8>,
}

fn on(
    engine: Engine,
    module: &Module,
    function: u32,
    arguments: &[u128],
    input: &[u8],
    policy: Policy,
) -> Ran {
    let mut host = StandardStreams {
        input,
        output: Vec::new(),
        error: Vec::new(),
    };
    let values: Vec<Value> = arguments.iter().map(|bits| Value::Int(*bits)).collect();
    let entry = module.function(function).expect("function exists");
    let outcome =
        run_on(engine, module, entry, &values, policy, &mut host).expect("the request is valid");
    Ran {
        outcome,
        output: host.output,
        error: host.error,
        unread: host.input.to_vec(),
    }
}

/// Run a function by interpreting it and as native code, with the three
/// standard streams. The two runs must do the same; with `counted`, in the
/// same number of steps, which holds for a program with one thread.
pub(crate) fn on_both(
    module: &Module,
    function: u32,
    arguments: &[u128],
    input: &[u8],
    policy: Policy,
    counted: bool,
) -> Ran {
    let code = Code::compile(module).expect("the module compiles for this host");
    let interpreted = on(
        Engine::Interpreter,
        module,
        function,
        arguments,
        input,
        policy,
    );
    let mut native = on(
        Engine::Native(&code),
        module,
        function,
        arguments,
        input,
        policy,
    );
    if !counted {
        native.outcome.steps = interpreted.outcome.steps;
    }
    assert_eq!(
        native, interpreted,
        "native code and the interpreter differ on function {function} with {arguments:x?}"
    );
    interpreted
}

fn authored() -> Module {
    Module::load(
        &std::fs::read(crate_dir().join("tests/interp/programs/programs.smo"))
            .expect("programs.smo"),
        Limits::default(),
    )
    .expect("programs.smo verifies and lowers")
}

#[test]
fn native_code_ends_every_authored_case_like_the_interpreter() {
    let module = authored();
    let code = Code::compile(&module).expect("the module compiles for this host");
    // The cases of the comparison with the reference machine, under its
    // limits, and each of them again under limits that most runs reach:
    // native code must stop at the same step.
    let tight = [
        Policy { fuel: 0, ..POLICY },
        Policy { fuel: 1, ..POLICY },
        Policy { fuel: 9, ..POLICY },
        Policy { fuel: 64, ..POLICY },
        Policy {
            max_frames: 2,
            ..POLICY
        },
        Policy {
            max_memory_bytes: 24,
            ..POLICY
        },
    ];
    let mut random = Sequence(0x534d_4952_4d31_0001);
    let (mut cases, mut returned, mut stopped) = (0, 0, 0);
    for program in &programs() {
        let entry = module
            .function(program.id)
            .expect("program is in the module");
        for (number, arguments) in vectors(&program.params, &mut random).iter().enumerate() {
            let values: Vec<Value> = arguments.iter().map(|value| Value::Int(*value)).collect();
            // Every case under the usual limits; every eighth under the
            // tight ones as well.
            let policies = std::iter::once(&POLICY).chain(tight.iter().filter(|_| number % 8 == 0));
            for policy in policies {
                let run = |engine| {
                    run_on(engine, &module, entry, &values, *policy, &mut NoHost)
                        .expect("entry request")
                };
                let (interpreted, native) = (run(Engine::Interpreter), run(Engine::Native(&code)));
                assert_eq!(
                    native, interpreted,
                    "{}{arguments:x?} under {policy:?}",
                    program.name
                );
                cases += 1;
                match interpreted.exit {
                    rax_smir_portable::interp::Exit::Return(_) => returned += 1,
                    _ => stopped += 1,
                }
            }
        }
    }
    eprintln!(
        "{cases} runs end alike as native code and interpreted: {returned} return, {stopped} stop otherwise"
    );
    assert!(cases >= 30_000, "only {cases} cases");
    assert!(returned >= 10_000 && stopped >= 5_000);
}

#[test]
fn code_runs_only_the_module_it_was_compiled_from() {
    let module = authored();
    let other = Module::load(
        &std::fs::read(crate_dir().join("tests/interp/programs/lifecycle.smo"))
            .expect("lifecycle.smo"),
        Limits::default(),
    )
    .expect("lifecycle.smo verifies and lowers");
    let code = Code::compile(&other).expect("the module compiles for this host");
    let entry = module.function(118).expect("function exists");
    let refused = run_on(
        Engine::Native(&code),
        &module,
        entry,
        &[Value::Int(7)],
        POLICY,
        &mut NoHost,
    )
    .unwrap_err();
    assert_eq!(refused.code(), "EXEC_ENGINE");
}

/// A host whose every answer is the same, to show that native code asks it
/// as often as the interpreter does.
struct Counting(u64);

impl Host for Counting {
    fn grants(&self, _capability: &str) -> bool {
        true
    }

    fn read(
        &mut self,
        _handle: u64,
        _buffer: &mut [u8],
    ) -> Result<usize, rax_smir_portable::interp::Errno> {
        self.0 += 1;
        Ok(0)
    }

    fn write(
        &mut self,
        _handle: u64,
        bytes: &[u8],
    ) -> Result<usize, rax_smir_portable::interp::Errno> {
        self.0 += 1;
        Ok(bytes.len())
    }

    fn now(
        &mut self,
        _clock: rax_smir_portable::interp::Clock,
    ) -> Result<u64, rax_smir_portable::interp::Errno> {
        self.0 += 1;
        Ok(42)
    }
}

#[test]
fn native_code_calls_the_host_as_often_as_the_interpreter() {
    let module = Module::load(
        &std::fs::read(crate_dir().join("tests/interp/programs/lifecycle.smo"))
            .expect("lifecycle.smo"),
        Limits::default(),
    )
    .expect("lifecycle.smo verifies and lowers");
    let code = Code::compile(&module).expect("the module compiles for this host");
    // main: three initializers, the entry and two finalizers each write once.
    let entry = module.function(300).expect("function exists");
    let calls = |engine| {
        let mut host = Counting(0);
        let outcome = run_on(engine, &module, entry, &[], Policy::default(), &mut host)
            .expect("the request is valid");
        (host.0, outcome)
    };
    let (interpreted, native) = (calls(Engine::Interpreter), calls(Engine::Native(&code)));
    assert_eq!(native, interpreted);
    assert_eq!(interpreted.0, 6);
}
