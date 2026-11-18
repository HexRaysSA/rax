//! Running a module as a program: its entry function, with arguments.

use crate::Error;
use crate::ir::{Module, Pointer, Scalar, Type, Value};

use super::exec::internal;
use super::host::Host;
use super::memory::{Fault, Memory};
use super::process::Process;
use super::{Engine, Exit, Outcome, Policy};

/// Place the argument strings and the vector of pointers to them in one new
/// object, and return the addresses of the argument vector and of the
/// environment vector.
///
/// The argument vector comes first: one pointer per argument and a null
/// pointer after the last. The environment vector follows; the environment
/// is empty, so it is one null pointer. Each string comes after that, with a
/// terminating zero byte. The program may modify all of it.
fn argument_vector(memory: &Memory, arguments: &[Vec<u8>]) -> Result<(Pointer, Pointer), Fault> {
    let slots = 8 * (arguments.len() as u64 + 2);
    let text: u64 = arguments
        .iter()
        .map(|argument| argument.len() as u64 + 1)
        .sum();
    let vector = memory.allocate(slots + text, 8)?;
    let at = |offset: u64| Pointer {
        address: vector.address + offset,
        origin: vector.origin,
    };
    let mut next = slots;
    for (position, argument) in arguments.iter().enumerate() {
        let slot = at(8 * position as u64);
        memory.store(slot, Value::DataPtr(at(next)), Scalar::DataPtr, 8, 8)?;
        memory.write_bytes(at(next), argument)?;
        memory.write_bytes(at(next + argument.len() as u64), &[0])?;
        next += argument.len() as u64 + 1;
    }
    let null = Value::DataPtr(Pointer::originless(0));
    let environment = at(8 * (arguments.len() as u64 + 1));
    memory.store(at(8 * arguments.len() as u64), null, Scalar::DataPtr, 8, 8)?;
    memory.store(environment, null, Scalar::DataPtr, 8, 8)?;
    Ok((vector, environment))
}

/// Run the module as a program, performing runtime services against `host`.
///
/// The entry is the exported function `_start`, which the compiler generates:
/// it takes a 32-bit argument count, a pointer to the argument vector and a
/// pointer to the environment vector, and returns a 32-bit status. A module
/// without one is entered at its exported `main`, which takes either nothing
/// or the count and the argument vector. The vectors are built from
/// `arguments`; by convention the first argument is the program's name. The
/// environment is empty.
///
/// # Errors
///
/// `EXEC_ENTRY` if the module exports no such function, or an argument holds
/// a zero byte. `EXEC_CAPABILITY` names a capability the module declares and
/// `host` does not grant.
pub fn run_program(
    module: &Module,
    arguments: &[Vec<u8>],
    policy: Policy,
    host: &mut dyn Host,
) -> Result<Outcome, Error> {
    run_program_on(Engine::Interpreter, module, arguments, policy, host)
}

/// Run the module as a program like [`run_program`], on the engine given.
///
/// # Errors
///
/// As [`run_program`]; `EXEC_ENGINE` if the engine's native code was
/// compiled from another module.
pub fn run_program_on(
    engine: Engine,
    module: &Module,
    arguments: &[Vec<u8>],
    policy: Policy,
    host: &mut dyn Host,
) -> Result<Outcome, Error> {
    let shape = |types: &[crate::ir::TypeId]| {
        types
            .iter()
            .map(|ty| match module.ty(*ty) {
                Type::Int { bits: 32 } => 'i',
                Type::DataPtr => 'p',
                _ => '?',
            })
            .collect::<String>()
    };
    // The function to enter and how many of the three arguments it takes.
    let (entry, taken) = match (module.export("_start"), module.export("main")) {
        (Some(start), _) => {
            let signature = module.signature(start);
            if (
                shape(&signature.params).as_str(),
                shape(&signature.results).as_str(),
            ) != ("ipp", "i")
            {
                return Err(Error::semantic(
                    "EXEC_ENTRY",
                    "_start must be int(int, char **, char **)",
                ));
            }
            (start, 3)
        }
        (None, Some(main)) => {
            let signature = module.signature(main);
            let taken = match (
                shape(&signature.params).as_str(),
                shape(&signature.results).as_str(),
            ) {
                ("", "i") => 0,
                ("ip", "i") => 2,
                _ => {
                    return Err(Error::semantic(
                        "EXEC_ENTRY",
                        "main must be int(void) or int(int, char **)",
                    ));
                }
            };
            (main, taken)
        }
        (None, None) => {
            return Err(Error::semantic(
                "EXEC_ENTRY",
                "the module exports neither _start nor main",
            ));
        }
    };
    if arguments.iter().any(|argument| argument.contains(&0)) {
        return Err(Error::semantic(
            "EXEC_ENTRY",
            "a program argument holds a zero byte",
        ));
    }
    let count = i32::try_from(arguments.len())
        .map_err(|_| Error::semantic("EXEC_ENTRY", "too many program arguments"))?;
    let process = match Process::start(module, policy, host, engine)? {
        Ok(process) => process,
        Err(outcome) => return Ok(outcome),
    };
    let mut values = Vec::new();
    if taken != 0 {
        match argument_vector(&process.memory, arguments) {
            Ok((vector, environment)) => {
                values = vec![
                    Value::Int(count as u128),
                    Value::DataPtr(vector),
                    Value::DataPtr(environment),
                ];
                values.truncate(taken);
            }
            Err(Fault::Resource(code)) => {
                return Ok(Outcome {
                    exit: Exit::Resource(code),
                    steps: 0,
                });
            }
            Err(_) => return Err(internal("argument vector staging")),
        }
    }
    process.execute(entry, &values)
}
