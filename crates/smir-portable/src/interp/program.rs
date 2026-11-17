//! Running a module as a program: its `main` function, with arguments.

use crate::Error;
use crate::ir::{Module, Pointer, Scalar, Type, Value};

use super::host::Host;
use super::memory::{Fault, Memory};
use super::{Exit, Outcome, Policy, execute, internal, start};

/// Place the argument strings and the vector of pointers to them in one new
/// object and return the vector's address.
///
/// The vector comes first: one pointer per argument and a null pointer after
/// the last. Each string follows with a terminating zero byte. The program
/// may modify all of it.
fn argument_vector(memory: &mut Memory, arguments: &[Vec<u8>]) -> Result<Pointer, Fault> {
    let slots = 8 * (arguments.len() as u64 + 1);
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
    let end = at(8 * arguments.len() as u64);
    memory.store(
        end,
        Value::DataPtr(Pointer::originless(0)),
        Scalar::DataPtr,
        8,
        8,
    )?;
    Ok(vector)
}

/// Run the module's `main` function as a program, performing runtime
/// services against `host`.
///
/// `main` is the exported function of that name. It returns a 32-bit integer
/// and takes either no parameters or a 32-bit argument count and a pointer
/// to the argument vector, which is built from `arguments`; by convention
/// the first argument is the program's name.
///
/// # Errors
///
/// `EXEC_ENTRY` if the module exports no such `main`, or an argument holds a
/// zero byte. `EXEC_CAPABILITY` names a capability the module declares and
/// `host` does not grant.
pub fn run_program(
    module: &Module,
    arguments: &[Vec<u8>],
    policy: Policy,
    host: &mut dyn Host,
) -> Result<Outcome, Error> {
    let entry = module.export("main").ok_or_else(|| {
        Error::semantic("EXEC_ENTRY", "the module exports no function named main")
    })?;
    let signature = module.signature(entry);
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
    let takes_arguments = match (
        shape(&signature.params).as_str(),
        shape(&signature.results).as_str(),
    ) {
        ("", "i") => false,
        ("ip", "i") => true,
        _ => {
            return Err(Error::semantic(
                "EXEC_ENTRY",
                "main must be int(void) or int(int, char **)",
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
    let mut state = match start(module, policy, host)? {
        Ok(state) => state,
        Err(outcome) => return Ok(outcome),
    };
    let values = if takes_arguments {
        match argument_vector(&mut state.memory, arguments) {
            Ok(vector) => vec![Value::Int(count as u128), Value::DataPtr(vector)],
            Err(Fault::Resource(code)) => {
                return Ok(Outcome {
                    exit: Exit::Resource(code),
                    steps: 0,
                });
            }
            Err(_) => return Err(internal("argument vector staging")),
        }
    } else {
        Vec::new()
    };
    execute(module, state, entry, &values, policy)
}
