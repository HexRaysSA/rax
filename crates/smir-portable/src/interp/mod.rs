//! Interpreter for the typed IR.
//!
//! Observable behaviour follows chapter 02 and is compared step for step with
//! the Python reference machine: one step commits a block's phis, executes one
//! operation, or executes one terminator. A call's results are bound in the
//! same step as the callee's `return`.
//!
//! A program that starts threads runs each on a host thread of its own, in
//! parallel. Their steps are counted together, and how such a program ends
//! can depend on which thread gets where first; a program that starts none
//! runs the same way every time.
//!
//! Undefined behaviour and traps end execution with a located fault; they are
//! outcomes, not errors. [`run`] returns `Err` only when the entry request
//! itself is unusable.
//!
//! A program reaches the world outside it only through runtime services,
//! which the interpreter performs against a [`Host`]. [`run`] grants nothing;
//! [`run_with`] and [`run_program`] take the host to use.

mod atomic;
mod exec;
pub mod faults;
mod float;
mod host;
mod int;
mod memory;
mod process;
mod program;
mod services;
mod softfloat;
mod threads;

pub use host::{
    Clock, Errno, Host, NoHost, STANDARD_ERROR, STANDARD_INPUT, STANDARD_OUTPUT, StandardStreams,
};
pub use program::run_program;

use crate::Error;
use crate::ir::{FuncIdx, Module, Value};

use process::Process;

/// Host limits for one run.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Maximum number of steps, of all the program's threads together.
    pub fuel: u64,
    /// Maximum call depth, of each thread.
    pub max_frames: usize,
    /// Maximum bytes of live memory objects.
    pub max_memory_bytes: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            fuel: 100_000,
            max_frames: 1024,
            max_memory_bytes: memory::DEFAULT_MAX_BYTES,
        }
    }
}

/// Where and why execution stopped abnormally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault {
    pub code: String,
    /// Function and block identifiers as written in the object.
    pub function: u32,
    pub block: u32,
    /// Index of the operation in its block; the block's operation count for
    /// its terminator; -1 while committing phis.
    pub operation: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exit {
    Return(Vec<Value>),
    /// A defined trap: a registered trap code, or the reason token of an
    /// explicit `trap` terminator.
    Trap(Fault),
    /// The program executed undefined behaviour.
    LanguageUb(Fault),
    /// A host limit from [`Policy`] was reached. The code is one of the
    /// registered resource faults: `"fuel"`, `"frames"` or `"resource_memory"`.
    Resource(&'static str),
    /// The program ended itself with this status through `process.exit`.
    Exited(i32),
    /// The program ended itself through `process.abort`.
    Aborted,
    /// Every thread of the program waits, without a deadline, for something
    /// only another of its threads could do.
    Deadlock,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub exit: Exit,
    pub steps: u64,
}

/// Run `entry` with `arguments` until it returns, faults, or exhausts `policy`.
///
/// The run is granted no capability, so a module that declares one is
/// refused; use [`run_with`] for those.
///
/// # Errors
///
/// `EXEC_ENTRY` if the arguments do not match the entry function's parameter
/// types in number or shape. `EXEC_CAPABILITY` if the module declares a
/// capability. `EXEC_INTERNAL` if the module violates an invariant the
/// verifier is relied on to establish; that is a defect in this crate, not a
/// property of the guest program.
pub fn run(
    module: &Module,
    entry: FuncIdx,
    arguments: &[Value],
    policy: Policy,
) -> Result<Outcome, Error> {
    run_with(module, entry, arguments, policy, &mut NoHost)
}

/// Run `entry` like [`run`], performing runtime services against `host`.
///
/// # Errors
///
/// As [`run`]; `EXEC_CAPABILITY` names a capability the module declares and
/// `host` does not grant.
pub fn run_with(
    module: &Module,
    entry: FuncIdx,
    arguments: &[Value],
    policy: Policy,
    host: &mut dyn Host,
) -> Result<Outcome, Error> {
    match Process::start(module, policy, host)? {
        Ok(process) => process.execute(entry, arguments),
        Err(outcome) => Ok(outcome),
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
