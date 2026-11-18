//! Native code for a module.
//!
//! A module is compiled, whole, to code for the host. That code works on
//! the interpreter's own records: a thread's activations are the same
//! [`Frame`]s, memory is the same [`Memory`](super::memory::Memory), and a
//! step is the same unit. What native code adds is the path between the
//! steps: which operation comes next, which block follows a terminator and
//! which function a call enters are instructions, not decisions of a loop.
//! Each step itself is performed by a helper below, which runs the
//! interpreter's code for that one operation or terminator. A run as native
//! code therefore ends the way the same run would when interpreted, with
//! the same values, the same faults at the same places, and the same count
//! of steps.
//!
//! The shape of the code for one function:
//!
//! - an entry, which keeps the return address and enters the first block;
//! - for each block, its operations in order and then its terminator;
//! - for each edge between blocks, a stub that makes the target block
//!   current and commits its phis for that predecessor;
//! - an exit, which returns a status to the caller.
//!
//! Every step starts by taking one step out of the thread's lease, as the
//! interpreter's loop does, and gets a new lease when that one is used up.
//! A function returns zero to the native code that called it when it
//! returned normally, and anything else when the thread is to stop: the
//! caller then returns the same, down to the host.

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod memory;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
use aarch64::{Assembler, Label};
#[cfg(target_arch = "x86_64")]
use x86_64::{Assembler, Label};

use std::collections::BTreeMap;

use crate::Error;
use crate::ir::{BlockIdx, Function, Module, Op, Terminator};

use super::exec::{Frame, Step, commit_phis, internal, operation, terminator};
use super::process::{Context, Ended, admit, apply, give_back};

/// What native code asks of the engine, by position in the thread's record.
#[derive(Clone, Copy)]
pub(super) enum Helper {
    Refill,
    Enter,
    Operation,
    Terminator,
}

const HELPERS: usize = 4;

/// Offsets in [`Header`] that native code uses.
pub(super) const LEASE: usize = 0;
pub(super) const TARGET: usize = 8;

pub(super) fn helper_offset(helper: Helper) -> usize {
    16 + 8 * helper as usize
}

/// What a helper returns when the thread is to stop.
const STOP: u64 = u64::MAX;

/// The part of a thread's record that native code reads and writes.
#[repr(C)]
struct Header {
    /// Steps the thread has leased and not taken.
    lease: u64,
    /// The address of the code of the function a call is about to enter.
    target: usize,
    helpers: [usize; HELPERS],
}

/// A thread while it runs native code.
#[repr(C)]
struct Thread<'run, 'thread, 'scope, 'env, 'process> {
    header: Header,
    context: &'run Context<'thread, 'scope, 'env, 'process>,
    code: &'run Code,
    stack: Vec<Frame>,
    /// How the call from the host ended, once it has.
    ended: Option<Ended>,
    /// A defect of the engine that ended it instead.
    defect: Option<Error>,
}

impl Thread<'_, '_, '_, '_, '_> {
    fn end(&mut self, ended: Ended) -> u64 {
        self.ended = Some(ended);
        STOP
    }

    fn fail(&mut self, defect: Error) -> u64 {
        self.defect = Some(defect);
        STOP
    }

    fn top(&mut self) -> Result<&mut Frame, Error> {
        self.stack
            .last_mut()
            .ok_or_else(|| internal("empty call stack"))
    }
}

/// A new lease for a thread whose lease is used up, if it may go on.
///
/// # Safety
///
/// `thread` is the record of the calling thread, which native code got from
/// [`run`]; no other reference to it is in use.
unsafe extern "C" fn refill(thread: *mut Thread, _: u64) -> u64 {
    // SAFETY: see the function's contract.
    let thread = unsafe { &mut *thread };
    let depth = thread.stack.len();
    match admit(thread.context.process, &mut thread.header.lease, depth) {
        None => 0,
        Some(ended) => thread.end(ended),
    }
}

/// Make a block current, coming from a predecessor, and commit its phis.
/// `edge` holds the block in its upper half and, in its lower half, one more
/// than the predecessor, or zero at a function's entry.
///
/// # Safety
///
/// As for [`refill`].
unsafe extern "C" fn enter(thread: *mut Thread, edge: u64) -> u64 {
    // SAFETY: see the function's contract.
    let thread = unsafe { &mut *thread };
    let module = thread.context.process.module;
    let entered = thread.top().and_then(|frame| {
        frame.block = BlockIdx((edge >> 32) as u32);
        frame.predecessor = (edge as u32).checked_sub(1).map(BlockIdx);
        frame.position = None;
        commit_phis(module, frame)
    });
    match entered {
        Ok(()) => 0,
        Err(defect) => thread.fail(defect),
    }
}

/// Perform the operation at `index` of the current block. After a call
/// operation, the callee's activation is on the stack and the record's
/// target is the callee's code.
///
/// # Safety
///
/// As for [`refill`].
unsafe extern "C" fn perform(thread: *mut Thread, index: u64) -> u64 {
    // SAFETY: see the function's contract.
    let thread = unsafe { &mut *thread };
    let context = thread.context;
    let process = context.process;
    // Once the program has ended, a thread has no further effect: like the
    // interpreter, which looks before every step, this looks before every
    // operation that the engine performs for native code.
    if process.stopping() {
        return thread.end(Ended::Cancelled);
    }
    let step = thread.top().and_then(|frame| {
        let block = &process.module.func(frame.function).blocks[frame.block.index()];
        let op = block
            .ops
            .get(index as usize)
            .ok_or_else(|| internal("native operation index"))?;
        frame.position = Some(index as usize);
        operation(context, frame, op)
    });
    let step = match step {
        Ok(step) => step,
        Err(defect) => return thread.fail(defect),
    };
    let calls = matches!(step, Step::Call { .. });
    match apply(process, &mut thread.stack, step) {
        Err(defect) => thread.fail(defect),
        Ok(Some(ended)) => thread.end(ended),
        Ok(None) if !calls => 0,
        Ok(None) => {
            let depth = thread.stack.len();
            // An activation too many is found before its first step, after
            // what else may stop the thread there.
            if depth > process.policy.max_frames
                && let Some(ended) = admit(process, &mut thread.header.lease, depth)
            {
                return thread.end(ended);
            }
            match thread.top().map(|frame| frame.function.index()) {
                Ok(callee) => {
                    thread.header.target = thread.code.function(callee);
                    0
                }
                Err(defect) => thread.fail(defect),
            }
        }
    }
}

/// Perform the terminator of the current block. Returns the index of the
/// block it branches to; after a return to a calling activation, zero.
///
/// # Safety
///
/// As for [`refill`].
unsafe extern "C" fn terminate(thread: *mut Thread, _: u64) -> u64 {
    // SAFETY: see the function's contract.
    let thread = unsafe { &mut *thread };
    let process = thread.context.process;
    let step = thread.top().and_then(|frame| {
        let block = &process.module.func(frame.function).blocks[frame.block.index()];
        frame.position = Some(block.ops.len());
        let step = terminator(process.module, frame, &block.term)?;
        Ok((step, frame.block))
    });
    match step {
        Err(defect) => thread.fail(defect),
        Ok((Step::Continue, target)) => target.index() as u64,
        Ok((step, _)) => match apply(process, &mut thread.stack, step) {
            Err(defect) => thread.fail(defect),
            Ok(Some(ended)) => thread.end(ended),
            Ok(None) => 0,
        },
    }
}

/// Native code for one module.
pub struct Code {
    memory: memory::Executable,
    /// Where the host enters.
    entry: usize,
    /// Where each function's code starts.
    functions: Vec<usize>,
    /// The identity of the module the code was compiled from.
    identity: [u8; 32],
}

impl Code {
    /// Compile every function of `module` for the host.
    ///
    /// # Errors
    ///
    /// `EXEC_NATIVE_MEMORY` if the host gives no memory for code, and
    /// `EXEC_NATIVE_SIZE` if the module is too large for one piece of code.
    pub fn compile(module: &Module) -> Result<Self, Error> {
        let mut assembler = Assembler::new();
        let entry = assembler.offset();
        assembler.host_entry();
        let mut functions = Vec::with_capacity(module.functions.len());
        for function in &module.functions {
            functions.push(assembler.offset());
            compile_function(&mut assembler, function);
        }
        Ok(Self {
            memory: memory::Executable::new(&assembler.finish()?)?,
            entry,
            functions,
            identity: module.identity(),
        })
    }

    /// Whether this is the code of `module`.
    pub(super) fn is_for(&self, module: &Module) -> bool {
        self.identity == module.identity() && self.functions.len() == module.functions.len()
    }

    /// The address of a function's code.
    fn function(&self, index: usize) -> usize {
        self.memory.address(self.functions[index])
    }
}

/// The blocks a terminator can branch to, each once.
fn successors(term: &Terminator) -> Vec<BlockIdx> {
    let mut targets = match term {
        Terminator::Jump(target) => vec![*target],
        Terminator::Branch {
            if_true, if_false, ..
        } => vec![*if_true, *if_false],
        Terminator::Switch { cases, default, .. } => cases
            .iter()
            .map(|(_, target)| *target)
            .chain([*default])
            .collect(),
        Terminator::Return(_) | Terminator::Trap { .. } | Terminator::Unreachable => Vec::new(),
    };
    targets.sort_by_key(|target| target.index());
    targets.dedup();
    targets
}

/// Code that enters the block `to` of a function: one step, in which the
/// block becomes current and its phis are committed, and then the block's
/// body. `from` is one more than the predecessor's index, or zero at the
/// function's entry.
fn arrive(assembler: &mut Assembler, exit: Label, body: Label, from: u64, to: usize) {
    assembler.step(exit);
    assembler.call_helper(Helper::Enter, (to as u64) << 32 | from);
    assembler.jump_if_result_nonzero(exit);
    assembler.jump(body);
}

fn compile_function(assembler: &mut Assembler, function: &Function) {
    let exit = assembler.label();
    let bodies: Vec<Label> = function.blocks.iter().map(|_| assembler.label()).collect();
    // The stub of each edge, by predecessor and target.
    let mut edges: BTreeMap<(usize, usize), Label> = BTreeMap::new();

    assembler.enter();
    let entry = function.entry.index();
    arrive(assembler, exit, bodies[entry], 0, entry);
    for (index, block) in function.blocks.iter().enumerate() {
        assembler.bind(bodies[index]);
        for (position, op) in block.ops.iter().enumerate() {
            assembler.step(exit);
            assembler.call_helper(Helper::Operation, position as u64);
            assembler.jump_if_result_nonzero(exit);
            if matches!(op, Op::Call { .. }) {
                // The callee's activation is in place; run its code. What it
                // returns is zero if it returned to this activation.
                assembler.call_target();
                assembler.jump_if_result_nonzero(exit);
            }
        }
        assembler.step(exit);
        let mut stub = |assembler: &mut Assembler, target: BlockIdx| -> Label {
            *edges
                .entry((index, target.index()))
                .or_insert_with(|| assembler.label())
        };
        match &block.term {
            Terminator::Jump(target) => {
                let stub = stub(assembler, *target);
                assembler.jump(stub);
            }
            Terminator::Branch { .. } | Terminator::Switch { .. } => {
                assembler.call_helper(Helper::Terminator, 0);
                for target in successors(&block.term) {
                    let stub = stub(assembler, target);
                    assembler.jump_if_result_is(target.index() as u64, stub);
                }
                // No block was chosen: the thread stops.
                assembler.jump(exit);
            }
            Terminator::Return(_) | Terminator::Trap { .. } | Terminator::Unreachable => {
                // The status is zero after a return to the caller.
                assembler.call_helper(Helper::Terminator, 0);
                assembler.leave();
            }
        }
    }
    for ((from, to), stub) in edges {
        assembler.bind(stub);
        arrive(assembler, exit, bodies[to], from as u64 + 1, to);
    }
    assembler.bind(exit);
    assembler.leave();
}

/// Run the activations of `stack`, whose only one is a call from the host
/// that has not taken a step, as native code.
pub(super) fn run(context: &Context, code: &Code, stack: Vec<Frame>) -> Result<Ended, Error> {
    let entered = stack
        .last()
        .ok_or_else(|| internal("empty call stack"))?
        .function
        .index();
    let mut thread = Thread {
        header: Header {
            lease: 0,
            target: 0,
            helpers: [
                refill as *const () as usize,
                enter as *const () as usize,
                perform as *const () as usize,
                terminate as *const () as usize,
            ],
        },
        context,
        code,
        stack,
        ended: None,
        defect: None,
    };
    // SAFETY: the address is that of the entry the assembler emitted, which
    // has this signature. The code it runs was compiled from the module the
    // context's process runs, which `Process::start` checked, so every index
    // it passes to a helper is in range for the activation on top of the
    // stack; and it calls the helpers with the record it was given, on this
    // thread, while nothing else refers to the record.
    let status = unsafe {
        let host: extern "C" fn(*mut Thread, usize) -> u64 =
            std::mem::transmute(code.memory.address(code.entry));
        host(&raw mut thread, code.function(entered))
    };
    give_back(context.process, thread.header.lease);
    if let Some(defect) = thread.defect {
        return Err(defect);
    }
    match (status, thread.ended) {
        (STOP, Some(ended)) => Ok(ended),
        _ => Err(internal("native code returned without an outcome")),
    }
}
