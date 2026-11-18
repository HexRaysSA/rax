//! Native code for a module.
//!
//! A module is compiled, whole, to code for the host. That code works on
//! the interpreter's own records: a thread's activations are the same
//! [`Frame`]s, memory is the same [`Memory`](super::memory::Memory), and a
//! step is the same unit. A run as native code therefore ends the way the
//! same run would when interpreted, with the same values, the same faults
//! at the same places, and the same count of steps.
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
//!
//! An operation is performed in one of two ways. The engine can always
//! perform it: a helper below runs the interpreter's code for that one
//! operation. For the operations in [`fast`], native code first tries
//! instructions of its own, which read and write the activation's values
//! in place. Those instructions cover the common case only, integers that
//! are there and well defined, and check that they have it; anything else
//! (poison, an undefined value, a pointer where an integer is usual, a
//! result that would be poison) goes to the helper, so the outcome is the
//! interpreter's in every case.

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod fast;
mod memory;
#[cfg(test)]
mod tests;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
use aarch64::{Assembler, Label};
#[cfg(target_arch = "x86_64")]
use x86_64::{Assembler, Label};

use std::collections::BTreeMap;

use crate::ir::{BlockIdx, Function, Module, Op, Terminator, Value};
use crate::{Error, ErrorClass};

use super::exec::{Frame, Step, commit_phis, internal, operation, terminator};
use super::process::{Context, Ended, admit, apply};

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
pub(super) const VALUES: usize = 16;
pub(super) const SCRATCH: usize = 24;
pub(super) const BLOCK: usize = 32;

pub(super) fn helper_offset(helper: Helper) -> usize {
    40 + 8 * helper as usize
}

/// The size of a [`Value`] in an activation, and where native code finds
/// the low and high halves of an integer in it. The tag is the first byte.
pub(super) const CELL: u64 = 32;
pub(super) const LOW: usize = 16;
pub(super) const HIGH: usize = 24;
/// The tags of the values native code makes.
pub(super) const INT: u8 = 0;
pub(super) const POISON: u8 = 4;
pub(super) const UNDEF: u8 = 5;

/// The registers an instruction sequence computes in.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Reg {
    A,
    /// Also the amount of a shift.
    B,
    C,
}

/// A comparison of two 64-bit integers.
#[derive(Clone, Copy)]
pub(super) enum Condition {
    Eq,
    Ne,
    Ult,
    Ule,
    Ugt,
    Uge,
    Slt,
    Sle,
    Sgt,
    Sge,
}

#[derive(Clone, Copy)]
pub(super) enum Shift {
    Left,
    Right,
    RightSigned,
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
    /// The values of the current activation.
    values: *mut Value,
    /// Cells for the values of phis while they are committed.
    scratch: *mut Value,
    /// The current block of the current activation. Native code writes it
    /// when it enters a block; the activation's own record of its block is
    /// brought up to date from it whenever the engine is asked for anything.
    block: u32,
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

    /// The current activation, with its record of its block up to date.
    fn top(&mut self) -> Result<&mut Frame, Error> {
        let block = BlockIdx(self.header.block);
        let frame = self
            .stack
            .last_mut()
            .ok_or_else(|| internal("empty call stack"))?;
        frame.block = block;
        Ok(frame)
    }

    /// Tell native code about the activation that is now current, after a
    /// call put one on the stack or a return took one off.
    fn switched(&mut self) {
        if let Some(frame) = self.stack.last_mut() {
            self.header.values = frame.values.as_mut_ptr();
            self.header.block = frame.block.0;
        }
    }
}

/// A new lease for a thread whose lease is used up, if it may go on.
///
/// # Safety
///
/// `thread` is the record of the calling thread, which native code got from
/// [`run`]; no other reference to it is in use.
unsafe fn refill(thread: *mut Thread, _: u64) -> u64 {
    // SAFETY: see the function's contract.
    let thread = unsafe { &mut *thread };
    let depth = thread.stack.len();
    match admit(thread.context.process, &mut thread.header.lease, depth) {
        None => 0,
        Some(ended) => thread.end(ended),
    }
}

/// Commit the phis of the block native code has just made current, coming
/// from the predecessor `from - 1`, or from nowhere at a function's entry.
/// Native code commits phis itself wherever every phi has a value for the
/// predecessor; this reports the defect where one has not.
///
/// # Safety
///
/// As for [`refill`].
unsafe fn enter(thread: *mut Thread, from: u64) -> u64 {
    // SAFETY: see the function's contract.
    let thread = unsafe { &mut *thread };
    let module = thread.context.process.module;
    let entered = thread.top().and_then(|frame| {
        frame.predecessor = (from as u32).checked_sub(1).map(BlockIdx);
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
unsafe fn perform(thread: *mut Thread, index: u64) -> u64 {
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
    // An operation may run a function inside itself, as a call of foreign
    // code that calls back does: that function goes on with the steps this
    // thread has leased, and leaves those it did not take.
    context.local.lease.set(thread.header.lease);
    let step = thread.top().and_then(|frame| {
        let block = &process.module.func(frame.function).blocks[frame.block.index()];
        let op = block
            .ops
            .get(index as usize)
            .ok_or_else(|| internal("native operation index"))?;
        frame.position = Some(index as usize);
        operation(context, frame, op)
    });
    thread.header.lease = context.local.lease.take();
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
            thread.switched();
            let depth = thread.stack.len();
            // An activation too many is found before its first step, after
            // what else may stop the thread there.
            if depth > process.policy.max_frames
                && let Some(ended) = admit(process, &mut thread.header.lease, depth)
            {
                return thread.end(ended);
            }
            match thread.stack.last().map(|frame| frame.function.index()) {
                Some(callee) => {
                    thread.header.target = thread.code.function(callee);
                    0
                }
                None => thread.fail(internal("empty call stack")),
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
unsafe fn terminate(thread: *mut Thread, _: u64) -> u64 {
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
            Ok(None) => {
                thread.switched();
                0
            }
        },
    }
}

/// The four functions above as native code calls them, and the entry of
/// native code as the host calls it: by the calling convention native code
/// uses, which is the standard one of the processor. On x86-64 that is the
/// System V convention on every system, also on Windows, whose own is
/// another: the instructions native code is made of are then the same on
/// every host, and the compiler passes between the two conventions where
/// they differ.
mod convention {
    use super::Thread;

    macro_rules! called_by_native_code {
        ($($name:ident)*) => {$(
            /// # Safety
            ///
            /// As for the function of this name that it calls.
            #[cfg(target_arch = "x86_64")]
            pub(super) unsafe extern "sysv64" fn $name(thread: *mut Thread, argument: u64) -> u64 {
                // SAFETY: the caller's promise is that function's contract.
                unsafe { super::$name(thread, argument) }
            }

            /// # Safety
            ///
            /// As for the function of this name that it calls.
            #[cfg(not(target_arch = "x86_64"))]
            pub(super) unsafe extern "C" fn $name(thread: *mut Thread, argument: u64) -> u64 {
                // SAFETY: the caller's promise is that function's contract.
                unsafe { super::$name(thread, argument) }
            }
        )*};
    }

    called_by_native_code!(refill enter perform terminate);

    /// Where the host enters native code: with the thread's record and the
    /// address of the function to run.
    #[cfg(target_arch = "x86_64")]
    pub(super) type Entry = extern "sysv64" fn(*mut Thread, usize) -> u64;
    #[cfg(not(target_arch = "x86_64"))]
    pub(super) type Entry = extern "C" fn(*mut Thread, usize) -> u64;
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
    /// The most phis any block has: the scratch cells a thread needs.
    scratch: usize,
}

/// Whether a [`Value`] is laid out the way native code reads and writes it.
fn layout_is_as_compiled() -> bool {
    let probe = Value::Int(0x0123_4567_89ab_cdef_1122_3344_5566_7788);
    let base = (&raw const probe).cast::<u8>();
    // SAFETY: the bytes read are inside `probe` and, for the layout the
    // type declares, are its tag and its field, which are initialized.
    let (tag, low, high) = unsafe {
        (
            base.read(),
            base.add(LOW).cast::<u64>().read_unaligned(),
            base.add(HIGH).cast::<u64>().read_unaligned(),
        )
    };
    let tag_of = |value: Value| {
        // SAFETY: the first byte of a value is its tag.
        unsafe { (&raw const value).cast::<u8>().read() }
    };
    size_of::<Value>() as u64 == CELL
        && (tag, low, high) == (INT, 0x1122_3344_5566_7788, 0x0123_4567_89ab_cdef)
        && tag_of(Value::Poison) == POISON
        && tag_of(Value::Undef) == UNDEF
}

impl Code {
    /// Compile every function of `module` for the host.
    ///
    /// # Errors
    ///
    /// `EXEC_NATIVE_MEMORY` if the host gives no memory for code, and
    /// `EXEC_NATIVE_SIZE` if the module is too large for one piece of code.
    /// `EXEC_UNLINKED` if the module calls functions of other modules: it is
    /// the linked program that is compiled.
    pub fn compile(module: &Module) -> Result<Self, Error> {
        if module.needs_linking() {
            return Err(Error::semantic(
                "EXEC_UNLINKED",
                "the module calls functions of other modules",
            ));
        }
        if !layout_is_as_compiled() {
            return Err(Error::new(
                ErrorClass::Unimplemented,
                "EXEC_UNIMPLEMENTED",
                "native code for this layout of values",
            ));
        }
        let mut assembler = Assembler::new();
        let entry = assembler.offset();
        assembler.host_entry();
        let mut functions = Vec::with_capacity(module.functions.len());
        for function in &module.functions {
            functions.push(assembler.offset());
            compile_function(&mut assembler, function);
        }
        let scratch = module
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .map(|block| block.phis.len())
            .max()
            .unwrap_or(0);
        Ok(Self {
            memory: memory::Executable::new(&assembler.finish()?)?,
            entry,
            functions,
            identity: module.identity(),
            scratch,
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
/// block becomes current and its phis are committed for the predecessor
/// `from`, and then the block's body.
fn arrive(
    assembler: &mut Assembler,
    function: &Function,
    exit: Label,
    body: Label,
    from: Option<usize>,
    to: usize,
) {
    assembler.step(exit);
    assembler.store_block(to as u32);
    // What each phi takes from this predecessor.
    let moves: Option<Vec<(u32, u32)>> = function.blocks[to]
        .phis
        .iter()
        .map(|phi| {
            phi.incoming
                .iter()
                .find(|(predecessor, _)| Some(predecessor.index()) == from)
                .map(|(_, source)| (phi.dst.0, source.0))
        })
        .collect();
    match moves {
        // A phi without a value for the predecessor is a defect of the
        // module, which the engine reports.
        None => {
            assembler.call_helper(Helper::Enter, from.map_or(0, |from| from as u64 + 1));
            assembler.jump_if_result_nonzero(exit);
        }
        Some(moves) => {
            // All phis read before any is written. Where no phi reads what
            // another writes, that is what copying them in turn does.
            let independent = moves
                .iter()
                .all(|(_, source)| moves.iter().all(|(target, _)| target != source));
            if independent {
                for (target, source) in &moves {
                    assembler.copy(*target, *source);
                }
            } else {
                for (index, (_, source)) in moves.iter().enumerate() {
                    assembler.save(index as u32, *source);
                }
                for (index, (target, _)) in moves.iter().enumerate() {
                    assembler.restore(*target, index as u32);
                }
            }
        }
    }
    assembler.jump(body);
}

fn compile_function(assembler: &mut Assembler, function: &Function) {
    let exit = assembler.label();
    let bodies: Vec<Label> = function.blocks.iter().map(|_| assembler.label()).collect();
    // The stub of each edge, by predecessor and target.
    let mut edges: BTreeMap<(usize, usize), Label> = BTreeMap::new();

    assembler.enter();
    assembler.load_values();
    let entry = function.entry.index();
    arrive(assembler, function, exit, bodies[entry], None, entry);
    for (index, block) in function.blocks.iter().enumerate() {
        assembler.bind(bodies[index]);
        for (position, op) in block.ops.iter().enumerate() {
            assembler.step(exit);
            let (slow, done) = (assembler.label(), assembler.label());
            // Instructions for the operation, if it has any; they leave for
            // `slow` when the values are not the ones they are for.
            let tried = fast::operation(assembler, op, slow);
            if tried {
                assembler.jump(done);
            }
            assembler.bind(slow);
            assembler.call_helper(Helper::Operation, position as u64);
            assembler.jump_if_result_nonzero(exit);
            if matches!(op, Op::Call { .. }) {
                // The callee's activation is in place; run its code. What it
                // returns is zero if it returned to this activation, whose
                // values are then current again.
                assembler.call_target();
                assembler.jump_if_result_nonzero(exit);
                assembler.load_values();
            }
            assembler.bind(done);
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
            Terminator::Branch {
                cond,
                if_true,
                if_false,
            } => {
                // An integer condition chooses here; anything else is for
                // the engine to judge.
                let slow = assembler.label();
                let (taken, other) = (stub(assembler, *if_true), stub(assembler, *if_false));
                assembler.load_truth(Reg::A, cond.0, slow);
                assembler.jump_if_zero(Reg::A, other);
                assembler.jump(taken);
                assembler.bind(slow);
                assembler.call_helper(Helper::Terminator, 0);
                assembler.jump_if_result_is(if_true.index() as u64, taken);
                assembler.jump_if_result_is(if_false.index() as u64, other);
                assembler.jump(exit);
            }
            Terminator::Switch { .. } => {
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
        arrive(assembler, function, exit, bodies[to], Some(from), to);
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
    let mut scratch = vec![Value::Undef; code.scratch];
    let mut thread = Thread {
        header: Header {
            // The steps the thread has leased, which native code counts
            // down in its record.
            lease: context.local.lease.take(),
            target: 0,
            values: std::ptr::null_mut(),
            scratch: scratch.as_mut_ptr(),
            block: 0,
            helpers: [
                convention::refill as *const () as usize,
                convention::enter as *const () as usize,
                convention::perform as *const () as usize,
                convention::terminate as *const () as usize,
            ],
        },
        context,
        code,
        stack,
        ended: None,
        defect: None,
    };
    thread.switched();
    // SAFETY: the address is that of the entry the assembler emitted, which
    // has this signature. The code it runs was compiled from the module the
    // context's process runs, which `Process::start` checked, so every index
    // it passes to a helper is in range for the activation on top of the
    // stack, and every cell it reads or writes is one of that activation's
    // values or of the scratch cells, which outlive the call. It calls the
    // helpers with the record it was given, on this thread, and touches the
    // values only between such calls, while no reference to them is in use.
    let status = unsafe {
        let host: convention::Entry = std::mem::transmute(code.memory.address(code.entry));
        host(&raw mut thread, code.function(entered))
    };
    context.local.lease.set(thread.header.lease);
    drop(scratch);
    if let Some(defect) = thread.defect {
        return Err(defect);
    }
    match (status, thread.ended) {
        (STOP, Some(ended)) => Ok(ended),
        _ => Err(internal("native code returned without an outcome")),
    }
}
