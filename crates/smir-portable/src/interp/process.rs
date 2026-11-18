//! A running program: what its threads share, and the loop each thread runs.
//!
//! Every guest thread is a host thread. They share the module, the memory,
//! the host and one step count; each has its own stack of activations. The
//! program ends when its first thread returns from the entry function, when
//! any thread ends it through a service, when any thread faults, or when
//! every thread waits for another. The other threads then stop at their next
//! step.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::Scope;
use std::time::Duration;

use crate::Error;
use crate::ir::{FuncIdx, Module, Pointer, RelocationKind, Value};

use super::exec::{Frame, Step, fault, fits, internal, step};
use super::faults::{self, FaultClass};
use super::host::Host;
use super::instance::{Called, Moved, Request, refuse};
use super::jit;
use super::memory::{self, Memory};
use super::{Engine, Exit, Fault, Outcome, Policy};

/// How often a blocked thread looks whether the program is ending.
pub(super) const POLL: Duration = Duration::from_millis(20);

/// A lock whose holder panicked still guards consistent data: every critical
/// section here leaves it so.
pub(super) fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One guest thread other than the first, as its handle sees it.
pub(super) struct Thread {
    pub(super) state: Mutex<ThreadState>,
    pub(super) changed: Condvar,
}

#[derive(Default)]
pub(super) struct ThreadState {
    /// The value the thread returned or exited with, once it has ended.
    pub(super) result: Option<u64>,
    /// A join has claimed the thread; a second one is refused.
    pub(super) joining: bool,
    /// The joining thread is parked until this one ends.
    pub(super) parked: bool,
}

/// A thread blocked in `sync.wait32`.
pub(super) struct Waiter {
    pub(super) woken: Mutex<bool>,
    pub(super) changed: Condvar,
    /// It waits without a deadline, so it is parked.
    pub(super) parked: bool,
}

/// Everything the threads of a run share.
pub(super) struct Process<'run> {
    pub(super) module: &'run Module,
    pub(super) memory: Memory,
    /// The object of each data segment, in segment order.
    pub(super) segments: Vec<Pointer>,
    pub(super) host: Mutex<&'run mut dyn Host>,
    pub(super) policy: Policy,
    /// Native code for the module, if the program runs as that.
    pub(super) code: Option<&'run jit::Code>,
    /// Steps of the limit that no thread has taken or leased.
    fuel: AtomicU64,
    /// Set once the program is ending.
    stopping: AtomicBool,
    /// How the program ended.
    ended: Mutex<Option<Exit>>,
    /// A defect of the engine found on a thread other than the first.
    defect: Mutex<Option<Error>>,
    /// Set once some thread runs the finalizers; they run once.
    finalizing: AtomicBool,
    /// Threads that can still be joined or detached, by handle. Handles
    /// start at 2; 1 identifies the first thread, which has no handle.
    pub(super) threads: Mutex<BTreeMap<u64, Arc<Thread>>>,
    pub(super) next_thread: AtomicU64,
    /// Threads that have started and not ended.
    pub(super) live: AtomicU64,
    /// Live threads that are not parked. A parked thread waits, without a
    /// deadline, for another thread to end or to wake it. When this reaches
    /// zero nothing can happen any more.
    runnable: AtomicU64,
    /// Threads blocked in `sync.wait32`, by the address they wait on, oldest
    /// first.
    pub(super) waiters: Mutex<BTreeMap<u64, VecDeque<Arc<Waiter>>>>,
}

/// What a thread has to itself.
#[derive(Default)]
pub(super) struct Local {
    /// The thread's copy of each thread-local segment, once it has used it.
    thread_local: RefCell<Vec<Option<Pointer>>>,
}

impl Local {
    /// End the thread's copies of the thread-local segments.
    fn release(&self, memory: &Memory) {
        for copy in self.thread_local.take().into_iter().flatten() {
            if let Some(object) = copy.origin {
                memory.release(object);
            }
        }
    }
}

/// What a step needs beyond its own activation.
#[derive(Clone, Copy)]
pub(super) struct Context<'thread, 'scope, 'env, 'run> {
    pub(super) process: &'env Process<'run>,
    /// Where the program's host threads are started.
    pub(super) scope: &'scope Scope<'scope, 'env>,
    /// The identity of the guest thread this is.
    pub(super) thread: u64,
    pub(super) local: &'thread Local,
}

impl Context<'_, '_, '_, '_> {
    /// The calling thread's copy of a thread-local segment. A thread gets
    /// its copy, a new object that starts as the segment's image, when it
    /// first asks for it; the copy ends with the thread.
    pub(super) fn thread_local(&self, segment: u32) -> Result<Pointer, memory::Fault> {
        let mut copies = self.local.thread_local.borrow_mut();
        let index = segment as usize;
        if copies.len() <= index {
            copies.resize(index + 1, None);
        }
        if let Some(copy) = copies[index] {
            return Ok(copy);
        }
        let image = &self.process.module.thread_local[index];
        let copy = self.process.memory.allocate_image(
            &image.bits,
            &image.poison,
            &image.undef,
            image.alignment,
        )?;
        if !image.mutable {
            self.process.memory.seal(copy);
        }
        copies[index] = Some(copy);
        Ok(copy)
    }
}

impl<'run> Process<'run> {
    /// Check the module's capabilities against the host, create each data
    /// segment's object and apply the relocations. Segments are allocated in
    /// order, before any stack object, so their addresses depend only on the
    /// module. The inner `Err` is the outcome of a run whose data does not
    /// fit the memory limit.
    pub(super) fn start(
        module: &'run Module,
        policy: Policy,
        host: &'run mut dyn Host,
        engine: Engine<'run>,
    ) -> Result<Result<Self, Outcome>, Error> {
        let code = match engine {
            Engine::Interpreter => None,
            Engine::Native(code) => {
                if !code.is_for(module) {
                    return Err(Error::semantic(
                        "EXEC_ENGINE",
                        "the native code was compiled from another module",
                    ));
                }
                Some(code)
            }
        };
        if module.needs_linking() {
            return Err(Error::semantic(
                "EXEC_UNLINKED",
                "the module calls functions of other modules",
            ));
        }
        if let Some(missing) = module
            .capabilities()
            .find(|capability| !host.grants(capability))
        {
            return Err(Error::semantic("EXEC_CAPABILITY", missing));
        }
        let memory = Memory::new(policy.max_memory_bytes);
        let segments = match Self::stage(module, &memory) {
            Ok(segments) => segments,
            Err(memory::Fault::Resource(code)) => {
                return Ok(Err(Outcome {
                    exit: Exit::Resource(code),
                    steps: 0,
                }));
            }
            Err(_) => return Err(internal("data segment staging")),
        };
        Ok(Ok(Self {
            module,
            memory,
            segments,
            host: Mutex::new(host),
            policy,
            code,
            fuel: AtomicU64::new(policy.fuel),
            stopping: AtomicBool::new(false),
            ended: Mutex::new(None),
            defect: Mutex::new(None),
            finalizing: AtomicBool::new(false),
            threads: Mutex::new(BTreeMap::new()),
            next_thread: AtomicU64::new(2),
            live: AtomicU64::new(1),
            runnable: AtomicU64::new(1),
            waiters: Mutex::new(BTreeMap::new()),
        }))
    }

    fn stage(module: &Module, memory: &Memory) -> Result<Vec<Pointer>, memory::Fault> {
        let segments = module
            .segments
            .iter()
            .map(|segment| {
                memory.allocate_image(
                    &segment.bits,
                    &segment.poison,
                    &segment.undef,
                    segment.alignment,
                )
            })
            .collect::<Result<Vec<Pointer>, _>>()?;
        for relocation in &module.relocations {
            let base = segments[relocation.segment.index()];
            // The target's address plus the addend, keeping the target's origin.
            let address = |target: crate::ir::SegIdx, addend: i64| {
                let object = segments[target.index()];
                Pointer {
                    address: object.address.wrapping_add(addend as u64),
                    origin: object.origin,
                }
            };
            match relocation.kind {
                RelocationKind::DataAddress { target, addend } => {
                    memory.patch_pointer(base, relocation.offset, address(target, addend));
                }
                RelocationKind::DataInteger {
                    target,
                    addend,
                    bytes,
                } => {
                    // An address published as an integer exposes its object.
                    memory.expose(segments[target.index()]);
                    memory.patch_integer(
                        base,
                        relocation.offset,
                        address(target, addend).address,
                        bytes,
                    );
                }
                RelocationKind::FunctionToken { function } => {
                    memory.patch_function(base, relocation.offset, function);
                }
                RelocationKind::FunctionInteger {
                    function,
                    addend,
                    bits,
                } => {
                    // A token published as an integer exposes its function.
                    memory.expose_code(function);
                    let token = crate::ir::CodeRef::Function(function).bits();
                    let mask = u64::MAX >> (64 - bits);
                    memory.patch_integer(
                        base,
                        relocation.offset,
                        (token & mask).wrapping_add(addend as u64) & mask,
                        bits.div_ceil(8),
                    );
                }
            }
        }
        for (segment, pointer) in module.segments.iter().zip(&segments) {
            if !segment.mutable {
                memory.seal(*pointer);
            }
        }
        Ok(segments)
    }

    pub(super) fn stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    /// End the program with `exit`, unless it is ending already: the first
    /// thread to end it decides how.
    fn end(&self, exit: Exit) {
        let mut ended = locked(&self.ended);
        if ended.is_none() {
            *ended = Some(exit);
        }
        self.stopping.store(true, Ordering::Release);
    }

    /// Take up to [`LEASE`] steps out of the limit; none if it is used up.
    fn lease(&self) -> u64 {
        let mut left = self.fuel.load(Ordering::Acquire);
        loop {
            let taken = left.min(LEASE);
            match self.fuel.compare_exchange_weak(
                left,
                left - taken,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return taken,
                Err(now) => left = now,
            }
        }
    }

    /// A thread starts: it is live and can run.
    pub(super) fn started(&self) {
        self.live.fetch_add(1, Ordering::AcqRel);
        self.runnable.fetch_add(1, Ordering::AcqRel);
    }

    /// The calling thread is about to wait, without a deadline, for another
    /// thread. Returns whether no thread is left to do what it waits for;
    /// the caller then does not wait.
    ///
    /// Whoever ends such a wait calls [`Process::unpark`] for the waiting
    /// thread, at the moment it decides to, so a thread that is about to run
    /// again is never taken for a parked one.
    #[must_use]
    pub(super) fn park(&self) -> bool {
        self.runnable.fetch_sub(1, Ordering::AcqRel) == 1
    }

    /// A parked thread is about to run again.
    pub(super) fn unpark(&self) {
        self.runnable.fetch_add(1, Ordering::AcqRel);
    }

    /// Run the module's initializers, then `entry`, then, if the program
    /// ended normally, its finalizers, all on the calling thread, which is
    /// the program's first. Steps are counted across all threads.
    pub(super) fn execute(self, entry: FuncIdx, arguments: &[Value]) -> Result<Outcome, Error> {
        shaped(self.module, entry, arguments)?;
        self.on_first_thread(|context| first_thread(context, entry, arguments))
    }

    /// Be an instance's process: run the initializers, then each call as it
    /// is asked for, then, when no more is asked or a call has ended the
    /// program normally, the finalizers; all on the calling thread, which
    /// is the program's first. Whoever calls after the program has ended is
    /// told how it ended.
    pub(super) fn serve(self, requests: &Receiver<Request>) -> Result<Outcome, Error> {
        let mut finished = false;
        let outcome = self.on_first_thread(|context| serving(context, requests, &mut finished))?;
        if !finished {
            refuse(requests, &outcome.exit);
        }
        Ok(outcome)
    }

    /// Run `body` as the program's first thread, stop the others when it is
    /// done, and say how the program ended. `body` returns how it ended the
    /// program, or nothing if another thread did.
    fn on_first_thread(
        self,
        body: impl FnOnce(&Context) -> Result<Option<Exit>, Error>,
    ) -> Result<Outcome, Error> {
        let process = &self;
        let first = std::thread::scope(|scope| {
            let local = Local::default();
            let context = Context {
                process,
                scope,
                thread: 1,
                local: &local,
            };
            let outcome = body(&context);
            local.release(&process.memory);
            match &outcome {
                Ok(Some(exit)) => process.end(exit.clone()),
                // Stopped by another thread, which has said how the program
                // ended, or by a defect, which is reported instead.
                Ok(None) | Err(_) => {}
            }
            // Whatever the first thread did, the others stop now; the scope
            // waits for them.
            process.stopping.store(true, Ordering::Release);
            outcome
        });
        first?;
        if let Some(defect) = locked(&self.defect).take() {
            return Err(defect);
        }
        let exit = locked(&self.ended)
            .take()
            .ok_or_else(|| internal("a run without an outcome"))?;
        Ok(Outcome {
            exit,
            steps: self.policy.fuel - self.fuel.load(Ordering::Acquire),
        })
    }
}

/// Check that `arguments` are what `entry` takes, in number and shape.
fn shaped(module: &Module, entry: FuncIdx, arguments: &[Value]) -> Result<(), Error> {
    let function = module
        .functions
        .get(entry.index())
        .ok_or_else(|| Error::semantic("EXEC_ENTRY", "unknown entry function"))?;
    if arguments.len() != function.signature.params.len()
        || !arguments
            .iter()
            .zip(&function.signature.params)
            .all(|(value, ty)| fits(module, module.ty(*ty), *value))
    {
        return Err(Error::semantic(
            "EXEC_ENTRY",
            "arguments do not match the entry signature",
        ));
    }
    Ok(())
}

/// What the first thread of an instance does. `finished` is set if it
/// stopped because no more was asked of the instance.
fn serving(
    context: &Context,
    requests: &Receiver<Request>,
    finished: &mut bool,
) -> Result<Option<Exit>, Error> {
    let process = context.process;
    // An initializer that does not return ends the program there.
    for initializer in &process.module.initializers {
        match call(context, *initializer, &[])? {
            Ended::Returned(_) => {}
            other => return conclude(context, other),
        }
    }
    loop {
        let (entry, arguments, reply) = match requests.recv() {
            Ok(Request::Call {
                entry,
                arguments,
                reply,
            }) => (entry, arguments, reply),
            // A question about an object, which the memory answers.
            Ok(Request::Offset {
                pointer,
                bytes,
                reply,
            }) => {
                let _ = reply.send(match process.memory.advance(pointer, bytes) {
                    Ok(Some(moved)) => Moved::To(moved),
                    Ok(None) => Moved::Outside,
                    Err(()) => Moved::Gone,
                });
                continue;
            }
            // Nobody has more to ask: the program ends in good order.
            Ok(Request::Finish) | Err(_) => {
                *finished = true;
                return conclude(context, Ended::Returned(Vec::new()));
            }
        };
        // A thread an earlier call started may have ended the program.
        if process.stopping() {
            let exit = locked(&process.ended).clone();
            let _ = reply.send(Ok(Called::Ended(exit.unwrap_or(Exit::Exited(0)))));
            return Ok(None);
        }
        if let Err(error) = shaped(process.module, entry, &arguments) {
            let _ = reply.send(Err(error));
            continue;
        }
        match call(context, entry, &arguments)? {
            Ended::Returned(values) => {
                let _ = reply.send(Ok(Called::Returned(values)));
            }
            other => {
                let exit = conclude(context, other)?;
                // If another thread ended the program, it has said how.
                let said = exit
                    .clone()
                    .or_else(|| locked(&process.ended).clone())
                    .unwrap_or(Exit::Exited(0));
                let _ = reply.send(Ok(Called::Ended(said)));
                return Ok(exit);
            }
        }
    }
}

/// Steps a thread takes out of the shared limit at a time, so that threads
/// do not contend for it at every step.
const LEASE: u64 = 4096;

/// The steps a thread has leased and not taken; they go back when it is
/// done.
struct Lease<'process> {
    pool: &'process AtomicU64,
    left: u64,
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.pool.fetch_add(self.left, Ordering::AcqRel);
    }
}

/// What the program's first thread does: initializers, the entry function,
/// finalizers. `None` if another thread ended the program meanwhile.
fn first_thread(
    context: &Context,
    entry: FuncIdx,
    arguments: &[Value],
) -> Result<Option<Exit>, Error> {
    // An initializer that does not return ends the run there.
    for initializer in &context.process.module.initializers {
        match call(context, *initializer, &[])? {
            Ended::Returned(_) => {}
            other => return Ok(other.exit()),
        }
    }
    let ended = call(context, entry, arguments)?;
    conclude(context, ended)
}

/// How the program ends when the calling thread ended it with `ended`.
/// Returning from the entry and a clean exit both run the finalizers first,
/// on the calling thread; any other end does not. A finalizer that does not
/// return ends the run.
fn conclude(context: &Context, ended: Ended) -> Result<Option<Exit>, Error> {
    let process = context.process;
    let clean = matches!(
        ended,
        Ended::Returned(_) | Ended::ThreadExited(_) | Ended::Exited { clean: true, .. }
    );
    if clean && !process.finalizing.swap(true, Ordering::AcqRel) {
        for finalizer in &process.module.finalizers {
            match call(context, *finalizer, &[])? {
                Ended::Returned(_) => {}
                other => return Ok(other.exit()),
            }
        }
    }
    Ok(ended.exit())
}

/// What a thread other than the first does: run `function` on `argument`,
/// and leave its result with its handle. If it ends the program instead, or
/// faults, that is how the program ends.
pub(super) fn spawned_thread(
    context: &Context,
    record: &Thread,
    function: FuncIdx,
    argument: Value,
) {
    let process = context.process;
    let ended = match call(context, function, &[argument]) {
        Ok(Ended::Returned(values)) => Ok(Ok(match values.as_slice() {
            [Value::Int(result)] => *result as u64,
            // An unspecified result refines to zero.
            _ => 0,
        })),
        Ok(Ended::ThreadExited(result)) => Ok(Ok(result)),
        Ok(other) => conclude(context, other).map(Err),
        Err(defect) => Err(defect),
    };
    let result = match ended {
        Ok(Ok(result)) => result,
        Ok(Err(exit)) => {
            if let Some(exit) = exit {
                process.end(exit);
            }
            0
        }
        Err(defect) => {
            locked(&process.defect).get_or_insert(defect);
            process.stopping.store(true, Ordering::Release);
            0
        }
    };
    // What the thread had to itself ends with it.
    context.local.release(&process.memory);
    let mut state = locked(&record.state);
    state.result = Some(result);
    process.live.fetch_sub(1, Ordering::AcqRel);
    if state.parked {
        // The thread that waits for this one runs again in its place.
        state.parked = false;
    } else if process.park() {
        // Every other thread waits for something only a thread could do.
        process.end(Exit::Deadlock);
    }
    drop(state);
    record.changed.notify_all();
}

/// How one call from the host ended.
pub(super) enum Ended {
    Returned(Vec<Value>),
    /// The program asked to end; `clean` if its cleanup is to run first.
    Exited {
        status: i32,
        clean: bool,
    },
    /// The thread asked to end with this result.
    ThreadExited(u64),
    /// The thread ended the program with a fault or at a limit.
    Stopped(Exit),
    /// Another thread ended the program.
    Cancelled,
}

impl Ended {
    /// How the program ended, if this thread is the one that ended it.
    fn exit(self) -> Option<Exit> {
        match self {
            Self::Returned(values) => Some(Exit::Return(values)),
            Self::Exited { status, .. } => Some(Exit::Exited(status)),
            // The first thread ending itself ends the program normally.
            Self::ThreadExited(_) => Some(Exit::Exited(0)),
            Self::Stopped(exit) => Some(exit),
            Self::Cancelled => None,
        }
    }
}

/// The activations of one call from the host: its entry function's first.
/// `Err` is how the call ended at once, because an argument was not what a
/// `noundef` parameter requires.
pub(super) fn activate(
    module: &Module,
    entry: FuncIdx,
    arguments: &[Value],
) -> Result<Vec<Frame>, Ended> {
    let function = module.func(entry);
    let stack = vec![Frame::new(function, entry, arguments, Vec::new())];
    if arguments
        .iter()
        .zip(&function.signature.param_noundef)
        .any(|(value, noundef)| *noundef && !value.is_well_defined())
    {
        let located = fault(module, &stack[0], "ub_noundef_argument".to_owned());
        return Err(Ended::Stopped(Exit::LanguageUb(located)));
    }
    Ok(stack)
}

/// What comes before every step: whether the thread may take one. `lease`
/// is the steps the thread has leased and not taken, `depth` the number of
/// its activations. `None` means it may; the step is not yet counted.
pub(super) fn admit(process: &Process, lease: &mut u64, depth: usize) -> Option<Ended> {
    // Another thread ended the program: this one stops where it is.
    if process.stopping() {
        return Some(Ended::Cancelled);
    }
    if *lease == 0 {
        *lease = process.lease();
        if *lease == 0 {
            return Some(Ended::Stopped(Exit::Resource("fuel")));
        }
    }
    if depth > process.policy.max_frames {
        return Some(Ended::Stopped(Exit::Resource("frames")));
    }
    None
}

/// Give back steps that were leased and not taken.
pub(super) fn give_back(process: &Process, lease: u64) {
    process.fuel.fetch_add(lease, Ordering::AcqRel);
}

/// Do what a step of the top activation asked for. `None` if the thread
/// goes on, with a new activation on the stack after a call and one fewer
/// after a return; otherwise how the call from the host ended.
pub(super) fn apply(
    process: &Process,
    stack: &mut Vec<Frame>,
    step: Step,
) -> Result<Option<Ended>, Error> {
    let module = process.module;
    // The stack objects of activations that end without returning, when the
    // program goes on without them.
    let unwind = |stack: &[Frame]| {
        for frame in stack {
            for object in &frame.owned {
                process.memory.release(*object);
            }
        }
    };
    let located = |stack: &[Frame], code: String| -> Result<Fault, Error> {
        let frame = stack.last().ok_or_else(|| internal("empty call stack"))?;
        Ok(fault(module, frame, code))
    };
    let exit = match step {
        Step::Continue => return Ok(None),
        Step::Call {
            callee,
            arguments,
            results_to,
        } => {
            stack.push(Frame::new(
                module.func(callee),
                callee,
                &arguments,
                results_to,
            ));
            return Ok(None);
        }
        Step::Return(values) => {
            let finished = stack.pop().ok_or_else(|| internal("empty call stack"))?;
            // The activation's stack objects end with it.
            for object in &finished.owned {
                process.memory.release(*object);
            }
            let Some(caller) = stack.last_mut() else {
                return Ok(Some(Ended::Returned(values)));
            };
            if finished.results_to.len() != values.len() {
                return Err(internal("call result arity"));
            }
            for (slot, value) in finished.results_to.iter().zip(values) {
                caller.set(*slot, value);
            }
            caller.position = caller.position.map(|position| position + 1);
            return Ok(None);
        }
        Step::Trap(code) => {
            debug_assert!(
                faults::is_registered(code, FaultClass::Trap),
                "unregistered trap {code}"
            );
            Exit::Trap(located(stack, code.to_owned())?)
        }
        Step::Explicit(reason) => Exit::Trap(located(stack, reason)?),
        Step::LanguageUb(code) => {
            debug_assert!(
                faults::is_registered(code, FaultClass::LanguageUb),
                "unregistered undefined behaviour {code}"
            );
            Exit::LanguageUb(located(stack, code.to_owned())?)
        }
        Step::Resource(code) => {
            debug_assert!(
                faults::is_registered(code, FaultClass::Resource),
                "unregistered limit {code}"
            );
            Exit::Resource(code)
        }
        Step::Exit { status, clean } => return Ok(Some(Ended::Exited { status, clean })),
        Step::Abort => Exit::Aborted,
        Step::Deadlock => Exit::Deadlock,
        Step::ThreadExit(result) => {
            unwind(stack);
            return Ok(Some(Ended::ThreadExited(result)));
        }
        Step::Stop => return Ok(Some(Ended::Cancelled)),
    };
    Ok(Some(Ended::Stopped(exit)))
}

/// Run one function to its end on the calling thread, by interpreting it or,
/// if the process has native code for the module, by running that. Steps
/// count against the one limit all threads share.
pub(super) fn call(context: &Context, entry: FuncIdx, arguments: &[Value]) -> Result<Ended, Error> {
    let process = context.process;
    let mut stack = match activate(process.module, entry, arguments) {
        Ok(stack) => stack,
        Err(ended) => return Ok(ended),
    };
    if let Some(code) = process.code {
        return jit::run(context, code, stack);
    }
    let mut lease = Lease {
        pool: &process.fuel,
        left: 0,
    };
    loop {
        if let Some(ended) = admit(process, &mut lease.left, stack.len()) {
            return Ok(ended);
        }
        lease.left -= 1;
        let frame = stack
            .last_mut()
            .ok_or_else(|| internal("empty call stack"))?;
        let step = step(context, frame)?;
        if let Some(ended) = apply(process, &mut stack, step)? {
            return Ok(ended);
        }
    }
}
