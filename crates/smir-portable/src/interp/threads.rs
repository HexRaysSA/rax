//! The `thread` and `sync` services: starting and joining guest threads, and
//! waiting on a word of guest memory.
//!
//! A guest thread runs on a host thread of its own. A thread that waits
//! without a deadline for another thread is parked; the process counts the
//! threads that are not, and a wait that would park the last of them ends the
//! program with [`Exit::Deadlock`](super::Exit::Deadlock) instead of never
//! returning. A blocked thread also looks, every [`POLL`], whether the
//! program is ending.

use std::collections::btree_map::Entry;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::Error;
use crate::ir::{CodeRef, FuncIdx, Module, Pointer, Scalar, Type, Value};

use super::exec::{Step, internal};
use super::host::Errno;
use super::process::{Context, Local, POLL, Thread, ThreadState, Waiter, locked, spawned_thread};

/// Most threads a program has at one time. Starting another fails with
/// `EAGAIN`.
pub(super) const THREAD_LIMIT: u64 = 1024;

/// A `timeout_ns` that means no deadline.
const FOREVER: u64 = u64::MAX;

type Results = Result<Result<Vec<Value>, Step>, Error>;

fn succeeded(value: u64) -> Results {
    Ok(Ok(vec![Value::Int(0), Value::Int(u128::from(value))]))
}

fn failed(errno: Errno) -> Results {
    Ok(Ok(vec![
        Value::Int(u128::from(errno.code())),
        Value::Int(0),
    ]))
}

/// Whether `function` can be a thread's entry: it takes one data pointer and
/// returns one 64-bit integer.
fn is_thread_entry(module: &Module, function: FuncIdx) -> bool {
    let signature = module.signature(function);
    matches!(signature.params.as_slice(), [only] if matches!(module.ty(*only), Type::DataPtr))
        && matches!(
            signature.results.as_slice(),
            [only] if matches!(module.ty(*only), Type::Int { bits: 64 })
        )
}

/// `thread.spawn(entry, argument, stack_bytes) -> (status, handle)`.
///
/// The new thread calls `entry(argument)`; what that returns is the thread's
/// result. `EINVAL` if `entry` is not a function of that shape; `EAGAIN` if
/// there are [`THREAD_LIMIT`] threads already or the host starts no more. An
/// activation's storage is not carved out of one stack here, so
/// `stack_bytes` reserves nothing; the call depth limit applies to each
/// thread.
pub(super) fn spawn(context: &Context, entry: Value, argument: Value) -> Results {
    let process = context.process;
    let function = match entry {
        Value::CodePtr(CodeRef::Function(function))
            if is_thread_entry(process.module, function) =>
        {
            function
        }
        // Bits without an origin, the null pointer among them, name no
        // function.
        Value::CodePtr(_) | Value::Undef => return failed(Errno::EINVAL),
        _ => return Err(internal("thread entry argument")),
    };
    if process.live.load(Ordering::Acquire) >= THREAD_LIMIT {
        return failed(Errno::EAGAIN);
    }
    let handle = process.next_thread.fetch_add(1, Ordering::AcqRel);
    let record = Arc::new(Thread {
        state: Mutex::new(ThreadState::default()),
        changed: Condvar::new(),
    });
    // The handle is known before the thread runs, so the thread can detach
    // itself.
    locked(&process.threads).insert(handle, Arc::clone(&record));
    process.started();
    let started = {
        let record = Arc::clone(&record);
        let scope = context.scope;
        std::thread::Builder::new()
            .name(format!("guest thread {handle}"))
            .spawn_scoped(scope, move || {
                let local = Local::default();
                let child = Context {
                    process,
                    scope,
                    thread: handle,
                    local: &local,
                };
                spawned_thread(&child, &record, function, argument);
            })
    };
    if started.is_err() {
        locked(&process.threads).remove(&handle);
        process.live.fetch_sub(1, Ordering::AcqRel);
        // This thread runs, so the count does not reach zero here.
        let _ = process.park();
        return failed(Errno::EAGAIN);
    }
    succeeded(handle)
}

/// `thread.join(thread) -> (status, result)`.
///
/// Waits until the thread has ended and returns its result; the handle is
/// then no longer valid. `EDEADLK` if the thread is the caller, `EINVAL` if
/// the handle names no joinable thread or another join has claimed it.
pub(super) fn join(context: &Context, handle: u64) -> Results {
    let process = context.process;
    if handle == context.thread {
        return failed(Errno::EDEADLK);
    }
    let Some(record) = locked(&process.threads).get(&handle).cloned() else {
        return failed(Errno::EINVAL);
    };
    let mut state = locked(&record.state);
    if state.joining {
        return failed(Errno::EINVAL);
    }
    state.joining = true;
    if state.result.is_none() {
        state.parked = true;
        if process.park() {
            return Ok(Err(Step::Deadlock));
        }
    }
    let result = loop {
        if let Some(result) = state.result {
            break result;
        }
        if process.stopping() {
            return Ok(Err(Step::Stop));
        }
        state = record
            .changed
            .wait_timeout(state, POLL)
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0;
    };
    drop(state);
    locked(&process.threads).remove(&handle);
    succeeded(result)
}

/// `thread.detach(thread) -> (status, 0)`.
///
/// Gives up the right to join the thread, which goes on running; the handle
/// is then no longer valid. `EINVAL` if the handle names no joinable thread
/// or a join has claimed it.
pub(super) fn detach(context: &Context, handle: u64) -> Results {
    let mut threads = locked(&context.process.threads);
    let Entry::Occupied(entry) = threads.entry(handle) else {
        return failed(Errno::EINVAL);
    };
    if locked(&entry.get().state).joining {
        return failed(Errno::EINVAL);
    }
    entry.remove();
    succeeded(0)
}

/// `thread.yield() -> (status, 0)`.
pub(super) fn yield_now() -> Results {
    std::thread::yield_now();
    succeeded(0)
}

/// `thread.id() -> (status, identity)`: 1 for the program's first thread, and
/// for any other thread the handle `thread.spawn` returned for it.
pub(super) fn id(context: &Context) -> Results {
    succeeded(context.thread)
}

/// `thread.concurrency() -> (status, count)`: how many of the program's
/// threads can run at one time. That is what the run's policy says, or else
/// what this machine runs at once; at least one, and no more than the
/// program may have.
pub(super) fn concurrency(context: &Context) -> Results {
    let count = match context.process.policy.processors {
        0 => std::thread::available_parallelism().map_or(1, |count| count.get() as u64),
        told => u64::from(told),
    };
    succeeded(count.min(THREAD_LIMIT))
}

/// The address a wait or a wake names, once the four bytes there are known
/// to be readable.
fn word(context: &Context, pointer: Pointer) -> Result<Result<(), Step>, Error> {
    if pointer.address % 4 != 0 {
        return Ok(Err(Step::Trap("service_argument")));
    }
    match context
        .process
        .memory
        .load(pointer, Scalar::Int { bits: 32 }, 4, 4)
    {
        Ok(_) => Ok(Ok(())),
        Err(fault) => Ok(Err(fault.into())),
    }
}

/// `sync.wait32(address, expected, timeout_ns) -> (status, 0)`.
///
/// If the 32-bit word at `address` holds `expected`, waits until a
/// `sync.wake32` on that address wakes this thread, or until `timeout_ns`
/// nanoseconds have passed. Comparing the word and starting to wait are one
/// action with respect to `sync.wake32`: a wake that follows a store to the
/// word is not lost.
///
/// `EAGAIN` if the word holds anything else, an unspecified value included;
/// `ETIMEDOUT` if the time passed first. A timeout of zero does not wait; the
/// greatest 64-bit value waits without a deadline. A success may be
/// spurious; callers test their condition again.
pub(super) fn wait(context: &Context, pointer: Pointer, expected: u32, timeout: u64) -> Results {
    let process = context.process;
    if let Err(step) = word(context, pointer)? {
        return Ok(Err(step));
    }
    let waiter = Arc::new(Waiter {
        woken: Mutex::new(false),
        changed: Condvar::new(),
        parked: timeout == FOREVER,
    });
    let deadline = if timeout == FOREVER {
        None
    } else {
        // A deadline too far for the host's clock is as good as none, but
        // the thread still counts as one that will run again.
        Some(Instant::now().checked_add(Duration::from_nanos(timeout)))
    };
    {
        let mut waiters = locked(&process.waiters);
        // Read under the lock a wake takes, so the word cannot change and be
        // announced between this comparison and the registration below.
        match process.memory.load(pointer, Scalar::Int { bits: 32 }, 4, 4) {
            Ok(Value::Int(bits)) if bits as u32 == expected => {}
            Ok(_) => return failed(Errno::EAGAIN),
            Err(fault) => return Ok(Err(fault.into())),
        }
        if timeout == 0 {
            return failed(Errno::ETIMEDOUT);
        }
        if waiter.parked && process.park() {
            return Ok(Err(Step::Deadlock));
        }
        waiters
            .entry(pointer.address)
            .or_default()
            .push_back(Arc::clone(&waiter));
    }
    let mut woken = locked(&waiter.woken);
    loop {
        if *woken {
            return succeeded(0);
        }
        if process.stopping() {
            return Ok(Err(Step::Stop));
        }
        let pause = match deadline {
            None | Some(None) => POLL,
            Some(Some(deadline)) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                left.min(POLL)
            }
        };
        woken = waiter
            .changed
            .wait_timeout(woken, pause)
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0;
    }
    drop(woken);
    // The time has passed. A wake may have chosen this thread meanwhile; it
    // then counts as woken, so that the wake is not spent on nobody.
    let mut waiters = locked(&process.waiters);
    if *locked(&waiter.woken) {
        return succeeded(0);
    }
    if let Entry::Occupied(mut queue) = waiters.entry(pointer.address) {
        queue.get_mut().retain(|other| !Arc::ptr_eq(other, &waiter));
        if queue.get().is_empty() {
            queue.remove();
        }
    }
    failed(Errno::ETIMEDOUT)
}

/// `sync.wake32(address, count) -> (status, woken)`.
///
/// Wakes up to `count` of the threads waiting on `address`, those that have
/// waited longest first, and returns how many.
pub(super) fn wake(context: &Context, pointer: Pointer, count: u32) -> Results {
    let process = context.process;
    if let Err(step) = word(context, pointer)? {
        return Ok(Err(step));
    }
    let mut woken = 0_u64;
    let mut waiters = locked(&process.waiters);
    if let Entry::Occupied(mut queue) = waiters.entry(pointer.address) {
        while woken < u64::from(count) {
            let Some(waiter) = queue.get_mut().pop_front() else {
                break;
            };
            if waiter.parked {
                process.unpark();
            }
            *locked(&waiter.woken) = true;
            waiter.changed.notify_all();
            woken += 1;
        }
        if queue.get().is_empty() {
            queue.remove();
        }
    }
    succeeded(woken)
}
