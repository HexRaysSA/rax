//! BSD sigwait ownership is separate from task holds and SSTOP metadata.
//!
//! kern_sig.c::sig_try_locked sleeps other signal-processing threads until
//! the selected thread finishes its wait. Threads without a deliverable
//! signal can run once the task user hold is released. The private waiter
//! set uses O(W) space and O(log(W + 2)) lookup for W entered waiters;
//! the scheduler's T-thread scan costs O(T log(W + 2)).

use super::{State, has_verdict};
use crate::user::darwin::process::{Proc, Thread};

#[derive(Clone, Copy, Debug)]
pub(super) struct SignalWait {
    pub(super) thread: u64,
    hard: bool,
}

pub(super) fn begin(state: &mut State, thread: u64, hard: bool) {
    state.sigwait = Some(SignalWait { thread, hard });
}

pub(super) fn is_hard_wait(state: &State, thread: u64) -> bool {
    state
        .sigwait
        .is_some_and(|wait| wait.thread == thread && wait.hard)
}

pub(crate) fn end_sigwait(state: &mut State, thread: u64) {
    if state.sigwait.is_some_and(|wait| wait.thread == thread) {
        state.sigwait = None;
    }
}

/// An exception reply or hard-stop verdict finishes the selected thread's
/// existing signal processing; other entries must wait before consuming bits.
pub(crate) fn signal_wait_blocked(state: &State, thread: u64) -> bool {
    state
        .sigwait
        .is_some_and(|wait| wait.thread != thread || !has_verdict(state, thread))
}

/// Enter the serialized BSD signal path before consuming any pending bit.
/// Only a thread which actually tried to process a signal becomes a waiter.
pub(crate) fn enter_signal_ast(state: &mut State, thread: u64, pending: bool) -> bool {
    if signal_wait_blocked(state, thread) {
        if pending {
            state.sigwaiters.insert(thread);
        }
        true
    } else {
        state.sigwaiters.remove(&thread);
        false
    }
}

pub(crate) fn thread_suspended(state: &State, thread: &Thread) -> bool {
    if state.exit_after_reply.is_some() {
        return true;
    }
    // Job-stop metadata survives an out-of-band task_resume. The task's
    // user hold, checked by the scheduler, is its execution barrier.
    signal_waiting(state, thread.tid)
}

/// A BSD wait is a scheduler wait, including while a task user hold exists.
/// A pending signal alone does not mean its thread has entered sig_try_locked.
pub(crate) fn signal_waiting(state: &State, thread: u64) -> bool {
    // A soft wait resumes through its Mach exception reply. Its kind
    // survives PT_DETACH changing the process's signal-exception flag.
    match state.sigwait {
        Some(wait) if wait.thread == thread => wait.hard && !has_verdict(state, thread),
        Some(_) => state.sigwaiters.contains(&thread),
        None => false,
    }
}

pub(crate) fn needs_signal_ast(state: &State, thread: &Thread) -> bool {
    has_verdict(state, thread.tid)
        || state.sigwaiters.contains(&thread.tid)
        || (state.tracer.is_some() && thread.sig.pending & !thread.sig.mask != 0)
}

/// A substituted signal interrupts a parked kernel continuation before its
/// user handler is saved. Replaying the original trap preserves indirect
/// arguments and each syscall's EINTR/ERESTART/Mach-abort contract. No guest
/// user instruction precedes that trap: only its exact restart PC is admitted.
/// Zero, masked, and fatal verdicts keep the ordinary signal AST path.
pub(crate) fn resume_before_verdict(proc: &Proc, thread: &mut Thread) -> bool {
    let state = &proc.tracing;
    let Some(verdict) = state.verdict.filter(|verdict| verdict.thread == thread.tid) else {
        return false;
    };
    let signal = verdict.signal;
    if signal == 0
        || signal == super::signal::SIGKILL
        || thread.sig.mask & super::signal::bit(signal) != 0
    {
        return false;
    }
    let handler = proc.sigacts.handler[signal as usize];
    if matches!(handler, super::signal::SIG_DFL | super::signal::SIG_IGN) {
        return false;
    }
    let Some(resume) = thread.resume else {
        return false;
    };
    let length = match thread.cpu {
        crate::user::darwin::arch::DarwinCpu::Arm64(_) => 4,
        crate::user::darwin::arch::DarwinCpu::X86_64(_) => 2,
    };
    if thread.cpu.pc() != resume.pc.wrapping_sub(length) {
        return false;
    }
    thread.sig.pending |= super::signal::bit(signal);
    true
}

/// A terminated wait owner cannot keep other signal-processing threads
/// asleep. Retained stop/status metadata is handled by the tracing protocol.
pub(super) fn reap(proc: &mut Proc, running: Option<&Thread>) {
    let threads = &proc.threads;
    proc.tracing.sigwaiters.retain(|&tid| {
        running
            .filter(|thread| thread.tid == tid)
            .or_else(|| threads.get(&tid))
            .is_some_and(|thread| !thread.exited)
    });
    let Some(wait) = proc.tracing.sigwait else {
        return;
    };
    let live = running
        .filter(|thread| thread.tid == wait.thread)
        .or_else(|| proc.threads.get(&wait.thread))
        .is_some_and(|thread| !thread.exited);
    if !live {
        end_sigwait(&mut proc.tracing, wait.thread);
        if has_verdict(&proc.tracing, wait.thread) {
            proc.tracing.verdict = None;
        }
    }
}
