//! Runtime-global UCRT registration, distinct from DLL-local startup tables.
//!
//! Global queues follow the retained Windows SDK 10.0.26100.0 implementation
//! receipts. CRT cleanup is distinct from normal OS DLL detachment. Raw OS
//! process exit discards, never executes, global callback queues.

mod exit;
mod fatal;
mod lock;
mod signal;
mod storage;

#[cfg(test)]
mod exit_tests;
#[cfg(test)]
mod tests;

use crate::user::windows::hle::{ApiErr, ApiResult, Arg::Ptr, Conv::Cdecl, Ctx, Export, Flow};
use crate::user::windows::nt::status::STATUS_NO_MEMORY;
use crate::user::windows::process::Proc;

use super::{RuntimeKind, runtime, state};
pub(super) use exit::ExitState;
pub(crate) use exit::UCRT_EXIT_EXPORTS;
pub(crate) use fatal::UCRT_FATAL_EXPORTS;
pub(super) use lock::ExitLockState;
pub(super) use lock::with_lock;
pub(crate) use signal::UCRT_SIGNAL_EXPORTS;
pub(super) use storage::TerminationState;
use storage::{Kind, TerminationError};

pub(crate) static UCRT_REGISTRATION_EXPORTS: &[Export] = &[
    Export::func("_crt_atexit", Cdecl, &[Ptr], ordinary),
    Export::func("_crt_at_quick_exit", Cdecl, &[Ptr], quick),
];

/// Shared actual abort behavior for getptd-based startup API failures.
pub(super) fn abort_runtime(c: &mut Ctx, runtime: RuntimeKind) -> ApiResult {
    fatal::abort_runtime(c, runtime)
}

fn ordinary(c: &mut Ctx) -> ApiResult {
    decode(c, runtime(c)?, Kind::Ordinary)
}
fn quick(c: &mut Ctx) -> ApiResult {
    decode(c, runtime(c)?, Kind::Quick)
}

fn decode(c: &mut Ctx, runtime: RuntimeKind, queue: Kind) -> ApiResult {
    match c.arg(0) {
        Ok(target) => with_lock(
            c,
            runtime,
            Box::new(move |c, _| register(c, runtime, queue, target)),
        ),
        Err(fault) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| decode(c, runtime, queue)),
        }),
    }
}

fn negative() -> ApiResult {
    Flow::ret(u32::MAX.into())
}

fn register(c: &mut Ctx, runtime: RuntimeKind, queue: Kind, target: u64) -> ApiResult {
    let heap = match state::ensure_heap(c, runtime) {
        Ok(heap) => heap,
        Err(ApiErr::Raise(record)) if record.code == STATUS_NO_MEMORY => return negative(),
        Err(ApiErr::Fault(fault)) => {
            return Ok(Flow::RetryFault {
                fault,
                retry: Box::new(move |c, _| register(c, runtime, queue, target)),
            });
        }
        Err(error) => return Err(error),
    };
    let queues = c.p.crt.runtimes[runtime.index()].termination.clone();
    match queues.register(c.p, heap, queue, target) {
        Ok(()) => Flow::ret(0),
        Err(TerminationError::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| register(c, runtime, queue, target)),
        }),
        Err(
            TerminationError::NoMemory
            | TerminationError::Invalid
            | TerminationError::GenerationExhausted,
        ) => negative(),
        Err(error) => Err(ApiErr::Internal(format!(
            "CRT global registration: {error:?}"
        ))),
    }
}

/// A terminal callback abandons its exact continuation, not its unconsumed
/// global entries. Nonterminal escapes remain diagnostics, never API success.
pub(crate) fn cleanup_abandoned(p: &mut Proc, terminal_owner: Option<u32>) -> Result<(), String> {
    reap(p, terminal_owner, false)
}

pub(crate) fn retire_process_drains(p: &mut Proc) -> Result<(), String> {
    reap(p, None, true)
}

fn reap(p: &mut Proc, terminal_owner: Option<u32>, all_terminal: bool) -> Result<(), String> {
    let mut failure = None;
    for runtime in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
        if let Err(error) = lock::cleanup_abandoned(p, runtime, terminal_owner, all_terminal) {
            failure.get_or_insert(error);
        }
        let queues = p.crt.runtimes[runtime.index()].termination.clone();
        let receipts = queues
            .take_abandoned()
            .map_err(|error| format!("CRT global receipts: {error:?}"))?;
        for receipt in receipts {
            let tid = receipt.tid;
            if let Err(error) = storage::cleanup_abandoned(p, receipt) {
                failure.get_or_insert_with(|| format!("CRT global cleanup: {error:?}"));
            } else if !all_terminal && terminal_owner != Some(tid) {
                failure.get_or_insert_with(|| {
                    format!("CRT global continuation abandoned on thread {tid}")
                });
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

/// Host-only teardown, no guest callbacks or pointer-table writes.
pub(crate) fn discard_process(p: &mut Proc) -> Result<(), String> {
    let mut failure = None;
    for runtime in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
        lock::discard_process(p, runtime);
        let queues = p.crt.runtimes[runtime.index()].termination.clone();
        if let Err(error) = queues.discard_process(p) {
            failure.get_or_insert_with(|| format!("CRT global discard: {error:?}"));
        }
    }
    failure.map_or(Ok(()), Err)
}
