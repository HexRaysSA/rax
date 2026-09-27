//! Explicit UCRT callback tables, not substitute process-wide CRT termination.
//! Public lifecycle and private profiles: windows-crt-onexit.md audit record.

mod storage;

use crate::user::windows::hle::{ApiErr, ApiResult, Arg::Ptr, Conv::Cdecl, Ctx, Export, Flow};
use crate::user::windows::nt::status::STATUS_NO_MEMORY;
use crate::user::windows::process::Proc;

use super::{RuntimeKind, runtime, state};
pub(super) use storage::OnExitState;
use storage::{Drain, TableError};

pub(crate) static UCRT_ONEXIT_EXPORTS: &[Export] = &[
    Export::func("_initialize_onexit_table", Cdecl, &[Ptr], initialize),
    Export::func("_register_onexit_function", Cdecl, &[Ptr, Ptr], register),
    Export::func("_execute_onexit_table", Cdecl, &[Ptr], execute),
];

#[derive(Clone, Copy)]
enum Request {
    Initialize,
    Register,
    Execute,
}

fn initialize(c: &mut Ctx) -> ApiResult {
    begin(c, Request::Initialize)
}
fn register(c: &mut Ctx) -> ApiResult {
    begin(c, Request::Register)
}
fn execute(c: &mut Ctx) -> ApiResult {
    begin(c, Request::Execute)
}

fn begin(c: &mut Ctx, request: Request) -> ApiResult {
    decode(c, runtime(c)?, request, [0; 2], 0)
}

/// Retain completed formals when a later stack argument needs guest repair.
fn decode(
    c: &mut Ctx,
    kind: RuntimeKind,
    request: Request,
    mut values: [u64; 2],
    mut cursor: usize,
) -> ApiResult {
    let count = if matches!(request, Request::Register) {
        2
    } else {
        1
    };
    while cursor < count {
        match c.arg(cursor) {
            Ok(value) => {
                values[cursor] = value;
                cursor += 1;
            }
            Err(fault) => {
                return Ok(Flow::RetryFault {
                    fault,
                    retry: Box::new(move |c, _| decode(c, kind, request, values, cursor)),
                });
            }
        }
    }
    // The SDK initializer does not acquire the exit lock. An independent
    // table can initialize while another thread is executing a locked table.
    if matches!(request, Request::Initialize) {
        return perform(c, kind, request, values);
    }
    super::termination::with_lock(
        c,
        kind,
        Box::new(move |c, _| perform(c, kind, request, values)),
    )
}

fn negative() -> ApiResult {
    // The particular negative value, null/invalid handling and errno policy
    // are explicit profiles; the public API specifies only a negative int.
    Flow::ret(u64::from(u32::MAX))
}

fn perform(c: &mut Ctx, kind: RuntimeKind, request: Request, values: [u64; 2]) -> ApiResult {
    let tables = c.p.crt.runtimes[kind.index()].onexit.clone();
    let result = match request {
        Request::Initialize => tables.initialize(c.p, values[0]),
        Request::Register => {
            let heap = match state::ensure_heap(c, kind) {
                Ok(heap) => heap,
                Err(ApiErr::Raise(record)) if record.code == STATUS_NO_MEMORY => return negative(),
                Err(ApiErr::Fault(fault)) => {
                    return Ok(Flow::RetryFault {
                        fault,
                        retry: Box::new(move |c, _| perform(c, kind, request, values)),
                    });
                }
                Err(error) => return Err(error),
            };
            tables.register(c.p, heap, values[0], values[1])
        }
        Request::Execute => match tables.begin_execute(c.p, values[0], c.t.tid) {
            Ok(drain) => return walk(c, drain),
            Err(error) => Err(error),
        },
    };
    match result {
        Ok(()) => Flow::ret(0),
        Err(TableError::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| perform(c, kind, request, values)),
        }),
        Err(TableError::NoMemory | TableError::Invalid | TableError::GenerationExhausted) => {
            negative()
        }
        Err(error) => Err(ApiErr::Internal(format!("CRT onexit storage: {error:?}"))),
    }
}

/// Lazy LIFO reads, with each callback logically consumed before entry.
/// The checked call holds the drain through callback-stack faults; returning
/// callbacks never reparse table/formals. No host borrow crosses guest code.
fn walk(c: &mut Ctx, mut drain: Drain) -> ApiResult {
    match drain.next(c.p) {
        Ok(Some(target)) => Flow::call_checked(target, Vec::new(), move |c, _| walk(c, drain)),
        Ok(None) => {
            drain
                .finish(c.p)
                .map_err(|error| ApiErr::Internal(format!("CRT onexit completion: {error:?}")))?;
            Flow::ret(0)
        }
        Err(TableError::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| walk(c, drain)),
        }),
        Err(error) => Err(ApiErr::Internal(format!("CRT onexit drain: {error:?}"))),
    }
}

/// Cleanup host-owned detached blocks before further guest execution. A
/// deliberate terminal owner is not reported as a successful API return or
/// as an unrelated failure; nonterminal escapes remain explicit diagnostics.
pub(crate) fn cleanup_abandoned(p: &mut Proc, terminal_owner: Option<u32>) -> Result<(), String> {
    reap_abandoned(p, terminal_owner, false)
}

/// Normal process exit abandons other threads' drains but must preserve
/// initialized DLL-local tables until DLL_PROCESS_DETACH executes them.
pub(crate) fn retire_process_drains(p: &mut Proc) -> Result<(), String> {
    reap_abandoned(p, None, true)
}

fn reap_abandoned(
    p: &mut Proc,
    terminal_owner: Option<u32>,
    all_terminal: bool,
) -> Result<(), String> {
    let mut failure = None;
    for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
        let tables = p.crt.runtimes[kind.index()].onexit.clone();
        let receipts = tables
            .take_abandoned()
            .map_err(|error| format!("CRT onexit receipt admission: {error:?}"))?;
        for receipt in receipts {
            let tid = receipt.tid;
            if let Err(error) = storage::cleanup_abandoned(p, receipt) {
                failure.get_or_insert_with(|| format!("CRT onexit cleanup: {error:?}"));
            } else if !all_terminal && terminal_owner != Some(tid) {
                failure.get_or_insert_with(|| {
                    format!("CRT onexit continuation abandoned on thread {tid}")
                });
            }
        }
    }
    match failure {
        Some(failure) => Err(failure),
        None => Ok(()),
    }
}

/// Dying process: release host block bookkeeping without guest writes or
/// callbacks and without replacing its deliberate supplied exit code.
pub(crate) fn discard_process(p: &mut Proc) {
    for kind in [RuntimeKind::Msvcrt, RuntimeKind::Ucrt] {
        let tables = p.crt.runtimes[kind.index()].onexit.clone();
        let _ = tables.discard_process(p);
    }
}

#[cfg(test)]
mod tests;
