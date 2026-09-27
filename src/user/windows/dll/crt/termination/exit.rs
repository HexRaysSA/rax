//! Dynamic retail desktop UCRT cleanup, independent of OS DLL detachment.
//!
//! The two completion flags and retained executable TLS callback follow the
//! inspected SDK 10.0.26100.0 `exit.cpp`. Returning cleanup is repeatable; there
//! is deliberately no in-progress recursion suppression.

use crate::user::windows::hle::{ApiErr, ApiResult, Arg::*, Conv::Cdecl, Ctx, Export, Flow};

use super::super::{RuntimeKind, runtime};
use super::storage::{Drain, Kind, TerminationError};
use super::{fatal, with_lock};

const CPP_EXCEPTION: u32 = 0xE06D_7363;

pub(in crate::user::windows::dll::crt) struct ExitState {
    pub(super) entered: bool,
    pub(super) completed: bool,
    pub(super) tls_callback: u64,
    pub(super) abort_behavior: u32,
}

impl Default for ExitState {
    fn default() -> Self {
        Self {
            entered: false,
            completed: false,
            tls_callback: 0,
            // Retail SDK _CALL_REPORTFAULT; _WRITE_ABORT_MSG is debug-only.
            abort_behavior: 2,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Cleanup {
    Full,
    Quick,
    None,
}

#[derive(Clone, Copy)]
struct Request {
    runtime: RuntimeKind,
    cleanup: Cleanup,
    status: Option<u32>,
}

pub(crate) static UCRT_EXIT_EXPORTS: &[Export] = &[
    Export::func("exit", Cdecl, &[I32], full),
    Export::func("quick_exit", Cdecl, &[I32], quick),
    Export::func("_exit", Cdecl, &[I32], minimal),
    Export::func("_Exit", Cdecl, &[I32], minimal),
    Export::func("_cexit", Cdecl, &[], returning_full),
    Export::func("_c_exit", Cdecl, &[], returning_minimal),
    Export::func(
        "_register_thread_local_exe_atexit_callback",
        Cdecl,
        &[Ptr],
        register_tls,
    ),
];

fn full(c: &mut Ctx) -> ApiResult {
    decode(c, runtime(c)?, Cleanup::Full)
}
fn quick(c: &mut Ctx) -> ApiResult {
    decode(c, runtime(c)?, Cleanup::Quick)
}
fn minimal(c: &mut Ctx) -> ApiResult {
    decode(c, runtime(c)?, Cleanup::None)
}
fn returning_full(c: &mut Ctx) -> ApiResult {
    start(c, runtime(c)?, Cleanup::Full, None)
}
fn returning_minimal(c: &mut Ctx) -> ApiResult {
    start(c, runtime(c)?, Cleanup::None, None)
}

fn decode(c: &mut Ctx, runtime: RuntimeKind, cleanup: Cleanup) -> ApiResult {
    match c.arg(0) {
        Ok(code) => start(c, runtime, cleanup, Some(code as u32)),
        Err(fault) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| decode(c, runtime, cleanup)),
        }),
    }
}

pub(super) fn start(
    c: &mut Ctx,
    runtime: RuntimeKind,
    cleanup: Cleanup,
    status: Option<u32>,
) -> ApiResult {
    let request = Request {
        runtime,
        cleanup,
        status,
    };
    with_lock(c, runtime, Box::new(move |c, _| enter(c, request)))
}

fn enter(c: &mut Ctx, request: Request) -> ApiResult {
    let state = &mut c.p.crt.runtimes[request.runtime.index()].exit;
    if state.completed {
        return finish(c, request);
    }
    state.entered = true;
    Ok(Flow::Protected {
        code: Some(CPP_EXCEPTION),
        handler: Box::new(move |c, _| fatal::terminate_runtime(c, request.runtime)),
        then: Box::new(move |c, _| selected(c, request)),
    })
}

fn selected(c: &mut Ctx, request: Request) -> ApiResult {
    if let Cleanup::Full = request.cleanup {
        let target = c.p.crt.runtimes[request.runtime.index()].exit.tls_callback;
        if target != 0 {
            // _tls_callback_type is WINAPI: x86 guest producer uses ret 12.
            // Execute in this calling thread. Do not clear its registration.
            return Flow::call_checked(target, vec![0, 0, 0], move |c, _| begin_queue(c, request));
        }
    }
    begin_queue(c, request)
}

fn failure(error: TerminationError) -> ApiErr {
    ApiErr::Internal(format!("CRT global exit drain: {error:?}"))
}

fn begin_queue(c: &mut Ctx, request: Request) -> ApiResult {
    let kind = match request.cleanup {
        Cleanup::Full => Kind::Ordinary,
        Cleanup::Quick => Kind::Quick,
        Cleanup::None => return finish(c, request),
    };
    let queues = c.p.crt.runtimes[request.runtime.index()]
        .termination
        .clone();
    let drain = queues.begin(kind, c.t.tid).map_err(failure)?;
    walk(c, request, drain)
}

fn walk(c: &mut Ctx, request: Request, mut drain: Drain) -> ApiResult {
    match drain.next(c.p) {
        Ok(Some(target)) => {
            Flow::call_checked(target, Vec::new(), move |c, _| walk(c, request, drain))
        }
        Ok(None) => {
            drain.finish(c.p).map_err(failure)?;
            finish(c, request)
        }
        Err(TerminationError::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| walk(c, request, drain)),
        }),
        Err(error) => Err(failure(error)),
    }
}

fn finish(c: &mut Ctx, request: Request) -> ApiResult {
    if let Some(code) = request.status {
        c.p.crt.runtimes[request.runtime.index()].exit.completed = true;
        // with_lock releases this invocation's guard before the dispatcher
        // begins normal desktop DLL detachment; minimal is not forced exit.
        Ok(Flow::ExitProcess(code))
    } else {
        Flow::void()
    }
}

fn register_tls(c: &mut Ctx) -> ApiResult {
    decode_tls(c, runtime(c)?)
}

fn decode_tls(c: &mut Ctx, runtime: RuntimeKind) -> ApiResult {
    match c.arg(0) {
        Ok(target) => {
            let state = &mut c.p.crt.runtimes[runtime.index()].exit;
            if state.tls_callback != 0 {
                return fatal::terminate_runtime(c, runtime);
            }
            // NULL preserves the available sentinel. No exit lock, target
            // validation, or idempotent duplicate exception is introduced.
            state.tls_callback = target;
            Flow::void()
        }
        Err(fault) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| decode_tls(c, runtime)),
        }),
    }
}
