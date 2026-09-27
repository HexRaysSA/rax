//! Actual guest invalid-parameter handlers and noncatchable default fail-fast.

use crate::user::windows::hle::{ApiResult, Cont, Ctx, Flow};
use crate::user::windows::nt::status::STATUS_STACK_BUFFER_OVERRUN;

use super::{RuntimeKind, runtime, state};

/// The existing fail-fast personality terminates without guest SEH, DLL, or
/// FLS notifications. FAST_FAIL_INVALID_ARG (5) is not separately observable
/// without a native debugger/exception-parameter reporting surface.
fn fatal() -> ApiResult {
    Ok(Flow::TerminateProcess(STATUS_STACK_BUFFER_OVERRUN))
}

pub(super) fn invoke(c: &mut Ctx, kind: RuntimeKind, args: [u64; 5], then: Cont) -> ApiResult {
    state::ensure_context(c, kind)?;
    let runtime = &c.p.crt.runtimes[kind.index()];
    let local = runtime.contexts[&c.t.tid].invalid_handler;
    let target = if local != 0 {
        local
    } else {
        runtime.invalid_handler
    };
    if target == 0 {
        return fatal();
    }
    Ok(Flow::Call {
        target,
        args: args.to_vec(),
        then,
    })
}

pub(super) fn set_global(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    let next = c.arg(0)?;
    let slot = &mut c.p.crt.runtimes[kind.index()].invalid_handler;
    let old = std::mem::replace(slot, next);
    Flow::ret(old)
}
pub(super) fn get_global(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    Flow::ret(c.p.crt.runtimes[kind.index()].invalid_handler)
}
pub(super) fn set_thread(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    let next = c.arg(0)?;
    state::ensure_context(c, kind)?;
    let slot = &mut c.p.crt.runtimes[kind.index()]
        .contexts
        .get_mut(&c.t.tid)
        .expect("established CRT thread context")
        .invalid_handler;
    let old = std::mem::replace(slot, next);
    Flow::ret(old)
}
pub(super) fn get_thread(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    state::ensure_context(c, kind)?;
    Flow::ret(c.p.crt.runtimes[kind.index()].contexts[&c.t.tid].invalid_handler)
}
pub(super) fn parameter(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    let args = [
        c.arg(0)?,
        c.arg(1)?,
        c.arg(2)?,
        c.arg(3)? as u32 as u64,
        c.arg(4)?,
    ];
    invoke(c, kind, args, Box::new(|_, _| Flow::void()))
}
pub(super) fn noinfo(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    invoke(c, kind, [0; 5], Box::new(|_, _| Flow::void()))
}
pub(super) fn noreturn(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    invoke(c, kind, [0; 5], Box::new(|_, _| fatal()))
}
pub(super) fn watson(_: &mut Ctx) -> ApiResult {
    fatal()
}
