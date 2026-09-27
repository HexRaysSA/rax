//! Guest FLS APIs and continuation-based callback drain.
//!
//! FlsFree callbacks execute in the caller's current fiber/thread context. A
//! context-deletion cleanup drains the target's values without temporarily
//! selecting its fiber. Exact native callback identity/order/reentrancy is
//! unknown; this is the documented personality profile.

use super::super::hle::{ApiErr, ApiResult, Arg::*, Cont, Conv::Stdcall, Ctx, Export, Flow};
use super::super::nt::error::{ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY};
use super::super::tls::{FlsCleanup, FlsError, FlsFree, FlsKey, TLS_OUT_OF_INDEXES};

pub(super) static EXPORTS: &[Export] = &[
    Export::func("FlsAlloc", Stdcall, &[Ptr], alloc),
    Export::func("FlsFree", Stdcall, &[I32], free),
    Export::func("FlsGetValue", Stdcall, &[I32], get),
    Export::func("FlsSetValue", Stdcall, &[I32, Ptr], set),
];

fn error(c: &mut Ctx, error: FlsError, value: u64) -> ApiResult {
    match error {
        FlsError::InvalidIndex => c.fail(ERROR_INVALID_PARAMETER, value),
        // Numeric cap exhaustion uses the existing OOM code as an explicit
        // profile; the API page does not establish its exact native error.
        FlsError::NoMemory => c.fail(ERROR_NOT_ENOUGH_MEMORY, value),
        other => Err(internal(other)),
    }
}

fn internal(error: FlsError) -> ApiErr {
    ApiErr::Internal(format!("FLS registry/cleanup failed: {error:?}"))
}

fn alloc(c: &mut Ctx) -> ApiResult {
    let callback = c.ptr(0)?;
    match c.p.tls.fls_alloc(callback) {
        Ok(index) => Flow::ret(u64::from(index)),
        Err(e) => error(c, e, u64::from(TLS_OUT_OF_INDEXES)),
    }
}

fn free(c: &mut Ctx) -> ApiResult {
    let index = c.u32(0)?;
    match c.p.tls.fls_begin_free(index) {
        Ok(mut plan) => {
            plan.set_owner(c.t.tid);
            next_free(c, plan)
        }
        Err(e) => error(c, e, 0),
    }
}

fn next_free(c: &mut Ctx, mut plan: FlsFree) -> ApiResult {
    if let Some(call) = plan.next() {
        Flow::call(call.callback, vec![call.value], move |c, _| {
            next_free(c, plan)
        })
    } else {
        plan.finish().map_err(internal)?;
        Flow::bool(true)
    }
}

fn get(c: &mut Ctx) -> ApiResult {
    let index = c.u32(0)?;
    match c.p.tls.fls_get(c.t.fls_key(), index) {
        Ok(value) => {
            // Successful clear-to-zero is an explicit profile pending a native
            // probe: unlike TlsGetValue, the primary FLS page is not explicit.
            c.set_last_error(0)?;
            Flow::ret(value)
        }
        Err(e) => error(c, e, 0),
    }
}

fn set(c: &mut Ctx) -> ApiResult {
    let (index, value) = (c.u32(0)?, c.ptr(1)?);
    match c.p.tls.fls_set(c.t.fls_key(), index, value) {
        Ok(()) => Flow::bool(true),
        Err(e) => error(c, e, 0),
    }
}

/// Drain a context before releasing its storage. The caller chooses when to run
/// this relative to DLL notifications, then owns final resource destruction.
pub(crate) fn cleanup(c: &mut Ctx, key: FlsKey, then: Cont) -> ApiResult {
    let mut plan = c.p.tls.fls_begin_cleanup(key).map_err(internal)?;
    plan.set_owner(c.t.tid);
    next_cleanup(c, plan, then)
}

fn next_cleanup(c: &mut Ctx, mut plan: FlsCleanup, then: Cont) -> ApiResult {
    if let Some(call) = plan.next().map_err(internal)? {
        Flow::call(call.callback, vec![call.value], move |c, _| {
            next_cleanup(c, plan, then)
        })
    } else {
        plan.finish().map_err(internal)?;
        then(c, 0)
    }
}

#[cfg(test)]
mod tests;
