//! Per-thread terminate handlers and retail abort termination policy.

use crate::user::windows::hle::{ApiErr, ApiResult, Arg::*, Conv::Cdecl, Ctx, Export, Flow};
use crate::user::windows::loader::{self, SymRef};
use crate::user::windows::nt::status::{STATUS_NO_MEMORY, STATUS_STACK_BUFFER_OVERRUN};

use super::super::{RuntimeKind, runtime, state};
use super::exit::{self, Cleanup};
use super::signal;

pub(crate) static UCRT_FATAL_EXPORTS: &[Export] = &[
    Export::func("terminate", Cdecl, &[], terminate),
    Export::func("set_terminate", Cdecl, &[Ptr], set_terminate),
    Export::func("_get_terminate", Cdecl, &[], get_terminate),
    Export::func("abort", Cdecl, &[], abort),
    Export::func(
        "_set_abort_behavior",
        Cdecl,
        &[I32, I32],
        set_abort_behavior,
    ),
];

fn terminate(c: &mut Ctx) -> ApiResult {
    terminate_runtime(c, runtime(c)?)
}

pub(super) fn terminate_runtime(c: &mut Ctx, runtime: RuntimeKind) -> ApiResult {
    match state::ensure_context(c, runtime) {
        Ok(_) => {}
        Err(ApiErr::Fault(fault)) => {
            return Ok(Flow::RetryFault {
                fault,
                retry: Box::new(move |c, _| terminate_runtime(c, runtime)),
            });
        }
        Err(ApiErr::Raise(record)) if record.code == STATUS_NO_MEMORY => {
            return abort_runtime(c, runtime);
        }
        Err(error) => return Err(error),
    }
    let target = c.p.crt.runtimes[runtime.index()].contexts[&c.t.tid].terminate_handler;
    if target == 0 {
        return abort_runtime(c, runtime);
    }
    Ok(Flow::Protected {
        code: None,
        handler: Box::new(move |c, _| abort_runtime(c, runtime)),
        then: Box::new(move |_, _| {
            Flow::call_checked(target, Vec::new(), move |c, _| abort_runtime(c, runtime))
        }),
    })
}

fn default_handler(c: &mut Ctx, runtime: RuntimeKind) -> Result<u64, ApiErr> {
    let name = match runtime {
        RuntimeKind::Ucrt => "ucrtbase.dll",
        RuntimeKind::Msvcrt => "msvcrt.dll",
    };
    let index =
        c.p.modules
            .by_name(name)
            .ok_or_else(|| ApiErr::Internal("CRT terminate runtime disappeared".into()))?;
    loader::lookup(c.p, index, &SymRef::Name(b"abort".to_vec(), None))
        .map_err(|error| ApiErr::Internal(format!("CRT abort binding: {error:?}")))?
        .ok_or_else(|| ApiErr::Internal("CRT abort binding unavailable".into()))
}

fn get_terminate(c: &mut Ctx) -> ApiResult {
    get_for(c, runtime(c)?)
}

fn get_for(c: &mut Ctx, runtime: RuntimeKind) -> ApiResult {
    match state::ensure_context(c, runtime) {
        Ok(_) => {
            let value = c.p.crt.runtimes[runtime.index()].contexts[&c.t.tid].terminate_handler;
            Flow::ret(if value == 0 {
                default_handler(c, runtime)?
            } else {
                value
            })
        }
        Err(ApiErr::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| get_for(c, runtime)),
        }),
        Err(ApiErr::Raise(record)) if record.code == STATUS_NO_MEMORY => abort_runtime(c, runtime),
        Err(error) => Err(error),
    }
}

fn set_terminate(c: &mut Ctx) -> ApiResult {
    decode_set(c, runtime(c)?)
}

fn decode_set(c: &mut Ctx, runtime: RuntimeKind) -> ApiResult {
    match c.arg(0) {
        Ok(target) => set_for(c, runtime, target),
        Err(fault) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| decode_set(c, runtime)),
        }),
    }
}

fn set_for(c: &mut Ctx, runtime: RuntimeKind, target: u64) -> ApiResult {
    match state::ensure_context(c, runtime) {
        Ok(_) => {
            let old = c.p.crt.runtimes[runtime.index()].contexts[&c.t.tid].terminate_handler;
            let result = if old == 0 {
                default_handler(c, runtime)?
            } else {
                old
            };
            c.p.crt.runtimes[runtime.index()]
                .contexts
                .get_mut(&c.t.tid)
                .unwrap()
                .terminate_handler = target;
            Flow::ret(result)
        }
        Err(ApiErr::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| set_for(c, runtime, target)),
        }),
        Err(ApiErr::Raise(record)) if record.code == STATUS_NO_MEMORY => abort_runtime(c, runtime),
        Err(error) => Err(error),
    }
}

fn abort(c: &mut Ctx) -> ApiResult {
    abort_runtime(c, runtime(c)?)
}

pub(super) fn abort_runtime(c: &mut Ctx, runtime: RuntimeKind) -> ApiResult {
    if signal::abort_action(c, runtime) != 0 {
        return signal::raise_for(
            c,
            runtime,
            22,
            Box::new(move |c, _| abort_finish(c, runtime)),
        );
    }
    abort_finish(c, runtime)
}

fn abort_finish(c: &mut Ctx, runtime: RuntimeKind) -> ApiResult {
    // The selected modern Windows profile has PF_FASTFAIL_AVAILABLE on x86
    // and x64; ARM64 takes this path unconditionally in the SDK. Forced exit
    // bypasses VEH/SEH, CRT callbacks, DLL detach and stdio flushing. Reason 7
    // is not separately observable through this personality's terminal API.
    if c.p.crt.runtimes[runtime.index()].exit.abort_behavior & 2 != 0 {
        Ok(Flow::TerminateProcess(STATUS_STACK_BUFFER_OVERRUN))
    } else {
        exit::start(c, runtime, Cleanup::None, Some(3))
    }
}

fn set_abort_behavior(c: &mut Ctx) -> ApiResult {
    decode_behavior(c, runtime(c)?)
}

fn decode_behavior(c: &mut Ctx, runtime: RuntimeKind) -> ApiResult {
    match c.arg(0) {
        Ok(flags) => decode_mask(c, runtime, flags as u32),
        Err(fault) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| decode_behavior(c, runtime)),
        }),
    }
}

fn decode_mask(c: &mut Ctx, runtime: RuntimeKind, flags: u32) -> ApiResult {
    match c.arg(1) {
        Ok(mask) => {
            let state = &mut c.p.crt.runtimes[runtime.index()].exit;
            let old = state.abort_behavior;
            let mask = mask as u32;
            state.abort_behavior = (old & !mask) | (flags & mask);
            Flow::ret(u64::from(old))
        }
        Err(fault) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| decode_mask(c, runtime, flags)),
        }),
    }
}
