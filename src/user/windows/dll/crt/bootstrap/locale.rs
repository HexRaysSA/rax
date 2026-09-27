//! Exact _configthreadlocale flag transitions from the pinned SDK source.

use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};

use super::super::{invalid, state};
use super::{RuntimeKind, runtime, with_ptd};

pub(super) fn configure(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    if c.arch() == WinArch::X86 {
        // The pinned x86 body calls getptd before loading the stack formal.
        with_ptd(c, kind, Box::new(move |c, _| decode_ready(c, kind)))
    } else {
        // Win64 bodies capture the register formal before getptd.
        decode(c, kind)
    }
}

fn decode_ready(c: &mut Ctx, kind: RuntimeKind) -> ApiResult {
    match c.arg(0) {
        Ok(value) => selected(c, kind, value as i32),
        Err(fault) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| decode_ready(c, kind)),
        }),
    }
}

fn decode(c: &mut Ctx, kind: RuntimeKind) -> ApiResult {
    match c.arg(0) {
        Ok(value) => with_ptd(
            c,
            kind,
            Box::new(move |c, _| selected(c, kind, value as i32)),
        ),
        Err(fault) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| decode(c, kind)),
        }),
    }
}

fn selected(c: &mut Ctx, kind: RuntimeKind, mode: i32) -> ApiResult {
    let runtime = &mut c.p.crt.runtimes[kind.index()];
    let flags = &mut runtime
        .contexts
        .get_mut(&c.t.tid)
        .ok_or_else(|| ApiErr::Internal("CRT locale PTD disappeared after establishment".into()))?
        .locale_flags;
    let previous = if *flags & 2 == 0 { 2 } else { 1 };
    match mode {
        0 => {}
        1 => *flags |= 2,
        2 => *flags &= !2,
        -1 => runtime.bootstrap.global_locale_status = u32::MAX,
        _ => return invalid_mode(c, kind),
    }
    Flow::ret(previous)
}

fn invalid_mode(c: &mut Ctx, kind: RuntimeKind) -> ApiResult {
    // SDK _VALIDATE_RETURN's errno write precedes the invalid handler. A
    // returning handler's own errno mutation must not be overwritten.
    match state::set_errno(c, kind, 22) {
        Ok(()) => invalid_callback(c, kind),
        Err(ApiErr::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| invalid_mode(c, kind)),
        }),
        Err(error) => Err(error),
    }
}

fn invalid_callback(c: &mut Ctx, kind: RuntimeKind) -> ApiResult {
    match invalid::invoke(
        c,
        kind,
        [0; 5],
        Box::new(|_, _| Flow::ret(u64::from(u32::MAX))),
    ) {
        Ok(Flow::Call { target, args, then }) => Ok(Flow::CallChecked { target, args, then }),
        Err(ApiErr::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| invalid_callback(c, kind)),
        }),
        other => other,
    }
}
