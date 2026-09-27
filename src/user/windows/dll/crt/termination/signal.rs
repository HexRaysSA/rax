//! Runtime-global software signals required by abort: SIGABRT and SIGTERM.
//!
//! Console delivery and the per-thread exception-action table are distinct
//! execution planes. Valid actions on their signal numbers remain explicit
//! unsupported frontiers, not silently installed handlers or fabricated native
//! errors. SDK rejection of actions 3/4 precedes that plane admission check.

use crate::user::windows::hle::{ApiErr, ApiResult, Arg::*, Cont, Conv::Cdecl, Ctx, Export, Flow};

use super::super::{RuntimeKind, invalid, runtime, state};
use super::exit::{self, Cleanup};

pub(crate) static UCRT_SIGNAL_EXPORTS: &[Export] = &[
    Export::func("signal", Cdecl, &[I32, Ptr], signal),
    Export::func("raise", Cdecl, &[I32], raise),
];

fn index(number: i32) -> Option<usize> {
    match number {
        6 | 22 => Some(0),
        15 => Some(1),
        _ => None,
    }
}

fn other_plane(number: i32) -> bool {
    matches!(number, 2 | 4 | 8 | 11 | 21)
}

pub(super) fn abort_action(c: &Ctx, runtime: RuntimeKind) -> u64 {
    c.p.crt.runtimes[runtime.index()].signals[0]
}

fn signal(c: &mut Ctx) -> ApiResult {
    decode_signal(c, runtime(c)?)
}

fn decode_signal(c: &mut Ctx, runtime: RuntimeKind) -> ApiResult {
    match c.arg(0) {
        Ok(number) => decode_action(c, runtime, number as i32),
        Err(fault) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| decode_signal(c, runtime)),
        }),
    }
}

fn decode_action(c: &mut Ctx, runtime: RuntimeKind, number: i32) -> ApiResult {
    match c.arg(1) {
        Ok(action) => set(c, runtime, number, action),
        Err(fault) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| decode_action(c, runtime, number)),
        }),
    }
}

fn failed(c: &mut Ctx, runtime: RuntimeKind, number: i32) -> ApiResult {
    if matches!(number, 1 | 3 | 13 | 16 | 17) {
        return Flow::ret(c.arch().ptr(u64::MAX));
    }
    match state::set_errno(c, runtime, 22) {
        Ok(()) => Flow::ret(c.arch().ptr(u64::MAX)),
        Err(ApiErr::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| failed(c, runtime, number)),
        }),
        Err(error) => Err(error),
    }
}

fn set(c: &mut Ctx, runtime: RuntimeKind, number: i32, action: u64) -> ApiResult {
    // SDK executable predicate rejects SIG_SGE=3 and SIG_ACK=4. Its comment
    // also calls SIG_DIE=5 illegal, but the actual predicate does not reject 5.
    if matches!(action, 3 | 4) {
        return failed(c, runtime, number);
    }
    let Some(index) = index(number) else {
        if other_plane(number) {
            return Err(c.unsupported("CRT console/per-thread exception signal plane"));
        }
        return failed(c, runtime, number);
    };
    let value = &mut c.p.crt.runtimes[runtime.index()].signals[index];
    let old = *value;
    // SIG_GET=2 queries without resetting or replacing the current action.
    if action != 2 {
        *value = action;
    }
    Flow::ret(old)
}

fn raise(c: &mut Ctx) -> ApiResult {
    decode_raise(c, runtime(c)?)
}

fn decode_raise(c: &mut Ctx, runtime: RuntimeKind) -> ApiResult {
    match c.arg(0) {
        Ok(number) => raise_for(c, runtime, number as i32, Box::new(|_, _| Flow::ret(0))),
        Err(fault) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| decode_raise(c, runtime)),
        }),
    }
}

fn invalid_raise(c: &mut Ctx, runtime: RuntimeKind) -> ApiResult {
    match invalid::invoke(
        c,
        runtime,
        [0; 5],
        Box::new(move |c, _| raise_error(c, runtime)),
    ) {
        Ok(Flow::Call { target, args, then }) => Ok(Flow::CallChecked { target, args, then }),
        Err(ApiErr::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| invalid_raise(c, runtime)),
        }),
        other => other,
    }
}

fn raise_error(c: &mut Ctx, runtime: RuntimeKind) -> ApiResult {
    match state::set_errno(c, runtime, 22) {
        Ok(()) => Flow::ret(u64::from(u32::MAX)),
        Err(ApiErr::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| raise_error(c, runtime)),
        }),
        Err(error) => Err(error),
    }
}

pub(super) fn raise_for(c: &mut Ctx, runtime: RuntimeKind, number: i32, then: Cont) -> ApiResult {
    let Some(index) = index(number) else {
        if other_plane(number) {
            return Err(c.unsupported("CRT console/per-thread exception signal plane"));
        }
        return invalid_raise(c, runtime);
    };
    let target = c.p.crt.runtimes[runtime.index()].signals[index];
    match target {
        0 => exit::start(c, runtime, Cleanup::None, Some(3)),
        1 => then(c, 0),
        _ => {
            // The signal lock is released before the guest handler. A host
            // metadata operation is serialized by the process scheduler; no
            // host borrow crosses the callback. Reset before any setup fault.
            c.p.crt.runtimes[runtime.index()].signals[index] = 0;
            Ok(Flow::CallChecked {
                target,
                args: vec![u64::from(number as u32)],
                then,
            })
        }
    }
}
