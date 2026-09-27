//! Application policy and math-handler registration, not callback delivery.

use crate::user::windows::hle::{ApiResult, Ctx, Flow};

use super::{RuntimeKind, runtime};

pub(super) fn set_app_type(c: &mut Ctx) -> ApiResult {
    decode_app(c, runtime(c)?)
}

fn decode_app(c: &mut Ctx, kind: RuntimeKind) -> ApiResult {
    match c.arg(0) {
        Ok(value) => {
            // The SDK enum store validates neither known values nor sign.
            c.p.crt.runtimes[kind.index()].bootstrap.app_type = value as u32;
            Flow::void()
        }
        Err(fault) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| decode_app(c, kind)),
        }),
    }
}

pub(super) fn query_app_type(c: &mut Ctx) -> ApiResult {
    Flow::ret(u64::from(
        c.p.crt.runtimes[runtime(c)?.index()].bootstrap.app_type,
    ))
}

pub(super) fn set_math_handler(c: &mut Ctx) -> ApiResult {
    decode_math(c, runtime(c)?)
}

fn decode_math(c: &mut Ctx, kind: RuntimeKind) -> ApiResult {
    match c.arg(0) {
        Ok(target) => {
            // Publisher bodies encode/store this identity, without validation
            // or immediate invocation. Keep the actual selected logical state.
            c.p.crt.runtimes[kind.index()].bootstrap.math_handler = target;
            Flow::void()
        }
        Err(fault) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| decode_math(c, kind)),
        }),
    }
}
