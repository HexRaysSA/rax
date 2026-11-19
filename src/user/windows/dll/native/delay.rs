//! NT delays share the native object wait clock domains.
use super::query::guard_result;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow, Value};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_ALERTED, STATUS_DATATYPE_MISALIGNMENT,
    STATUS_NO_YIELD_PERFORMED, STATUS_SUCCESS,
};
use crate::user::windows::process::thread::AlertCheck;
use crate::user::windows::sync::{self, NativeDeadline, Wait};

pub(super) fn execute(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    match guard_result(c, result) {
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        result => result,
    }
}

fn checked(c: &mut Ctx) -> ApiResult {
    let alertable = c.u32(0)? as u8 != 0;
    let interval = c.ptr(1)?;
    // Native capture probes this LARGE_INTEGER at ULONG alignment before
    // consulting pending alerts, including for an inaccessible address.
    if !interval.is_multiple_of(4) {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    if interval == 0 {
        return Flow::ret(STATUS_ACCESS_VIOLATION.into());
    }
    let ticks = c.mem().u64(interval)? as i64;
    let apc = if alertable {
        match c.t.check_user_alert() {
            AlertCheck::Alerted => return Flow::ret(STATUS_ALERTED.into()),
            AlertCheck::PendingApcs => true,
            AlertCheck::Empty => false,
        }
    } else {
        false
    };
    if ticks == 0 && !apc {
        return if sync::has_ready_peer(c.p, c.t) {
            Ok(Flow::Yield(Value::Int(STATUS_SUCCESS.into())))
        } else {
            Flow::ret(STATUS_NO_YIELD_PERFORMED.into())
        };
    }
    let deadline = NativeDeadline::new(ticks)
        .map_err(|error| ApiErr::Internal(format!("native delay clock: {error}")))?;
    if !apc && deadline.expired()? {
        return Flow::ret(STATUS_SUCCESS.into());
    }
    Flow::block(
        Wait::NativeDelay {
            deadline,
            alertable,
        },
        |_, status| Flow::ret(status),
    )
}
