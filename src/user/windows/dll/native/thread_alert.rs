//! Dedicated thread-ID alerts, measured independently of user alerts and APCs.
use super::query::guard_result;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use crate::user::windows::sync::{NativeDeadline, Wait};

/// The optional lock is an opaque scheduler hint, not a user-memory capture.
/// Native29704 accepts NULL, inaccessible and guarded addresses without
/// visiting them; acquired shared/exclusive locks remain byte-for-byte intact.
/// Both entry points use the same coalescing thread-owned alert channel.
pub(super) fn alert_ex(c: &mut Ctx) -> ApiResult {
    let _lock_hint = c.ptr(1)?;
    alert(c)
}

pub(super) fn alert(c: &mut Ctx) -> ApiResult {
    let raw = c.ptr(0)?;
    let wow = c.arch() == WinArch::X86;
    // Native CID lookup ignores two tag bits. The measured WoW64 thunk
    // accepts only exact IDs and returns SUCCESS even when no ID is found.
    let tid = if wow { raw } else { raw & !3 };
    let id = if tid == u64::from(c.t.tid) {
        Some(c.t.obj)
    } else if let Ok(tid) = u32::try_from(tid)
        && let Some(thread) = c.p.threads.get(&tid)
    {
        Some(thread.obj)
    } else {
        c.p.objects.iter().find_map(|(id, object)| {
            matches!(object, Object::Thread { tid: target, .. } if u64::from(*target) == tid)
                .then_some(id)
        })
    };
    let Some(id) = id else {
        return Flow::ret(
            if wow {
                STATUS_SUCCESS
            } else {
                STATUS_INVALID_CID
            }
            .into(),
        );
    };
    let Some(Object::Thread {
        tid: target,
        exit_code,
    }) = c.p.objects.obj(id)
    else {
        return Err(c.unsupported("thread-ID alert has no matching thread object"));
    };
    let (target, exited) = (*target, exit_code.is_some());
    if u64::from(target) != tid {
        return Err(c.unsupported("thread-ID alert scheduler identity mismatch"));
    }
    let owned = id == c.t.obj
        || c.p
            .threads
            .get(&target)
            .is_some_and(|thread| thread.obj == id)
        || (exited && c.p.objects.thread_start(id).is_some());
    if !owned {
        return Err(c.unsupported("thread-ID alert belongs to an external process"));
    }
    if !exited {
        c.p.sync.alert_thread(id);
    }
    Flow::ret(STATUS_SUCCESS.into())
}

pub(super) fn wait(c: &mut Ctx) -> ApiResult {
    let result = checked_wait(c);
    match guard_result(c, result) {
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        result => result,
    }
}

fn checked_wait(c: &mut Ctx) -> ApiResult {
    // Address is diagnostic metadata, not a dereferenced wake key.
    let (_address, timeout) = (c.ptr(0)?, c.ptr(1)?);
    // Capture all eight bytes, without alignment restriction, before touching
    // the pending latch. A fault/consumed guard must leave the alert pending.
    let ticks = if timeout == 0 {
        None
    } else {
        Some(c.mem().u64(timeout)? as i64)
    };
    if c.p.sync.take_thread_alert(c.t.obj) {
        return Flow::ret(STATUS_ALERTED.into());
    }
    if ticks == Some(0) {
        return Flow::ret(STATUS_TIMEOUT.into());
    }
    let deadline = ticks
        .map(NativeDeadline::new)
        .transpose()
        .map_err(|error| ApiErr::Internal(format!("thread-alert wait clock: {error}")))?;
    if let Some(deadline) = &deadline
        && deadline.expired()?
    {
        return Flow::ret(STATUS_TIMEOUT.into());
    }
    Flow::block(
        Wait::ThreadAlert {
            object: c.t.obj,
            deadline,
        },
        |_, status| Flow::ret(status),
    )
}
