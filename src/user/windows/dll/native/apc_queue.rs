//! Ordinary user APCs targeting a thread in the current emulated process.
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE,
    STATUS_OBJECT_TYPE_MISMATCH, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};
use crate::user::windows::process::{ThreadState, UserApc};

const THREAD_SET_CONTEXT: u32 = 0x0010;

pub(super) fn queue(c: &mut Ctx) -> ApiResult {
    enqueue(c, 1)
}

pub(super) fn queue_ex(c: &mut Ctx) -> ApiResult {
    if c.ptr(1)? != 0 {
        return Err(c.unsupported("APC reserve objects and special APCs require a different queue"));
    }
    enqueue(c, 2)
}

pub(super) fn queue_ex2(c: &mut Ctx) -> ApiResult {
    if c.ptr(1)? != 0 || c.u32(2)? != 0 {
        return Err(c.unsupported("APC reserve objects and APC flags require a different queue"));
    }
    enqueue(c, 3)
}

fn enqueue(c: &mut Ctx, start: usize) -> ApiResult {
    let handle = c.ptr(0)?;
    let apc = UserApc::Native {
        routine: c.ptr(start)?,
        arguments: [c.ptr(start + 1)?, c.ptr(start + 2)?, c.ptr(start + 3)?],
    };
    let current_thread = handle == c.arch().ptr(CURRENT_THREAD);
    let id = if current_thread {
        c.t.obj
    } else {
        if handle == c.arch().ptr(CURRENT_PROCESS) {
            return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
        }
        let Some(id) = c.p.objects.id(handle) else {
            return Flow::ret(STATUS_INVALID_HANDLE.into());
        };
        id
    };
    let Some(Object::Thread { tid, exit_code }) = c.p.objects.obj(id) else {
        return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
    };
    if !current_thread && c.p.objects.access(handle).unwrap_or(0) & THREAD_SET_CONTEXT == 0 {
        return Flow::ret(STATUS_ACCESS_DENIED.into());
    }
    if exit_code.is_some() {
        return Flow::ret(STATUS_UNSUCCESSFUL.into());
    }
    let target = if id == c.t.obj {
        &mut *c.t
    } else {
        let Some(target) = c.p.threads.get_mut(tid).filter(|thread| thread.obj == id) else {
            return Err(c.unsupported("APC target is outside the current guest process"));
        };
        target
    };
    if target.terminate.is_some() || matches!(target.state, ThreadState::Exited(_)) {
        return Flow::ret(STATUS_UNSUCCESSFUL.into());
    }
    if target.apcs.try_reserve(1).is_err() {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    }
    target.apcs.push_back(apc);
    Flow::ret(STATUS_SUCCESS.into())
}
