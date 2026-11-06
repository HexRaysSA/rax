//! Native NT entry into guest-owned thread suspend counts and scheduling.
use super::query::{guard_result, probe_write};
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};
use crate::user::windows::process::thread::ThreadState;

const THREAD_SUSPEND_RESUME: u32 = 2;
const THREAD_RESUME: u32 = 0x1000;
const MAXIMUM_SUSPEND_COUNT: u32 = 127;
const STATUS_SUSPEND_COUNT_EXCEEDED: u32 = 0xc000_004a;
const STATUS_THREAD_IS_TERMINATING: u32 = 0xc000_004b;

pub(super) fn suspend(c: &mut Ctx) -> ApiResult {
    let result = change(c, true);
    guard_result(c, result)
}

pub(super) fn resume(c: &mut Ctx) -> ApiResult {
    let result = change(c, false);
    guard_result(c, result)
}

fn change(c: &mut Ctx, suspend: bool) -> ApiResult {
    let (handle, output) = (c.ptr(0)?, c.ptr(1)?);
    if output != 0 {
        probe_write(c, output, 4)?;
    }
    let id = if handle == c.arch().ptr(CURRENT_THREAD) {
        c.t.obj
    } else {
        if handle == c.arch().ptr(CURRENT_PROCESS) {
            return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
        }
        let Some(id) = c.p.objects.id(handle) else {
            return Flow::ret(STATUS_INVALID_HANDLE.into());
        };
        let Some(Object::Thread { .. }) = c.p.objects.obj(id) else {
            return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
        };
        let allowed = if suspend {
            THREAD_SUSPEND_RESUME
        } else {
            THREAD_SUSPEND_RESUME | THREAD_RESUME
        };
        if c.p.objects.access(handle).unwrap_or(0) & allowed == 0 {
            return Flow::ret(STATUS_ACCESS_DENIED.into());
        }
        id
    };
    let Some(Object::Thread { tid, exit_code }) = c.p.objects.obj(id) else {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    };
    let tid = *tid;
    if exit_code.is_some() {
        return publish(c, output, 0, terminating_status(suspend));
    }
    let target = if id == c.t.obj {
        &mut *c.t
    } else {
        let Some(target) = c.p.threads.get_mut(&tid).filter(|thread| thread.obj == id) else {
            return Err(c.unsupported("thread owner is outside the guest scheduler"));
        };
        target
    };
    if target.terminate.is_some() || matches!(target.state, ThreadState::Exited(_)) {
        return publish(c, output, 0, terminating_status(suspend));
    }
    let previous = target.suspend;
    if suspend {
        if previous >= MAXIMUM_SUSPEND_COUNT {
            return publish(c, output, 0, STATUS_SUSPEND_COUNT_EXCEEDED);
        }
        target.suspend += 1;
    } else {
        target.suspend = previous.saturating_sub(1);
    }
    publish(c, output, previous, STATUS_SUCCESS)
}

fn terminating_status(suspend: bool) -> u32 {
    if suspend {
        STATUS_THREAD_IS_TERMINATING
    } else {
        STATUS_SUCCESS
    }
}

fn publish(c: &mut Ctx, output: u64, previous: u32, status: u32) -> ApiResult {
    if output != 0 {
        c.mem().w32(output, previous)?;
    }
    Flow::ret(status.into())
}
