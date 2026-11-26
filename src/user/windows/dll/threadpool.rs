//! Built-in thread-pool timer registration and scheduling.

use super::super::{
    hle::{ApiResult, Arg::*, Conv::Stdcall, Ctx, Export, Flow},
    memory::Mem,
    nt::error::{ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY},
    objects::{Object, Timer2Schedule},
};

pub(super) static TIMER_EXPORTS: &[Export] = &[
    Export::func("CreateThreadpoolTimer", Stdcall, &[Ptr, Ptr, Ptr], create),
    Export::func("SetThreadpoolTimer", Stdcall, &[Ptr, Ptr, I32, I32], set),
    Export::func(
        "WaitForThreadpoolTimerCallbacks",
        Stdcall,
        &[Ptr, I32],
        wait,
    ),
    Export::func("CloseThreadpoolTimer", Stdcall, &[Ptr], close),
];

pub(super) static KERNEL32_FORWARDS: &[Export] = &[
    Export::forward("CreateThreadpoolTimer", "KERNELBASE.CreateThreadpoolTimer"),
    Export::forward("SetThreadpoolTimer", "KERNELBASE.SetThreadpoolTimer"),
    Export::forward(
        "WaitForThreadpoolTimerCallbacks",
        "KERNELBASE.WaitForThreadpoolTimerCallbacks",
    ),
    Export::forward("CloseThreadpoolTimer", "KERNELBASE.CloseThreadpoolTimer"),
];

fn create(c: &mut Ctx) -> ApiResult {
    let (callback, context, environment) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    if callback == 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    if environment != 0 {
        return Err(c.unsupported("CreateThreadpoolTimer with a custom callback environment"));
    }
    let Some(id) = c.p.objects.try_create(Object::ThreadpoolTimer {
        callback,
        context,
        schedule: None,
    }) else {
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    };
    let Some(handle) = c.p.objects.open_access(id, false, 0) else {
        c.p.objects.release(id);
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    };
    Flow::ret(u64::from(handle))
}

fn set(c: &mut Ctx) -> ApiResult {
    let (timer, due, period, window) = (c.ptr(0)?, c.ptr(1)?, c.u32(2)?, c.u32(3)?);
    let schedule = if due == 0 {
        None
    } else {
        if window != 0 {
            return Err(c.unsupported("SetThreadpoolTimer with a coalescing window"));
        }
        let ticks = c.mem().u64(due)? as i64;
        Some(
            Timer2Schedule::new(ticks, i64::from(period) * 10_000)
                .map_err(|error| c.unsupported(format!("SetThreadpoolTimer clock: {error}")))?,
        )
    };
    let Some(Object::ThreadpoolTimer {
        schedule: current, ..
    }) = c.p.objects.get_mut(timer)
    else {
        return Err(c.unsupported("SetThreadpoolTimer for an invalid timer"));
    };
    *current = schedule;
    Flow::void()
}

fn wait(c: &mut Ctx) -> ApiResult {
    let timer = c.ptr(0)?;
    if !matches!(c.p.objects.get(timer), Some(Object::ThreadpoolTimer { .. })) {
        return Err(c.unsupported("WaitForThreadpoolTimerCallbacks for an invalid timer"));
    }
    // The scheduler stops at the delivery frontier, so there are no queued
    // or running callbacks to cancel or await in this profile.
    Flow::void()
}

fn close(c: &mut Ctx) -> ApiResult {
    let timer = c.ptr(0)?;
    if !matches!(c.p.objects.get(timer), Some(Object::ThreadpoolTimer { .. })) {
        return Err(c.unsupported("CloseThreadpoolTimer for an invalid timer"));
    }
    c.p.objects
        .close(timer)
        .map_err(|()| c.unsupported("CloseThreadpoolTimer for a protected timer"))?;
    Flow::void()
}
