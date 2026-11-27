//! Built-in thread-pool registrations and timer scheduling.

use super::super::{
    hle::{ApiResult, Arg::*, Conv::Stdcall, Ctx, Export, Flow},
    memory::Mem,
    nt::error::{ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY},
    objects::{ObjId, Object, Timer2Schedule},
    process::{Proc, thread},
    sync::Wait,
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

pub(super) static KERNEL32_WORK_FORWARDS: &[Export] = &[
    Export::forward("CreateThreadpoolWork", "KERNELBASE.CreateThreadpoolWork"),
    Export::forward("SubmitThreadpoolWork", "KERNELBASE.SubmitThreadpoolWork"),
    Export::forward(
        "WaitForThreadpoolWorkCallbacks",
        "KERNELBASE.WaitForThreadpoolWorkCallbacks",
    ),
    Export::forward("CloseThreadpoolWork", "KERNELBASE.CloseThreadpoolWork"),
    Export::forward(
        "SetEventWhenCallbackReturns",
        "KERNELBASE.SetEventWhenCallbackReturns",
    ),
];

pub(super) static WORK_EXPORTS: &[Export] = &[
    Export::func(
        "CreateThreadpoolWork",
        Stdcall,
        &[Ptr, Ptr, Ptr],
        create_work,
    ),
    Export::func("SubmitThreadpoolWork", Stdcall, &[Ptr], submit_work),
    Export::func(
        "WaitForThreadpoolWorkCallbacks",
        Stdcall,
        &[Ptr, I32],
        wait_work,
    ),
    Export::func("CloseThreadpoolWork", Stdcall, &[Ptr], close_work),
    Export::func(
        "SetEventWhenCallbackReturns",
        Stdcall,
        &[Ptr, Ptr],
        set_event_on_return,
    ),
];

#[derive(Debug)]
pub(crate) struct WorkCall {
    object: ObjId,
    handle: u64,
    instance: u64,
    events: Vec<ObjId>,
}

pub(crate) fn work_arguments(p: &Proc, tid: u32, context: u64) -> Option<Vec<u64>> {
    let call = p.sync.pool_workers.get(&tid)?;
    Some(vec![call.instance, context, call.handle])
}

pub(crate) fn retire_work(p: &mut Proc, tid: u32, returned: bool) {
    let Some(call) = p.sync.pool_workers.remove(&tid) else {
        return;
    };
    for event in call.events {
        if returned && let Some(Object::Event { signaled, .. }) = p.objects.obj_mut(event) {
            *signaled = 1;
        }
        p.objects.release(event);
    }
    match p.objects.obj_mut(call.object) {
        Some(Object::ThreadpoolWork { pending, .. }) if *pending != 0 => *pending -= 1,
        _ => p.fail("thread-pool worker has no outstanding registration".to_owned()),
    }
    p.objects.release(call.object);
    if let Err(error) = p.heaps.free(p.process_heap, call.instance) {
        p.fail(format!(
            "thread-pool callback instance cleanup failed: {error:?}"
        ));
    }
}

fn create_work(c: &mut Ctx) -> ApiResult {
    let (callback, context, environment) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    if callback == 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    if environment != 0 {
        return Err(c.unsupported("CreateThreadpoolWork with a custom callback environment"));
    }
    allocate(
        c,
        Object::ThreadpoolWork {
            callback,
            context,
            pending: 0,
        },
    )
}

fn submit_work(c: &mut Ctx) -> ApiResult {
    let handle = c.ptr(0)?;
    let Some(object) = c.p.objects.id(handle) else {
        return Err(c.unsupported("SubmitThreadpoolWork for an invalid work object"));
    };
    let Some(&Object::ThreadpoolWork {
        callback,
        context,
        pending,
    }) = c.p.objects.obj(object)
    else {
        return Err(c.unsupported("SubmitThreadpoolWork for a non-work object"));
    };
    let pending = pending
        .checked_add(1)
        .ok_or_else(|| c.unsupported("thread-pool work submission count overflow"))?;
    let instance_size = c.psize();
    let Some(instance) =
        c.p.heaps
            .alloc(&mut c.p.vm, c.p.process_heap, instance_size, true)
    else {
        return Err(c.unsupported("cannot allocate a thread-pool callback instance"));
    };
    let tid = match thread::create(c.p, callback, context, 0, false) {
        Ok(tid) => tid,
        Err(status) => {
            c.p.heaps
                .free(c.p.process_heap, instance)
                .map_err(|error| {
                    c.unsupported(format!("thread-pool callback instance cleanup: {error:?}"))
                })?;
            return Err(c.unsupported(format!(
                "cannot create a thread-pool worker ({status:#010x})"
            )));
        }
    };
    if let Some(Object::ThreadpoolWork {
        pending: current, ..
    }) = c.p.objects.obj_mut(object)
    {
        *current = pending;
    }
    c.p.objects.retain(object);
    c.p.sync.pool_workers.insert(
        tid,
        WorkCall {
            object,
            handle,
            instance,
            events: Vec::new(),
        },
    );
    Flow::void()
}

fn wait_work(c: &mut Ctx) -> ApiResult {
    let (work, cancel) = (c.ptr(0)?, c.u32(1)? != 0);
    let Some(id) =
        c.p.objects
            .id(work)
            .filter(|id| matches!(c.p.objects.obj(*id), Some(Object::ThreadpoolWork { .. })))
    else {
        return Err(c.unsupported("WaitForThreadpoolWorkCallbacks for an invalid work object"));
    };
    if c.p
        .sync
        .pool_workers
        .get(&c.t.tid)
        .is_some_and(|call| call.object == id)
    {
        return Err(c.unsupported("thread-pool callback cannot wait for itself"));
    }
    if cancel {
        let pending: Vec<_> =
            c.p.sync
                .pool_workers
                .iter()
                .filter_map(|(&tid, call)| {
                    let worker = c.p.threads.get(&tid)?;
                    (call.object == id
                        && worker.cpu.pc() == c.p.traps.thread_start()
                        && worker.frames.is_empty())
                    .then_some(tid)
                })
                .collect();
        for tid in pending {
            if let Some(worker) = c.p.threads.remove(&tid) {
                thread::destroy(c.p, worker, 0);
            }
        }
    }
    if matches!(
        c.p.objects.obj(id),
        Some(Object::ThreadpoolWork { pending: 0, .. })
    ) {
        return Flow::void();
    }
    Flow::block(
        Wait::Objects {
            objs: vec![id],
            all: true,
            deadline: None,
            alertable: false,
        },
        |_, _| Flow::void(),
    )
}

fn close_work(c: &mut Ctx) -> ApiResult {
    let work = c.ptr(0)?;
    if !matches!(c.p.objects.get(work), Some(Object::ThreadpoolWork { .. })) {
        return Err(c.unsupported("CloseThreadpoolWork for an invalid work object"));
    }
    c.p.objects
        .close(work)
        .map_err(|()| c.unsupported("CloseThreadpoolWork for a protected work object"))?;
    Flow::void()
}

fn set_event_on_return(c: &mut Ctx) -> ApiResult {
    let (instance, handle) = (c.ptr(0)?, c.ptr(1)?);
    let Some(event) = c.p.objects.id(handle).filter(|id| {
        matches!(c.p.objects.obj(*id), Some(Object::Event { .. }))
            && c.p
                .objects
                .access(handle)
                .is_some_and(|access| access & 2 != 0)
    }) else {
        return Err(
            c.unsupported("SetEventWhenCallbackReturns requires an event with modify access")
        );
    };
    let Some(call) =
        c.p.sync
            .pool_workers
            .get_mut(&c.t.tid)
            .filter(|call| call.instance == instance)
    else {
        return Err(
            c.unsupported("SetEventWhenCallbackReturns requires the current callback instance")
        );
    };
    if !call.events.contains(&event) {
        c.p.objects.retain(event);
        call.events.push(event);
    }
    Flow::void()
}

fn create(c: &mut Ctx) -> ApiResult {
    let (callback, context, environment) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    if callback == 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    if environment != 0 {
        return Err(c.unsupported("CreateThreadpoolTimer with a custom callback environment"));
    }
    allocate(
        c,
        Object::ThreadpoolTimer {
            callback,
            context,
            schedule: None,
        },
    )
}

fn allocate(c: &mut Ctx, object: Object) -> ApiResult {
    let Some(id) = c.p.objects.try_create(object) else {
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
