//! Built-in thread-pool registrations and timer scheduling.

use super::super::{
    hle::{ApiResult, Arg::*, Conv::Stdcall, Ctx, Export, Flow},
    memory::Mem,
    nt::error::{ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY},
    nt::status::{
        STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
        STATUS_SUCCESS,
    },
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

pub(super) static KERNEL32_WAIT_FORWARDS: &[Export] = &[
    Export::forward("CreateThreadpoolWait", "KERNELBASE.CreateThreadpoolWait"),
    Export::forward("SetThreadpoolWait", "KERNELBASE.SetThreadpoolWait"),
    Export::forward(
        "WaitForThreadpoolWaitCallbacks",
        "KERNELBASE.WaitForThreadpoolWaitCallbacks",
    ),
    Export::forward("CloseThreadpoolWait", "KERNELBASE.CloseThreadpoolWait"),
];

pub(super) static WAIT_EXPORTS: &[Export] = &[
    Export::func(
        "CreateThreadpoolWait",
        Stdcall,
        &[Ptr, Ptr, Ptr],
        create_event_wait,
    ),
    Export::func(
        "SetThreadpoolWait",
        Stdcall,
        &[Ptr, Ptr, Ptr],
        set_event_wait,
    ),
    Export::func(
        "WaitForThreadpoolWaitCallbacks",
        Stdcall,
        &[Ptr, I32],
        wait_event_callbacks,
    ),
    Export::func("CloseThreadpoolWait", Stdcall, &[Ptr], close_event_wait),
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

pub(super) static CALLBACK_HINT_EXPORTS: &[Export] = &[Export::func(
    "CallbackMayRunLong",
    Stdcall,
    &[Ptr],
    callback_may_run_long,
)];

pub(super) static KERNEL32_CALLBACK_HINT_FORWARDS: &[Export] = &[Export::forward(
    "CallbackMayRunLong",
    "KERNELBASE.CallbackMayRunLong",
)];

pub(super) static NATIVE_ANALYSIS_EXPORTS: &[Export] = &[
    Export::func("TpAllocWork", Stdcall, &[Ptr, Ptr, Ptr, Ptr], tp_alloc_work),
    Export::func("TpReleaseWork", Stdcall, &[Ptr], close_work),
    Export::func("TpPostWork", Stdcall, &[Ptr], submit_work),
    Export::func("TpWaitForWork", Stdcall, &[Ptr, I32], wait_work),
    Export::func(
        "TpAllocIoCompletion",
        Stdcall,
        &[Ptr, Ptr, Ptr, Ptr, Ptr],
        tp_alloc_io,
    ),
    Export::func("TpReleaseIoCompletion", Stdcall, &[Ptr], tp_release_io),
    Export::func("TpStartAsyncIoOperation", Stdcall, &[Ptr], tp_start_io),
    Export::func("TpCancelAsyncIoOperation", Stdcall, &[Ptr], tp_cancel_io),
    Export::func("TpDisassociateCallback", Stdcall, &[Ptr], tp_disassociate),
    Export::func("TpWaitForIoCompletion", Stdcall, &[Ptr, I32], tp_wait_io),
];

fn tp_alloc_work(c: &mut Ctx) -> ApiResult {
    let (out, callback, context, environment) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?, c.ptr(3)?);
    if out == 0 || callback == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if environment != 0 {
        return Err(c.unsupported("TpAllocWork with a custom callback environment"));
    }
    publish_native(
        c,
        out,
        Object::ThreadpoolWork {
            callback,
            context,
            pending: 0,
        },
    )
}

fn tp_alloc_io(c: &mut Ctx) -> ApiResult {
    let (out, handle, callback, context, environment) =
        (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?, c.ptr(3)?, c.ptr(4)?);
    if out == 0 || callback == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if environment != 0 || !c.p.cfg.gameos_analysis {
        return Err(c.unsupported("TpAllocIoCompletion outside the default GameOS analysis queue"));
    }
    let Some(file) = c.p.objects.id(handle) else {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    };
    if !matches!(c.p.objects.obj(file), Some(Object::GameOsXvcQueue { .. })) {
        return Err(c.unsupported("TpAllocIoCompletion for an unsupported file type"));
    }
    c.p.objects.retain(file);
    publish_native(
        c,
        out,
        Object::ThreadpoolIo {
            file,
            callback,
            context,
            armed: 0,
        },
    )
}

fn publish_native(c: &mut Ctx, out: u64, registration: Object) -> ApiResult {
    let file = match &registration {
        Object::ThreadpoolIo { file, .. } => Some(*file),
        _ => None,
    };
    let Some(object) = c.p.objects.try_create(registration) else {
        if let Some(file) = file {
            c.p.objects.release(file);
        }
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let Some(handle) = c.p.objects.open_access(object, false, 0) else {
        c.p.objects.release(object);
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    if let Err(fault) = c.write_ptr(out, u64::from(handle)) {
        let _ = c.p.objects.close(handle.into());
        return Err(fault.into());
    }
    Flow::ret(STATUS_SUCCESS.into())
}

fn tp_release_io(c: &mut Ctx) -> ApiResult {
    let handle = c.ptr(0)?;
    if !matches!(c.p.objects.get(handle), Some(Object::ThreadpoolIo { .. })) {
        return Err(c.unsupported("TpReleaseIoCompletion with an invalid registration"));
    }
    c.p.objects
        .close(handle)
        .map_err(|()| c.unsupported("protected thread-pool I/O registration"))?;
    Flow::void()
}

fn tp_start_io(c: &mut Ctx) -> ApiResult {
    change_io_count(c, u32::checked_add)
}

fn tp_cancel_io(c: &mut Ctx) -> ApiResult {
    change_io_count(c, u32::checked_sub)
}

fn tp_wait_io(c: &mut Ctx) -> ApiResult {
    let (handle, cancel) = (c.ptr(0)?, c.u32(1)? != 0);
    let Some(id) =
        c.p.objects
            .id(handle)
            .filter(|id| matches!(c.p.objects.obj(*id), Some(Object::ThreadpoolIo { .. })))
    else {
        return Err(c.unsupported("TpWaitForIoCompletion with an invalid registration"));
    };
    wait_callbacks(c, id, cancel)
}

fn change_io_count(c: &mut Ctx, change: fn(u32, u32) -> Option<u32>) -> ApiResult {
    let handle = c.ptr(0)?;
    let Some(id) = c.p.objects.id(handle) else {
        return Err(c.unsupported("invalid thread-pool I/O registration"));
    };
    if let Some(Object::ThreadpoolIo { armed, .. }) = c.p.objects.obj_mut(id)
        && let Some(next) = change(*armed, 1)
    {
        *armed = next;
        return Flow::void();
    }
    Err(c.unsupported("invalid thread-pool I/O operation count"))
}

#[derive(Debug)]
pub(crate) struct WorkCall {
    object: ObjId,
    handle: u64,
    instance: u64,
    disassociated: bool,
    args: CallbackArgs,
    events: Vec<ObjId>,
}

#[derive(Debug)]
enum CallbackArgs {
    Work,
    Wait(u64),
    Io { context: u64, status: u64 },
}

pub(crate) fn work_arguments(p: &Proc, tid: u32, context: u64) -> Option<Vec<u64>> {
    let call = p.sync.pool_workers.get(&tid)?;
    let mut args = vec![call.instance, context, call.handle];
    match call.args {
        CallbackArgs::Work => {}
        CallbackArgs::Wait(result) => args.push(result),
        CallbackArgs::Io { context, status } => {
            args.truncate(2);
            args.extend([context, status, call.handle]);
        }
    }
    Some(args)
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
    if !call.disassociated && !complete_work(p, call.object) {
        p.fail("thread-pool worker has no outstanding registration".to_owned());
    }
    p.objects.release(call.object);
    if let Err(error) = p.heaps.free(p.process_heap, call.instance) {
        p.fail(format!(
            "thread-pool callback instance cleanup failed: {error:?}"
        ));
    }
}

fn complete_work(p: &mut Proc, id: ObjId) -> bool {
    if let Some(
        Object::ThreadpoolWork { pending, .. }
        | Object::ThreadpoolWait { pending, .. }
        | Object::ThreadpoolIo { armed: pending, .. },
    ) = p.objects.obj_mut(id)
        && *pending != 0
    {
        *pending -= 1;
        return true;
    }
    false
}

fn tp_disassociate(c: &mut Ctx) -> ApiResult {
    let instance = c.ptr(0)?;
    let Some(call) =
        c.p.sync
            .pool_workers
            .get_mut(&c.t.tid)
            .filter(|call| call.instance == instance)
    else {
        return Err(c.unsupported("TpDisassociateCallback requires the current callback instance"));
    };
    let object = call.object;
    if !std::mem::replace(&mut call.disassociated, true) && !complete_work(c.p, object) {
        return Err(c.unsupported("thread-pool callback has no outstanding registration"));
    }
    Flow::void()
}

fn callback_may_run_long(c: &mut Ctx) -> ApiResult {
    let instance = c.ptr(0)?;
    if !c
        .p
        .sync
        .pool_workers
        .get(&c.t.tid)
        .is_some_and(|call| call.instance == instance)
    {
        return Err(c.unsupported("CallbackMayRunLong requires the current callback instance"));
    }
    // Each submission has its own guest worker. A long callback does not
    // reserve a shared worker slot or delay dispatch of another submission.
    Flow::bool(true)
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
        callback, context, ..
    }) = c.p.objects.obj(object)
    else {
        return Err(c.unsupported("SubmitThreadpoolWork for a non-work object"));
    };
    submit_callback(c.p, object, handle, callback, context, CallbackArgs::Work)
        .map_err(|error| c.unsupported(error))?;
    Flow::void()
}

fn submit_callback(
    p: &mut Proc,
    object: ObjId,
    handle: u64,
    callback: u64,
    context: u64,
    args: CallbackArgs,
) -> Result<(), String> {
    let pending = match p.objects.obj(object) {
        Some(Object::ThreadpoolWork { pending, .. } | Object::ThreadpoolWait { pending, .. }) => {
            pending
                .checked_add(1)
                .ok_or("thread-pool submission count overflow")?
        }
        Some(Object::ThreadpoolIo { armed, .. }) if *armed != 0 => *armed,
        _ => return Err("invalid thread-pool registration".to_owned()),
    };
    let Some(instance) = p
        .heaps
        .alloc(&mut p.vm, p.process_heap, p.arch.ptr_size(), true)
    else {
        return Err("cannot allocate a thread-pool callback instance".to_owned());
    };
    let tid = match thread::create(p, callback, context, 0, false) {
        Ok(tid) => tid,
        Err(status) => {
            p.heaps
                .free(p.process_heap, instance)
                .map_err(|error| format!("thread-pool callback instance cleanup: {error:?}"))?;
            return Err(format!(
                "cannot create a thread-pool worker ({status:#010x})"
            ));
        }
    };
    if let Some(
        Object::ThreadpoolWork {
            pending: current, ..
        }
        | Object::ThreadpoolWait {
            pending: current, ..
        },
    ) = p.objects.obj_mut(object)
    {
        *current = pending;
    }
    p.objects.retain(object);
    p.sync.pool_workers.insert(
        tid,
        WorkCall {
            object,
            handle,
            instance,
            disassociated: false,
            args,
            events: Vec::new(),
        },
    );
    Ok(())
}

pub(super) fn complete_io(
    p: &mut Proc,
    file: ObjId,
    context: u64,
    status: u64,
) -> Result<(), String> {
    let Some((object, callback, callback_context)) =
        p.objects.iter().find_map(|(id, object)| match object {
            Object::ThreadpoolIo {
                file: registered,
                callback,
                context,
                armed,
            } if *registered == file && *armed != 0 => Some((id, *callback, *context)),
            _ => None,
        })
    else {
        return Ok(());
    };
    let handle = p
        .objects
        .handle_for(object)
        .ok_or("thread-pool I/O registration lost its handle")?;
    submit_callback(
        p,
        object,
        handle,
        callback,
        callback_context,
        CallbackArgs::Io { context, status },
    )
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
    wait_callbacks(c, id, cancel)
}

fn wait_callbacks(c: &mut Ctx, id: ObjId, cancel: bool) -> ApiResult {
    if c.p
        .sync
        .pool_workers
        .get(&c.t.tid)
        .is_some_and(|call| call.object == id && !call.disassociated)
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
        Some(
            Object::ThreadpoolWork { pending: 0, .. }
                | Object::ThreadpoolWait { pending: 0, .. }
                | Object::ThreadpoolIo { armed: 0, .. }
        )
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

fn create_event_wait(c: &mut Ctx) -> ApiResult {
    let (callback, context, environment) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    if callback == 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    if environment != 0 {
        return Err(c.unsupported("CreateThreadpoolWait with a custom callback environment"));
    }
    allocate(
        c,
        Object::ThreadpoolWait {
            callback,
            context,
            armed: None,
            pending: 0,
        },
    )
}

fn event_wait_id(c: &Ctx, handle: u64) -> Option<ObjId> {
    c.p.objects
        .id(handle)
        .filter(|&id| matches!(c.p.objects.obj(id), Some(Object::ThreadpoolWait { .. })))
}

fn arm_event_wait(p: &mut Proc, id: ObjId, arm: Option<(u64, ObjId)>) {
    let Some(Object::ThreadpoolWait { armed, .. }) = p.objects.obj_mut(id) else {
        p.sync.pool_waits.remove(&id);
        return;
    };
    let old = std::mem::replace(armed, arm);
    if let Some((_, event)) = arm {
        p.objects.retain(event);
        p.sync.pool_waits.insert(id);
    } else {
        p.sync.pool_waits.remove(&id);
    }
    if let Some((_, event)) = old {
        p.objects.release(event);
    }
}

fn set_event_wait(c: &mut Ctx) -> ApiResult {
    let (handle, event, due) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    let Some(id) = event_wait_id(c, handle) else {
        return Err(c.unsupported("SetThreadpoolWait for an invalid registration"));
    };
    let arm = if event == 0 {
        None
    } else {
        if due != 0 {
            return Err(c.unsupported("SetThreadpoolWait with a timeout"));
        }
        let Some(event_id) = c.p.objects.id(event).filter(|&id| {
            matches!(c.p.objects.obj(id), Some(Object::Event { .. }))
                && c.p
                    .objects
                    .access(event)
                    .is_some_and(|access| access & 0x0010_0000 != 0)
        }) else {
            return Err(
                c.unsupported("SetThreadpoolWait requires an event with synchronize access")
            );
        };
        Some((handle, event_id))
    };
    arm_event_wait(c.p, id, arm);
    Flow::void()
}

fn wait_event_callbacks(c: &mut Ctx) -> ApiResult {
    let (handle, cancel) = (c.ptr(0)?, c.u32(1)? != 0);
    let Some(id) = event_wait_id(c, handle) else {
        return Err(c.unsupported("WaitForThreadpoolWaitCallbacks for an invalid registration"));
    };
    wait_callbacks(c, id, cancel)
}

fn close_event_wait(c: &mut Ctx) -> ApiResult {
    let handle = c.ptr(0)?;
    let Some(id) = event_wait_id(c, handle) else {
        return Err(c.unsupported("CloseThreadpoolWait for an invalid registration"));
    };
    c.p.objects
        .close(handle)
        .map_err(|()| c.unsupported("CloseThreadpoolWait for a protected registration"))?;
    arm_event_wait(c.p, id, None);
    Flow::void()
}

pub(crate) fn poll_event_waits(p: &mut Proc) -> Result<(), String> {
    let waits: Vec<_> = p.sync.pool_waits.iter().copied().collect();
    for id in waits {
        let Some(&Object::ThreadpoolWait {
            callback,
            context,
            armed: Some((handle, event)),
            ..
        }) = p.objects.obj(id)
        else {
            p.sync.pool_waits.remove(&id);
            continue;
        };
        let Some(&Object::Event { manual, signaled }) = p.objects.obj(event) else {
            return Err("thread-pool wait lost its event".to_owned());
        };
        if signaled == 0 {
            continue;
        }
        submit_callback(p, id, handle, callback, context, CallbackArgs::Wait(0))?;
        if !manual && let Some(Object::Event { signaled, .. }) = p.objects.obj_mut(event) {
            *signaled = 0;
        }
        arm_event_wait(p, id, None);
    }
    Ok(())
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
