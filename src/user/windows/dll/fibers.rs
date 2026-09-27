//! Win32 fiber API frontiers. Context switching completes the old API return
//! before selecting the target; it is not a call into the target fiber's stack.

use crate::user::windows::hle::dispatch::{self, CallSite, Outcome};
use crate::user::windows::hle::{
    Api, ApiErr, ApiResult, Arg::*, Conv, Conv::Stdcall, Ctx, Export, Flow,
};
use crate::user::windows::nt::{error::*, status_to_error};
use crate::user::windows::process::{Proc, Thread, fiber};
use crate::user::windows::tls::FlsKey;

pub(super) static EXPORTS: &[Export] = &[
    Export::func("ConvertThreadToFiber", Stdcall, &[Ptr], convert),
    Export::func("ConvertThreadToFiberEx", Stdcall, &[Ptr, I32], convert_ex),
    Export::func("ConvertFiberToThread", Stdcall, &[], reconvert),
    Export::func("CreateFiber", Stdcall, &[Ptr, Ptr, Ptr], create),
    Export::func(
        "CreateFiberEx",
        Stdcall,
        &[Ptr, Ptr, I32, Ptr, Ptr],
        create_ex,
    ),
    Export::func("SwitchToFiber", Stdcall, &[Ptr], switch),
    Export::func("DeleteFiber", Stdcall, &[Ptr], delete),
    Export::func("IsThreadAFiber", Stdcall, &[], is_fiber),
];

fn convert_flags(c: &mut Ctx, parameter: u64, flags: u32) -> ApiResult {
    if c.t.current_fiber.is_some() {
        return c.fail(ERROR_ALREADY_FIBER, 0);
    }
    match fiber::convert(c.p, c.t, parameter, flags) {
        Ok(handle) => Flow::ret(handle),
        Err(status) => c.fail(status_to_error(status), 0),
    }
}

fn convert(c: &mut Ctx) -> ApiResult {
    let parameter = c.ptr(0)?;
    convert_flags(c, parameter, 0)
}

fn convert_ex(c: &mut Ctx) -> ApiResult {
    let (parameter, flags) = (c.ptr(0)?, c.u32(1)?);
    convert_flags(c, parameter, flags)
}

fn reconvert(c: &mut Ctx) -> ApiResult {
    if c.t.current_fiber.is_none() {
        return c.fail(ERROR_ALREADY_THREAD, 0);
    }
    match fiber::reconvert(c.p, c.t) {
        Ok(()) => Flow::bool(true),
        Err(status) => c.fail(status_to_error(status), 0),
    }
}

fn create(c: &mut Ctx) -> ApiResult {
    let (commit, start, parameter) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    match fiber::create(c.p, c.t, 0, commit, 0, start, parameter) {
        Ok(handle) => Flow::ret(handle),
        Err(status) => c.fail(status_to_error(status), 0),
    }
}

fn create_ex(c: &mut Ctx) -> ApiResult {
    let (commit, reserve, flags, start, parameter) =
        (c.ptr(0)?, c.ptr(1)?, c.u32(2)?, c.ptr(3)?, c.ptr(4)?);
    match fiber::create(c.p, c.t, reserve, commit, flags, start, parameter) {
        Ok(handle) => Flow::ret(handle),
        Err(status) => c.fail(status_to_error(status), 0),
    }
}

fn switch(c: &mut Ctx) -> ApiResult {
    let target = c.ptr(0)?;
    if c.t.fls_exiting {
        return Err(c.unsupported("fiber switching during final FLS exit cleanup"));
    }
    if let Err(status) = fiber::validate_switch(c.p, c.t, target) {
        // Invalid/self/active target behavior is not a native exception oracle.
        return Err(ApiErr::Internal(format!(
            "SwitchToFiber: target {target:#x} rejected with {status:#010x}"
        )));
    }
    Ok(Flow::SwitchFiber(target))
}

fn delete(c: &mut Ctx) -> ApiResult {
    let handle = c.ptr(0)?;
    let current = fiber::begin_delete(c.p, c.t, handle).map_err(|status| {
        ApiErr::Internal(format!(
            "DeleteFiber: target {handle:#x} rejected with {status:#010x}"
        ))
    })?;
    if current {
        // Keep the active stack available to normal DLL/FLS exit stages.
        return Ok(Flow::ExitThread(0));
    }
    super::fls::cleanup(
        c,
        FlsKey::Fiber(handle),
        Box::new(move |c, _| {
            fiber::finish_delete(c.p, handle).map_err(|status| {
                ApiErr::Internal(format!("fiber resource release failed: {status:#010x}"))
            })?;
            Flow::void()
        }),
    )
}

fn is_fiber(c: &mut Ctx) -> ApiResult {
    Flow::bool(c.t.current_fiber.is_some())
}

static START: Api = Api {
    name: "RtlUserFiberStart",
    args: &[],
    conv: Conv::Custom,
    imp: start,
};

fn start(c: &mut Ctx) -> ApiResult {
    let (target, parameter) = fiber::start_info(c.p, c.t)
        .map_err(|status| ApiErr::Internal(format!("invalid fiber start: {status:#010x}")))?;
    Flow::call(target, vec![parameter], |_, _| Ok(Flow::ExitThread(0)))
}

/// A created fiber begins only when explicitly selected, without DLL_THREAD_ATTACH.
pub(crate) fn fiber_start(p: &mut Proc, t: &mut Thread) -> Outcome {
    let sp = t.cpu.sp();
    let site = CallSite {
        api: &START,
        entry_pc: p.traps.fiber_start(),
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp.saturating_sub(32) & !15,
        framed: false,
    };
    dispatch::run(p, t, site, start)
}
