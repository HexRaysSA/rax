use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::nt::error::ERROR_INVALID_PARAMETER;
use crate::user::windows::nt::status::STATUS_INVALID_PARAMETER;
use crate::user::windows::sync::{self, SyncError, Wait};

pub(super) fn initialize(c: &mut Ctx) -> ApiResult {
    let addr = c.ptr(0)?;
    sync::cs_init(c.p, addr, 0)?;
    Flow::void()
}

pub(super) fn initialize_spin(c: &mut Ctx) -> ApiResult {
    let (addr, spin) = (c.ptr(0)?, c.u32(1)?);
    sync::cs_init(c.p, addr, spin.into())?;
    Flow::bool(true)
}

pub(super) fn initialize_ex(c: &mut Ctx) -> ApiResult {
    let (addr, spin, flags) = (c.ptr(0)?, c.u32(1)?, c.u32(2)?);
    if flags != 0 && flags != 0x0100_0000 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    sync::cs_init(c.p, addr, spin.into())?;
    Flow::bool(true)
}

pub(super) fn delete(c: &mut Ctx) -> ApiResult {
    let addr = c.ptr(0)?;
    sync::cs_delete(c.p, addr)?;
    Flow::void()
}

pub(super) fn enter(c: &mut Ctx) -> ApiResult {
    enter_with_result(c, Flow::void)
}

fn enter_with_result(c: &mut Ctx, success: fn() -> ApiResult) -> ApiResult {
    let addr = c.ptr(0)?;
    if sync::cs_try_enter(c.p, addr, c.t.tid)? {
        return success();
    }
    Ok(Flow::Block {
        wait: Wait::CritSec { addr },
        then: Box::new(move |_, _| success()),
    })
}

pub(super) fn rtl_initialize(c: &mut Ctx) -> ApiResult {
    initialize(c)?;
    Flow::ret(0)
}

pub(super) fn rtl_initialize_spin(c: &mut Ctx) -> ApiResult {
    initialize_spin(c)?;
    Flow::ret(0)
}

pub(super) fn rtl_initialize_ex(c: &mut Ctx) -> ApiResult {
    let (addr, spin, flags) = (c.ptr(0)?, c.u32(1)?, c.u32(2)?);
    if flags != 0 && flags != 0x0100_0000 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    sync::cs_init(c.p, addr, spin.into())?;
    Flow::ret(0)
}

pub(super) fn rtl_delete(c: &mut Ctx) -> ApiResult {
    delete(c)?;
    Flow::ret(0)
}

pub(super) fn rtl_enter(c: &mut Ctx) -> ApiResult {
    enter_with_result(c, || Flow::ret(0))
}

pub(super) fn rtl_leave(c: &mut Ctx) -> ApiResult {
    leave(c)?;
    Flow::ret(0)
}

pub(super) fn try_enter(c: &mut Ctx) -> ApiResult {
    let addr = c.ptr(0)?;
    Flow::bool(sync::cs_try_enter(c.p, addr, c.t.tid)?)
}

pub(super) fn leave(c: &mut Ctx) -> ApiResult {
    let addr = c.ptr(0)?;
    if !sync::cs_leave(c.p, addr, c.t.tid)? {
        return Err(SyncError::Invalid("critical-section release by non-owner").into());
    }
    Flow::void()
}

pub(super) fn spin(c: &mut Ctx) -> ApiResult {
    let (addr, spin) = (c.ptr(0)?, c.u32(1)?);
    Flow::ret(sync::cs_spin(c.p, addr, spin.into())?)
}
