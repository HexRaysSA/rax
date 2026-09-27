use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::nt::error::ERROR_INVALID_PARAMETER;
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
    let addr = c.ptr(0)?;
    if sync::cs_try_enter(c.p, addr, c.t.tid)? {
        return Flow::void();
    }
    Ok(Flow::Block {
        wait: Wait::CritSec { addr },
        then: Box::new(|_, _| Flow::void()),
    })
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
