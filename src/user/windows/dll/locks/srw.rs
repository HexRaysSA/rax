use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::sync::{self, Wait};

pub(super) fn initialize(c: &mut Ctx) -> ApiResult {
    let addr = c.ptr(0)?;
    sync::srw_init(c.p, addr)?;
    Flow::void()
}

fn acquire(c: &mut Ctx, exclusive: bool, attempt: bool) -> ApiResult {
    let addr = c.ptr(0)?;
    let acquired = sync::srw_try(c.p, addr, c.t.tid, exclusive)?;
    if attempt {
        return Flow::bool(acquired);
    }
    if acquired {
        return Flow::void();
    }
    Ok(Flow::Block {
        wait: Wait::Srw { addr, exclusive },
        then: Box::new(|_, _| Flow::void()),
    })
}

pub(super) fn acquire_exclusive(c: &mut Ctx) -> ApiResult {
    acquire(c, true, false)
}
pub(super) fn acquire_shared(c: &mut Ctx) -> ApiResult {
    acquire(c, false, false)
}
pub(super) fn try_exclusive(c: &mut Ctx) -> ApiResult {
    acquire(c, true, true)
}
pub(super) fn try_shared(c: &mut Ctx) -> ApiResult {
    acquire(c, false, true)
}
fn release(c: &mut Ctx, exclusive: bool) -> ApiResult {
    let addr = c.ptr(0)?;
    sync::srw_release(c.p, addr, c.t.tid, exclusive)?;
    Flow::void()
}
pub(super) fn release_exclusive(c: &mut Ctx) -> ApiResult {
    release(c, true)
}
pub(super) fn release_shared(c: &mut Ctx) -> ApiResult {
    release(c, false)
}
