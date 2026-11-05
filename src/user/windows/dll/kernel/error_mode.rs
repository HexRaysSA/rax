//! Builtin exports share process state with installed NT query/set services.
use crate::user::windows::hle::{ApiResult, Ctx, Flow};

pub(super) fn get(c: &mut Ctx) -> ApiResult {
    Flow::ret(u64::from(c.p.error_mode.public()))
}

pub(super) fn set(c: &mut Ctx) -> ApiResult {
    let mode = c.u32(0)?;
    Flow::ret(u64::from(c.p.error_mode.set_public(mode)))
}
