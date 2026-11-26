//! Floating point helpers used by the built-in Universal CRT.

use crate::user::windows::hle::{ApiResult, Arg::F64, Conv::Cdecl, Ctx, Export, Flow};

pub(crate) static UCRT_MATH_EXPORTS: &[Export] = &[Export::func("_o_atan", Cdecl, &[F64], atan)];

fn atan(c: &mut Ctx) -> ApiResult {
    Flow::f64(c.f64(0)?.atan())
}
