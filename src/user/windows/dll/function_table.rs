//! Dynamic function-table registration for 64-bit structured exception handling.

use super::super::hle::{ApiResult, Archs, Arg::*, Conv::Stdcall, Ctx, Export, Flow};
use super::super::seh::dynamic;

pub(super) static EXPORTS: &[Export] = &[
    Export::func(
        "RtlAddFunctionTable",
        Stdcall,
        &[Ptr, I32, Ptr],
        add_function_table,
    )
    .only(Archs::WIN64),
    Export::func(
        "RtlDeleteFunctionTable",
        Stdcall,
        &[Ptr],
        delete_function_table,
    )
    .only(Archs::WIN64),
];

fn add_function_table(c: &mut Ctx) -> ApiResult {
    let (pointer, count, base) = (c.ptr(0)?, c.u32(1)?, c.ptr(2)?);
    Flow::bool(dynamic::register(c.p, pointer, count, base)?)
}

fn delete_function_table(c: &mut Ctx) -> ApiResult {
    let pointer = c.ptr(0)?;
    Flow::bool(dynamic::delete(c.p, pointer))
}
