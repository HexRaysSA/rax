//! `NtRaiseException`: dispatch the caller-supplied record and context.

use crate::user::windows::context::{ExceptionRecord, RegContext};
use crate::user::windows::hle::{ApiResult, Ctx, Flow};

pub(super) fn raise(c: &mut Ctx) -> ApiResult {
    let (record, context) = (c.ptr(0)?, c.ptr(1)?);
    let record = ExceptionRecord::read(&c.p.space, c.p.arch, record)?;
    // The context names the state the record was raised in, which is not
    // necessarily this export's caller (a dispatcher may re-raise an earlier
    // fault). The first-chance flag only selects debugger reporting.
    let context = RegContext::read(&c.p.space, c.p.arch, context)?;
    Ok(Flow::RaiseIn {
        record,
        context: Box::new(context),
    })
}
