//! Source-version UCRT startup policy and architecture-specific FP reset.
//!
//! Reference/member/body receipts: docs/specifications/windows/crt-bootstrap/.
//! Locale/NLS and math-error delivery are separate consumers, not no-op aliases.

mod fp;
mod locale;
mod policy;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod fp_tests;

use crate::user::windows::hle::{ApiErr, ApiResult, Arg::*, Cont, Conv::Cdecl, Ctx, Export, Flow};
use crate::user::windows::nt::status::STATUS_NO_MEMORY;

use super::{RuntimeKind, runtime, state, termination};

pub(super) struct BootstrapState {
    pub(super) app_type: u32,
    /// SDK __globallocalestatus; -1 disables global-to-PTD synchronization.
    pub(super) global_locale_status: u32,
    /// Logical callback identity. Opaque publisher pointer-cookie encoding
    /// is not an exposed guest object in this personality.
    pub(super) math_handler: u64,
}

impl Default for BootstrapState {
    fn default() -> Self {
        Self {
            app_type: 0,
            global_locale_status: !1,
            math_handler: 0,
        }
    }
}

pub(crate) static UCRT_BOOTSTRAP_EXPORTS: &[Export] = &[
    Export::func("_set_app_type", Cdecl, &[I32], policy::set_app_type),
    Export::func("_query_app_type", Cdecl, &[], policy::query_app_type),
    Export::func("__setusermatherr", Cdecl, &[Ptr], policy::set_math_handler),
    Export::func("_configthreadlocale", Cdecl, &[I32], locale::configure),
    Export::func("_fpreset", Cdecl, &[], fp::reset),
    Export::func("__pxcptinfoptrs", Cdecl, &[], exception_slot),
];

/// getptd-backed APIs abort on PTD establishment OOM, unlike callers that
/// deliberately use getptd_noexit. Captured API requests survive setup faults.
fn with_ptd(c: &mut Ctx, kind: RuntimeKind, then: Cont) -> ApiResult {
    match state::ensure_context(c, kind) {
        Ok(cells) => then(c, cells),
        Err(ApiErr::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| with_ptd(c, kind, then)),
        }),
        Err(ApiErr::Raise(record)) if record.code == STATUS_NO_MEMORY => {
            termination::abort_runtime(c, kind)
        }
        Err(error) => Err(error),
    }
}

fn exception_slot(c: &mut Ctx) -> ApiResult {
    with_ptd(c, runtime(c)?, Box::new(|_, cells| Flow::ret(cells + 8)))
}
