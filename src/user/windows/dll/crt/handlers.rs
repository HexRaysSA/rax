//! CRT queries about handlers a guest could install, answered from what this
//! runtime lets it install.
//!
//! `_seh_filter_exe` is the exception filter `__scrt_common_main_seh` wraps
//! `main` in: it maps an exception to the CRT signal action for its class and
//! returns `EXCEPTION_CONTINUE_SEARCH` when that action is the default. Valid
//! actions for the exception-class signals (SIGSEGV, SIGILL, SIGFPE, and the
//! console signals) are an unsupported frontier in this runtime — `signal`
//! refuses to install them — so every action is the default and the answer is
//! exact. It never dereferences its `EXCEPTION_POINTERS` argument, because the
//! default path does not need it.
//!
//! `_callnewh` calls the C++ new handler and reports whether one ran.
//! `_set_new_handler` is deliberately not exported, so no handler can exist
//! and the answer is always that none ran.

use crate::user::windows::hle::{ApiResult, Arg::*, Conv::Cdecl, Ctx, Export, Flow};

/// ucrtbase only: msvcrt.dll exports the older `_XcptFilter` instead.
pub(crate) static UCRT_EXCEPTION_FILTER_EXPORTS: &[Export] = &[Export::func(
    "_seh_filter_exe",
    Cdecl,
    &[I32, Ptr],
    seh_filter_exe,
)];

/// Both runtimes export `_callnewh`.
pub(crate) static NEW_HANDLER_EXPORTS: &[Export] =
    &[Export::func("_callnewh", Cdecl, &[Ptr], call_new_handler)];

const EXCEPTION_CONTINUE_SEARCH: u64 = 0;

fn seh_filter_exe(_: &mut Ctx) -> ApiResult {
    Flow::ret(EXCEPTION_CONTINUE_SEARCH)
}

fn call_new_handler(_: &mut Ctx) -> ApiResult {
    Flow::ret(0)
}
