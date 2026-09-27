//! Lazy, reentrant guest constructor-table traversal.
//!
//! Tables are end-exclusive arrays of guest pointers. Each continuation owns
//! just its current cursor and endpoint; callbacks may change later entries,
//! nest initializer calls, or abandon the call through guest exception/unwind
//! machinery without leaving a process-global traversal cursor behind.

use crate::user::windows::hle::{
    ApiErr, ApiResult, Archs, Arg::Ptr, Conv::Cdecl, Ctx, Export, Flow,
};
use crate::user::windows::memory::MemFault;

pub(crate) static INIT_EXPORTS: &[Export] =
    &[Export::func("_initterm", Cdecl, &[Ptr, Ptr], initialize)];

// The primary MSVCRT DEF declares this import on ARM, while the x86/x64
// archives supply only local compatibility members. Preserve that asymmetry.
pub(crate) static MSVCRT_INIT_EXPORTS: &[Export] =
    &[Export::func("_initterm_e", Cdecl, &[Ptr, Ptr], initialize_e).only(Archs::ARM64)];

pub(crate) static UCRT_INIT_EXPORTS: &[Export] = &[Export::func(
    "_initterm_e",
    Cdecl,
    &[Ptr, Ptr],
    initialize_e,
)];

fn advance(c: &Ctx, cursor: u64) -> Result<u64, ApiErr> {
    cursor
        .checked_add(c.psize())
        .filter(|&next| c.arch().ptr(next) == next)
        .ok_or_else(|| {
            MemFault {
                addr: cursor,
                write: false,
            }
            .into()
        })
}

/// O(N) pointer reads, O(1) host auxiliary space per invocation. No whole-table
/// preflight or snapshot: a later fault must not suppress earlier callbacks.
fn walk(c: &mut Ctx, mut cursor: u64, end: u64, fallible: bool) -> ApiResult {
    while cursor < end {
        let target = match c.read_ptr(cursor) {
            Ok(target) => target,
            Err(fault) => {
                return Ok(Flow::RetryFault {
                    fault,
                    retry: Box::new(move |c, _| walk(c, cursor, end, fallible)),
                });
            }
        };
        if target != 0 {
            return Flow::call(target, Vec::new(), move |c, result| {
                // C int occupies exactly 32 bits on all admitted Windows ABIs.
                // Test before advancing: no later slot is read on failure.
                if fallible && result as u32 != 0 {
                    return Flow::ret(u64::from(result as u32));
                }
                let next = advance(c, cursor)?;
                walk(c, next, end, fallible)
            });
        }
        cursor = advance(c, cursor)?;
    }
    if fallible { Flow::ret(0) } else { Flow::void() }
}

pub(super) fn initialize(c: &mut Ctx) -> ApiResult {
    let first = c.arg(0)?;
    let end = c.arg(1)?;
    walk(c, first, end, false)
}

pub(super) fn initialize_e(c: &mut Ctx) -> ApiResult {
    let first = c.arg(0)?;
    let end = c.arg(1)?;
    walk(c, first, end, true)
}

#[cfg(test)]
#[path = "initialize_tests.rs"]
mod tests;
