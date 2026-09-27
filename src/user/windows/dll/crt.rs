//! Windows CRT allocation, error, memory/string and initializer services.

mod allocation;
mod initialize;
mod invalid;
mod memory;
mod state;
mod strings;

#[cfg(test)]
mod tests;

use std::collections::HashMap;

use super::super::hle::{ApiErr, Ctx};
use super::super::loader::ModuleKind;

pub(crate) use allocation::ALLOCATION_EXPORTS;
pub(crate) use initialize::{INIT_EXPORTS, MSVCRT_INIT_EXPORTS, UCRT_INIT_EXPORTS};
pub(crate) use memory::{MEMORY_EXPORTS, VCRUNTIME_MEMORY_EXPORTS};
pub(crate) use state::{STATE_EXPORTS, UCRT_STATE_EXPORTS, release_thread};
pub(crate) use strings::{STRING_EXPORTS, UCRT_STRING_EXPORTS, VCRUNTIME_STRING_EXPORTS};

/// A runtime namespace; a module's trap address, not its caller, selects it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeKind {
    Msvcrt,
    Ucrt,
}

impl RuntimeKind {
    fn index(self) -> usize {
        match self {
            Self::Msvcrt => 0,
            Self::Ucrt => 1,
        }
    }
}

pub(super) fn runtime(c: &Ctx) -> Result<RuntimeKind, ApiErr> {
    match c.p.modules.by_address(c.entry_pc).map(|(_, m)| m.kind) {
        Some(ModuleKind::Builtin(dll)) if dll.name == "msvcrt.dll" => Ok(RuntimeKind::Msvcrt),
        Some(ModuleKind::Builtin(dll)) if dll.name == "ucrtbase.dll" => Ok(RuntimeKind::Ucrt),
        _ => Err(ApiErr::Internal(
            "CRT entry does not belong to a live runtime".into(),
        )),
    }
}

#[derive(Default)]
struct RuntimeState {
    heap: u64,
    /// Only ordinary CRT allocations, excluding its private thread cells.
    allocations: HashMap<u64, u64>,
    contexts: HashMap<u32, ThreadState>,
    invalid_handler: u64,
}

struct ThreadState {
    /// Two guest-authoritative 32-bit cells: errno and _doserrno.
    cells: u64,
    invalid_handler: u64,
}

/// State whose lifetime is the guest process.
///
/// Construct through [`Default`]. The public compatibility fields/path remain,
/// but the private runtime ledger makes the former two-field struct literal
/// unavailable; no tracked consumer uses that construction form.
#[derive(Default)]
pub struct CrtState {
    /// Dormant compatibility field; this group does not implement CRT exit.
    pub atexit: Vec<u64>,
    /// Dormant compatibility field, not the runtime's thread-local errno.
    pub errno: u64,
    runtimes: [RuntimeState; 2],
}
