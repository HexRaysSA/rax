//! Windows CRT allocation, error, memory/string and initializer services.

mod allocation;
mod initialize;
mod invalid;
mod memory;
pub(crate) mod onexit;
pub(crate) mod startup;
mod state;
pub(crate) mod stdio;
mod strings;
pub(crate) mod termination;

#[cfg(test)]
mod tests;

use std::collections::HashMap;

use super::super::hle::{ApiErr, Ctx};
use super::super::loader::ModuleKind;

pub(crate) use allocation::ALLOCATION_EXPORTS;
pub(crate) use initialize::{INIT_EXPORTS, MSVCRT_INIT_EXPORTS, UCRT_INIT_EXPORTS};
pub(crate) use memory::{MEMORY_EXPORTS, VCRUNTIME_MEMORY_EXPORTS};
pub(crate) use onexit::UCRT_ONEXIT_EXPORTS;
pub(crate) use startup::{MSVCRT_STARTUP_EXPORTS, UCRT_STARTUP_EXPORTS};
pub(crate) use state::{STATE_EXPORTS, UCRT_STATE_EXPORTS, release_thread};
pub(crate) use stdio::{MSVCRT_STDIO_EXPORTS, STDIO_EXPORTS, UCRT_STDIO_EXPORTS};
pub(crate) use strings::{STRING_EXPORTS, UCRT_STRING_EXPORTS, VCRUNTIME_STRING_EXPORTS};
pub(crate) use termination::{
    UCRT_EXIT_EXPORTS, UCRT_FATAL_EXPORTS, UCRT_REGISTRATION_EXPORTS, UCRT_SIGNAL_EXPORTS,
};

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
    startup: Option<startup::StartupState>,
    /// FILE/descriptor ownership is separate from malloc and onexit tables.
    stdio: Option<stdio::StdioState>,
    argv_modes: [Option<i32>; 2],
    /// Both vectors share one architectural C int count. Reusing an inactive
    /// width must not pair its vector with the other width's count.
    argv_active: Option<usize>,
    /// No new-handler registration export is admitted yet. With the primary
    /// documented default of no handler, mode 1 retains ordinary OOM behavior.
    new_mode: u32,
    /// Explicit tables own detached callback generations independently of
    /// process-global CRT exit and ordinary caller allocations.
    onexit: onexit::OnExitState,
    /// Genuine UCRT global registries are not DLL startup's explicit tables.
    termination: termination::TerminationState,
    /// Dynamic cleanup state is independent of the OS process-exit lifecycle.
    exit: termination::ExitState,
    /// Global software signal actions: SIGABRT (including alias 6), SIGTERM.
    signals: [u64; 2],
    /// Registration and table execution share a recursive runtime exit lock.
    exit_lock: termination::ExitLockState,
}

struct ThreadState {
    /// Two guest-authoritative 32-bit cells: errno and _doserrno.
    cells: u64,
    invalid_handler: u64,
    terminate_handler: u64,
}

/// State whose lifetime is the guest process.
///
/// Construct through [`Default`]. The public compatibility fields/path remain,
/// but the private runtime ledger makes the former two-field struct literal
/// unavailable; no tracked consumer uses that construction form.
#[derive(Default)]
pub struct CrtState {
    /// Dormant compatibility field; global queues are runtime-private.
    pub atexit: Vec<u64>,
    /// Dormant compatibility field, not the runtime's thread-local errno.
    pub errno: u64,
    runtimes: [RuntimeState; 2],
}
