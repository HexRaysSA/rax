//! Windows CRT allocation, error, memory/string and initializer services.

mod allocation;
mod bootstrap;
mod handlers;
mod initialize;
mod invalid;
mod kernel_onexit;
mod legacy_onexit;
mod math;
mod memory;
pub(crate) mod onexit;
mod random;
pub(crate) mod startup;
mod state;
pub(crate) mod stdio;
mod strings;
pub(crate) mod termination;
mod time;

#[cfg(test)]
mod tests;

use std::collections::HashMap;

use super::super::hle::{ApiErr, Ctx, Export};
use super::super::loader::ModuleKind;

pub(crate) use allocation::{
    ALLOCATION_EXPORTS, UCRT_ALIGNED_ALLOCATION_EXPORTS, UCRT_RTTI_CLEANUP_EXPORTS,
};

pub(super) static UCRT_BASE_ALLOCATION_FORWARDS: &[Export] = &[
    Export::forward("_calloc_base", "ucrtbase.calloc"),
    Export::forward("_free_base", "ucrtbase.free"),
    Export::forward("_malloc_base", "ucrtbase.malloc"),
    Export::forward("_realloc_base", "ucrtbase.realloc"),
];
pub(crate) use bootstrap::{UCRT_BOOTSTRAP_EXPORTS, UCRT_LOCALE_EXPORTS};
pub(crate) use handlers::{NEW_HANDLER_EXPORTS, UCRT_EXCEPTION_FILTER_EXPORTS};
pub(crate) use initialize::{INIT_EXPORTS, MSVCRT_INIT_EXPORTS, UCRT_INIT_EXPORTS};
pub(crate) use legacy_onexit::MSVCRT_ONEXIT_EXPORTS;
pub(crate) use math::{UCRT_MATH_EXPORTS, UCRT_SCALAR_MATH_EXPORTS};
pub(crate) use memory::{MEMORY_EXPORTS, VCRUNTIME_MEMORY_EXPORTS};
pub(crate) use onexit::UCRT_ONEXIT_EXPORTS;
pub(crate) use random::UCRT_RANDOM_EXPORTS;
pub(crate) use startup::{MSVCRT_STARTUP_EXPORTS, UCRT_STARTUP_EXPORTS};
pub(crate) use state::{STATE_EXPORTS, UCRT_STATE_EXPORTS, release_thread};
pub(crate) use stdio::{
    MSVCRT_STDIO_EXPORTS, MSVCRT_WIDE_BUFFER_FORMAT_EXPORTS, STDIO_EXPORTS,
    UCRT_BUFFER_FORMAT_EXPORTS, UCRT_SECURE_BUFFER_FORMAT_EXPORTS, UCRT_STDIO_EXPORTS,
    UCRT_STREAM_BUFFER_EXPORTS, UCRT_WIDE_BUFFER_FORMAT_EXPORTS,
};
pub(crate) use strings::{
    NTDLL_STRING_EXPORTS, STRING_EXPORTS, UCRT_CASE_STRING_EXPORTS, UCRT_SECURE_COPY_EXPORTS,
    UCRT_SECURE_STRING_EXPORTS, UCRT_STRING_EXPORTS, VCRUNTIME_STRING_EXPORTS,
};
pub(crate) use termination::{
    UCRT_EXIT_EXPORTS, UCRT_FATAL_EXPORTS, UCRT_REGISTRATION_EXPORTS, UCRT_SIGNAL_EXPORTS,
};
pub(crate) use time::{KERNELBASE_TIME_FORWARDS, UCRT_TIME_EXPORTS};

// The portable UCRT has one guest-owned runtime state. Its private system
// entry points reach the same state as the corresponding public entries.
pub(super) static UCRT_PRIVATE_FORWARDS: &[Export] = &[
    Export::forward(
        "_o__initialize_onexit_table",
        "ucrtbase._initialize_onexit_table",
    ),
    Export::forward("_o__execute_onexit_table", "ucrtbase._execute_onexit_table"),
    Export::forward(
        "_o__configure_narrow_argv",
        "ucrtbase._configure_narrow_argv",
    ),
    Export::forward(
        "_o__initialize_narrow_environment",
        "ucrtbase._initialize_narrow_environment",
    ),
    Export::forward("_o__cexit", "ucrtbase._cexit"),
    Export::forward("_o__errno", "ucrtbase._errno"),
    Export::forward(
        "_o__invalid_parameter_noinfo",
        "ucrtbase._invalid_parameter_noinfo",
    ),
    Export::forward(
        "_o__register_onexit_function",
        "ucrtbase._register_onexit_function",
    ),
    Export::forward("_o___acrt_iob_func", "ucrtbase.__acrt_iob_func"),
    Export::forward("_o_malloc", "ucrtbase.malloc"),
    Export::forward("_o_free", "ucrtbase.free"),
    Export::forward("_o__crt_atexit", "ucrtbase._crt_atexit"),
    Export::forward("_o____mb_cur_max_func", "ucrtbase.___mb_cur_max_func"),
    Export::forward(
        "_o____lc_locale_name_func",
        "ucrtbase.___lc_locale_name_func",
    ),
    Export::forward("_o____lc_collate_cp_func", "ucrtbase.___lc_collate_cp_func"),
    Export::forward("_o____lc_codepage_func", "ucrtbase.___lc_codepage_func"),
    Export::forward("_o_setlocale", "ucrtbase.setlocale"),
    Export::forward("_o___pctype_func", "ucrtbase.__pctype_func"),
    Export::forward(
        "_o__get_stream_buffer_pointers",
        "ucrtbase._get_stream_buffer_pointers",
    ),
    Export::forward("_o__wcsdup", "ucrtbase._wcsdup"),
    Export::forward("_o__calloc_base", "ucrtbase.calloc"),
    Export::forward("_o__free_base", "ucrtbase.free"),
    Export::forward("_o__malloc_base", "ucrtbase.malloc"),
    Export::forward("_o__realloc_base", "ucrtbase.realloc"),
    Export::forward("_o_calloc", "ucrtbase.calloc"),
    Export::forward("_o_wcscat_s", "ucrtbase.wcscat_s"),
];

// The system KernelBase also exports these stateless CRT table walkers.
pub(super) static KERNELBASE_INIT_FORWARDS: &[Export] = &[
    Export::forward("_initterm", "ucrtbase._initterm"),
    Export::forward("_initterm_e", "ucrtbase._initterm_e"),
];

pub(super) use kernel_onexit::KERNELBASE_ONEXIT_EXPORTS;

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
    /// An aligned guest pointer maps back to its allocator-owned backing block.
    aligned_allocations: HashMap<u64, u64>,
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
    /// Version-selected startup policy, separate from argument construction.
    bootstrap: bootstrap::BootstrapState,
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
    legacy_locks: HashMap<usize, (u32, u32)>,
}

struct ThreadState {
    /// errno/_doserrno followed by a distinct guest-authoritative pointer slot.
    /// This allocation is not a public native PTD layout.
    cells: u64,
    invalid_handler: u64,
    terminate_handler: u64,
    /// SDK _own_locale: GLOBAL bit initially set, PER_THREAD bit initially clear.
    locale_flags: u32,
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
