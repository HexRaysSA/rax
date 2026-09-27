//! Windows processes.
//!
//! [`WindowsProcess::spawn`] does what `CreateProcess` and the loader do
//! before the first instruction of a new process: it maps the executable
//! and its DLLs, builds `KUSER_SHARED_DATA`, the PEB, the process
//! parameters and environment, the loader's module lists, the process
//! heap, and the main thread's stack and TEB. [`WindowsProcess::run`]
//! executes the threads until the process ends: the main thread begins in
//! `ntdll!RtlUserThreadStart`, which runs the DLL and TLS initializers and
//! then the image's entry point.

pub(crate) mod fiber;
mod fls_exit;
mod lifecycle;
mod sched;
pub(crate) mod stack;
mod start;
pub(crate) mod thread;

pub use super::dll::libraries::LoaderState;
pub use fiber::FiberState;
pub use thread::{Thread, ThreadState};

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use super::arch::WinArch;
use super::dll::crt::CrtState;
use super::fs::DriveMap;
use super::heap::Heaps;
use super::loader::Modules;
use super::memory::VirtualMemory;
use super::objects::Objects;
use super::seh::SehState;
use super::sync::SyncState;
use super::tls::TlsState;
use super::traps::Traps;
use crate::user::mm::AddressSpace;

/// Guest instructions per bounded scheduling slice for every CPU adapter.
pub const DEFAULT_SLICE_INSNS: u64 = 1 << 20;
/// Default guest-memory arena: 16 GiB, committed as pages are touched.
pub const DEFAULT_ARENA_BYTES: u64 = 16 << 30;

/// The Windows version the process observes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WinVersion {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Build number.
    pub build: u32,
    /// `VER_NT_WORKSTATION` (1) or a server product type.
    pub product_type: u8,
}

impl Default for WinVersion {
    /// Windows 11 24H2 (10.0.26100), workstation.
    fn default() -> Self {
        WinVersion {
            major: 10,
            minor: 0,
            build: 26100,
            product_type: 1,
        }
    }
}

/// How to start a process.
#[derive(Clone, Debug)]
pub struct WindowsConfig {
    /// Host path of the executable.
    pub exe_host_path: PathBuf,
    /// Arguments after the program name.
    pub args: Vec<String>,
    /// The program name as it appears in the command line (default: the
    /// executable's Windows path).
    pub argv0: Option<String>,
    /// The complete command line, overriding `argv0` and `args`.
    pub command_line: Option<String>,
    /// Environment variables; `None` selects the default Windows
    /// environment ([`WindowsConfig::default_environment`]).
    pub env: Option<Vec<(String, String)>>,
    /// Variables added to (or replacing ones in) the environment.
    pub env_overrides: Vec<(String, String)>,
    /// Guest current directory as a Windows path (default: the host
    /// current directory through the drive map).
    pub cwd: Option<String>,
    /// Drive letters and the host directories they map to.
    pub drives: DriveMap,
    /// Additional host directories searched for DLLs after the
    /// application directory.
    pub dll_paths: Vec<PathBuf>,
    /// Guest-memory arena size in bytes.
    pub arena_bytes: u64,
    /// Guest instructions per bounded scheduling slice.
    pub slice_insns: u64,
    /// Log every built-in function call to standard error.
    pub trace: bool,
    /// Seed for the personality's pseudo-random state and security cookies;
    /// `None` initializes that state from host entropy.
    pub seed: Option<u64>,
    /// Reported Windows version.
    pub version: WinVersion,
    /// `GetComputerName`.
    pub computer_name: String,
    /// `GetUserName`.
    pub user_name: String,
}

impl WindowsConfig {
    /// A configuration for the executable at `exe` with `args`.
    pub fn new(exe: impl Into<PathBuf>, args: Vec<String>) -> Self {
        WindowsConfig {
            exe_host_path: exe.into(),
            args,
            argv0: None,
            command_line: None,
            env: None,
            env_overrides: Vec::new(),
            cwd: None,
            drives: DriveMap::default(),
            dll_paths: Vec::new(),
            arena_bytes: DEFAULT_ARENA_BYTES,
            slice_insns: DEFAULT_SLICE_INSNS,
            trace: false,
            seed: None,
            version: WinVersion::default(),
            computer_name: "RAX".into(),
            user_name: "user".into(),
        }
    }
}

/// How a process ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    /// The process exited with this code (`ExitProcess`, the last thread's
    /// exit, or an unhandled exception's code).
    Exited(u32),
    /// The emulator could not continue.
    Internal(String),
}

impl ExitStatus {
    /// The status a Unix shell reports: the low 8 bits of the exit code,
    /// or 125 for an emulator failure.
    pub fn shell_code(&self) -> i32 {
        match self {
            ExitStatus::Exited(code) => (*code & 0xFF) as i32,
            ExitStatus::Internal(_) => 125,
        }
    }
}

impl std::fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExitStatus::Exited(code) => match super::seh::exception_name(*code) {
                Some(name) => write!(f, "exited with status {code:#010x} ({name})"),
                None => write!(f, "exited with status {code} ({code:#x})"),
            },
            ExitStatus::Internal(e) => write!(f, "emulator failure: {e}"),
        }
    }
}

/// Why a process could not start.
#[derive(Debug)]
pub enum SpawnError {
    /// The executable could not be read.
    Io(std::io::Error),
    /// The file is not a PE image this personality can run.
    BadImage(String),
    /// Loading failed with an `NTSTATUS` (a missing DLL or export, an
    /// invalid image) and a description.
    Load {
        /// The status `CreateProcess` or the loader reports.
        status: u32,
        /// What failed.
        message: String,
    },
    /// The guest address space could not be built.
    Memory(String),
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpawnError::Io(e) => write!(f, "{e}"),
            SpawnError::BadImage(e) => write!(f, "{e}"),
            SpawnError::Load { status, message } => write!(f, "{message} (status {status:#010x})"),
            SpawnError::Memory(e) => write!(f, "cannot build the address space: {e}"),
        }
    }
}

impl std::error::Error for SpawnError {}

impl SpawnError {
    /// The exit code Windows reports for a process that failed to start
    /// (the loader's status, e.g. `STATUS_DLL_NOT_FOUND`), or 126.
    pub fn exit_code(&self) -> u32 {
        match self {
            SpawnError::Load { status, .. } => *status,
            _ => 126,
        }
    }
}

/// Process-wide state that built-in functions operate on.
pub struct Proc {
    /// Architecture.
    pub arch: WinArch,
    /// The address space.
    pub space: AddressSpace,
    /// Allocation state of the address space.
    pub vm: VirtualMemory,
    /// Configuration.
    pub cfg: Arc<WindowsConfig>,
    /// Process identifier.
    pub pid: u32,
    /// The PEB.
    pub peb: u64,
    /// `RTL_USER_PROCESS_PARAMETERS`.
    pub params: u64,
    /// The process heap handle.
    pub process_heap: u64,
    /// Loaded modules.
    pub modules: Modules,
    /// Reentrant DLL-entrypoint serialization and normal-exit lifecycle stages.
    pub loader: LoaderState,
    /// Fiber execution contexts and their host-owned stack/object ledgers.
    pub fibers: FiberState,
    /// Trap slots of built-in DLLs.
    pub traps: Traps,
    /// Kernel objects and the handle table.
    pub objects: Objects,
    /// Heaps.
    pub heaps: Heaps,
    /// TLS and FLS slot allocation.
    pub tls: TlsState,
    /// Exception-dispatch state (vectored handlers, unhandled filter).
    pub seh: SehState,
    /// Address-keyed synchronization (critical sections, SRW locks,
    /// condition variables, `WaitOnAddress`).
    pub sync: SyncState,
    /// C runtime state.
    pub crt: CrtState,
    /// Threads other than the one currently executing built-in code.
    pub threads: BTreeMap<u32, Thread>,
    /// Next thread identifier.
    pub next_tid: u32,
    /// Set when the process is ending: the exit code.
    pub exit_code: Option<u32>,
    /// Set when the emulator cannot continue.
    pub failure: Option<String>,
    /// Process start time.
    pub start_time: Instant,
    /// Deterministic pseudo-random state.
    pub rng: u64,
    /// Current directory (Windows path, with a trailing backslash).
    pub cwd: Vec<u16>,
    /// The executable's `SizeOfStackReserve` (the default thread stack).
    pub exe_stack_reserve: u64,
    /// The executable's `SizeOfStackCommit` (default fiber commitment).
    pub exe_stack_commit: u64,
}

impl Proc {
    /// A new thread identifier (multiples of 4, as Windows allocates
    /// client IDs from its handle table).
    pub fn alloc_tid(&mut self) -> u32 {
        let t = self.next_tid;
        self.next_tid += 4;
        t
    }

    /// The next pseudo-random 64-bit value (SplitMix64).
    pub fn random(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Records an emulator failure; the process ends.
    pub fn fail(&mut self, message: impl Into<String>) {
        if self.failure.is_none() {
            self.failure = Some(message.into());
        }
    }

    /// Milliseconds since process start.
    pub fn uptime_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }
}

/// A running Windows process.
pub struct WindowsProcess {
    proc: Proc,
}

impl WindowsProcess {
    /// Creates the process for `config`.
    pub fn spawn(config: WindowsConfig) -> Result<Self, SpawnError> {
        start::spawn(config).map(|proc| WindowsProcess { proc })
    }

    /// Starts from supplied executable bytes while retaining the configured
    /// host path for DLL search and guest process parameters.
    pub fn spawn_image(config: WindowsConfig, bytes: Vec<u8>) -> Result<Self, SpawnError> {
        start::spawn_image(config, bytes).map(|proc| WindowsProcess { proc })
    }

    /// The architecture.
    pub fn arch(&self) -> WinArch {
        self.proc.arch
    }

    /// Runs the process to completion. Embedders must not mutate mappings
    /// through a retained address-space clone concurrently with execution;
    /// see [`crate::user::mm::AddressSpace`]'s concurrency contract.
    pub fn run(&mut self) -> ExitStatus {
        sched::run(&mut self.proc)
    }

    /// Process state (for tests and embedders). Retained address-space clones
    /// remain subject to the no-concurrent-mapping-change contract of `run`.
    pub fn state(&self) -> &Proc {
        &self.proc
    }

    /// Mutable process state.
    pub fn state_mut(&mut self) -> &mut Proc {
        &mut self.proc
    }
}
