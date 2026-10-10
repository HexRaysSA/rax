//! Windows process emulation for PE32 x86 and PE32+ x64/ARM64 images.
//!
//! Guest instructions execute in the existing unprivileged ISA adapters.
//! The personality supplies process memory, loader state, threads, and DLL
//! services through checked guest-memory accesses.

pub mod arch;
pub mod context;
pub mod dll;
pub mod fs;
pub mod heap;
pub mod hle;
pub mod layout;
pub mod loader;
pub mod memory;
pub(crate) mod native;
pub mod nt;
pub mod objects;
pub mod process;
pub mod seh;
pub mod sync;
pub mod tls;
pub mod traps;

pub use arch::WinArch;
pub use process::{ExitStatus, SpawnError, WinVersion, WindowsConfig, WindowsProcess};
