//! Windows process emulation for PE32 x86 and PE32+ x64/ARM64 images.
//!
//! Guest instructions execute in the existing unprivileged ISA adapters.
//! The personality supplies process memory, loader state, threads, and DLL
//! services through checked guest-memory accesses.

mod appcompat;
pub mod arch;
pub mod context;
pub mod dll;
pub mod fs;
pub(crate) mod gui;
pub mod heap;
pub mod hle;
pub mod layout;
pub mod loader;
mod mapped_filename;
pub mod memory;
pub(crate) mod native;
mod nls;
pub mod nt;
pub mod object_namespace;
pub mod objects;
mod performance_clock;
pub mod process;
pub mod registry;
mod security;
pub mod seh;
pub mod sync;
mod system_time;
pub mod tls;
pub mod traps;
mod wnf;

pub use arch::WinArch;
pub use process::{ExitStatus, SpawnError, WinVersion, WindowsConfig, WindowsProcess};
