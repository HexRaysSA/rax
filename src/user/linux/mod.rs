//! Linux personality: runs Linux user-space programs.
//!
//! The personality implements the Linux 6.19 system-call ABI for x86-64,
//! AArch64, and RV64 guests on a Unix host. Guest programs are loaded as
//! `binfmt_elf` would load them (with address-space randomization disabled),
//! execute on RAX's CPU cores in user mode, and have their system calls
//! serviced against the host: files and directories map to host files
//! (optionally overlaid by a guest sysroot), time comes from host clocks,
//! and memory management operates on the emulated address space.
//!
//! | Module | Owns |
//! |---|---|
//! | [`abi`] | Per-ABI numbering, constants, and structure layouts |
//! | [`arch`] | Per-ISA register conventions and exception-to-signal mapping |
//! | [`loader`] | `execve` image loading |
//! | [`stack`] | Initial stack and auxiliary vector |
//! | [`fs`] | Guest paths, the sysroot overlay, open files, descriptors |
//! | [`procfs`] | Synthesized `/proc` and `/sys` entries |
//! | [`process`] | Processes, threads, and the execution loop |
//! | [`syscall`] | System-call dispatch and handlers |
//! | [`signal`] | Signal numbers and signal records |
//! | [`host`] | The host services `std` does not expose |

pub mod abi;
pub mod arch;
pub mod fs;
pub mod host;
pub mod loader;
pub mod process;
pub mod procfs;
pub mod signal;
pub mod stack;
pub mod syscall;

#[cfg(test)]
mod tests;

pub use process::{ExitStatus, LinuxConfig, LinuxProcess, SpawnError};
