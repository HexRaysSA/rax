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
//! | [`loader`] | ELF image loading |
//! | [`exec`] | Program images and the `execve` point of no return |
//! | [`stack`] | Initial stack and auxiliary vector |
//! | [`fs`] | Guest paths, the sysroot overlay, open files, descriptors |
//! | [`procfs`] | Synthesized `/proc` and `/sys` entries |
//! | [`process`] | Processes and threads |
//! | [`sched`] | Running threads on the one emulated CPU |
//! | [`syscall`] | System-call dispatch and handlers |
//! | [`signal`] | Signals: records, queues, frames, delivery |
//! | [`futex`] | Futex wait queues, PI ownership, robust lists |
//! | [`children`] | Child processes and their status records |
//! | [`timers`] | Interval timers |
//! | [`wait`] | Sleeping in system calls on descriptors, deadlines, and signals |
//! | [`host`] | The host services `std` does not expose |

pub mod abi;
pub mod arch;
pub mod children;
pub mod exec;
pub mod fs;
pub mod futex;
pub mod host;
pub mod loader;
pub mod process;
pub mod procfs;
pub mod sched;
pub mod signal;
pub mod stack;
pub mod syscall;
pub mod timers;
pub mod wait;

#[cfg(test)]
mod tests;

pub use process::{ExitStatus, LinuxConfig, LinuxProcess, SpawnError};
