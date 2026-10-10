//! Darwin personality: runs macOS user-space programs.
//!
//! The personality implements the XNU user-space ABI for x86-64 and arm64
//! programs. The portable closed profile loads Mach-O images, `dyld`, and
//! shared-cache bytes only from caller-supplied immutable files, captures
//! standard streams, and services admitted calls against guest-owned state.
//! The legacy Unix profile additionally exposes host filesystem, process,
//! signal, and Mach services. `HOST_SERVICES_AVAILABLE` reports that profile's
//! availability; constructing it on non-Unix hosts returns a configuration
//! error before loading the image. Neither profile randomizes image addresses.
//!
//! | Module | Owns |
//! |---|---|
//! | [`abi`] | Numbering, conventions, error numbers, and machine parameters |
//! | [`arch`] | Per-ISA registers, kernel entry, and result conventions |
//! | [`loader`] | `exec`: mapping the image and `dyld`, the stack, the commpage |
//! | [`exception`] | Mach exception delivery to handlers, then the host's signals |
//! | [`exec`] | `execve` and `posix_spawn`: image activation, arguments, what a new image keeps |
//! | [`fork`] | `fork`: the child's process, thread, and task state |
//! | [`stack`] | The initial stack (`exec_copyout_strings`) |
//! | [`commpage`] | The commpage |
//! | [`codesign`] | The executable's code signature as `csops` reports it |
//! | [`shared_region`] | The dyld shared cache |
//! | [`vm`] | Mach VM attributes and address selection |
//! | [`vfs`] | Guest paths and the root overlay |
//! | [`fd`] | Descriptor tables |
//! | [`host`] | The host side of file and descriptor calls |
//! | [`io`] | Open-file flags |
//! | [`kevent`] | kqueues, knotes, and filters |
//! | [`mach`] | Ports, messages, and kernel objects |
//! | [`mig`] | The kernel's MIG servers (host, task, thread, port, VM, clock) |
//! | [`process`] | Processes, threads, and scheduling |
//! | [`psynch`] | Kernel wait queues of pthread mutexes, condition variables, and read-write locks |
//! | [`signal`] | Signals |
//! | [`syscall`] | System calls and Mach traps |
//! | [`thread_state`] | Machine thread state in the kernel's exported layouts |
//! | [`thread_status`] | Thread state by flavor (`thread_get_state`, `thread_set_state`) |
//! | [`wait`] | Sleeping in system calls |
//! | [`workq`] | Work queues and their threads |

/// Availability of the legacy Unix host-service profile. The supplied-file
/// embedding profile does not require Unix host services.
pub const HOST_SERVICES_AVAILABLE: bool = cfg!(unix);

pub mod abi;
pub mod arch;
pub mod bridge;
pub mod codesign;
pub mod commpage;
pub mod exception;
pub mod exec;
pub mod fd;
pub mod fork;
pub mod host;
pub mod io;
pub mod kevent;
pub mod loader;
pub mod mach;
pub mod mig;
pub mod process;
pub mod psynch;
pub mod runtime_files;
pub mod shared_region;
pub mod signal;
pub mod stack;
pub mod syscall;
pub mod thread_state;
pub mod thread_status;
pub mod vfs;
pub mod vm;
pub mod wait;
pub mod workq;

pub use process::{DarwinConfig, DarwinProcess, ExitStatus, RunStatus, SpawnError};
