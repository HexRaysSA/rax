//! Darwin personality: runs macOS user-space programs.
//!
//! The personality implements the XNU user-space ABI for x86-64 and arm64
//! programs: images are loaded as `exec_mach_imgact` loads them (ASLR
//! disabled), `dyld` and the dyld shared cache come from the host (or a
//! guest root), and the programs' BSD system calls, Mach traps, and Mach
//! messages to kernel objects are serviced against the host.
//!
//! | Module | Owns |
//! |---|---|
//! | [`abi`] | Numbering, conventions, error numbers, and machine parameters |
//! | [`arch`] | Per-ISA registers, kernel entry, and result conventions |
//! | [`loader`] | `exec`: mapping the image and `dyld`, the stack, the commpage |
//! | [`stack`] | The initial stack (`exec_copyout_strings`) |
//! | [`commpage`] | The commpage |
//! | [`shared_region`] | The dyld shared cache |
//! | [`vm`] | Mach VM attributes and address selection |
//! | [`vfs`] | Guest paths and the root overlay |
//! | [`fd`] | Descriptor tables |
//! | [`host`] | The host side of file and descriptor calls |
//! | [`io`] | Open-file flags |
//! | [`mach`] | Ports, messages, and kernel objects |
//! | [`mig`] | The kernel's MIG servers (host, task, thread, port, VM, clock) |
//! | [`process`] | Processes, threads, and scheduling |
//! | [`psynch`] | Kernel wait queues of pthread mutexes, condition variables, and read-write locks |
//! | [`signal`] | Signals |
//! | [`syscall`] | System calls and Mach traps |
//! | [`thread_state`] | Machine thread state in the kernel's exported layouts |
//! | [`wait`] | Sleeping in system calls |

pub mod abi;
pub mod arch;
pub mod commpage;
pub mod fd;
pub mod host;
pub mod io;
pub mod loader;
pub mod mach;
pub mod mig;
pub mod process;
pub mod psynch;
pub mod shared_region;
pub mod signal;
pub mod stack;
pub mod syscall;
pub mod thread_state;
pub mod vfs;
pub mod vm;
pub mod wait;

pub use process::{DarwinConfig, DarwinProcess, ExitStatus, SpawnError};
