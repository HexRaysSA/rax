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
