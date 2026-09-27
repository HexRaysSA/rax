//! Mach: ports and messages, kernel objects, and the Mach traps.
//!
//! | Module | Owns |
//! |---|---|
//! | [`kr`] | `kern_return_t` and `mach_msg_return_t` values |
//! | [`ipc`] | Ports, rights, and a task's name space |
//! | [`msg`] | Messages in transit |
//! | [`sync`] | Semaphores |
//! | [`task`] | Task and thread special ports, exception ports, accounting |

pub mod ipc;
pub mod kr;
pub mod msg;
pub mod sync;
pub mod task;
