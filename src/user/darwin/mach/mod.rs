//! Mach: ports and messages, kernel objects, and the Mach traps.
//!
//! | Module | Owns |
//! |---|---|
//! | [`exception`] | Exception types, behaviors, flavors, and handler checks |
//! | [`kr`] | `kern_return_t` and `mach_msg_return_t` values |
//! | [`ipc`] | Ports, rights, and a task's name space |
//! | [`msg`] | Messages in transit |
//! | [`sync`] | Semaphores |
//! | [`task`] | Task and thread special ports, exception ports, accounting |
//! | [`voucher`] | Vouchers and their attribute managers |

pub mod exception;
pub mod ipc;
pub mod kr;
pub mod msg;
pub mod sync;
pub mod task;
pub mod voucher;
