//! Mach port guard exceptions (`mach_port_guard_exception`,
//! `osfmk/ipc/ipc_policy.c`; codes from `osfmk/mach/port.h`).
//!
//! Reasons up to `MAX_FATAL_kGUARD_EXC_CODE` (misusing a guarded or
//! immovable port) are fatal: the task dies of `SIGKILL` as an unhandled
//! `EXC_GUARD` kills it. The optional reasons (invalid names, rights, and
//! values) are fatal only for a task whose guard behavior includes
//! `TASK_EXC_GUARD_MP_FATAL`; otherwise the kernel reports them without
//! stopping the task.

use crate::user::darwin::mach::ipc::PortName;
use crate::user::darwin::process::{ExitStatus, Proc};

/// `kGUARD_EXC_*` reasons.
pub mod reason {
    /// `kGUARD_EXC_DESTROY`.
    pub const DESTROY: u32 = 1;
    /// `kGUARD_EXC_MOD_REFS`.
    pub const MOD_REFS: u32 = 2;
    /// `kGUARD_EXC_SET_CONTEXT`.
    pub const SET_CONTEXT: u32 = 4;
    /// `kGUARD_EXC_UNGUARDED`.
    pub const UNGUARDED: u32 = 8;
    /// `kGUARD_EXC_INCORRECT_GUARD`.
    pub const INCORRECT_GUARD: u32 = 16;
    /// `kGUARD_EXC_IMMOVABLE`.
    pub const IMMOVABLE: u32 = 32;
    /// `kGUARD_EXC_INVALID_RIGHT`.
    pub const INVALID_RIGHT: u32 = 256;
    /// `kGUARD_EXC_INVALID_NAME`.
    pub const INVALID_NAME: u32 = 512;
    /// `kGUARD_EXC_INVALID_VALUE`.
    pub const INVALID_VALUE: u32 = 1 << 10;
    /// `kGUARD_EXC_INVALID_ARGUMENT` (an already guarded port).
    pub const INVALID_ARGUMENT: u32 = 1 << 11;
    /// `kGUARD_EXC_SEND_INVALID_REPLY`.
    pub const SEND_INVALID_REPLY: u32 = 1 << 16;
    /// `kGUARD_EXC_SEND_INVALID_VOUCHER`.
    pub const SEND_INVALID_VOUCHER: u32 = 1 << 17;
    /// `kGUARD_EXC_SEND_INVALID_RIGHT`.
    pub const SEND_INVALID_RIGHT: u32 = 1 << 18;
    /// `kGUARD_EXC_RCV_INVALID_NAME`.
    pub const RCV_INVALID_NAME: u32 = 1 << 19;
}

/// `MAX_FATAL_kGUARD_EXC_CODE` (`kGUARD_EXC_MSG_FILTERED`).
const MAX_FATAL: u32 = 128;
/// `MAX_OPTIONAL_kGUARD_EXC_CODE` (`kGUARD_EXC_RCV_INVALID_NAME`).
const MAX_OPTIONAL: u32 = 1 << 19;
/// `TASK_EXC_GUARD_MP_FATAL`.
const TASK_EXC_GUARD_MP_FATAL: u32 = 0x80;
/// `SIGKILL`.
const SIGKILL: i32 = 9;

/// Whether `reason` kills a task with guard behavior `behavior`.
pub fn is_fatal(reason: u32, behavior: u32) -> bool {
    reason <= MAX_FATAL || (reason <= MAX_OPTIONAL && behavior & TASK_EXC_GUARD_MP_FATAL != 0)
}

/// Raises a Mach port guard exception for `name`.
pub fn raise(proc: &mut Proc, name: PortName, reason: u32) {
    let fatal = is_fatal(reason, proc.task.exc_guard);
    if proc.config.strace || std::env::var_os("RAX_DARWIN_WARN").is_some() {
        eprintln!(
            "rax-user: EXC_GUARD (mach port {name:#x}, reason {reason:#x}){}",
            if fatal { ": fatal" } else { "" }
        );
    }
    if fatal {
        proc.exit_with(ExitStatus::Signaled {
            signo: SIGKILL,
            core: false,
            pc: 0,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fatal_reasons_follow_the_thresholds() {
        assert!(is_fatal(reason::UNGUARDED, 0));
        assert!(is_fatal(reason::INCORRECT_GUARD, 0));
        assert!(is_fatal(reason::IMMOVABLE, 0));
        assert!(!is_fatal(reason::INVALID_NAME, 0));
        assert!(is_fatal(reason::INVALID_NAME, TASK_EXC_GUARD_MP_FATAL));
        assert!(!is_fatal(1 << 21, TASK_EXC_GUARD_MP_FATAL));
    }
}
