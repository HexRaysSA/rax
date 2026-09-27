//! Mach port guard exceptions (`mach_port_guard_exception` and
//! `mach_port_guard_ast`, `osfmk/ipc/ipc_policy.c`; codes and payloads
//! from `osfmk/mach/port.h`).
//!
//! A violation is noted on the thread and handled on its way back to user
//! mode (see [`crate::user::darwin::exception::guard_ast`]). Reasons up to
//! `MAX_FATAL_kGUARD_EXC_CODE` (misusing a guarded or immovable port) are
//! fatal: the `EXC_GUARD` goes to the thread's and task's handlers, then
//! the task dies of `SIGKILL`. The optional reasons (invalid names,
//! rights, and values) are delivered only to a task whose guard behavior
//! includes `TASK_EXC_GUARD_MP_DELIVER` (once, with
//! `TASK_EXC_GUARD_MP_ONCE`), and kill it after delivery with
//! `TASK_EXC_GUARD_MP_FATAL`.

use crate::user::darwin::exception::{self, GuardAst};
use crate::user::darwin::mach::ipc::PortName;
use crate::user::darwin::process::Proc;

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

/// `task_exc_guard_behavior_t` bits for Mach port guards.
pub mod behavior {
    /// `TASK_EXC_GUARD_MP_DELIVER`.
    pub const MP_DELIVER: u32 = 0x10;
    /// `TASK_EXC_GUARD_MP_ONCE`.
    pub const MP_ONCE: u32 = 0x20;
    /// `TASK_EXC_GUARD_MP_FATAL`.
    pub const MP_FATAL: u32 = 0x80;
}

/// `GUARD_TYPE_MACH_PORT`.
pub const GUARD_TYPE_MACH_PORT: u64 = 1;
/// `GUARD_TYPE_VIRT_MEMORY`.
pub const GUARD_TYPE_VIRT_MEMORY: u64 = 5;

/// `MPG_FLAGS_INVALID_RIGHT_RECV`: a receive right was needed (the whole
/// payload of the routines that translate one).
pub const INVALID_RIGHT_RECV: u64 = 0x01;
/// `MPG_FLAGS_INVALID_RIGHT_DELTA` and `MPG_FLAGS_INVALID_VALUE_DELTA`
/// (`ipc_right_delta`).
pub const FLAG_DELTA: u8 = 0x02;
/// `MPG_FLAGS_INVALID_RIGHT_DESTRUCT` and
/// `MPG_FLAGS_INVALID_VALUE_DESTRUCT` (`ipc_right_destruct`).
pub const FLAG_DESTRUCT: u8 = 0x03;
/// `MPG_FLAGS_INVALID_RIGHT_DEALLOC` (`ipc_right_dealloc`).
pub const FLAG_DEALLOC: u8 = 0x05;

/// `EXC_GUARD`'s code: type, flavor (the reason), and target
/// (`EXC_GUARD_ENCODE_*`, `osfmk/kern/exc_guard.h`).
pub fn code(guard_type: u64, flavor: u32, target: u32) -> u64 {
    (guard_type << 61) | (u64::from(flavor & 0x1fff_ffff) << 32) | u64::from(target)
}

/// `MPG_PAYLOAD(flag, a, b)`: the flag in bits 63:56, 24 bits of `a` in
/// 55:32, `b` in 31:0.
pub fn payload(flag: u8, a: u32, b: u32) -> u64 {
    (u64::from(flag) << 56) | (u64::from(a & 0xff_ffff) << 32) | u64::from(b)
}

/// `MPG_PAYLOAD(flag, a, b, c)`: as [`payload`] with 16-bit `b` and `c`
/// in 31:16 and 15:0.
pub fn payload3(flag: u8, a: u32, b: u16, c: u16) -> u64 {
    payload(flag, a, (u32::from(b) << 16) | u32::from(c))
}

/// The `ie_bits` of `name`'s entry the payloads carry: its generation
/// (from the name), capability type, and user references. The
/// generation's rollover bits are not kept: they read as zero.
pub fn entry_bits(proc: &Proc, name: PortName) -> u32 {
    proc.ipc.lookup(name).map_or(0, |e| {
        let urefs = if e.send > 0 {
            e.send
        } else if e.dead > 0 {
            e.dead
        } else {
            u32::from(e.send_once)
        };
        ((name & 0xfc) << 24) | (e.port_type() & 0x001f_0000) | (urefs & 0xffff)
    })
}

/// Whether a violation for `reason` is sticky: a pending one of another
/// reason cannot replace it (`mach_port_guard_exception`).
pub fn is_sticky(reason: u32, behavior: u32) -> bool {
    reason <= MAX_FATAL || (reason <= MAX_OPTIONAL && behavior & behavior::MP_FATAL != 0)
}

/// Raises a Mach port guard exception for `name` with `payload` (the
/// exception's subcode): the calling thread handles it on its way back
/// to user mode.
pub fn raise(proc: &mut Proc, name: PortName, reason: u32, payload: u64) {
    if proc.config.strace || std::env::var_os("RAX_DARWIN_WARN").is_some() {
        eprintln!(
            "rax-user: EXC_GUARD (mach port {name:#x}, reason {reason:#x}, payload {payload:#x})"
        );
    }
    let sticky = is_sticky(reason, proc.task.exc_guard);
    exception::post_guard(
        &mut proc.guard_ast,
        GuardAst {
            code: code(GUARD_TYPE_MACH_PORT, reason, name),
            subcode: payload,
            sticky,
        },
    );
}

/// `mach_port_guard_ast`: whether a violation with `code` is delivered,
/// and if so whether the task dies after it (`Some(fatal)`); a task
/// asking for one delivery loses `TASK_EXC_GUARD_MP_DELIVER`.
pub fn ast(proc: &mut Proc, code: u64) -> Option<bool> {
    let reason = ((code >> 32) & 0x1fff_ffff) as u32;
    if reason <= MAX_FATAL {
        // exit_with_fatal_exception_and_notify.
        return Some(true);
    }
    let b = proc.task.exc_guard;
    if b & behavior::MP_DELIVER == 0 {
        return None;
    }
    if b & behavior::MP_ONCE != 0 {
        proc.task.exc_guard &= !behavior::MP_DELIVER;
    }
    Some(b & behavior::MP_FATAL != 0 && reason <= MAX_OPTIONAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sticky_reasons_follow_the_thresholds() {
        assert!(is_sticky(reason::UNGUARDED, 0));
        assert!(is_sticky(reason::INCORRECT_GUARD, 0));
        assert!(is_sticky(reason::IMMOVABLE, 0));
        assert!(!is_sticky(reason::INVALID_NAME, 0));
        assert!(is_sticky(reason::INVALID_NAME, behavior::MP_FATAL));
        assert!(!is_sticky(1 << 21, behavior::MP_FATAL));
    }

    #[test]
    fn codes_and_payloads_follow_the_encodings() {
        // The native kGUARD_EXC_DESTROY of port 0x1d03.
        assert_eq!(
            code(GUARD_TYPE_MACH_PORT, reason::DESTROY, 0x1d03),
            0x2000_0001_0000_1d03
        );
        assert_eq!(payload(FLAG_DEALLOC, 0x1234_5678, 7), 0x0534_5678_0000_0007);
        assert_eq!(
            payload3(FLAG_DELTA, 1, (-2i16) as u16, 3),
            0x0200_0001_fffe_0003
        );
    }
}
