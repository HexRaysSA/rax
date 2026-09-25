//! The system call a stopped thread is in, as each architecture's
//! `asm/syscall.h` reads and writes it for a tracer (Linux 6.19), and
//! `struct ptrace_syscall_info` (`PTRACE_GET_SYSCALL_INFO`,
//! `PTRACE_SET_SYSCALL_INFO`, `kernel/ptrace.c`).
//!
//! The number is x86-64's `orig_ax`, AArch64's `syscallno` (both the
//! thread's [`SyscallEntry`], with none for -1 on x86-64), or RISC-V's `a7`,
//! always as an `int`. The first argument is the register itself on x86-64
//! (`rdi`, or `rbx` for `INT 0x80`) and the saved `orig_x0` or `orig_a0` on
//! the others, whose first argument register returns the result.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::{AUDIT_ARCH_I386, LinuxAbi};
use super::super::arch::GuestCpu;
use super::super::signal::deliver::SyscallEntry;
use super::super::signal::{SIGTRAP, SigInfo};
use super::{EVENTMSG_SYSCALL_ENTRY, EVENTMSG_SYSCALL_EXIT};

/// `PTRACE_SYSCALL_INFO_*`.
pub const INFO_NONE: u8 = 0;
pub const INFO_ENTRY: u8 = 1;
pub const INFO_EXIT: u8 = 2;
pub const INFO_SECCOMP: u8 = 3;

/// `sizeof(struct ptrace_syscall_info)`: the header (op, reserved, flags,
/// arch, instruction and stack pointers: 24 bytes) and the 64-byte union.
pub const INFO_SIZE: usize = 88;
/// `offsetof(struct ptrace_syscall_info, entry)`.
const INFO_HEADER: u64 = 24;
/// `offsetofend(..., entry.args)`.
const INFO_ENTRY_END: u64 = 80;
/// `offsetofend(..., exit.is_error)`.
const INFO_EXIT_END: u64 = 33;

/// `PTRACE_EVENT_SECCOMP`.
const EVENT_SECCOMP: i32 = 7;

/// `syscall_get_nr`.
pub fn nr(cpu: &GuestCpu, syscall: Option<SyscallEntry>) -> i32 {
    match cpu {
        GuestCpu::Riscv64(c) => c.core().x(17) as i32,
        _ => syscall.map_or(-1, |s| s.nr as i32),
    }
}

/// `syscall_set_nr`: AArch64 also makes -1's result `ENOSYS`, since the
/// skipped call would otherwise return its first argument.
pub fn set_nr(cpu: &mut GuestCpu, syscall: &mut Option<SyscallEntry>, nr: i32) {
    let wide = nr as i64 as u64;
    let arg0 = syscall.map_or(0, |s| s.arg0);
    match cpu {
        GuestCpu::X86_64(_) => {
            *syscall = (nr != -1).then_some(SyscallEntry { nr: wide, arg0 });
        }
        GuestCpu::Aarch64(c) => {
            *syscall = Some(SyscallEntry { nr: wide, arg0 });
            if nr == -1 {
                c.core_mut().set_x(0, Errno(ENOSYS).as_return());
            }
        }
        GuestCpu::Riscv64(c) => c.core_mut().set_x(17, wide),
    }
}

/// `syscall_get_arguments` (`INT 0x80`'s under `compat`).
pub fn args(cpu: &GuestCpu, syscall: Option<SyscallEntry>, compat: bool) -> [u64; 6] {
    match cpu {
        GuestCpu::X86_64(c) => {
            let r = c.vcpu().user_regs();
            if compat {
                [r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp]
            } else {
                [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9]
            }
        }
        GuestCpu::Aarch64(c) => {
            let core = c.core();
            let arg0 = syscall.map_or(core.get_x(0), |s| s.arg0);
            [
                arg0,
                core.get_x(1),
                core.get_x(2),
                core.get_x(3),
                core.get_x(4),
                core.get_x(5),
            ]
        }
        GuestCpu::Riscv64(c) => {
            let core = c.core();
            let arg0 = syscall.map_or(core.x(10), |s| s.arg0);
            [
                arg0,
                core.x(11),
                core.x(12),
                core.x(13),
                core.x(14),
                core.x(15),
            ]
        }
    }
}

/// `syscall_set_arguments`: AArch64 sets `x0` and `orig_x0` alike.
pub fn set_args(cpu: &mut GuestCpu, syscall: &mut Option<SyscallEntry>, compat: bool, a: [u64; 6]) {
    let mut keep_arg0 = || {
        if let Some(s) = syscall.as_mut() {
            s.arg0 = a[0];
        }
    };
    match cpu {
        GuestCpu::X86_64(c) => {
            let r = c.vcpu_mut().user_regs_mut();
            let regs = if compat {
                [
                    &mut r.rbx, &mut r.rcx, &mut r.rdx, &mut r.rsi, &mut r.rdi, &mut r.rbp,
                ]
            } else {
                [
                    &mut r.rdi, &mut r.rsi, &mut r.rdx, &mut r.r10, &mut r.r8, &mut r.r9,
                ]
            };
            for (slot, v) in regs.into_iter().zip(a) {
                *slot = v;
            }
        }
        GuestCpu::Aarch64(c) => {
            for (r, v) in a.into_iter().enumerate() {
                c.core_mut().set_x(r as u8, v);
            }
            keep_arg0();
        }
        GuestCpu::Riscv64(c) => {
            for (r, &v) in a.iter().enumerate().skip(1) {
                c.core_mut().set_x(10 + r as u8, v);
            }
            keep_arg0();
        }
    }
}

/// `syscall_get_error`: the result when it is an error
/// (`IS_ERR_VALUE`), else 0; `INT 0x80`'s result is an `int`.
pub fn error(cpu: &GuestCpu, compat: bool) -> i64 {
    let v = cpu.syscall_return_value();
    let v = if compat { v as i32 as i64 } else { v as i64 };
    if (v as u64) >= (-4095i64) as u64 {
        v
    } else {
        0
    }
}

/// `ptrace_get_syscall_info_op`: which system-call stop the thread is in,
/// from its `last_siginfo`'s code and `ptrace_message`.
pub fn op(info: Option<&SigInfo>, message: u64) -> u8 {
    match info.map_or(0, |i| i.code) {
        c if c == SIGTRAP | 0x80 => match message {
            EVENTMSG_SYSCALL_ENTRY => INFO_ENTRY,
            EVENTMSG_SYSCALL_EXIT => INFO_EXIT,
            _ => INFO_NONE,
        },
        c if c == SIGTRAP | (EVENT_SECCOMP << 8) => INFO_SECCOMP,
        _ => INFO_NONE,
    }
}

/// `ptrace_get_syscall_info`: the whole structure and how much of it is
/// meaningful (`actual_size`).
pub fn info(
    abi: LinuxAbi,
    cpu: &GuestCpu,
    syscall: Option<SyscallEntry>,
    op: u8,
    compat: bool,
    message: u64,
) -> ([u8; INFO_SIZE], u64) {
    let mut b = [0u8; INFO_SIZE];
    let arch = if compat {
        AUDIT_ARCH_I386
    } else {
        abi.audit_arch()
    };
    b[0] = op;
    b[4..8].copy_from_slice(&arch.to_le_bytes());
    b[8..16].copy_from_slice(&cpu.pc().to_le_bytes());
    b[16..24].copy_from_slice(&cpu.sp().to_le_bytes());
    let entry = |b: &mut [u8; INFO_SIZE]| {
        let n = nr(cpu, syscall) as i64 as u64;
        b[24..32].copy_from_slice(&n.to_le_bytes());
        for (i, a) in args(cpu, syscall, compat).iter().enumerate() {
            b[32 + 8 * i..40 + 8 * i].copy_from_slice(&a.to_le_bytes());
        }
    };
    let size = match op {
        INFO_ENTRY => {
            entry(&mut b);
            INFO_ENTRY_END
        }
        INFO_SECCOMP => {
            entry(&mut b);
            b[80..84].copy_from_slice(&(message as u32).to_le_bytes());
            INFO_ENTRY_END + 4
        }
        INFO_EXIT => {
            let err = error(cpu, compat);
            let rval = if err != 0 {
                err
            } else {
                cpu.syscall_return_value() as i64
            };
            b[24..32].copy_from_slice(&rval.to_le_bytes());
            b[32] = u8::from(err != 0);
            INFO_EXIT_END
        }
        _ => INFO_HEADER,
    };
    (b, size)
}

/// `ptrace_set_syscall_info` on the thread, after the tracer copied the
/// structure in: reserved fields are zero (`EINVAL`), the stop is of the
/// kind named (`EINVAL`), and a number is an `int` (`ERANGE`; the
/// arguments and the result, 64-bit, always fit). A number of -1 leaves the
/// arguments alone: on the architectures whose first argument register
/// returns the result, writing them would overwrite the result.
pub fn set_info(
    cpu: &mut GuestCpu,
    syscall: &mut Option<SyscallEntry>,
    compat: bool,
    current: u8,
    b: &[u8],
) -> Result<(), Errno> {
    let u64at = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    let flags = u16::from_le_bytes([b[2], b[3]]);
    if flags != 0 || b[1] != 0 {
        return Err(Errno(EINVAL));
    }
    if b[0] != current {
        return Err(Errno(EINVAL));
    }
    match b[0] {
        INFO_ENTRY | INFO_SECCOMP => {
            let raw = u64at(24);
            let n = raw as i32;
            if n as i64 as u64 != raw {
                return Err(Errno(ERANGE));
            }
            set_nr(cpu, syscall, n);
            if n != -1 {
                let mut a = [0u64; 6];
                for (i, v) in a.iter_mut().enumerate() {
                    *v = u64at(32 + 8 * i);
                }
                set_args(cpu, syscall, compat, a);
            }
            Ok(())
        }
        INFO_EXIT => {
            // syscall_set_return_value(rval, 0) for an error, whose `int
            // error` keeps the low 32 bits, else (0, rval).
            let rval = u64at(24) as i64;
            let v = if b[32] != 0 { rval as i32 as i64 } else { rval };
            cpu.set_syscall_result(v as u64);
            Ok(())
        }
        _ => Err(Errno(EINVAL)),
    }
}
