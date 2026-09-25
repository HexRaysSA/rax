//! Linux signals: numbers and classes, `si_code` values, dispositions,
//! pending queues, alternate stacks, per-architecture signal frames, and
//! delivery.
//!
//! Numbers and flag values are from `asm-generic/signal.h`,
//! `asm-generic/signal-defs.h`, and `asm-generic/siginfo.h`, which x86-64,
//! arm64, and riscv share. Behavior follows `kernel/signal.c` and the
//! architectures' `signal.c` in Linux 6.19.
//!
//! | Module | Owns |
//! |---|---|
//! | [`info`] | `siginfo_t` records and their 128-byte encoding |
//! | [`pending`] | Pending sets and queues, dequeue order |
//! | [`frame`] | `rt_sigframe` construction and `rt_sigreturn` per architecture |
//! | [`deliver`] | Generation, delivery, default actions, system-call restart |

pub mod deliver;
pub mod frame;
pub mod info;
pub mod pending;

pub use info::SigInfo;
pub use pending::SigPending;

use super::abi::LinuxAbi;

/// `SIGHUP`.
pub const SIGHUP: i32 = 1;
/// `SIGINT`.
pub const SIGINT: i32 = 2;
/// `SIGQUIT`.
pub const SIGQUIT: i32 = 3;
/// `SIGILL`.
pub const SIGILL: i32 = 4;
/// `SIGTRAP`.
pub const SIGTRAP: i32 = 5;
/// `SIGABRT`.
pub const SIGABRT: i32 = 6;
/// `SIGBUS`.
pub const SIGBUS: i32 = 7;
/// `SIGFPE`.
pub const SIGFPE: i32 = 8;
/// `SIGKILL`.
pub const SIGKILL: i32 = 9;
/// `SIGUSR1`.
pub const SIGUSR1: i32 = 10;
/// `SIGSEGV`.
pub const SIGSEGV: i32 = 11;
/// `SIGUSR2`.
pub const SIGUSR2: i32 = 12;
/// `SIGPIPE`.
pub const SIGPIPE: i32 = 13;
/// `SIGALRM`.
pub const SIGALRM: i32 = 14;
/// `SIGTERM`.
pub const SIGTERM: i32 = 15;
/// `SIGSTKFLT`.
pub const SIGSTKFLT: i32 = 16;
/// `SIGCHLD`.
pub const SIGCHLD: i32 = 17;
/// `SIGCONT`.
pub const SIGCONT: i32 = 18;
/// `SIGSTOP`.
pub const SIGSTOP: i32 = 19;
/// `SIGTSTP`.
pub const SIGTSTP: i32 = 20;
/// `SIGTTIN`.
pub const SIGTTIN: i32 = 21;
/// `SIGTTOU`.
pub const SIGTTOU: i32 = 22;
/// `SIGURG`.
pub const SIGURG: i32 = 23;
/// `SIGXCPU`.
pub const SIGXCPU: i32 = 24;
/// `SIGXFSZ`.
pub const SIGXFSZ: i32 = 25;
/// `SIGVTALRM`.
pub const SIGVTALRM: i32 = 26;
/// `SIGPROF`.
pub const SIGPROF: i32 = 27;
/// `SIGWINCH`.
pub const SIGWINCH: i32 = 28;
/// `SIGIO`.
pub const SIGIO: i32 = 29;
/// `SIGPWR`.
pub const SIGPWR: i32 = 30;
/// `SIGSYS`.
pub const SIGSYS: i32 = 31;
/// `SIGRTMIN` as the kernel defines it.
pub const SIGRTMIN: i32 = 32;
/// `_NSIG`: highest signal number.
pub const NSIG: i32 = 64;

/// `si_code` values.
pub mod code {
    /// Sent by `kill`.
    pub const SI_USER: i32 = 0;
    /// Sent by the kernel.
    pub const SI_KERNEL: i32 = 0x80;
    /// Sent by `sigqueue` (`rt_sigqueueinfo`).
    pub const SI_QUEUE: i32 = -1;
    /// Sent by a POSIX timer expiring.
    pub const SI_TIMER: i32 = -2;
    /// A message arrived on an empty POSIX message queue (`mq_notify`).
    pub const SI_MESGQ: i32 = -3;
    /// Sent by `tkill`/`tgkill`.
    pub const SI_TKILL: i32 = -6;
    /// A child exited (`SIGCHLD`).
    pub const CLD_EXITED: i32 = 1;
    /// A child was killed.
    pub const CLD_KILLED: i32 = 2;
    /// A child was killed and dumped core.
    pub const CLD_DUMPED: i32 = 3;
    /// A traced child stopped for its tracer.
    pub const CLD_TRAPPED: i32 = 4;
    /// A child stopped.
    pub const CLD_STOPPED: i32 = 5;
    /// A stopped child continued.
    pub const CLD_CONTINUED: i32 = 6;
    /// A seccomp filter stopped a system call (`SIGSYS`).
    pub const SYS_SECCOMP: i32 = 1;
    /// Illegal opcode.
    pub const ILL_ILLOPC: i32 = 1;
    /// Illegal operand.
    pub const ILL_ILLOPN: i32 = 2;
    /// Privileged opcode.
    pub const ILL_PRVOPC: i32 = 5;
    /// Privileged register.
    pub const ILL_PRVREG: i32 = 6;
    /// Integer divide by zero.
    pub const FPE_INTDIV: i32 = 1;
    /// Integer overflow.
    pub const FPE_INTOVF: i32 = 2;
    /// Floating-point divide by zero.
    pub const FPE_FLTDIV: i32 = 3;
    /// Floating-point overflow.
    pub const FPE_FLTOVF: i32 = 4;
    /// Floating-point underflow.
    pub const FPE_FLTUND: i32 = 5;
    /// Floating-point inexact result.
    pub const FPE_FLTRES: i32 = 6;
    /// Floating-point invalid operation.
    pub const FPE_FLTINV: i32 = 7;
    /// Undiagnosed floating-point exception.
    pub const FPE_FLTUNK: i32 = 14;
    /// Address not mapped.
    pub const SEGV_MAPERR: i32 = 1;
    /// Invalid permissions.
    pub const SEGV_ACCERR: i32 = 2;
    /// Invalid address alignment.
    pub const BUS_ADRALN: i32 = 1;
    /// Nonexistent physical address.
    pub const BUS_ADRERR: i32 = 2;
    /// Process breakpoint.
    pub const TRAP_BRKPT: i32 = 1;
    /// Process trace trap.
    pub const TRAP_TRACE: i32 = 2;
}

/// Whether a signal's default action terminates the process with a core
/// dump (`SIG_KERNEL_COREDUMP_MASK`).
pub fn default_dumps_core(sig: i32) -> bool {
    matches!(
        sig,
        SIGQUIT
            | SIGILL
            | SIGTRAP
            | SIGABRT
            | SIGBUS
            | SIGFPE
            | SIGSEGV
            | SIGXCPU
            | SIGXFSZ
            | SIGSYS
    )
}

/// Whether a signal's default action is to ignore it
/// (`SIG_KERNEL_IGNORE_MASK`).
pub fn default_ignored(sig: i32) -> bool {
    matches!(sig, SIGCONT | SIGCHLD | SIGWINCH | SIGURG)
}

/// The conventional name of a signal (`SIGSEGV`, ...).
pub fn signal_name(sig: i32) -> String {
    let name = match sig {
        SIGHUP => "SIGHUP",
        SIGINT => "SIGINT",
        SIGQUIT => "SIGQUIT",
        SIGILL => "SIGILL",
        SIGTRAP => "SIGTRAP",
        SIGABRT => "SIGABRT",
        SIGBUS => "SIGBUS",
        SIGFPE => "SIGFPE",
        SIGKILL => "SIGKILL",
        SIGUSR1 => "SIGUSR1",
        SIGSEGV => "SIGSEGV",
        SIGUSR2 => "SIGUSR2",
        SIGPIPE => "SIGPIPE",
        SIGALRM => "SIGALRM",
        SIGTERM => "SIGTERM",
        SIGSTKFLT => "SIGSTKFLT",
        SIGCHLD => "SIGCHLD",
        SIGCONT => "SIGCONT",
        SIGSTOP => "SIGSTOP",
        SIGTSTP => "SIGTSTP",
        SIGTTIN => "SIGTTIN",
        SIGTTOU => "SIGTTOU",
        SIGURG => "SIGURG",
        SIGXCPU => "SIGXCPU",
        SIGXFSZ => "SIGXFSZ",
        SIGVTALRM => "SIGVTALRM",
        SIGPROF => "SIGPROF",
        SIGWINCH => "SIGWINCH",
        SIGIO => "SIGIO",
        SIGPWR => "SIGPWR",
        SIGSYS => "SIGSYS",
        s if (SIGRTMIN..=NSIG).contains(&s) => return format!("SIGRT{}", s - SIGRTMIN),
        s => return format!("signal {s}"),
    };
    name.to_string()
}

/// The bit for `sig` in a kernel `sigset_t` (`sigmask()`).
pub const fn sigmask(sig: i32) -> u64 {
    1u64 << (sig - 1)
}

/// Signals that cannot be caught, blocked, or ignored (`sig_kernel_only`).
pub const KERNEL_ONLY_MASK: u64 = sigmask(SIGKILL) | sigmask(SIGSTOP);

/// Signals raised by faults, dequeued before any other
/// (`SYNCHRONOUS_MASK`).
pub const SYNCHRONOUS_MASK: u64 = sigmask(SIGSEGV)
    | sigmask(SIGBUS)
    | sigmask(SIGILL)
    | sigmask(SIGTRAP)
    | sigmask(SIGFPE)
    | sigmask(SIGSYS);

/// Whether `sig` is a valid signal number (`valid_signal`, 1..=64).
pub fn valid_signal(sig: i32) -> bool {
    (1..=NSIG).contains(&sig)
}

/// Whether the default action of `sig` stops the process
/// (`sig_kernel_stop`).
pub fn default_stops(sig: i32) -> bool {
    matches!(sig, SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU)
}

/// `SIG_DFL`.
pub const SIG_DFL: u64 = 0;
/// `SIG_IGN`.
pub const SIG_IGN: u64 = 1;

/// `sa_flags` values (`asm-generic/signal-defs.h`).
pub mod sa {
    /// `SA_NOCLDSTOP`.
    pub const NOCLDSTOP: u64 = 0x0000_0001;
    /// `SA_NOCLDWAIT`.
    pub const NOCLDWAIT: u64 = 0x0000_0002;
    /// `SA_SIGINFO`.
    pub const SIGINFO: u64 = 0x0000_0004;
    /// `SA_EXPOSE_TAGBITS`.
    pub const EXPOSE_TAGBITS: u64 = 0x0000_0800;
    /// `SA_RESTORER` (x86 and arm64 only).
    pub const RESTORER: u64 = 0x0400_0000;
    /// `SA_ONSTACK`.
    pub const ONSTACK: u64 = 0x0800_0000;
    /// `SA_RESTART`.
    pub const RESTART: u64 = 0x1000_0000;
    /// `SA_NODEFER`.
    pub const NODEFER: u64 = 0x4000_0000;
    /// `SA_RESETHAND`.
    pub const RESETHAND: u64 = 0x8000_0000;
}

/// `UAPI_SA_FLAGS`: the flags `rt_sigaction` keeps; unknown bits are
/// cleared so user space can detect unsupported flags.
pub fn uapi_sa_flags(abi: LinuxAbi) -> u64 {
    let mut flags = sa::NOCLDSTOP
        | sa::NOCLDWAIT
        | sa::SIGINFO
        | sa::ONSTACK
        | sa::RESTART
        | sa::NODEFER
        | sa::RESETHAND
        | sa::EXPOSE_TAGBITS;
    if abi.has_sa_restorer() {
        flags |= sa::RESTORER;
    }
    flags
}

/// `sigaltstack` flags (`linux/signal.h`).
pub mod ss {
    /// `SS_ONSTACK`.
    pub const ONSTACK: u32 = 1;
    /// `SS_DISABLE`.
    pub const DISABLE: u32 = 2;
    /// `SS_AUTODISARM`.
    pub const AUTODISARM: u32 = 1 << 31;
    /// `SS_FLAG_BITS`.
    pub const FLAG_BITS: u32 = AUTODISARM;
}

/// `MINSIGSTKSZ`, the smallest stack `sigaltstack` accepts: 5120 bytes on
/// arm64 (`arch/arm64/include/uapi/asm/signal.h`), 2048 on x86-64 and
/// riscv.
pub fn minsigstksz(abi: LinuxAbi) -> u64 {
    match abi {
        LinuxAbi::Aarch64 => 5120,
        LinuxAbi::X86_64 | LinuxAbi::Riscv64 => 2048,
    }
}

/// A thread's alternate signal stack (`sas_ss_sp`, `sas_ss_size`,
/// `sas_ss_flags`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AltStack {
    /// `ss_sp`.
    pub sp: u64,
    /// `ss_size`.
    pub size: u64,
    /// The `ss_flags` last installed (`SS_DISABLE` when there is none).
    pub flags: u32,
}

impl Default for AltStack {
    fn default() -> Self {
        AltStack::DISABLED
    }
}

impl AltStack {
    /// No alternate stack (`sas_ss_reset`).
    pub const DISABLED: AltStack = AltStack {
        sp: 0,
        size: 0,
        flags: ss::DISABLE,
    };

    /// `__on_sig_stack`: whether `sp` lies within the stack.
    pub fn contains(&self, sp: u64) -> bool {
        sp > self.sp && sp - self.sp <= self.size
    }

    /// `on_sig_stack`: an `SS_AUTODISARM` stack is never considered in use.
    pub fn on_stack(&self, sp: u64) -> bool {
        self.flags & ss::AUTODISARM == 0 && self.contains(sp)
    }

    /// `sas_ss_flags`: `SS_DISABLE` without a stack, else `SS_ONSTACK`
    /// while on it.
    pub fn ss_flags(&self, sp: u64) -> u32 {
        if self.size == 0 {
            ss::DISABLE
        } else if self.on_stack(sp) {
            ss::ONSTACK
        } else {
            0
        }
    }

    /// `sigsp`: the stack top a handler with `sa_flags` starts from.
    pub fn sigsp(&self, sp: u64, sa_flags: u64) -> u64 {
        if sa_flags & sa::ONSTACK != 0 && self.ss_flags(sp) == 0 {
            self.sp.wrapping_add(self.size)
        } else {
            sp
        }
    }

    /// The `stack_t` `sigaltstack` reports as the old stack for a thread at
    /// `sp`.
    pub fn report(&self, sp: u64) -> (u64, u32, u64) {
        (
            self.sp,
            self.ss_flags(sp) | (self.flags & ss::FLAG_BITS),
            self.size,
        )
    }

    /// `do_sigaltstack` with a new stack `(ss_sp, ss_flags, ss_size)` for a
    /// thread at `sp`, returning the errno it fails with.
    pub fn install(&mut self, new: (u64, u32, u64), sp: u64, min_size: u64) -> Result<(), i32> {
        use super::abi::errno_table::{EINVAL, ENOMEM, EPERM};
        let (new_sp, flags, size) = new;
        if self.on_stack(sp) {
            return Err(EPERM);
        }
        let mode = flags & !ss::FLAG_BITS;
        if mode != ss::DISABLE && mode != ss::ONSTACK && mode != 0 {
            return Err(EINVAL);
        }
        if (self.sp, self.size, self.flags) == (new_sp, size, flags) {
            return Ok(());
        }
        let (new_sp, size) = if mode == ss::DISABLE {
            (0, 0)
        } else if size < min_size {
            return Err(ENOMEM);
        } else {
            (new_sp, size)
        };
        *self = AltStack {
            sp: new_sp,
            size,
            flags,
        };
        Ok(())
    }

    /// Encodes a `stack_t` (`ss_sp`, `ss_flags`, `ss_size`; 24 bytes).
    pub fn encode_stack_t(sp: u64, flags: u32, size: u64) -> [u8; 24] {
        let mut b = [0u8; 24];
        b[..8].copy_from_slice(&sp.to_le_bytes());
        b[8..12].copy_from_slice(&flags.to_le_bytes());
        b[16..].copy_from_slice(&size.to_le_bytes());
        b
    }

    /// Decodes a `stack_t`.
    pub fn decode_stack_t(b: &[u8; 24]) -> (u64, u32, u64) {
        (
            u64::from_le_bytes(b[..8].try_into().unwrap()),
            u32::from_le_bytes(b[8..12].try_into().unwrap()),
            u64::from_le_bytes(b[16..].try_into().unwrap()),
        )
    }
}

#[cfg(test)]
mod tests;
