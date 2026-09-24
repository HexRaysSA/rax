//! Linux signal numbers, `si_code` values, and synchronous signal records.
//!
//! Values are from `asm-generic/signal.h` and `asm-generic/siginfo.h`, which
//! x86-64, arm64, and riscv share.

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
    /// Sent by `tkill`/`tgkill`.
    pub const SI_TKILL: i32 = -6;
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

/// A synchronous signal raised by the executing thread (a fault or trap).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigInfo {
    /// Signal number.
    pub signo: i32,
    /// `si_code`.
    pub code: i32,
    /// `si_addr` for fault signals.
    pub addr: u64,
}

impl SigInfo {
    /// A fault signal with an address.
    pub fn fault(signo: i32, code: i32, addr: u64) -> Self {
        SigInfo { signo, code, addr }
    }
}
