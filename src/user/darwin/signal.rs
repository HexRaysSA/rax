//! Darwin signals: numbering, default actions, and the translation of
//! machine exceptions.
//!
//! A machine exception becomes a Mach exception (`EXC_*` with a code) and,
//! with no exception port claiming it, a BSD signal (`ux_exception` in
//! `bsd/uxkern/ux_exception.c` with the machine hooks of
//! `bsd/dev/{arm,i386}/unix_signal.c`): a bad access to an unmapped address
//! is `SIGSEGV`, to a mapped but protected page `SIGBUS`, an x86-64 general
//! protection fault `SIGSEGV`, an undefined instruction `SIGILL`, an
//! arithmetic fault `SIGFPE`, a breakpoint `SIGTRAP`, and an invalid system
//! call `SIGSYS`.

use super::arch::Exception;
use super::process::{ExitStatus, Proc, Thread};
use crate::isa::x86_64::X86EventSource;
use crate::user::cpu::AccessFaultKind;

/// A signal number.
pub type Signal = i32;

/// Darwin signal numbers (`bsd/sys/signal.h`).
#[allow(non_upper_case_globals, missing_docs)]
pub mod nums {
    pub const SIGHUP: i32 = 1;
    pub const SIGINT: i32 = 2;
    pub const SIGQUIT: i32 = 3;
    pub const SIGILL: i32 = 4;
    pub const SIGTRAP: i32 = 5;
    pub const SIGABRT: i32 = 6;
    pub const SIGEMT: i32 = 7;
    pub const SIGFPE: i32 = 8;
    pub const SIGKILL: i32 = 9;
    pub const SIGBUS: i32 = 10;
    pub const SIGSEGV: i32 = 11;
    pub const SIGSYS: i32 = 12;
    pub const SIGPIPE: i32 = 13;
    pub const SIGALRM: i32 = 14;
    pub const SIGTERM: i32 = 15;
    pub const SIGURG: i32 = 16;
    pub const SIGSTOP: i32 = 17;
    pub const SIGTSTP: i32 = 18;
    pub const SIGCONT: i32 = 19;
    pub const SIGCHLD: i32 = 20;
    pub const SIGTTIN: i32 = 21;
    pub const SIGTTOU: i32 = 22;
    pub const SIGIO: i32 = 23;
    pub const SIGXCPU: i32 = 24;
    pub const SIGXFSZ: i32 = 25;
    pub const SIGVTALRM: i32 = 26;
    pub const SIGPROF: i32 = 27;
    pub const SIGWINCH: i32 = 28;
    pub const SIGINFO: i32 = 29;
    pub const SIGUSR1: i32 = 30;
    pub const SIGUSR2: i32 = 31;
}

pub use nums::*;

/// Names, indexed by number.
const NAMES: [&str; 32] = [
    "0",
    "SIGHUP",
    "SIGINT",
    "SIGQUIT",
    "SIGILL",
    "SIGTRAP",
    "SIGABRT",
    "SIGEMT",
    "SIGFPE",
    "SIGKILL",
    "SIGBUS",
    "SIGSEGV",
    "SIGSYS",
    "SIGPIPE",
    "SIGALRM",
    "SIGTERM",
    "SIGURG",
    "SIGSTOP",
    "SIGTSTP",
    "SIGCONT",
    "SIGCHLD",
    "SIGTTIN",
    "SIGTTOU",
    "SIGIO",
    "SIGXCPU",
    "SIGXFSZ",
    "SIGVTALRM",
    "SIGPROF",
    "SIGWINCH",
    "SIGINFO",
    "SIGUSR1",
    "SIGUSR2",
];

/// The signal's name (`SIGSEGV`), or its number.
pub fn name(sig: Signal) -> String {
    NAMES
        .get(sig as usize)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("signal {sig}"))
}

/// A signal's default action (`sigprop` in `bsd/sys/signalvar.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultAction {
    /// Terminate the process.
    Kill,
    /// Terminate the process and dump core.
    Core,
    /// Ignore the signal.
    Ignore,
    /// Stop the process.
    Stop,
    /// Continue a stopped process.
    Continue,
}

/// The default action of `sig`.
pub fn default_action(sig: Signal) -> DefaultAction {
    use DefaultAction::*;
    match sig {
        SIGQUIT | SIGILL | SIGTRAP | SIGABRT | SIGEMT | SIGFPE | SIGBUS | SIGSEGV | SIGSYS
        | SIGXCPU | SIGXFSZ => Core,
        SIGURG | SIGCHLD | SIGIO | SIGWINCH | SIGINFO => Ignore,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => Stop,
        SIGCONT => Continue,
        _ => Kill,
    }
}

/// `SIG_DFL`.
pub const SIG_DFL: u64 = 0;
/// `SIG_IGN`.
pub const SIG_IGN: u64 = 1;

/// A signal's disposition (`struct sigaction` with the `sa_tramp` of
/// `__sigaction`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigAction {
    /// `SIG_DFL`, `SIG_IGN`, or the handler.
    pub handler: u64,
    /// The trampoline libSystem registered (`_sigtramp`).
    pub tramp: u64,
    /// Signals blocked while the handler runs.
    pub mask: u32,
    /// `SA_*` flags.
    pub flags: u32,
}

/// The Mach exception a machine exception raises, with its signal.
pub fn exception_signal(exc: &Exception) -> Signal {
    match exc {
        Exception::Access(f) => match f.kind {
            // EXC_BAD_ACCESS / KERN_INVALID_ADDRESS.
            AccessFaultKind::Unmapped => SIGSEGV,
            // KERN_PROTECTION_FAILURE, alignment (EXC_ARM_DA_ALIGN), and
            // backing-store errors.
            AccessFaultKind::Permission | AccessFaultKind::Alignment | AccessFaultKind::Bus => {
                SIGBUS
            }
        },
        Exception::Undefined { .. } => SIGILL,
        Exception::Breakpoint { .. } => SIGTRAP,
        Exception::X86(e) => match e.vector {
            // #DE, #OF, #MF, #XM: EXC_ARITHMETIC.
            0 | 4 | 16 | 19 => SIGFPE,
            // #DB, #BP: EXC_BREAKPOINT; #BR: EXC_SOFTWARE/EXC_I386_BOUND.
            1 | 3 | 5 => SIGTRAP,
            // #UD, #SS (EXC_BAD_INSTRUCTION/EXC_I386_STKFLT).
            6 | 12 => SIGILL,
            // #AC: EXC_BAD_ACCESS/EXC_I386_ALIGNFLT.
            17 => SIGBUS,
            // #GP and a software interrupt without a user gate.
            _ if e.source == X86EventSource::SoftwareInterrupt => SIGSEGV,
            _ => SIGSEGV,
        },
    }
}

/// The host's number for signal `sig` (the same numbers on a macOS host).
pub fn to_host(sig: Signal) -> Option<i32> {
    #[cfg(target_os = "macos")]
    {
        (0..=31).contains(&sig).then_some(sig)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(match sig {
            0 => 0,
            SIGHUP => libc::SIGHUP,
            SIGINT => libc::SIGINT,
            SIGQUIT => libc::SIGQUIT,
            SIGILL => libc::SIGILL,
            SIGTRAP => libc::SIGTRAP,
            SIGABRT => libc::SIGABRT,
            SIGFPE => libc::SIGFPE,
            SIGKILL => libc::SIGKILL,
            SIGBUS => libc::SIGBUS,
            SIGSEGV => libc::SIGSEGV,
            SIGSYS => libc::SIGSYS,
            SIGPIPE => libc::SIGPIPE,
            SIGALRM => libc::SIGALRM,
            SIGTERM => libc::SIGTERM,
            SIGURG => libc::SIGURG,
            SIGSTOP => libc::SIGSTOP,
            SIGTSTP => libc::SIGTSTP,
            SIGCONT => libc::SIGCONT,
            SIGCHLD => libc::SIGCHLD,
            SIGTTIN => libc::SIGTTIN,
            SIGTTOU => libc::SIGTTOU,
            SIGIO => libc::SIGIO,
            SIGXCPU => libc::SIGXCPU,
            SIGXFSZ => libc::SIGXFSZ,
            SIGVTALRM => libc::SIGVTALRM,
            SIGPROF => libc::SIGPROF,
            SIGWINCH => libc::SIGWINCH,
            SIGUSR1 => libc::SIGUSR1,
            SIGUSR2 => libc::SIGUSR2,
            _ => return None,
        })
    }
}

fn bit(sig: Signal) -> u32 {
    1 << (sig - 1)
}

/// Sends `sig` to the process (`psignal`): it becomes pending for the
/// process and a thread that does not block it takes it.
pub fn post_process(proc: &mut Proc, running: &mut Thread, sig: Signal) {
    if ignored(proc, sig) {
        return;
    }
    proc.pending |= bit(sig);
    let _ = running;
    for t in proc.threads.values_mut() {
        if t.sigmask & bit(sig) == 0 && t.wait.as_ref().is_some_and(|w| w.interruptible) {
            t.woken = true;
        }
    }
}

/// Sends `sig` to one thread (`psignal_uthread`).
pub fn post_thread(proc: &mut Proc, thread: &mut Thread, sig: Signal) {
    if ignored(proc, sig) {
        return;
    }
    thread.pending |= bit(sig);
}

/// Whether `sig` is discarded when sent: ignored explicitly or by default.
fn ignored(proc: &Proc, sig: Signal) -> bool {
    let a = proc.sigactions[sig as usize - 1];
    a.handler == SIG_IGN || (a.handler == SIG_DFL && default_action(sig) == DefaultAction::Ignore)
}

/// Delivers the pending, unblocked signals of `thread` that end the
/// process by their default action. Returns the signals left pending for
/// a handler.
pub fn deliver_defaults(proc: &mut Proc, thread: &mut Thread) -> u32 {
    let ready = (thread.pending | proc.pending) & !thread.sigmask;
    for sig in 1..=31 {
        if ready & bit(sig) == 0 {
            continue;
        }
        let a = proc.sigactions[sig as usize - 1];
        if a.handler != SIG_DFL {
            continue;
        }
        thread.pending &= !bit(sig);
        proc.pending &= !bit(sig);
        match default_action(sig) {
            DefaultAction::Kill | DefaultAction::Core => {
                let pc = thread.cpu.pc();
                terminate(proc, thread, sig, pc);
                return 0;
            }
            // Job control is not modelled: stop and continue do nothing.
            DefaultAction::Ignore | DefaultAction::Stop | DefaultAction::Continue => {}
        }
    }
    (thread.pending | proc.pending) & !thread.sigmask
}

/// Raises a machine exception on `thread`. Without handler support in
/// place of a delivery frame, the signal's default action applies: the
/// process ends by the signal.
pub fn raise_exception(proc: &mut Proc, thread: &mut Thread, exc: &Exception) {
    let sig = exception_signal(exc);
    terminate(proc, thread, sig, exc.pc());
}

/// Ends the process by `sig`.
pub fn terminate(proc: &mut Proc, thread: &mut Thread, sig: Signal, pc: u64) {
    let _ = thread;
    proc.exit_with(ExitStatus::Signaled {
        signo: sig,
        core: default_action(sig) == DefaultAction::Core,
        pc,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::MemoryAccessKind;
    use crate::user::cpu::AccessFault;

    #[test]
    fn exceptions_translate_as_ux_exception_does() {
        let fault = |kind| {
            Exception::Access(AccessFault {
                addr: 0,
                access: MemoryAccessKind::Write,
                kind,
                pc: 0,
            })
        };
        assert_eq!(exception_signal(&fault(AccessFaultKind::Unmapped)), SIGSEGV);
        assert_eq!(
            exception_signal(&fault(AccessFaultKind::Permission)),
            SIGBUS
        );
        assert_eq!(exception_signal(&fault(AccessFaultKind::Alignment)), SIGBUS);
        assert_eq!(
            exception_signal(&Exception::Undefined {
                pc: 0,
                reason: String::new()
            }),
            SIGILL
        );
        assert_eq!(
            exception_signal(&Exception::Breakpoint { pc: 0, imm: 0 }),
            SIGTRAP
        );
    }

    #[test]
    fn default_actions() {
        assert_eq!(default_action(SIGSEGV), DefaultAction::Core);
        assert_eq!(default_action(SIGTERM), DefaultAction::Kill);
        assert_eq!(default_action(SIGCHLD), DefaultAction::Ignore);
        assert_eq!(default_action(SIGTSTP), DefaultAction::Stop);
        assert_eq!(name(SIGUSR2), "SIGUSR2");
        assert_eq!(name(40), "signal 40");
    }
}
