//! Darwin signals: dispositions, posting, and delivery
//! (`bsd/kern/kern_sig.c`), and the translation of machine exceptions
//! (`bsd/uxkern/ux_exception.c` with the machine hooks of
//! `bsd/dev/{arm,i386}/unix_signal.c`).
//!
//! As in XNU, every pending signal belongs to a thread: a signal sent to
//! the process is posted to the first thread (in creation order) that
//! does not block it ([`psignal`]), one sent to a thread stays with it,
//! and a machine exception signals the faulting thread ([`threadsignal`]).
//! On the way back to user mode — after a system call, an exception, or
//! the end of a time slice — [`ast`] takes the thread's deliverable
//! signals (`issignal`) and acts on each (`postsig`): the default action
//! ends the process, a handler gets a signal frame ([`frame::sendsig`]).
//! A signal ends an interruptible sleep: the call fails with `EINTR`, or
//! restarts after the handler when the action has `SA_RESTART`
//! ([`interruption`]).
//!
//! Job control is the host's: a stop signal's default action stops the
//! emulator process ([`host::stop`]), which the host continues.

pub mod frame;
pub mod host;
pub mod timer;

use std::collections::BTreeMap;

use super::arch::Exception;
use super::process::{ExitStatus, Proc, Thread};
use crate::isa::x86_64::X86EventSource;
use crate::user::cpu::AccessFaultKind;

pub use host::{die_by_signal, to_host};

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

/// `NSIG`: signal numbers are below it.
pub const NSIG: i32 = 32;

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

/// Signal properties (`SA_KILL` ... `SA_CONT` in `bsd/sys/signalvar.h`).
pub mod prop {
    /// Terminates the process by default.
    pub const KILL: u32 = 0x01;
    /// Terminates the process and dumps core by default.
    pub const CORE: u32 = 0x02;
    /// Stops the process by default.
    pub const STOP: u32 = 0x04;
    /// A stop from the terminal.
    pub const TTYSTOP: u32 = 0x08;
    /// Ignored by default.
    pub const IGNORE: u32 = 0x10;
    /// Continues a stopped process.
    pub const CONT: u32 = 0x20;
}

/// `sigprop[]`.
const PROPS: [u32; 32] = {
    use prop::*;
    [
        0,
        KILL,           // SIGHUP
        KILL,           // SIGINT
        KILL | CORE,    // SIGQUIT
        KILL | CORE,    // SIGILL
        KILL | CORE,    // SIGTRAP
        KILL | CORE,    // SIGABRT
        KILL | CORE,    // SIGEMT
        KILL | CORE,    // SIGFPE
        KILL,           // SIGKILL
        KILL | CORE,    // SIGBUS
        KILL | CORE,    // SIGSEGV
        KILL | CORE,    // SIGSYS
        KILL,           // SIGPIPE
        KILL,           // SIGALRM
        KILL,           // SIGTERM
        IGNORE,         // SIGURG
        STOP,           // SIGSTOP
        STOP | TTYSTOP, // SIGTSTP
        IGNORE | CONT,  // SIGCONT
        IGNORE,         // SIGCHLD
        STOP | TTYSTOP, // SIGTTIN
        STOP | TTYSTOP, // SIGTTOU
        IGNORE,         // SIGIO
        KILL,           // SIGXCPU
        KILL,           // SIGXFSZ
        KILL,           // SIGVTALRM
        KILL,           // SIGPROF
        IGNORE,         // SIGWINCH
        IGNORE,         // SIGINFO
        KILL,           // SIGUSR1
        KILL,           // SIGUSR2
    ]
};

/// The properties of `sig` (1 ..= 31).
pub fn props(sig: Signal) -> u32 {
    PROPS[sig as usize]
}

/// A signal's default action.
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
    /// Continue a stopped process (and otherwise ignore the signal).
    Continue,
}

/// The default action of `sig`.
pub fn default_action(sig: Signal) -> DefaultAction {
    let p = props(sig);
    if p & prop::CORE != 0 {
        DefaultAction::Core
    } else if p & prop::KILL != 0 {
        DefaultAction::Kill
    } else if p & prop::STOP != 0 {
        DefaultAction::Stop
    } else if p & prop::CONT != 0 {
        DefaultAction::Continue
    } else {
        DefaultAction::Ignore
    }
}

/// `sigmask(sig)`.
pub fn bit(sig: Signal) -> u32 {
    1 << (sig - 1)
}

/// `sigcantmask`: signals that can be neither caught nor blocked.
pub const CANTMASK: u32 = (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1));

/// `threadmask`: the signals a machine exception can raise on a thread.
pub const THREADMASK: u32 = (1 << (SIGILL - 1))
    | (1 << (SIGTRAP - 1))
    | (1 << (SIGABRT - 1))
    | (1 << (SIGEMT - 1))
    | (1 << (SIGFPE - 1))
    | (1 << (SIGBUS - 1))
    | (1 << (SIGSEGV - 1))
    | (1 << (SIGSYS - 1))
    | (1 << (SIGPIPE - 1))
    | (1 << (SIGKILL - 1));

/// `stopsigmask`.
const STOPMASK: u32 =
    (1 << (SIGSTOP - 1)) | (1 << (SIGTSTP - 1)) | (1 << (SIGTTIN - 1)) | (1 << (SIGTTOU - 1));

/// `contsigmask`.
const CONTMASK: u32 = 1 << (SIGCONT - 1);

/// `sigaction` flags (`bsd/sys/signal.h`).
pub mod sa {
    /// `SA_ONSTACK`.
    pub const ONSTACK: u32 = 0x0001;
    /// `SA_RESTART`.
    pub const RESTART: u32 = 0x0002;
    /// `SA_RESETHAND`.
    pub const RESETHAND: u32 = 0x0004;
    /// `SA_NOCLDSTOP`.
    pub const NOCLDSTOP: u32 = 0x0008;
    /// `SA_NODEFER`.
    pub const NODEFER: u32 = 0x0010;
    /// `SA_NOCLDWAIT`.
    pub const NOCLDWAIT: u32 = 0x0020;
    /// `SA_SIGINFO`.
    pub const SIGINFO: u32 = 0x0040;
    /// `SA_VALIDATE_SIGRETURN_FROM_SIGTRAMP`.
    pub const VALIDATE_SIGRETURN: u32 = 0x0400;
    /// `SA_USERSPACE_MASK`: the flags the kernel keeps.
    pub const USERSPACE_MASK: u32 =
        ONSTACK | RESTART | RESETHAND | NOCLDSTOP | NODEFER | NOCLDWAIT | SIGINFO;
}

/// `SS_ONSTACK` (`SA_ONSTACK` in the kernel's stack flags).
pub const SS_ONSTACK: u32 = 0x0001;
/// `SS_DISABLE` (`SA_DISABLE`).
pub const SS_DISABLE: u32 = 0x0004;

/// `SIG_DFL`.
pub const SIG_DFL: u64 = 0;
/// `SIG_IGN`.
pub const SIG_IGN: u64 = 1;

/// Whether `sigreturn` checks its token (`ps_sigreturn_validation`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Validation {
    /// No `sigaction` set it yet: tokens are checked.
    #[default]
    Default,
    /// A `sigaction` asked for checks (`SA_VALIDATE_SIGRETURN_FROM_SIGTRAMP`).
    Enabled,
    /// A `sigaction` without that flag came first: tokens are not checked.
    Disabled,
}

/// Where the last caught signal came from, for its `siginfo_t`
/// (`p->si_pid`, `si_uid`, `si_status`, `si_code`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Origin {
    /// The sending process (0 for the kernel).
    pub pid: i32,
    /// Its real user ID.
    pub uid: u32,
    /// `si_status` with the exit code in bits 8-15 (`W_EXITCODE`).
    pub status: i32,
    /// `si_code`.
    pub code: i32,
}

impl Origin {
    /// A signal the kernel sent (a timer's).
    pub const KERNEL: Origin = Origin {
        pid: 0,
        uid: 0,
        status: 0,
        code: 0,
    };

    /// A signal `kill` (or the kernel on the process's behalf) sent from
    /// process `pid` with real user `uid`.
    pub fn process(pid: i32, uid: u32) -> Self {
        Origin {
            pid,
            uid,
            status: 0,
            code: 0,
        }
    }

    /// A signal the process sent itself.
    pub fn own(proc: &Proc) -> Self {
        Origin::process(proc.pid, proc.creds.0)
    }
}

/// A process's signal actions (`struct sigacts` and the `p_sig*` sets).
#[derive(Clone, Debug)]
pub struct SigActs {
    /// `SIG_DFL`, `SIG_IGN`, or the handler, by signal number.
    pub handler: [u64; 32],
    /// The trampoline libSystem registered with each (`_sigtramp`).
    pub tramp: [u64; 32],
    /// Signals blocked while each handler runs (`ps_catchmask`).
    pub catchmask: [u32; 32],
    /// Handlers taking `siginfo_t` (`ps_siginfo`).
    pub siginfo: u32,
    /// Signals that interrupt system calls instead of restarting them
    /// (`ps_sigintr`: those without `SA_RESTART`).
    pub intr: u32,
    /// Signals handled on the alternate stack (`ps_sigonstack`).
    pub onstack: u32,
    /// Signals whose action resets when taken (`ps_sigreset`).
    pub reset: u32,
    /// Signals not blocked during their handler (`ps_signodefer`).
    pub nodefer: u32,
    /// Signals discarded when sent (`p_sigignore`).
    pub ignore: u32,
    /// Signals with a handler (`p_sigcatch`).
    pub catch: u32,
    /// `P_NOCLDSTOP`.
    pub nocldstop: bool,
    /// `P_NOCLDWAIT`.
    pub nocldwait: bool,
    /// `ps_sigreturn_validation`.
    pub validation: Validation,
    /// The origin of the last caught signal.
    pub origin: Origin,
    /// Signals taken (`ru_nsignals`).
    pub taken: u64,
}

impl Default for SigActs {
    /// `siginit`: every action is the default, and the signals the
    /// default ignores (but `SIGCONT`) are discarded.
    fn default() -> Self {
        let ignore = (1..NSIG)
            .filter(|&s| props(s) & prop::IGNORE != 0 && s != SIGCONT)
            .fold(0, |m, s| m | bit(s));
        SigActs {
            handler: [SIG_DFL; 32],
            tramp: [0; 32],
            catchmask: [0; 32],
            siginfo: 0,
            intr: 0,
            onstack: 0,
            reset: 0,
            nodefer: 0,
            ignore,
            catch: 0,
            nocldstop: false,
            nocldwait: false,
            validation: Validation::Default,
            origin: Origin::default(),
            taken: 0,
        }
    }
}

/// Signal state a program inherits across `exec` (`execsigs`): what its
/// parent ignored, the flag sets of the actions, and the blocked mask.
/// Caught signals revert to their default actions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Inherited {
    /// Signals set to `SIG_IGN`.
    pub ignore: u32,
    /// Signals whose actions lack `SA_RESTART`.
    pub intr: u32,
    /// `SA_ONSTACK` actions.
    pub onstack: u32,
    /// `SA_SIGINFO` actions.
    pub siginfo: u32,
    /// `SA_NODEFER` actions.
    pub nodefer: u32,
    /// `SA_RESETHAND` actions.
    pub reset: u32,
    /// The blocked mask.
    pub mask: u32,
}

impl SigActs {
    /// The actions of a program started with `inh`.
    pub fn inherited(inh: &Inherited) -> Self {
        let mut acts = SigActs {
            intr: inh.intr,
            onstack: inh.onstack,
            siginfo: inh.siginfo,
            nodefer: inh.nodefer,
            reset: inh.reset,
            ..SigActs::default()
        };
        for sig in 1..NSIG {
            if inh.ignore & bit(sig) != 0 && bit(sig) & CANTMASK == 0 {
                acts.handler[sig as usize] = SIG_IGN;
                if sig != SIGCONT {
                    acts.ignore |= bit(sig);
                }
            }
        }
        acts
    }
}

/// A new action for a signal (`struct __kern_sigaction`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigAction {
    /// `SIG_DFL`, `SIG_IGN`, or the handler.
    pub handler: u64,
    /// The trampoline.
    pub tramp: u64,
    /// Signals blocked while the handler runs.
    pub mask: u32,
    /// `SA_*` flags.
    pub flags: u32,
}

impl SigActs {
    /// Installs `sa` for `sig` (`setsigvec`). Returns whether the new
    /// action discards the signal, so that its pending instances must go
    /// (`clear_procsiglist`).
    pub fn set(&mut self, sig: Signal, sa: &SigAction) -> bool {
        let b = bit(sig);
        let i = sig as usize;
        self.handler[i] = sa.handler;
        self.tramp[i] = sa.tramp;
        self.catchmask[i] = sa.mask & !CANTMASK;
        let assign = |set: &mut u32, on: bool| {
            if on { *set |= b } else { *set &= !b }
        };
        assign(&mut self.siginfo, sa.flags & sa::SIGINFO != 0);
        assign(&mut self.intr, sa.flags & sa::RESTART == 0);
        assign(&mut self.onstack, sa.flags & sa::ONSTACK != 0);
        assign(&mut self.reset, sa.flags & sa::RESETHAND != 0);
        assign(&mut self.nodefer, sa.flags & sa::NODEFER != 0);
        if sig == SIGCHLD {
            self.nocldstop = sa.flags & sa::NOCLDSTOP != 0;
            self.nocldwait = sa.flags & sa::NOCLDWAIT != 0 || sa.handler == SIG_IGN;
        }
        if sa.handler == SIG_IGN || (props(sig) & prop::IGNORE != 0 && sa.handler == SIG_DFL) {
            if sig != SIGCONT {
                self.ignore |= b;
            }
            self.catch &= !b;
            true
        } else {
            self.ignore &= !b;
            assign(&mut self.catch, sa.handler != SIG_DFL);
            false
        }
    }

    /// The action `sigaction` reports for `sig`: the handler, the mask,
    /// and the flags the kernel can reconstruct (`SA_RESETHAND` is not
    /// among them).
    pub fn get(&self, sig: Signal) -> SigAction {
        let b = bit(sig);
        let mut flags = 0;
        if self.onstack & b != 0 {
            flags |= sa::ONSTACK;
        }
        if self.intr & b == 0 {
            flags |= sa::RESTART;
        }
        if self.siginfo & b != 0 {
            flags |= sa::SIGINFO;
        }
        if self.nodefer & b != 0 {
            flags |= sa::NODEFER;
        }
        if sig == SIGCHLD && self.nocldstop {
            flags |= sa::NOCLDSTOP;
        }
        if sig == SIGCHLD && self.nocldwait {
            flags |= sa::NOCLDWAIT;
        }
        SigAction {
            handler: self.handler[sig as usize],
            tramp: self.tramp[sig as usize],
            mask: self.catchmask[sig as usize],
            flags,
        }
    }
}

/// A thread's alternate signal stack (`uu_sigstk` and `UT_ALTSTACK`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AltStack {
    /// `ss_sp`.
    pub sp: u64,
    /// `ss_size`.
    pub size: u64,
    /// `ss_flags`: `SS_ONSTACK` while a handler runs on it, `SS_DISABLE`.
    pub flags: u32,
    /// Whether one is installed (`UT_ALTSTACK`).
    pub enabled: bool,
}

/// The machine state of a thread's last kernel entry that the exception
/// state flavors report (`ARM_EXCEPTION_STATE64`, `x86_EXCEPTION_STATE64`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EntryState {
    /// arm64 `FAR_EL1`; x86-64 `CR2`.
    pub far: u64,
    /// arm64 `ESR_EL1`.
    pub esr: u32,
    /// x86-64 trap number.
    pub trapno: u32,
    /// x86-64 error code.
    pub err: u32,
}

/// A thread's signal state (the `uu_sig*` fields of `struct uthread`).
#[derive(Clone, Debug, Default)]
pub struct ThreadSig {
    /// Blocked signals (`uu_sigmask`).
    pub mask: u32,
    /// Pending signals (`uu_siglist`).
    pub pending: u32,
    /// The mask to restore after the next handler (`uu_oldmask` with
    /// `UT_SAS_OLDMASK`), set by `sigsuspend` and `sigwait`.
    pub oldmask: Option<u32>,
    /// Signals `sigwait` waits for (`uu_sigwait`).
    pub waiting: u32,
    /// The signal a `sigwait` wait received.
    pub waited: u32,
    /// The alternate signal stack.
    pub altstack: AltStack,
    /// The exception code of the last machine exception (`uu_code`).
    pub code: i64,
    /// Its subcode (`uu_subcode`).
    pub subcode: i64,
    /// Handlers entered and not yet returned (`uu_pending_sigreturn`).
    pub pending_sigreturn: u32,
    /// The secret `sigreturn` tokens are made with (`uu_sigreturn_token`).
    pub token: u64,
    /// The arm64 thread-state diversifier (`uu_sigreturn_diversifier`).
    pub diversifier: u32,
    /// The last kernel entry's exception state.
    pub entry: EntryState,
}

/// The process's threads in creation order, `running` (not in the
/// thread map while it runs) included.
fn threads_in_order<'a>(
    threads: &'a mut BTreeMap<u64, Thread>,
    running: Option<&'a mut Thread>,
) -> Vec<&'a mut Thread> {
    let mut v: Vec<&mut Thread> = threads.values_mut().collect();
    if let Some(r) = running {
        let i = v.partition_point(|t| t.tid < r.tid);
        v.insert(i, r);
    }
    v
}

/// Interrupts `t`'s wait: an interruptible one (`thread_abort_safely`),
/// or any (`thread_abort`) when `hard`.
fn abort_wait(t: &mut Thread, hard: bool) {
    if t.wait.as_ref().is_some_and(|w| hard || w.interruptible) {
        t.woken = true;
    }
}

/// Who a signal is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    /// The process: a thread that does not block it takes it.
    Process,
    /// One thread (`PSIG_THREAD`).
    Thread(u64),
    /// Preferably one thread, else as for the process (`PSIG_TRY_THREAD`).
    TryThread(u64),
}

/// Sends `sig` to the process (`psignal`). `running` is the thread that
/// is executing, if any.
pub fn psignal(proc: &mut Proc, running: Option<&mut Thread>, sig: Signal, origin: Origin) {
    post(proc, running, Target::Process, sig, origin);
}

/// Sends `sig` to thread `tid` (`psignal_uthread`, `__pthread_kill`).
pub fn psignal_thread(
    proc: &mut Proc,
    running: Option<&mut Thread>,
    tid: u64,
    sig: Signal,
    origin: Origin,
) {
    post(proc, running, Target::Thread(tid), sig, origin);
}

/// Sends `sig` to thread `tid` unless it blocks it, else to the process
/// (`psignal_try_thread`).
pub fn psignal_try_thread(
    proc: &mut Proc,
    running: Option<&mut Thread>,
    tid: u64,
    sig: Signal,
    origin: Origin,
) {
    post(proc, running, Target::TryThread(tid), sig, origin);
}

/// `psignal_internal`.
fn post(
    proc: &mut Proc,
    running: Option<&mut Thread>,
    target: Target,
    sig: Signal,
    origin: Origin,
) {
    debug_assert!((1..NSIG).contains(&sig));
    let b = bit(sig);
    let p = props(sig);
    if proc.sigacts.ignore & b != 0 || proc.exit.is_some() {
        return;
    }
    let acts = &mut proc.sigacts;
    let mut threads = threads_in_order(&mut proc.threads, running);
    let takes = |t: &Thread| !t.exited && (t.sig.mask & b == 0 || t.sig.waiting & b != 0);
    let index = match target {
        Target::Thread(tid) => threads.iter().position(|t| t.tid == tid && !t.exited),
        Target::TryThread(tid) => threads
            .iter()
            .position(|t| t.tid == tid && takes(t))
            .or_else(|| threads.iter().position(|t| takes(t)))
            .or_else(|| threads.iter().position(|t| !t.exited)),
        // get_signalthread, then get_signalact (any thread).
        Target::Process => threads
            .iter()
            .position(|t| takes(t))
            .or_else(|| threads.iter().position(|t| !t.exited)),
    };
    let Some(index) = index else {
        return;
    };
    let t = &mut *threads[index];
    enum Action {
        Wait,
        Hold,
        Catch,
        Default,
    }
    let action = if t.sig.waiting & b != 0 {
        Action::Wait
    } else if t.sig.mask & b != 0 {
        Action::Hold
    } else if acts.catch & b != 0 {
        Action::Catch
    } else {
        Action::Default
    };
    if p & prop::CONT != 0 {
        t.sig.pending &= !STOPMASK;
    }
    if p & prop::STOP != 0 {
        t.sig.pending &= !CONTMASK;
    }
    t.sig.pending |= b;
    match action {
        Action::Hold => {}
        Action::Wait => {
            // The waiting sigwait takes it (and waits for no other).
            t.sig.waiting = b;
            t.sig.waited = b;
            t.sig.pending &= !b;
            abort_wait(t, false);
        }
        Action::Catch => {
            if sig != SIGCHLD {
                acts.origin = Origin {
                    status: sig << 8,
                    code: 0,
                    ..origin
                };
            }
            abort_wait(t, false);
        }
        Action::Default => {
            if b & STOPMASK != 0 {
                // The process stops now.
                t.sig.pending &= !b;
                drop(threads);
                host::stop(proc);
            } else if sig == SIGKILL {
                abort_wait(t, true);
            } else if sig == SIGCONT {
                // Continuing is the host's; wake only for other signals
                // this one uncovered.
                let others = t.sig.pending & !t.sig.mask & !acts.ignore & !b;
                t.sig.pending &= !b;
                if others != 0 {
                    abort_wait(t, false);
                }
            } else if p & prop::KILL != 0 {
                abort_wait(t, true);
            } else {
                abort_wait(t, false);
            }
        }
    }
}

/// Raises `sig` on `thread` for a machine exception with Mach exception
/// code `code` (`threadsignal`): the thread takes it even when it blocks
/// it, unless the process ignores it.
pub fn threadsignal(proc: &mut Proc, thread: &mut Thread, sig: Signal, code: i64) {
    let b = bit(sig);
    if b & THREADMASK == 0 || proc.sigacts.ignore & b != 0 {
        return;
    }
    thread.sig.pending |= b;
    thread.sig.code = code;
}

/// Removes `sig` from every thread's pending set (`clear_procsiglist`).
pub fn clear_pending(proc: &mut Proc, running: Option<&mut Thread>, sig: Signal) {
    for t in threads_in_order(&mut proc.threads, running) {
        t.sig.pending &= !bit(sig);
    }
}

/// The signal a sleep would be interrupted by (`CURSIG`): the lowest
/// pending, unblocked signal that is not discarded.
pub fn cursig(proc: &Proc, thread: &Thread) -> Option<Signal> {
    let bits = thread.sig.pending & !thread.sig.mask;
    (1..NSIG).find(|&sig| {
        let b = bit(sig);
        if bits & b == 0 || proc.sigacts.ignore & b != 0 {
            return false;
        }
        match proc.sigacts.handler[sig as usize] {
            SIG_DFL => props(sig) & prop::IGNORE == 0 || props(sig) & prop::STOP != 0,
            SIG_IGN => false,
            _ => true,
        }
    })
}

/// How a pending signal ends an interruptible sleep: `EINTR`, or
/// `ERESTART` (the call runs again after the handler) for an action with
/// `SA_RESTART`. `None` when no signal is deliverable.
pub fn interruption(proc: &Proc, thread: &Thread) -> Option<crate::user::darwin::abi::Errno> {
    use crate::user::darwin::abi::Errno;
    let sig = cursig(proc, thread)?;
    Some(if proc.sigacts.intr & bit(sig) != 0 {
        Errno::EINTR
    } else {
        Errno::ERESTART
    })
}

/// The next signal to act on (`issignal_locked`): discarded signals are
/// dropped, and a stop signal's default action stops the process.
fn issignal(proc: &mut Proc, thread: &mut Thread) -> Option<Signal> {
    loop {
        let bits = thread.sig.pending & !thread.sig.mask;
        if bits == 0 {
            return None;
        }
        let sig = bits.trailing_zeros() as Signal + 1;
        let b = bit(sig);
        let p = props(sig);
        thread.sig.pending &= !b;
        if proc.sigacts.ignore & b != 0 {
            continue;
        }
        match proc.sigacts.handler[sig as usize] {
            SIG_DFL if p & prop::STOP != 0 => host::stop(proc),
            SIG_DFL if p & prop::IGNORE != 0 => {}
            SIG_IGN => {}
            _ => return Some(sig),
        }
    }
}

/// Acts on `sig` (`postsig_locked`): the default action ends the process;
/// a handler is entered with the signal blocked.
fn postsig(proc: &mut Proc, thread: &mut Thread, sig: Signal) {
    let b = bit(sig);
    let catcher = proc.sigacts.handler[sig as usize];
    if catcher == SIG_DFL {
        let pc = thread.cpu.pc();
        terminate(proc, thread, sig, pc);
        return;
    }
    let returnmask = thread.sig.oldmask.take().unwrap_or(thread.sig.mask);
    let acts = &mut proc.sigacts;
    thread.sig.mask |= acts.catchmask[sig as usize];
    if acts.nodefer & b == 0 {
        thread.sig.mask |= b;
    }
    let siginfo = acts.siginfo;
    if sig != SIGILL && sig != SIGTRAP && acts.reset & b != 0 {
        if sig != SIGCONT && props(sig) & prop::IGNORE != 0 {
            acts.ignore |= b;
        }
        acts.handler[sig as usize] = SIG_DFL;
        acts.siginfo &= !b;
        acts.nodefer &= !b;
    }
    acts.taken += 1;
    if frame::sendsig(proc, thread, catcher, sig, returnmask, siginfo).is_err() {
        // The frame could not be written: SIGILL with its default action
        // ends the process.
        let ill = bit(SIGILL);
        let acts = &mut proc.sigacts;
        acts.handler[SIGILL as usize] = SIG_DFL;
        acts.ignore &= !ill;
        acts.catch &= !ill;
        thread.sig.mask &= !ill;
        let tid = thread.tid;
        psignal_try_thread(proc, Some(thread), tid, SIGILL, Origin::own(proc));
    }
}

/// Delivers `thread`'s deliverable signals on its way back to user mode
/// (`bsd_ast`).
pub fn ast(proc: &mut Proc, thread: &mut Thread) {
    while proc.exit.is_none() && !thread.exited {
        let Some(sig) = issignal(proc, thread) else {
            return;
        };
        postsig(proc, thread, sig);
    }
}

/// Mach exception types (`osfmk/mach/exception_types.h`).
pub mod exc {
    /// `EXC_BAD_ACCESS`.
    pub const BAD_ACCESS: i32 = 1;
    /// `EXC_BAD_INSTRUCTION`.
    pub const BAD_INSTRUCTION: i32 = 2;
    /// `EXC_ARITHMETIC`.
    pub const ARITHMETIC: i32 = 3;
    /// `EXC_SOFTWARE`.
    pub const SOFTWARE: i32 = 5;
    /// `EXC_BREAKPOINT`.
    pub const BREAKPOINT: i32 = 6;
    /// `EXC_SYSCALL`.
    pub const SYSCALL: i32 = 7;
    /// `KERN_INVALID_ADDRESS` as an `EXC_BAD_ACCESS` code.
    pub const KERN_INVALID_ADDRESS: i64 = 1;
    /// `KERN_PROTECTION_FAILURE` as an `EXC_BAD_ACCESS` code.
    pub const KERN_PROTECTION_FAILURE: i64 = 2;
    /// `KERN_MEMORY_ERROR` as an `EXC_BAD_ACCESS` code.
    pub const KERN_MEMORY_ERROR: i64 = 10;
    /// `EXC_ARM_DA_ALIGN`.
    pub const ARM_DA_ALIGN: i64 = 0x101;
    /// `EXC_ARM_UNDEFINED`, `EXC_ARM_BREAKPOINT`, `EXC_I386_INVOP`,
    /// `EXC_I386_DIV`, `EXC_I386_SGL`.
    pub const CODE_1: i64 = 1;
    /// `EXC_I386_BPT`, `EXC_I386_INTO`.
    pub const CODE_2: i64 = 2;
    /// `EXC_I386_EXTERR`.
    pub const I386_EXTERR: i64 = 5;
    /// `EXC_I386_BOUND`.
    pub const I386_BOUND: i64 = 7;
    /// `EXC_I386_SSEEXTERR`.
    pub const I386_SSEEXTERR: i64 = 8;
    /// `EXC_I386_SEGNPFLT`.
    pub const I386_SEGNPFLT: i64 = 11;
    /// `EXC_I386_STKFLT`.
    pub const I386_STKFLT: i64 = 12;
    /// `EXC_I386_GPFLT`.
    pub const I386_GPFLT: i64 = 13;
}

/// The Mach exception a machine exception raises: type, code, subcode
/// (`user_trap` in `osfmk/i386/trap.c`, `sleh.c` on arm64).
pub fn mach_exception(e: &Exception) -> (i32, i64, i64) {
    match e {
        Exception::Access(f) => {
            let code = match f.kind {
                AccessFaultKind::Unmapped => exc::KERN_INVALID_ADDRESS,
                AccessFaultKind::Permission => exc::KERN_PROTECTION_FAILURE,
                AccessFaultKind::Alignment => exc::ARM_DA_ALIGN,
                AccessFaultKind::Bus => exc::KERN_MEMORY_ERROR,
            };
            (exc::BAD_ACCESS, code, f.addr as i64)
        }
        Exception::Undefined { .. } => (exc::BAD_INSTRUCTION, exc::CODE_1, 0),
        Exception::Breakpoint { imm, .. } => (exc::BREAKPOINT, exc::CODE_1, i64::from(*imm)),
        Exception::X86(e) => {
            let err = e.error_code.unwrap_or(0) as i64;
            match e.vector {
                0 => (exc::ARITHMETIC, exc::CODE_1, 0),
                1 => (exc::BREAKPOINT, exc::CODE_1, 0),
                3 => (exc::BREAKPOINT, exc::CODE_2, 0),
                4 => (exc::ARITHMETIC, exc::CODE_2, 0),
                5 => (exc::SOFTWARE, exc::I386_BOUND, 0),
                11 => (exc::BAD_INSTRUCTION, exc::I386_SEGNPFLT, err),
                12 => (exc::BAD_INSTRUCTION, exc::I386_STKFLT, err),
                16 => (exc::ARITHMETIC, exc::I386_EXTERR, 0),
                19 => (exc::ARITHMETIC, exc::I386_SSEEXTERR, 0),
                // #GP and a software interrupt through a gate user code
                // may not use: SIGSEGV.
                13 => (exc::BAD_ACCESS, exc::I386_GPFLT, err),
                _ if e.source == X86EventSource::SoftwareInterrupt => {
                    (exc::BAD_ACCESS, exc::I386_GPFLT, err)
                }
                _ => (exc::BAD_INSTRUCTION, exc::CODE_1, 0),
            }
        }
    }
}

/// The signal a Mach exception becomes (`ux_exception` with the machine
/// hooks): 0 for none.
pub fn ux_exception(abi: crate::user::darwin::abi::DarwinAbi, exception: i32, code: i64) -> Signal {
    use crate::user::darwin::abi::DarwinAbi;
    // machine_exception.
    match (abi, exception) {
        (DarwinAbi::X86_64, exc::BAD_ACCESS) if code == exc::I386_GPFLT => return SIGSEGV,
        (DarwinAbi::X86_64, exc::SOFTWARE) if code == exc::I386_BOUND => return SIGTRAP,
        (_, exc::BAD_INSTRUCTION) => return SIGILL,
        (_, exc::ARITHMETIC) => return SIGFPE,
        _ => {}
    }
    match exception {
        exc::BAD_ACCESS if code == exc::KERN_INVALID_ADDRESS => SIGSEGV,
        exc::BAD_ACCESS => SIGBUS,
        exc::SYSCALL => SIGSYS,
        exc::BREAKPOINT => SIGTRAP,
        _ => 0,
    }
}

/// The signal a machine exception raises when no exception port takes
/// it (before the stack-overflow correction of [`raise_exception`]).
pub fn exception_signal(abi: crate::user::darwin::abi::DarwinAbi, e: &Exception) -> Signal {
    let (exception, code, _) = mach_exception(e);
    ux_exception(abi, exception, code)
}

/// The exception state a machine exception leaves (`FAR`/`ESR` on arm64,
/// trap number, error code, and `CR2` on x86-64).
fn entry_state(e: &Exception) -> EntryState {
    use crate::error::MemoryAccessKind;
    match e {
        Exception::Access(f) => {
            let write = f.access == MemoryAccessKind::Write;
            let fetch = f.access == MemoryAccessKind::Fetch;
            // Data or instruction abort from EL0, IL set, with the fault
            // status of a level-3 translation, permission, or alignment
            // fault, or a synchronous external abort.
            let fsc = match f.kind {
                AccessFaultKind::Unmapped => 0x07,
                AccessFaultKind::Permission => 0x0f,
                AccessFaultKind::Alignment => 0x21,
                AccessFaultKind::Bus => 0x10,
            };
            let ec: u32 = if fetch { 0x20 } else { 0x24 };
            let esr = (ec << 26) | (1 << 25) | if write { 1 << 6 } else { 0 } | fsc;
            // The page-fault error code: present, write, user, fetch.
            let err = u32::from(f.kind != AccessFaultKind::Unmapped)
                | if write { 2 } else { 0 }
                | 4
                | if fetch { 0x10 } else { 0 };
            EntryState {
                far: f.addr,
                esr,
                trapno: 14,
                err,
            }
        }
        Exception::Undefined { .. } => EntryState {
            esr: 1 << 25,
            trapno: 6,
            ..Default::default()
        },
        Exception::Breakpoint { imm, .. } => EntryState {
            esr: (0x3c << 26) | (1 << 25) | u32::from(*imm),
            trapno: 3,
            ..Default::default()
        },
        Exception::X86(e) => EntryState {
            trapno: u32::from(e.vector),
            err: e.error_code.unwrap_or(0) as u32,
            ..Default::default()
        },
    }
}

/// `MAXSSIZ`: the reservation of the main thread's stack.
const MAXSSIZ: u64 = 64 << 20;

/// Raises a machine exception on `thread` (`exception_triage` without an
/// exception port, then `handle_ux_exception`).
pub fn raise_exception(proc: &mut Proc, thread: &mut Thread, e: &Exception) {
    let (exception, code, subcode) = mach_exception(e);
    thread.sig.entry = entry_state(e);
    raise_mach(proc, thread, exception, code, subcode);
}

/// Raises Mach exception `exception` with `code` and `subcode` on
/// `thread`, which no exception port takes: the thread gets its signal
/// (`handle_ux_exception`).
pub fn raise_mach(proc: &mut Proc, thread: &mut Thread, exception: i32, code: i64, subcode: i64) {
    let mut sig = ux_exception(proc.abi, exception, code);
    // A stack overflow into the guard is a protection failure, but a
    // SIGSEGV, forced to its default action unless it can be handled on
    // the alternate stack.
    if code == exc::KERN_PROTECTION_FAILURE && sig == SIGBUS {
        let top = proc.program.stack.top;
        let addr = subcode as u64;
        if addr >= top.saturating_sub(MAXSSIZ) && addr < top {
            sig = SIGSEGV;
            let b = bit(SIGSEGV);
            let acts = &mut proc.sigacts;
            if acts.ignore & b != 0
                || thread.sig.waiting & b != 0
                || thread.sig.mask & b != 0
                || acts.handler[SIGSEGV as usize] == SIG_IGN
                || acts.onstack & b == 0
            {
                acts.ignore &= !b;
                acts.catch &= !b;
                acts.handler[SIGSEGV as usize] = SIG_DFL;
                thread.sig.waiting &= !b;
                thread.sig.mask &= !b;
            }
        }
    }
    if sig != 0 {
        thread.sig.subcode = subcode;
        threadsignal(proc, thread, sig, code);
    }
}

/// Ends the process by `sig` (the default action of a fatal signal).
pub fn terminate(proc: &mut Proc, thread: &mut Thread, sig: Signal, pc: u64) {
    let _ = thread;
    proc.exit_with(ExitStatus::Signaled {
        signo: sig,
        core: props(sig) & prop::CORE != 0,
        pc,
    });
}

#[cfg(test)]
mod tests;
