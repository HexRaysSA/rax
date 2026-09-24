//! Signal generation and delivery.
//!
//! Generation follows `__send_signal_locked`/`prepare_signal` and
//! `force_sig_info_to_task` in `kernel/signal.c`; delivery follows
//! `get_signal`, `signal_delivered`, and the architectures'
//! `arch_do_signal_or_restart`, which the kernel runs on every return to
//! user mode with a signal pending. The personality calls
//! [`LinuxProcess::deliver_signals`] before resuming a thread.
//!
//! System calls interrupted by a signal return one of the kernel-internal
//! restart codes; they never reach user space. With a handler to run,
//! `-ERESTARTNOHAND` and `-ERESTART_RESTARTBLOCK` become `-EINTR`, as does
//! `-ERESTARTSYS` unless the action has `SA_RESTART`; otherwise the call is
//! re-executed (`restart_syscall` for `-ERESTART_RESTARTBLOCK`).

use super::frame::{self, Delivery, FaultUpdate};
use super::{
    AltStack, KERNEL_ONLY_MASK, SIG_DFL, SIG_IGN, SIGCONT, SIGKILL, SIGSEGV, SIGSTOP, SIGTSTP,
    SIGTTIN, SIGTTOU, SigInfo, default_dumps_core, default_ignored, default_stops, sa, sigmask,
    signal_name, ss,
};
use crate::user::linux::abi::errno_table::EINTR;
use crate::user::linux::process::{ExitStatus, LinuxProcess, ProcState, Thread};

/// Kernel-internal restart codes (`include/linux/errno.h`), returned by
/// interrupted system calls and resolved before the return to user mode.
pub mod restart {
    /// Restart if the handler has `SA_RESTART` (or there is no handler).
    pub const ERESTARTSYS: i32 = 512;
    /// Always restart.
    pub const ERESTARTNOINTR: i32 = 513;
    /// Restart only if no handler runs.
    pub const ERESTARTNOHAND: i32 = 514;
    /// Restart through `restart_syscall` if no handler runs.
    pub const ERESTART_RESTARTBLOCK: i32 = 516;

    /// Whether `value` (a result register) holds a restart code.
    pub fn is_restart(value: u64) -> bool {
        matches!(-(value as i64), 512 | 513 | 514 | 516)
    }
}

/// `__NR_restart_syscall` of an ABI.
fn restart_syscall_nr(p: &ProcState) -> u64 {
    p.abi
        .number(crate::user::linux::abi::Sysno::RestartSyscall)
        .expect("every ABI defines restart_syscall")
}

/// The system call a thread is returning from, kept until the return to
/// user mode for restart processing (x86 `orig_ax`, arm64 `orig_x0` and
/// `syscallno`, riscv `orig_a0` and `cause == EXC_SYSCALL`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallEntry {
    /// The number.
    pub nr: u64,
    /// The first argument.
    pub arg0: u64,
}

/// How a forced signal treats the current disposition
/// (`enum sig_handler`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForceMode {
    /// Keep a handler; reset only an ignored or blocked signal
    /// (`HANDLER_CURRENT`, `force_sig_fault`, `force_sig`).
    Current,
    /// Reset the disposition to `SIG_DFL` (`HANDLER_SIG_DFL`,
    /// `force_fatal_sig`).
    Default,
}

/// Whether `sig` is ignored for delivery to `t` (`sig_ignored`): blocked
/// signals are never ignored, since the handler may change before they are
/// unblocked.
fn sig_ignored(p: &ProcState, t: &Thread, sig: i32, force: bool) -> bool {
    if t.sigmask & sigmask(sig) != 0 {
        return false;
    }
    let handler = p.sigactions[(sig - 1) as usize].handler;
    // sig_task_ignored: a namespace init ignores default-action signals
    // unless SIGKILL/SIGSTOP are forced on it.
    if p.unkillable && handler == SIG_DFL && !(force && sigmask(sig) & KERNEL_ONLY_MASK != 0) {
        return true;
    }
    handler == SIG_IGN || (handler == SIG_DFL && default_ignored(sig))
}

/// `prepare_signal`: stop and continue signals cancel each other, and an
/// ignored signal is dropped at generation.
fn prepare_signal(p: &mut ProcState, t: &mut Thread, sig: i32, force: bool) -> bool {
    let stops = sigmask(SIGSTOP) | sigmask(SIGTSTP) | sigmask(SIGTTIN) | sigmask(SIGTTOU);
    if default_stops(sig) {
        p.shared_pending.flush(sigmask(SIGCONT));
        t.pending.flush(sigmask(SIGCONT));
    } else if sig == SIGCONT {
        p.shared_pending.flush(stops);
        t.pending.flush(stops);
    }
    !sig_ignored(p, t, sig, force)
}

/// Generates `info` for the process (`to_thread == false`, `PIDTYPE_TGID`)
/// or for thread `t` (`PIDTYPE_PID`). `force` marks kernel-generated
/// signals that a namespace init cannot ignore. Returns whether the
/// signal is now pending.
pub fn send_signal(
    p: &mut ProcState,
    t: &mut Thread,
    info: SigInfo,
    to_thread: bool,
    force: bool,
) -> bool {
    if !prepare_signal(p, t, info.signo, force) {
        return false;
    }
    if to_thread {
        t.pending.enqueue(info);
    } else {
        p.shared_pending.enqueue(info);
    }
    true
}

/// `force_sig_info_to_task`: a synchronous signal the thread cannot block
/// or ignore; a blocked or ignored signal (or any, with
/// [`ForceMode::Default`]) is reset to its default action and unblocked.
pub fn force_signal(p: &mut ProcState, t: &mut Thread, info: SigInfo, mode: ForceMode) {
    let idx = (info.signo - 1) as usize;
    let action = &mut p.sigactions[idx];
    let blocked = t.sigmask & sigmask(info.signo) != 0;
    if blocked || action.handler == SIG_IGN || mode != ForceMode::Current {
        action.handler = SIG_DFL;
        if blocked {
            t.sigmask &= !sigmask(info.signo);
        }
    }
    if p.sigactions[idx].handler == SIG_DFL {
        p.unkillable = false;
    }
    let force = info.code == super::code::SI_KERNEL;
    send_signal(p, t, info, true, force);
}

/// `force_sigsegv`: after a handler frame could not be written. A failure
/// delivering `SIGSEGV` itself makes it fatal.
pub fn force_sigsegv(p: &mut ProcState, t: &mut Thread, sig: i32) {
    let mode = if sig == SIGSEGV {
        ForceMode::Default
    } else {
        ForceMode::Current
    };
    force_signal(p, t, SigInfo::kernel(SIGSEGV), mode);
}

/// What `get_signal` found.
enum Next {
    /// Nothing deliverable.
    None,
    /// Run a handler.
    Handler(Delivery),
    /// The process is exiting.
    Exit,
}

/// Formats a delivered signal the way `strace` does.
fn trace_signal(tid: i32, info: &SigInfo) {
    eprintln!(
        "[{tid}] --- {} {{si_signo={}, si_code={}, si_pid={}, si_uid={}, si_addr={:#x}}} ---",
        signal_name(info.signo),
        signal_name(info.signo),
        info.code,
        info.pid(),
        info.uid(),
        info.addr()
    );
}

impl LinuxProcess {
    /// Whether thread `idx` has work at its return to user mode: a signal
    /// it does not block, a system call to finish, or a mask to restore.
    fn signal_work(&self, idx: usize) -> bool {
        let t = &self.threads[idx];
        t.syscall.is_some()
            || t.saved_sigmask.is_some()
            || t.pending.next(t.sigmask).is_some()
            || self.state.shared_pending.next(t.sigmask).is_some()
    }

    /// `get_signal`: dequeues signals for thread `idx` until one has a
    /// handler, taking default actions on the way.
    fn get_signal(&mut self, idx: usize) -> Next {
        loop {
            let (p, t) = (&mut self.state, &mut self.threads[idx]);
            let info = t
                .pending
                .dequeue_synchronous(t.sigmask)
                .or_else(|| t.pending.dequeue(t.sigmask))
                .or_else(|| p.shared_pending.dequeue(t.sigmask));
            let Some(info) = info else {
                return Next::None;
            };
            if p.config.strace {
                trace_signal(t.tid, &info);
            }
            let sig = info.signo;
            let action = p.sigactions[(sig - 1) as usize];
            if action.handler == SIG_IGN {
                continue;
            }
            if action.handler != SIG_DFL {
                if action.flags & sa::RESETHAND != 0 {
                    p.sigactions[(sig - 1) as usize].handler = SIG_DFL;
                }
                return Next::Handler(Delivery {
                    sig,
                    info,
                    action,
                    saved_mask: t.saved_sigmask.unwrap_or(t.sigmask),
                });
            }
            if default_ignored(sig) {
                continue;
            }
            if p.unkillable && sigmask(sig) & KERNEL_ONLY_MASK == 0 {
                continue;
            }
            if default_stops(sig) {
                // Group stop. Process groups are never treated as
                // orphaned, so SIGTSTP/SIGTTIN/SIGTTOU stop as SIGSTOP does:
                // the host process stops until the host continues it.
                let _ = std::io::Write::flush(&mut std::io::stdout());
                crate::user::linux::host::stop_self();
                continue;
            }
            let pc = t.cpu.pc();
            p.exit = Some(ExitStatus::Signaled {
                info,
                pc,
                core: default_dumps_core(sig) && sig != SIGKILL,
            });
            return Next::Exit;
        }
    }

    /// `handle_signal` minus the restart fixups: builds the frame, then
    /// `signal_setup_done`.
    fn handle_signal(&mut self, idx: usize, d: &Delivery) {
        let (p, t) = (&mut self.state, &mut self.threads[idx]);
        if frame::setup_rt_frame(t, &p.space, d, p.sigtramp).is_err() {
            force_sigsegv(p, t, d.sig);
            return;
        }
        // signal_delivered.
        t.saved_sigmask = None;
        let mut blocked = t.sigmask | d.action.mask;
        if d.action.flags & sa::NODEFER == 0 {
            blocked |= sigmask(d.sig);
        }
        t.sigmask = blocked & !KERNEL_ONLY_MASK;
        if t.altstack.flags & ss::AUTODISARM != 0 {
            t.altstack = AltStack::DISABLED;
        }
    }

    /// The work the kernel does on return to user mode for thread `idx`:
    /// system-call restart, then delivery of every signal it does not
    /// block. Handlers nest: each delivery builds a frame below the last.
    pub fn deliver_signals(&mut self, idx: usize) {
        if !self.signal_work(idx) {
            return;
        }
        use restart::*;
        let restart_nr = restart_syscall_nr(&self.state);
        let t = &mut self.threads[idx];
        // arch_do_signal_or_restart: provisionally restart the call.
        let mut rewound = None;
        if let Some(entry) = t.syscall.take() {
            let value = t.cpu.syscall_return_value();
            if is_restart(value) {
                let continue_pc = t.cpu.pc();
                t.cpu.rewind_syscall(entry.nr, entry.arg0);
                rewound = Some((-(value as i64) as i32, continue_pc));
            }
        }
        loop {
            match self.get_signal(idx) {
                Next::Exit => return,
                Next::Handler(d) => {
                    if let Some((code, continue_pc)) = rewound.take() {
                        let interrupt = code == ERESTARTNOHAND
                            || code == ERESTART_RESTARTBLOCK
                            || (code == ERESTARTSYS && d.action.flags & sa::RESTART == 0);
                        if interrupt {
                            let cpu = &mut self.threads[idx].cpu;
                            cpu.set_pc(continue_pc);
                            cpu.set_syscall_result(-(EINTR as i64) as u64);
                        }
                    }
                    self.handle_signal(idx, &d);
                }
                Next::None => {
                    let t = &mut self.threads[idx];
                    if let Some((ERESTART_RESTARTBLOCK, _)) = rewound {
                        t.cpu.set_syscall_number(restart_nr);
                    }
                    // restore_saved_sigmask.
                    if let Some(mask) = t.saved_sigmask.take() {
                        t.sigmask = mask;
                    }
                    return;
                }
            }
        }
    }

    /// Delivers a CPU-raised synchronous signal to thread `idx`.
    pub fn trap_signal(&mut self, idx: usize, info: SigInfo, update: FaultUpdate) {
        let (p, t) = (&mut self.state, &mut self.threads[idx]);
        t.fault.apply(update);
        force_signal(p, t, info, ForceMode::Current);
    }
}
