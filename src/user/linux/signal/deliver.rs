//! Signal generation and delivery.
//!
//! Generation follows `__send_signal_locked`/`prepare_signal`,
//! `complete_signal`, and `force_sig_info_to_task` in `kernel/signal.c`: a
//! signal is queued for one thread or for the process, and the thread that
//! should take it is woken (`signal_wake_up` sets its
//! [`sigpending`](crate::user::linux::process::Thread::sigpending) flag,
//! `TIF_SIGPENDING`), which ends a system call it sleeps in. A process
//! signal goes to the suggested thread if it wants it (`wants_signal`),
//! otherwise to the next thread in the list that does, starting from
//! `signal->curr_target`; one whose default action is fatal (and does not
//! dump core) takes the whole process down at once.
//!
//! Delivery follows `get_signal`, `signal_delivered`, and the
//! architectures' `arch_do_signal_or_restart`, which the kernel runs on
//! every return to user mode with the flag set. The personality calls
//! [`LinuxProcess::deliver_signals`] before resuming a thread.
//!
//! System calls interrupted by a signal return one of the kernel-internal
//! restart codes; they never reach user space. With a handler to run,
//! `-ERESTARTNOHAND` and `-ERESTART_RESTARTBLOCK` become `-EINTR`, as does
//! `-ERESTARTSYS` unless the action has `SA_RESTART`; otherwise the call is
//! re-executed (`restart_syscall` for `-ERESTART_RESTARTBLOCK`).

use super::frame::{self, Delivery, FaultUpdate};
use super::{
    AltStack, KERNEL_ONLY_MASK, SIG_DFL, SIG_IGN, SIGCONT, SIGKILL, SIGSEGV, SIGSTOP, SIGTRAP,
    SIGTSTP, SIGTTIN, SIGTTOU, SigInfo, default_dumps_core, default_ignored, default_stops, sa,
    sigmask, signal_name, ss,
};
use crate::user::linux::abi::LinuxAbi;
use crate::user::linux::abi::errno_table::EINTR;
use crate::user::linux::posix_timers::{self, Firing, Notify};
use crate::user::linux::process::{ExitStatus, LinuxProcess, ProcState, Thread, Threads};

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

/// Where a signal is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dest {
    /// One thread (`PIDTYPE_PID`: `tgkill`, faults, `SIGPIPE`).
    Thread(i32),
    /// The process (`PIDTYPE_TGID`), through the thread with this TID if
    /// it wants the signal (`kill` of that TID; the leader otherwise).
    Process(i32),
}

/// Whether `sig` is ignored for delivery to a thread with mask `blocked`
/// (`sig_ignored`): blocked signals are never ignored, since the handler
/// may change before they are unblocked, nor any but `SIGKILL` to a traced
/// thread, whose tracer may want to know of it.
fn sig_ignored(p: &ProcState, blocked: u64, sig: i32, force: bool, traced: bool) -> bool {
    if blocked & sigmask(sig) != 0 {
        return false;
    }
    if traced && sig != SIGKILL {
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

/// `sig_fatal`: the default action of `sig`, which has no handler, ends
/// the process.
fn sig_fatal(p: &ProcState, sig: i32) -> bool {
    p.sigactions[(sig - 1) as usize].handler == SIG_DFL
        && !default_ignored(sig)
        && !default_stops(sig)
}

/// The mask of the thread a signal is aimed at, for `sig_ignored`: the
/// thread's own, or the exited leader's final mask.
fn target_mask(p: &ProcState, th: &Threads<'_>, tid: i32) -> Option<u64> {
    th.iter()
        .find(|t| t.tid == tid)
        .map(|t| t.sigmask | t.real_blocked)
        .or_else(|| (tid == p.pid).then_some(p.leader_exit).flatten())
}

/// `prepare_signal`: stop and continue signals cancel each other in every
/// queue, and an ignored signal is dropped at generation.
fn prepare_signal(
    p: &mut ProcState,
    th: &mut Threads<'_>,
    sig: i32,
    mask: u64,
    force: bool,
    traced: bool,
) -> bool {
    let stops = sigmask(SIGSTOP) | sigmask(SIGTSTP) | sigmask(SIGTTIN) | sigmask(SIGTTOU);
    let flush = if default_stops(sig) {
        sigmask(SIGCONT)
    } else if sig == SIGCONT {
        stops
    } else {
        0
    };
    if flush != 0 {
        flush_signals(p, th, flush);
    }
    !sig_ignored(p, mask, sig, force, traced)
}

/// `flush_sigqueue_mask` on every queue of the process: discards the
/// pending instances of the signals in `mask`. A periodic POSIX timer
/// whose signal is discarded keeps it parked until the signal is no longer
/// ignored (`sigqueue_free_ignored`).
pub fn flush_signals(p: &mut ProcState, th: &mut Threads<'_>, mask: u64) {
    let mut timers = p.shared_pending.flush(mask);
    for t in th.iter_mut() {
        timers.extend(t.pending.flush(mask));
    }
    for uid in timers {
        p.timers.sig_ignore(uid);
    }
}

/// `signalfd_notify`: threads sleeping until a signal of theirs is queued
/// (reading or polling a `signalfd`) run again to look.
fn signalfd_notify(th: &mut Threads<'_>, sig: i32) {
    for t in th.iter_mut() {
        if let Some(b) = t.blocked.as_mut()
            && b.wait.signals & sigmask(sig) != 0
        {
            b.woken = true;
        }
    }
}

/// `signal_wake_up`: the thread should take a signal; a system call it
/// sleeps in ends.
pub fn signal_wake_up(t: &mut Thread) {
    t.sigpending = true;
}

/// `recalc_sigpending_tsk`: whether a signal the thread does not block is
/// pending for it or for the process.
pub fn recalc_sigpending(p: &ProcState, t: &Thread) -> bool {
    t.pending.next(t.sigmask).is_some() || p.shared_pending.next(t.sigmask).is_some()
}

/// `wants_signal`: an unblocked thread takes the signal if it is running
/// or has no signal pending yet (`SIGKILL` always).
fn wants_signal(sig: i32, t: &Thread, running: Option<i32>) -> bool {
    if t.sigmask & sigmask(sig) != 0 {
        return false;
    }
    sig == SIGKILL || running == Some(t.tid) || !t.sigpending
}

/// `complete_signal`: finds the thread to wake for `info`, now queued for
/// `dest`; a fatal signal without a core dump ends the process at once.
fn complete_signal(p: &mut ProcState, th: &mut Threads<'_>, info: &SigInfo, dest: Dest) {
    let sig = info.signo;
    let running = th.running();
    let suggested = match dest {
        Dest::Thread(tid) | Dest::Process(tid) => tid,
    };
    let chosen = if th
        .iter()
        .any(|t| t.tid == suggested && wants_signal(sig, t, running))
    {
        suggested
    } else if matches!(dest, Dest::Thread(_)) || th.len() <= 1 {
        // One thread, or a thread signal: it will dequeue unblocked
        // signals before it runs again.
        return;
    } else {
        // Search from curr_target in list order.
        let tids: Vec<i32> = th.iter().map(|t| t.tid).collect();
        let start = tids.iter().position(|&t| t == p.curr_target).unwrap_or(0);
        let found = (0..tids.len())
            .map(|i| tids[(start + i) % tids.len()])
            .find(|&tid| {
                th.iter()
                    .any(|t| t.tid == tid && wants_signal(sig, t, running))
            });
        let Some(tid) = found else {
            return;
        };
        p.curr_target = tid;
        tid
    };
    let t = th.get_mut(chosen).expect("chosen thread exists");
    if sig_fatal(p, sig)
        && p.exit.is_none()
        && t.real_blocked & sigmask(sig) == 0
        && !default_dumps_core(sig)
        && (sig == SIGKILL || t.ptrace.is_none())
    {
        // The signal will be fatal to the whole group: start the group
        // exit now rather than after the thread dequeues it (not for a
        // traced thread, whose tracer sees the signal first).
        p.exit = Some(ExitStatus::Signaled {
            info: *info,
            pc: t.cpu.pc(),
            core: false,
        });
        return;
    }
    signal_wake_up(t);
}

/// Generates `info` for `dest` (`__send_signal_locked`). `force` marks
/// kernel-generated signals that a namespace init cannot ignore. Returns
/// whether the signal is now pending.
pub fn send_signal(
    p: &mut ProcState,
    th: &mut Threads<'_>,
    info: SigInfo,
    dest: Dest,
    force: bool,
) -> bool {
    let target = match dest {
        Dest::Thread(tid) | Dest::Process(tid) => tid,
    };
    let mask = target_mask(p, th, target).unwrap_or(0);
    let traced = th.iter().any(|t| t.tid == target && t.ptrace.is_some());
    if !prepare_signal(p, th, info.signo, mask, force, traced) {
        return false;
    }
    signalfd_notify(th, info.signo);
    match dest {
        Dest::Thread(tid) => {
            let Some(t) = th.get_mut(tid) else {
                return false;
            };
            t.pending.enqueue(info);
        }
        Dest::Process(_) => {
            p.shared_pending.enqueue(info);
        }
    }
    complete_signal(p, th, &info, dest);
    true
}

/// `retarget_shared_pending`: process signals in `which` that the current
/// thread will not take (it exits, or now blocks them) wake other threads
/// that can.
pub fn retarget_shared_pending(p: &ProcState, th: &mut Threads<'_>, which: u64) {
    let mut retarget = p.shared_pending.set() & which;
    if retarget == 0 {
        return;
    }
    let me = th.running();
    for t in th.iter_mut() {
        if Some(t.tid) == me {
            continue;
        }
        if retarget & !t.sigmask == 0 {
            continue;
        }
        retarget &= t.sigmask;
        if !t.sigpending {
            signal_wake_up(t);
        }
        if retarget == 0 {
            break;
        }
    }
}

/// `__set_current_blocked` for the current thread: signals it newly blocks
/// that the process has pending are retargeted, and its flag recomputed.
pub fn set_blocked(p: &ProcState, th: &mut Threads<'_>, new: u64) {
    let new = new & !KERNEL_ONLY_MASK;
    let t = th.current().expect("a current thread");
    let (old, pending) = (t.sigmask, t.sigpending);
    if pending && th.len() > 1 {
        retarget_shared_pending(p, th, new & !old);
    }
    let t = th.current().expect("a current thread");
    t.sigmask = new;
    t.sigpending = recalc_sigpending(p, t);
}

/// `force_sig_info_to_task` for the current thread: a synchronous signal it
/// cannot block or ignore; a blocked or ignored signal (or any, with
/// [`ForceMode::Default`]) is reset to its default action and unblocked.
pub fn force_signal(p: &mut ProcState, th: &mut Threads<'_>, info: SigInfo, mode: ForceMode) {
    let idx = (info.signo - 1) as usize;
    let t = th.current().expect("a current thread");
    let tid = t.tid;
    let blocked = t.sigmask & sigmask(info.signo) != 0;
    let action = &mut p.sigactions[idx];
    if blocked || action.handler == SIG_IGN || mode != ForceMode::Current {
        action.handler = SIG_DFL;
        if blocked {
            t.sigmask &= !sigmask(info.signo);
            t.sigpending = recalc_sigpending(p, t);
        }
    }
    if p.sigactions[idx].handler == SIG_DFL {
        p.unkillable = false;
    }
    let force = info.code == super::code::SI_KERNEL;
    send_signal(p, th, info, Dest::Thread(tid), force);
}

/// `force_sigsegv`: after a handler frame could not be written. A failure
/// delivering `SIGSEGV` itself makes it fatal.
pub fn force_sigsegv(p: &mut ProcState, th: &mut Threads<'_>, sig: i32) {
    let mode = if sig == SIGSEGV {
        ForceMode::Default
    } else {
        ForceMode::Current
    };
    force_signal(p, th, SigInfo::kernel(SIGSEGV), mode);
}

/// Generates the signals of events outside the process: forwarded host
/// signals (`SI_USER` with the sender when another process sent them with
/// `kill`, else `SI_KERNEL`, as terminal-generated signals are) and expired
/// interval timers (`SEND_SIG_PRIV`), all aimed at the process through its
/// leader, and the signals of expired POSIX timers.
pub fn collect_async(p: &mut ProcState, th: &mut Threads<'_>) {
    // Tracing messages: a tracee's answers and stops, a tracer's requests.
    crate::user::linux::ptrace::tracee::poll_links(p, th);
    if crate::user::linux::host::take_child_event() {
        crate::user::linux::syscall::child::refresh(p, th);
    }
    let leader = p.pid;
    for hs in crate::user::linux::host::take_host_signals() {
        let info = match hs.sender {
            Some((pid, uid)) if hs.code != super::code::SI_USER => {
                SigInfo::queued(hs.sig, hs.code, pid, uid, hs.value)
            }
            Some((pid, uid)) => SigInfo::kill(hs.sig, super::code::SI_USER, pid, uid),
            None => SigInfo::kernel(hs.sig),
        };
        let force = info.code == super::code::SI_KERNEL;
        send_signal(p, th, info, Dest::Process(leader), force);
    }
    if p.itimers.next_deadline().is_some() || p.itimers.cpu_armed() {
        let fired = p.itimers.expire(
            std::time::Instant::now(),
            crate::user::linux::timers::cpu_samples,
        );
        for sig in fired {
            send_signal(p, th, SigInfo::kernel(sig), Dest::Process(leader), true);
        }
    }
    if p.timers.armed() {
        for f in p.timers.expire(posix_timers::clock_now) {
            send_timer_signal(p, th, f);
        }
    }
}

/// The destination of a POSIX timer's signal and the task it is checked
/// against (`posixtimer_get_target`): the process through its leader, or
/// one thread, which must still exist.
fn timer_target(p: &ProcState, th: &Threads<'_>, notify: Notify) -> Option<(Dest, u64)> {
    let (dest, tid) = match notify {
        Notify::Thread(tid) => (Dest::Thread(tid), tid),
        Notify::Process => (Dest::Process(p.pid), p.pid),
        Notify::None => return None,
    };
    target_mask(p, th, tid).map(|mask| (dest, mask))
}

/// Queues a POSIX timer's record for `dest` (`posixtimer_queue_sigqueue`).
fn queue_timer_signal(p: &mut ProcState, th: &mut Threads<'_>, f: Firing, dest: Dest) {
    let info = SigInfo::timer(f.signo, f.id, f.value);
    signalfd_notify(th, f.signo);
    match dest {
        Dest::Thread(tid) => match th.get_mut(tid) {
            Some(t) => t.pending.enqueue_timer(info, f.uid),
            None => return,
        },
        Dest::Process(_) => p.shared_pending.enqueue_timer(info, f.uid),
    }
    complete_signal(p, th, &info, dest);
}

/// Whether POSIX timer `uid`'s record is queued anywhere.
fn timer_queued(p: &ProcState, th: &Threads<'_>, uid: u64) -> bool {
    p.shared_pending.has_timer(uid) || th.iter().any(|t| t.pending.has_timer(uid))
}

/// `posixtimer_send_sigqueue`: an expired POSIX timer's signal. A target
/// thread that has exited takes nothing. An ignored signal is parked if
/// the expiry was periodic (so that the timer re-arms once the signal is
/// no longer ignored and delivered); a record already queued stays, as the
/// one instance of the timer's signal.
pub fn send_timer_signal(p: &mut ProcState, th: &mut Threads<'_>, f: Firing) {
    let Some((dest, mask)) = timer_target(p, th, f.notify) else {
        return;
    };
    let queued = timer_queued(p, th, f.uid);
    if !prepare_signal(p, th, f.signo, mask, false, false) {
        if !queued {
            p.timers.park_ignored(f.uid);
        }
        return;
    }
    if queued {
        return;
    }
    p.timers.unpark(f.uid);
    queue_timer_signal(p, th, f, dest);
}

/// `posixtimer_sig_unignore`: `sig` is no longer ignored; the parked
/// signals of periodic POSIX timers are queued again.
pub fn unignore_timer_signals(p: &mut ProcState, th: &mut Threads<'_>, sig: i32) {
    for f in p.timers.sig_unignore(sig) {
        if let Some((dest, _)) = timer_target(p, th, f.notify) {
            queue_timer_signal(p, th, f, dest);
        }
    }
}

/// `dequeue_signal`: the thread's pending signals, then the process's; a
/// `SIGALRM` taken from the process queue re-arms `ITIMER_REAL`. A POSIX
/// timer's signal re-arms its periodic timer and reports the overrun
/// count, or is dropped when the timer was changed or deleted since it was
/// queued, and the next signal is taken instead.
pub fn dequeue_signal(p: &mut ProcState, t: &mut Thread, blocked: u64) -> Option<SigInfo> {
    loop {
        let (mut info, timer) = match t.pending.dequeue_tagged(blocked) {
            Some(x) => x,
            None => {
                let x = p.shared_pending.dequeue_tagged(blocked)?;
                if x.0.signo == super::SIGALRM {
                    p.itimers.rearm_real(std::time::Instant::now());
                }
                x
            }
        };
        let Some(uid) = timer else {
            return Some(info);
        };
        if let Some(overrun) = p.timers.deliver(uid, posix_timers::clock_now) {
            info.set_overrun(overrun);
            return Some(info);
        }
    }
}

/// What `get_signal` found.
enum Next {
    /// Nothing deliverable.
    None,
    /// Run a handler.
    Handler(Delivery),
    /// The process is exiting.
    Exit,
    /// The thread stopped for its tracer.
    Traced,
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
    /// Generates the signals of events outside the process
    /// ([`collect_async`]), with thread `running` (an index) current.
    pub fn collect_async(&mut self, running: Option<usize>) {
        let mut th = Threads::split(&mut self.threads, running);
        collect_async(&mut self.state, &mut th);
    }

    /// Whether thread `idx` has work at its return to user mode: a signal
    /// to take (`TIF_SIGPENDING`), a system call to finish, or a mask to
    /// restore.
    fn signal_work(&self, idx: usize) -> bool {
        let t = &self.threads[idx];
        t.sigpending
            || t.syscall.is_some()
            || t.saved_sigmask.is_some()
            || t.ptrace.as_ref().is_some_and(|tr| tr.stop.is_some())
    }

    /// `get_signal`: dequeues signals for thread `idx` until one has a
    /// handler, taking default actions on the way.
    fn get_signal(&mut self, idx: usize) -> Next {
        use crate::user::linux::ptrace::StopKind;
        use crate::user::linux::ptrace::tracee::{self as ptrace, Verdict};
        loop {
            let (p, t) = (&mut self.state, &mut self.threads[idx]);
            let blocked = t.sigmask;
            // ptrace_signal after the tracer resumed the thread: the signal
            // it left (or none), requeued if it is now blocked; after a
            // system-call stop, the signal is sent as the kernel's.
            let info = match ptrace::take_verdict(p, t) {
                Some(Verdict::Drop) => continue,
                Some(Verdict::Send(sig)) => {
                    let tid = t.tid;
                    let mut th = Threads::split(&mut self.threads, Some(idx));
                    let info = SigInfo::kernel(sig);
                    send_signal(&mut self.state, &mut th, info, Dest::Thread(tid), false);
                    continue;
                }
                Some(Verdict::Deliver(info)) if blocked & sigmask(info.signo) != 0 => {
                    t.pending.enqueue(info);
                    continue;
                }
                Some(Verdict::Deliver(info)) => info,
                None => {
                    let info = match t.pending.dequeue_synchronous(blocked) {
                        Some(info) => Some(info),
                        None => dequeue_signal(p, t, blocked),
                    };
                    let Some(info) = info else {
                        return Next::None;
                    };
                    // A traced thread stops for its tracer before taking
                    // any signal but SIGKILL (signal-delivery-stop).
                    if t.ptrace.is_some() && info.signo != SIGKILL {
                        ptrace::stop(p, t, info.signo, Some(info), StopKind::Signal, 0);
                        return Next::Traced;
                    }
                    info
                }
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
            if default_stops(sig) && t.ptrace.is_some() {
                // do_signal_stop for a traced thread: a group stop its
                // tracer is told of (do_jobctl_trap), with no siginfo.
                ptrace::stop(p, t, sig, None, StopKind::Quiet, 0);
                return Next::Traced;
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
    /// `signal_setup_done`; false when the frame could not be built.
    fn handle_signal(&mut self, idx: usize, d: &Delivery) -> bool {
        let mut th = Threads::split(&mut self.threads, Some(idx));
        let p = &mut self.state;
        let t = th.current().expect("running thread");
        // rseq_signal_deliver: an interrupted critical section is aborted
        // before the frame saves the instruction pointer.
        let task_size = p.abi.task_size();
        if !crate::user::linux::rseq::signal_deliver(&p.space, task_size, t) {
            force_sigsegv(p, &mut th, d.sig);
        }
        let t = th.current().expect("running thread");
        if frame::setup_rt_frame(t, &p.space, d, p.sigtramp).is_err() {
            force_sigsegv(p, &mut th, d.sig);
            return false;
        }
        let t = th.current().expect("running thread");
        // signal_delivered.
        t.saved_sigmask = None;
        let mut blocked = t.sigmask | d.action.mask;
        if d.action.flags & sa::NODEFER == 0 {
            blocked |= sigmask(d.sig);
        }
        if t.altstack.flags & ss::AUTODISARM != 0 {
            t.altstack = AltStack::DISABLED;
        }
        set_blocked(p, &mut th, blocked);
        true
    }

    /// The work the kernel does on return to user mode for thread `idx`:
    /// `set_child_tid`, system-call restart, then delivery of every signal
    /// it does not block. Handlers nest: each delivery builds a frame below
    /// the last.
    pub fn deliver_signals(&mut self, idx: usize) {
        // schedule_tail: CLONE_CHILD_SETTID is written as the new thread
        // first runs.
        let t = &mut self.threads[idx];
        if t.set_child_tid != 0 {
            let addr = std::mem::take(&mut t.set_child_tid);
            let _ = self.state.space.write(addr, &(t.tid as u32).to_le_bytes());
        }
        if !self.signal_work(idx) {
            return;
        }
        use restart::*;
        let restart_nr = restart_syscall_nr(&self.state);
        let t = &mut self.threads[idx];
        // arch_do_signal_or_restart: provisionally restart the call.
        let mut rewound = None;
        let entry = t.syscall.take();
        // in_syscall: x86-64 and AArch64 take a number of -1 for none.
        let riscv = self.state.abi == LinuxAbi::Riscv64;
        if let Some(entry) = entry
            && (riscv || entry.nr as i32 != -1)
        {
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
                Next::Traced => {
                    // The tracer sees the call as it ended (its result, the
                    // instruction after it, orig_rax); the restart is
                    // decided once the thread goes on.
                    let t = &mut self.threads[idx];
                    if let Some((code, continue_pc)) = rewound.take() {
                        t.cpu.set_pc(continue_pc);
                        t.cpu.set_syscall_result(-(code as i64) as u64);
                    }
                    t.syscall = entry;
                    return;
                }
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
                    let delivered = self.handle_signal(idx, &d);
                    let t = &mut self.threads[idx];
                    if delivered && crate::user::linux::ptrace::tracee::mode(t).step {
                        // signal_delivered while stepping: ptrace_notify(
                        // SIGTRAP, 0) before the handler's first
                        // instruction; x86-64 stops stepping first.
                        if let Some(tr) = t.ptrace.as_mut()
                            && self.state.abi == LinuxAbi::X86_64
                        {
                            tr.mode.step = false;
                        }
                        let p = &mut self.state;
                        let quiet = crate::user::linux::ptrace::StopKind::Quiet;
                        crate::user::linux::ptrace::tracee::notify(p, t, SIGTRAP, 0, quiet);
                        t.syscall = entry;
                        return;
                    }
                }
                Next::None => {
                    let t = &mut self.threads[idx];
                    if let Some((ERESTART_RESTARTBLOCK, _)) = rewound {
                        t.cpu.set_syscall_number(restart_nr);
                    }
                    // restore_saved_sigmask.
                    if let Some(mask) = t.saved_sigmask.take() {
                        let mut th = Threads::split(&mut self.threads, Some(idx));
                        set_blocked(&self.state, &mut th, mask);
                    }
                    let t = &mut self.threads[idx];
                    t.sigpending = recalc_sigpending(&self.state, t);
                    return;
                }
            }
        }
    }

    /// Delivers a CPU-raised synchronous signal to thread `idx`.
    pub fn trap_signal(&mut self, idx: usize, info: SigInfo, update: FaultUpdate) {
        self.threads[idx].fault.apply(update);
        let mut th = Threads::split(&mut self.threads, Some(idx));
        force_signal(&mut self.state, &mut th, info, ForceMode::Current);
    }
}
