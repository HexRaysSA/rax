//! System-call stops and single-stepping: the scheduler's side of tracing,
//! after the architectures' system-call entry paths (`do_syscall_64` and
//! `do_int80_emulation`, `el0_svc_common`, `do_trap_ecall_u`) and the
//! generic `syscall_trace_enter` and `syscall_exit_work` (Linux 6.19).
//!
//! A thread its tracer runs with `PTRACE_SYSCALL` or `PTRACE_SYSEMU` stops
//! as a system call enters, before seccomp sees it, in each architecture's
//! entry view: x86-64's `rax` and RISC-V's `a0` already `-ENOSYS`, AArch64's
//! `x7` showing the direction (0 entering, 1 leaving) in place of its own
//! value. Once resumed, the call is made with the number and arguments the
//! registers then hold; -1 (or, on RISC-V, any number outside the table)
//! skips it, keeping the result register as the tracer left it, and so does
//! a stop under `PTRACE_SYSEMU`. Under `PTRACE_SYSCALL` the thread stops
//! again as the call finishes, its result in place, before the call is
//! restarted or any signal delivered. The signal a tracer resumes a
//! system-call stop with is sent to the thread from the kernel
//! (`SI_KERNEL`).
//!
//! A stepping thread runs one instruction, then takes `SIGTRAP`
//! (`TRAP_TRACE`, reporting the next instruction). A stepped system call
//! reports as it finishes instead: x86-64's `send_sigtrap(..., TRAP_BRKPT)`,
//! AArch64's generic `user_single_step_report` (`SI_USER` from no one).
//! RISC-V has no stepping.

use super::super::abi::LinuxAbi;
use super::super::abi::errno::Errno;
use super::super::abi::errno_table::ENOSYS;
use super::super::arch::GuestCpu;
use super::super::children::{exited_status, signaled_status};
use super::super::process::{ExitStatus, LinuxProcess, Peers, Thread, Threads};
use super::super::sched::After;
use super::super::signal::deliver::{Dest, SyscallEntry, send_signal};
use super::super::signal::frame::FaultUpdate;
use super::super::signal::{SIGKILL, SIGTRAP, SigInfo, code};
use super::super::syscall::{self, Call};
use super::tracee as ptrace;
use super::{EVENT_SECCOMP, Exiting, StopKind, call};

/// RISC-V's `NR_syscalls` (`asm-generic/unistd.h`'s `__NR_syscalls`): a
/// number outside the table is no call at all.
const RISCV_NR_SYSCALLS: i32 = 471;

/// `report_syscall`: while stopped at a system call, AArch64's `x7` holds
/// the direction; its own value is put back as the thread goes on.
fn show_direction(t: &mut Thread, dir: u64) {
    if let GuestCpu::Aarch64(c) = &mut t.cpu
        && let Some(s) = t.ptrace.as_mut().and_then(|tr| tr.stop.as_mut())
    {
        s.saved = Some(c.core().get_x(7));
        c.core_mut().set_x(7, dir);
    }
}

impl LinuxProcess {
    /// A system call thread `idx` made: its tracer's entry stop when the
    /// tracer asks for one, else the call.
    pub fn enter_syscall(&mut self, idx: usize, nr: u64, args: [u64; 6]) -> After {
        let t = &mut self.threads[idx];
        t.syscall = Some(SyscallEntry { nr, arg0: args[0] });
        if let Some(tr) = t.ptrace.as_mut() {
            tr.compat = false;
            self.entry_view(idx);
        }
        if self.syscall_entry_stop(idx) {
            return After::Next;
        }
        self.syscall(idx, Call::new(nr, args))
    }

    /// An x86-64 `INT 0x80` call of thread `idx`: for a traced thread,
    /// `do_int80_emulation`'s `orig_ax` (the low 32 bits of `rax`) and its
    /// tracer's entry stop.
    pub fn enter_compat(&mut self, idx: usize, nr: u64, args: [u64; 6]) -> After {
        let t = &mut self.threads[idx];
        if let Some(tr) = t.ptrace.as_mut() {
            tr.compat = true;
            t.syscall = Some(SyscallEntry { nr, arg0: args[0] });
            self.entry_view(idx);
            if self.syscall_entry_stop(idx) {
                return After::Next;
            }
        }
        self.compat_call(idx, nr, args, false)
    }

    fn compat_call(&mut self, idx: usize, nr: u64, args: [u64; 6], recheck: bool) -> After {
        let outcome = {
            let (lo, rest) = self.threads.split_at_mut(idx);
            let (t, hi) = rest.split_first_mut().expect("thread index is valid");
            syscall::dispatch_compat(&mut self.state, t, Peers { lo, hi }, nr, args, recheck)
        };
        self.apply(idx, nr, args, outcome)
    }

    /// The architecture's entry view of a traced thread's call, which its
    /// tracer sees at any stop inside the call: `entry_SYSCALL_64`'s
    /// `rax=$-ENOSYS` (and `do_int80_emulation`'s) and `do_trap_ecall_u`'s
    /// `a0 = -ENOSYS`; `el0_svc_common` does it only for a user's own
    /// `syscall(-1)`, whose `x0` would otherwise come back.
    fn entry_view(&mut self, idx: usize) {
        let t = &mut self.threads[idx];
        if self.state.abi != LinuxAbi::Aarch64 || call::nr(&t.cpu, t.syscall) == -1 {
            t.cpu.set_syscall_result(Errno(ENOSYS).as_return());
        }
    }

    /// `syscall_trace_enter`'s tracing: under `PTRACE_SYSCALL` or
    /// `PTRACE_SYSEMU`, stops thread `idx` at its call's entry. True when
    /// it stopped.
    fn syscall_entry_stop(&mut self, idx: usize) -> bool {
        let (p, t) = (&mut self.state, &mut self.threads[idx]);
        let mode = ptrace::mode(t);
        if !(mode.syscall || mode.emu) {
            return false;
        }
        ptrace::syscall_stop(p, t, false);
        show_direction(t, 0);
        true
    }

    /// Goes on with the system call of thread `idx` once its tracer resumed
    /// it from a stop inside it: after an entry stop, the call with the
    /// number and arguments the registers now hold (skipped for -1, after
    /// a stop under `PTRACE_SYSEMU`, or when the process is dying), then
    /// its exit work; after an event stop, the exit work; after
    /// `PTRACE_EVENT_SECCOMP`, the call looked at again (skipped for a
    /// negative number); after `PTRACE_EVENT_EXIT`, the end of the thread
    /// or the process.
    pub fn resume_in_call(&mut self, idx: usize) -> After {
        let t = &mut self.threads[idx];
        let tid = t.tid;
        let compat = t.ptrace.as_ref().is_some_and(|tr| tr.compat);
        let exiting = t.ptrace.as_mut().and_then(|tr| tr.exiting.take());
        let Some((kind, sig)) = ptrace::take_in_call(t) else {
            return After::Stay;
        };
        if sig != 0 {
            let mut th = Threads::split(&mut self.threads, Some(idx));
            let info = SigInfo::kernel(sig);
            send_signal(&mut self.state, &mut th, info, Dest::Thread(tid), false);
        }
        let dying = self.state.exit.is_some()
            || self.threads[idx].pending.contains(SIGKILL)
            || self.state.shared_pending.contains(SIGKILL);
        let emu = match kind {
            StopKind::Entry { emu } => emu,
            StopKind::Exiting => return self.finish_exit(idx, exiting),
            StopKind::Seccomp => return self.recheck(idx, compat, dying),
            _ => return self.after_exit_work(idx),
        };
        let t = &mut self.threads[idx];
        let nr = call::nr(&t.cpu, t.syscall);
        let args = call::args(&t.cpu, t.syscall, compat);
        let skip = emu
            || dying
            || nr == -1
            || (self.state.abi == LinuxAbi::Riscv64 && !(0..RISCV_NR_SYSCALLS).contains(&nr));
        if skip {
            return self.after_exit_work(idx);
        }
        let wide = nr as i64 as u64;
        if let Some(s) = t.syscall.as_mut() {
            s.nr = wide;
        }
        self.make_call(idx, compat, wide, args, false)
    }

    /// Makes the call thread `idx` is in with these registers, seccomp
    /// looking at it again after its tracer's stop when `recheck`.
    fn make_call(
        &mut self,
        idx: usize,
        compat: bool,
        nr: u64,
        args: [u64; 6],
        recheck: bool,
    ) -> After {
        if compat {
            let lo = |v: u64| v & 0xFFFF_FFFF;
            self.compat_call(idx, lo(nr), args.map(lo), recheck)
        } else {
            let mut call = Call::new(nr, args);
            call.recheck = recheck;
            self.syscall(idx, call)
        }
    }

    /// `__seccomp_filter` after `PTRACE_EVENT_SECCOMP`: skipped when the
    /// process is dying or the tracer made the number negative, else looked
    /// at again with the registers the tracer left (`SECCOMP_RET_TRACE` now
    /// allowing it).
    fn recheck(&mut self, idx: usize, compat: bool, dying: bool) -> After {
        let t = &mut self.threads[idx];
        let nr = call::nr(&t.cpu, t.syscall);
        if dying || nr < 0 {
            return self.after_exit_work(idx);
        }
        let args = call::args(&t.cpu, t.syscall, compat);
        let wide = nr as i64 as u64;
        if let Some(s) = t.syscall.as_mut() {
            s.nr = wide;
        }
        self.make_call(idx, compat, wide, args, true)
    }

    /// The event due as thread `idx`'s call finishes (clone's), before its
    /// exit work. True when it stopped.
    pub fn call_event(&mut self, idx: usize) -> bool {
        let (p, t) = (&mut self.state, &mut self.threads[idx]);
        ptrace::event_stop(p, t)
    }

    /// `PTRACE_EVENT_SECCOMP` for thread `idx`, the filter's data as the
    /// message.
    pub fn seccomp_stop(&mut self, idx: usize, data: u16) {
        let (p, t) = (&mut self.state, &mut self.threads[idx]);
        let exit = SIGTRAP | (EVENT_SECCOMP << 8);
        ptrace::notify(p, t, exit, u64::from(data), StopKind::Seccomp);
    }

    /// `PTRACE_EVENT_EXIT` for thread `idx` leaving alone (`exit`, a
    /// thread's seccomp death), `code` the message. True when it stopped.
    pub fn exit_event(&mut self, idx: usize, code: i32, how: Exiting) -> bool {
        let (p, t) = (&mut self.state, &mut self.threads[idx]);
        if !ptrace::exit_traced(p, t) {
            return false;
        }
        ptrace::exit_event(p, t, code, how);
        true
    }

    /// `do_group_exit` for thread `idx` when its tracer stops it at
    /// `PTRACE_EVENT_EXIT`: the other threads die at once
    /// (`zap_other_threads`: with the group's status, and without stopping,
    /// a fatal signal pending), then the thread stops. True when it stopped;
    /// the thread's index may have changed.
    pub fn group_exit_event(&mut self, idx: usize, code: i32, how: Exiting) -> bool {
        if !ptrace::exit_traced(&self.state, &self.threads[idx]) {
            return false;
        }
        let tid = self.threads[idx].tid;
        let status = match &how {
            Exiting::Group(c) | Exiting::Thread(c) => exited_status(*c),
            Exiting::Killed(sig) => signaled_status(*sig, false),
            Exiting::Signaled { info, .. } => signaled_status(info.signo, false),
        };
        ptrace::group_exit(&mut self.state, status);
        let others: Vec<i32> = self
            .threads
            .iter()
            .map(|t| t.tid)
            .filter(|&t| t != tid)
            .collect();
        for other in others {
            if let Some(i) = self.threads.iter().position(|t| t.tid == other) {
                self.end_thread(i, status);
            }
        }
        let idx = self
            .threads
            .iter()
            .position(|t| t.tid == tid)
            .expect("the exiting thread lives");
        let (p, t) = (&mut self.state, &mut self.threads[idx]);
        ptrace::exit_event(p, t, code, how);
        true
    }

    /// The end of thread `idx` its tracer resumed from `PTRACE_EVENT_EXIT`.
    fn finish_exit(&mut self, idx: usize, how: Option<Exiting>) -> After {
        match how {
            Some(Exiting::Thread(code)) => {
                self.exit_thread(idx, code);
                After::Gone
            }
            Some(Exiting::Killed(sig)) => {
                self.end_thread(idx, signaled_status(sig, false));
                After::Gone
            }
            Some(Exiting::Group(code)) => {
                self.state.exit = Some(ExitStatus::Exited(code));
                After::Stay
            }
            Some(Exiting::Signaled { info, pc, core }) => {
                self.state.exit = Some(ExitStatus::Signaled { info, pc, core });
                After::Stay
            }
            None => After::Stay,
        }
    }

    /// `exit_notify` for the traced threads of a process that ends: each
    /// one's tracer is told, with the process's status.
    pub fn report_exits(&mut self) {
        let status = match &self.state.exit {
            Some(ExitStatus::Exited(code)) => exited_status(*code),
            Some(ExitStatus::Signaled { info, .. }) => signaled_status(info.signo, false),
            _ => return,
        };
        ptrace::group_exit(&mut self.state, status);
        for t in &self.threads {
            ptrace::gone(&mut self.state, t, status);
        }
    }

    /// The exit work of a call that was not made: the thread continues
    /// unless it stopped.
    fn after_exit_work(&mut self, idx: usize) -> After {
        if self.syscall_exit_work(idx) {
            After::Next
        } else {
            After::Stay
        }
    }

    /// `syscall_exit_work`'s tracing for thread `idx`, whose call finished
    /// with its result in place: the exit stop under `PTRACE_SYSCALL`, or
    /// the report of a stepped call. True when the thread stopped.
    pub fn syscall_exit_work(&mut self, idx: usize) -> bool {
        let Some(tr) = self.threads[idx].ptrace.as_ref() else {
            return false;
        };
        // ptrace_stop does not stop a thread about to die.
        if self.state.exit.is_some() {
            return false;
        }
        let mode = tr.mode;
        match self.state.abi {
            // report_single_step: a stepped call reports as it finishes,
            // unless emulated (its entry stop was the report).
            LinuxAbi::X86_64 | LinuxAbi::Riscv64 => {
                if mode.step && !mode.emu {
                    self.step_report(idx);
                    return false;
                }
            }
            // syscall_trace_exit: stepping reports in place of the exit
            // stop, whatever the entry was.
            LinuxAbi::Aarch64 => {
                if mode.step {
                    self.step_report(idx);
                    return false;
                }
            }
        }
        if !mode.syscall {
            return false;
        }
        let (p, t) = (&mut self.state, &mut self.threads[idx]);
        ptrace::syscall_stop(p, t, true);
        show_direction(t, 1);
        true
    }

    /// `user_single_step_report` for a stepped system call of thread
    /// `idx`.
    fn step_report(&mut self, idx: usize) {
        let (info, update) = match self.state.abi {
            LinuxAbi::X86_64 => {
                let pc = self.threads[idx].cpu.pc();
                (SigInfo::fault(SIGTRAP, code::TRAP_BRKPT, pc), debug_trap())
            }
            _ => (
                SigInfo::kill(SIGTRAP, code::SI_USER, 0, 0),
                FaultUpdate::None,
            ),
        };
        self.trap_signal(idx, info, update);
    }

    /// The trap after thread `idx` stepped an instruction
    /// (`exc_debug_user`'s `DR_STEP`, `single_step_handler`): `SIGTRAP`,
    /// `TRAP_TRACE`, at the next instruction.
    pub fn step_trap(&mut self, idx: usize) {
        let pc = self.threads[idx].cpu.pc();
        let update = match self.state.abi {
            LinuxAbi::X86_64 => debug_trap(),
            _ => FaultUpdate::None,
        };
        self.trap_signal(idx, SigInfo::fault(SIGTRAP, code::TRAP_TRACE, pc), update);
    }
}

/// x86-64's `send_sigtrap`: the thread's trap record is the debug
/// exception (vector 1, error code 0).
fn debug_trap() -> FaultUpdate {
    FaultUpdate::X86 {
        trap_nr: 1,
        error_code: 0,
        cr2: None,
    }
}
