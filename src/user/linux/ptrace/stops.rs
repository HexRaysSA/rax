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
use super::super::process::{LinuxProcess, Peers, Thread, Threads};
use super::super::sched::After;
use super::super::signal::deliver::{Dest, SyscallEntry, send_signal};
use super::super::signal::frame::FaultUpdate;
use super::super::signal::{SIGKILL, SIGTRAP, SigInfo, code};
use super::super::syscall::{self, Call, ptrace};
use super::{StopKind, call};

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
            if self.syscall_entry_stop(idx) {
                return After::Next;
            }
        }
        self.compat_call(idx, nr, args)
    }

    fn compat_call(&mut self, idx: usize, nr: u64, args: [u64; 6]) -> After {
        let outcome = {
            let (lo, rest) = self.threads.split_at_mut(idx);
            let (t, hi) = rest.split_first_mut().expect("thread index is valid");
            syscall::dispatch_compat(&mut self.state, t, Peers { lo, hi }, nr, args)
        };
        self.apply(idx, nr, args, outcome)
    }

    /// `syscall_trace_enter`'s tracing: under `PTRACE_SYSCALL` or
    /// `PTRACE_SYSEMU`, stops thread `idx` at its call's entry in the
    /// architecture's entry view. True when it stopped.
    fn syscall_entry_stop(&mut self, idx: usize) -> bool {
        let (p, t) = (&mut self.state, &mut self.threads[idx]);
        let mode = ptrace::mode(t);
        if !(mode.syscall || mode.emu) {
            return false;
        }
        // entry_SYSCALL_64's `rax=$-ENOSYS` and do_trap_ecall_u's
        // `a0 = -ENOSYS`; el0_svc_common does it only for a user's own
        // syscall(-1), whose x0 would otherwise come back.
        if p.abi != LinuxAbi::Aarch64 || call::nr(&t.cpu, t.syscall) == -1 {
            t.cpu.set_syscall_result(Errno(ENOSYS).as_return());
        }
        ptrace::syscall_stop(p, t, false);
        show_direction(t, 0);
        true
    }

    /// Goes on with the system call of thread `idx` once its tracer resumed
    /// it from a stop inside it: after an entry stop, the call with the
    /// number and arguments the registers now hold (skipped for -1, after
    /// a stop under `PTRACE_SYSEMU`, or when the process is dying), then
    /// its exit work; after an event stop, the exit work.
    pub fn resume_in_call(&mut self, idx: usize) -> After {
        let t = &mut self.threads[idx];
        let tid = t.tid;
        let compat = t.ptrace.as_ref().is_some_and(|tr| tr.compat);
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
        let StopKind::Entry { emu } = kind else {
            return self.after_exit_work(idx);
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
        if compat {
            let lo = |v: u64| v & 0xFFFF_FFFF;
            self.compat_call(idx, lo(wide), args.map(lo))
        } else {
            self.syscall(idx, Call::new(wide, args))
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
