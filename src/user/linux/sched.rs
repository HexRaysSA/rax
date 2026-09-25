//! Thread scheduling.
//!
//! Every thread of a process runs on one emulated CPU (the CPU 0 that
//! `sched_getaffinity` reports), in time slices, round-robin in thread-list
//! order: a thread runs until its slice ends (an instruction budget on
//! AArch64 and RV64, about 1 ms on x86-64), it sleeps in a system call, it
//! yields (`sched_yield`), or it exits. Only one guest instruction stream
//! executes at a time, so guest atomic instructions stay atomic and a
//! program's interleaving depends only on its slice boundaries.
//!
//! A system call that must sleep parks its thread (see
//! [`wait`](super::wait)). When every thread is parked the host sleeps in
//! [`wait::sleep`] until an event can wake one; when nothing can, the
//! process ends with a deadlock diagnostic (with host signals forwarded, a
//! signal can always arrive, so the process waits as it would on Linux).

use std::time::Instant;

use super::arch::CpuEvent;
use super::children::{exited_status, signaled_status};
use super::futex::{self, BITSET_MATCH_ANY, FutexKey};
use super::process::{ExitStatus, LinuxProcess, Peers, Threads};
use super::signal::SigInfo;
use super::signal::deliver::{SyscallEntry, retarget_shared_pending};
use super::syscall::{self, Call, Outcome};
use super::wait::{self, Blocked};

/// Where the scheduler continues after a thread's system call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum After {
    /// The thread continues its slice.
    Stay,
    /// The thread gave up the CPU (it sleeps or yields).
    Next,
    /// The thread exited; the next thread took its place in the list.
    Gone,
}

impl After {
    /// The list index to continue from after thread `idx`.
    fn from(self, idx: usize) -> usize {
        match self {
            After::Stay | After::Gone => idx,
            After::Next => idx + 1,
        }
    }
}

impl LinuxProcess {
    /// Runs until the process exits.
    pub fn run(&mut self) -> ExitStatus {
        let slice = self.state.config.slice_insns;
        let mut current = 0usize;
        loop {
            if self.state.exit.is_some() {
                // exit_mmap: the System V attaches go before the parent
                // can see the exit.
                super::syscall::ipc::exit(&mut self.state);
                // exit_mm and exit_files: the process's files close.
                if let Some(h) = &self.state.fsnotify {
                    h.exit();
                }
            }
            if let Some(status) = &self.state.exit {
                if let Some(me) = self.state.forked.take() {
                    finish_forked(me, status);
                }
                return status.clone();
            }
            self.collect_async(None);
            if self.state.exit.is_some() {
                continue;
            }
            let Some(idx) = self.pick(current) else {
                if let Err(dead) = self.idle() {
                    self.state.exit = Some(ExitStatus::Internal(dead.message()));
                }
                continue;
            };
            current = idx;
            if self.threads[idx].blocked.is_some() {
                current = self.resume(idx).from(idx);
                continue;
            }
            // The return to user mode: restart processing and signals.
            self.deliver_signals(idx);
            if self.state.exit.is_some() {
                continue;
            }
            match self.threads[idx].cpu.run(slice) {
                CpuEvent::Syscall { nr, args } => {
                    self.threads[idx].syscall = Some(SyscallEntry { nr, arg0: args[0] });
                    current = self.syscall(idx, Call::new(nr, args)).from(idx);
                }
                CpuEvent::CompatSyscall { nr, args } => {
                    let outcome = {
                        let (lo, rest) = self.threads.split_at_mut(idx);
                        let (t, hi) = rest.split_first_mut().expect("thread index is valid");
                        syscall::dispatch_compat(&mut self.state, t, Peers { lo, hi }, nr, args)
                    };
                    current = self.apply(idx, nr, args, outcome).from(idx);
                }
                CpuEvent::Signal(info, update) => self.trap_signal(idx, info, update),
                CpuEvent::Yield => current = idx + 1,
                CpuEvent::Internal(why) => {
                    let pc = self.threads[idx].cpu.pc();
                    self.state.exit = Some(ExitStatus::Internal(format!("{why} (pc {pc:#x})")));
                }
            }
        }
    }

    /// The thread to run next, starting at `start`: the thread there if it
    /// is not asleep (it continues its slice), else the first in list order
    /// that is runnable or whose sleep can end.
    fn pick(&mut self, start: usize) -> Option<usize> {
        let n = self.threads.len();
        if n == 0 {
            return None;
        }
        let start = start % n;
        if self.threads[start].blocked.is_none() {
            return Some(start);
        }
        wait::poll_ready(self.threads.iter_mut().filter_map(|t| t.blocked.as_mut()));
        let now = Instant::now();
        (0..n).map(|i| (start + i) % n).find(|&i| {
            let t = &self.threads[i];
            t.blocked
                .as_ref()
                .is_none_or(|b| b.can_wake(t.sigpending, now))
        })
    }

    /// Every thread sleeps: waits on the host for the earliest event that
    /// can wake one.
    fn idle(&mut self) -> Result<(), wait::Deadlock> {
        let mut fds = Vec::new();
        let mut deadline = self.state.timer_deadline();
        for b in self.threads.iter().filter_map(|t| t.blocked.as_ref()) {
            fds.extend_from_slice(&b.wait.fds);
            deadline = match (deadline, b.wait.deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        wait::sleep(&fds, deadline)
    }

    /// Dispatches the call thread `idx` sleeps in again.
    fn resume(&mut self, idx: usize) -> After {
        let b = self.threads[idx].blocked.take().expect("thread sleeps");
        let call = Call {
            nr: b.nr,
            args: b.args,
            resume: Some(b.resume),
            woken: b.woken,
        };
        self.syscall(idx, call)
    }

    /// Runs a system call of thread `idx` and applies its outcome.
    pub fn syscall(&mut self, idx: usize, call: Call) -> After {
        let (nr, args) = (call.nr, call.args);
        let mut spawned = Vec::new();
        let outcome = {
            let (lo, rest) = self.threads.split_at_mut(idx);
            let (t, hi) = rest.split_first_mut().expect("thread index is valid");
            syscall::dispatch(&mut self.state, t, Peers { lo, hi }, &mut spawned, call)
        };
        self.threads.extend(spawned);
        self.apply(idx, nr, args, outcome)
    }

    /// Applies a system call's outcome to thread `idx`.
    fn apply(&mut self, idx: usize, nr: u64, args: [u64; 6], outcome: Outcome) -> After {
        match outcome {
            Outcome::Return(value) => self.threads[idx].cpu.set_syscall_result(value),
            Outcome::Yield(value) => {
                self.threads[idx].cpu.set_syscall_result(value);
                return After::Next;
            }
            Outcome::Unchanged => {
                // The call replaced the register state (rt_sigreturn):
                // nothing is left to restart.
                self.threads[idx].syscall = None;
            }
            Outcome::Block(wait, resume) => {
                self.threads[idx].blocked = Some(Blocked {
                    nr,
                    args,
                    wait,
                    resume,
                    woken: false,
                    ready: false,
                });
                return After::Next;
            }
            Outcome::ExitThread(code) => {
                self.exit_thread(idx, code);
                return After::Gone;
            }
            Outcome::KillThread(sig) => {
                self.end_thread(idx, signaled_status(sig, false));
                return After::Gone;
            }
            Outcome::ExitGroup(code) => {
                self.state.exit = Some(ExitStatus::Exited(code));
            }
            Outcome::Exec(image) => {
                self.commit_exec(idx, *image.0);
                return After::Gone;
            }
            Outcome::Forked(me) => {
                // The new process has only the thread that forked.
                let t = self.threads.swap_remove(idx);
                self.threads.clear();
                self.threads.push(t);
                self.threads[0].cpu.set_syscall_result(0);
                self.threads[0].cpu.discard_native_code();
                self.state.forked = Some(me);
                return After::Gone;
            }
            Outcome::Fatal(why) => {
                self.state.exit = Some(ExitStatus::Internal(why));
            }
        }
        After::Stay
    }

    /// Dispatches a system call of thread `idx` and, while it sleeps, waits
    /// on the host and dispatches it again, returning its final outcome
    /// without applying it (other threads do not run). Tests and embedders
    /// use it to drive calls directly.
    pub fn dispatch_to_completion(&mut self, idx: usize, nr: u64, args: [u64; 6]) -> Outcome {
        let mut call = Call::new(nr, args);
        loop {
            let mut spawned = Vec::new();
            let outcome = {
                let (lo, rest) = self.threads.split_at_mut(idx);
                let (t, hi) = rest.split_first_mut().expect("thread index is valid");
                syscall::dispatch(&mut self.state, t, Peers { lo, hi }, &mut spawned, call)
            };
            self.threads.extend(spawned);
            let Outcome::Block(wait, resume) = outcome else {
                return outcome;
            };
            self.threads[idx].blocked = Some(Blocked {
                nr,
                args,
                wait,
                resume,
                woken: false,
                ready: false,
            });
            loop {
                self.collect_async(None);
                let deadline = self.state.timer_deadline();
                let t = &mut self.threads[idx];
                wait::poll_ready(t.blocked.iter_mut());
                let b = t.blocked.as_ref().expect("thread sleeps");
                if b.can_wake(t.sigpending, Instant::now()) {
                    break;
                }
                let fds = b.wait.fds.clone();
                let deadline = match (deadline, b.wait.deadline) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                if let Err(dead) = wait::sleep(&fds, deadline) {
                    self.threads[idx].blocked = None;
                    return Outcome::Fatal(dead.message());
                }
            }
            let b = self.threads[idx].blocked.take().expect("thread sleeps");
            call = Call {
                nr,
                args,
                resume: Some(b.resume),
                woken: b.woken,
            };
        }
    }

    /// Dispatches again the call of every sleeping thread whose sleep can
    /// end now, applying the outcomes; returns how many ran. Tests use it to
    /// step threads without running guest code.
    pub fn wake_sleepers(&mut self) -> usize {
        self.collect_async(None);
        wait::poll_ready(self.threads.iter_mut().filter_map(|t| t.blocked.as_mut()));
        let now = Instant::now();
        let mut ran = 0;
        let mut i = 0;
        while i < self.threads.len() {
            let t = &self.threads[i];
            if t.blocked
                .as_ref()
                .is_some_and(|b| b.can_wake(t.sigpending, now))
            {
                ran += 1;
                if self.resume(i) == After::Gone {
                    continue;
                }
            }
            i += 1;
        }
        ran
    }

    /// `do_exit` for thread `idx` (`exit`): process signals it would have
    /// taken go to other threads (`exit_signals`); its robust futexes are
    /// marked and its PI futexes handed on (`futex_exit_release`); its
    /// `clear_child_tid` word is cleared and woken while other threads
    /// remain (`mm_release`), as is a `CLONE_VFORK` parent. The last
    /// thread's exit ends the process with that thread's code
    /// (`synchronize_group_exit`).
    pub fn exit_thread(&mut self, idx: usize, code: i32) {
        self.end_thread(idx, exited_status(code));
    }

    /// `do_exit` for thread `idx` with wait status `status` (its
    /// `exit_code`): as [`LinuxProcess::exit_thread`], a status of a death by
    /// signal ending the process, when the thread is its last, as that
    /// signal would.
    pub fn end_thread(&mut self, idx: usize, status: i32) {
        let t = &self.threads[idx];
        let (tid, robust, clear, vfork_parent, mask, pc) = (
            t.tid,
            t.robust_list.0,
            t.clear_child_tid,
            t.vfork_parent,
            t.sigmask,
            t.cpu.pc(),
        );
        let others = self.threads.len() > 1;
        {
            let mut th = Threads::split(&mut self.threads, Some(idx));
            if others && th.current().is_some_and(|t| t.sigpending) {
                retarget_shared_pending(&self.state, &mut th, !mask);
            }
            if robust != 0 {
                futex::exit_robust_list(&mut self.state, &mut th, tid, robust);
            }
            futex::exit_pi(&mut self.state, &mut th, tid);
            self.state.futex.unqueue(tid);
            if clear != 0 && others {
                let _ = futex::put_u32(&self.state, clear, 0);
                let key = FutexKey {
                    addr: clear,
                    shared: true,
                };
                if futex::key(&self.state, clear, true, false).is_ok() {
                    let _ = self.state.futex.wake(&mut th, key, 1, BITSET_MATCH_ANY);
                }
            }
            if let Some(parent) = vfork_parent
                && let Some(b) = th.get_mut(parent).and_then(|t| t.blocked.as_mut())
            {
                b.woken = true;
            }
        }
        self.threads.remove(idx);
        // A thread other than the leader is released as it exits: its
        // pidfds report it gone, and their pollers look again.
        if tid != self.state.pid
            && self
                .state
                .pidfds
                .task_ended(self.state.pid, tid, Some(status))
        {
            for b in self.threads.iter_mut().filter_map(|t| t.blocked.as_mut()) {
                if matches!(b.resume, wait::Resume::Until(_)) {
                    b.woken = true;
                }
            }
        }
        // forget_original_parent: its children pass to the first live
        // thread (find_new_reaper), whose __WNOTHREAD waits then see them.
        if let Some(heir) = self.threads.first().map(|t| t.tid) {
            for ch in self.state.children.list.iter_mut() {
                if ch.creator == tid {
                    ch.creator = heir;
                }
            }
        }
        if self.threads.is_empty() {
            self.state.exit = Some(match status & 0x7f {
                0 => ExitStatus::Exited((status >> 8) & 0xff),
                sig => ExitStatus::Signaled {
                    info: SigInfo::kernel(sig),
                    pc,
                    core: false,
                },
            });
        } else if tid == self.state.pid {
            self.state.leader_exit = Some(mask);
        }
    }
}

/// Ends a forked emulator process as its guest process ended: the Linux
/// wait status goes to the parent through the status pipe, then the host
/// process ends the same way (by the signal when it does not dump core, so
/// host observers see it) without running the parent's cleanup.
fn finish_forked(me: super::children::ForkedSelf, status: &ExitStatus) -> ! {
    let (wait_status, code) = match status {
        ExitStatus::Exited(code) => (exited_status(*code), code & 0xff),
        ExitStatus::Signaled { info, core, .. } => {
            // No core file is written, so the wait status never carries
            // the core-dump flag (coredump_finish sets it only for a
            // written dump).
            let status = signaled_status(info.signo, false);
            if !core {
                me.exit(status);
                super::host::die_by_signal(info.signo);
            }
            (status, 128 + info.signo)
        }
        ExitStatus::Internal(why) => {
            eprintln!(
                "rax-user: pid {}: emulator error: {why}",
                super::host::pid()
            );
            (exited_status(125), 125)
        }
    };
    me.exit(wait_status);
    super::host::exit_now(code)
}
