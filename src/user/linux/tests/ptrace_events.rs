//! Events of traced threads against `kernel/fork.c`, `kernel/exit.c`,
//! `kernel/seccomp.c`, and `kernel/ptrace.c` (Linux 6.19), on every ABI:
//! `PTRACE_EVENT_CLONE` (the new thread traced as its maker is, starting
//! with `SIGSTOP` or, seized, a trap; its tracer told of it; `CLONE_PTRACE`
//! without the option, `CLONE_UNTRACED`), `PTRACE_EVENT_EXIT` for `exit`,
//! `exit_group` (the other threads gone first), and a fatal signal (none
//! for `SIGKILL`), `PTRACE_EVENT_SECCOMP` (after the entry stop; the call
//! looked at again, or skipped), and a tracer reaping the traced threads
//! that exited.

use super::harness::{Harness, each_abi};
use super::ptrace_stops::{Tracer, ask, ask_on, resume};
use super::seccomp::{fprog, nnp, on};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::process::{ExitStatus, Threads};
use crate::user::linux::ptrace::tracee::parked;
use crate::user::linux::ptrace::{
    EVENT_CLONE, EVENT_EXIT, EVENT_SECCOMP, Link, LinkId, Msg, StopKind, Traced, call, opt, req,
};
use crate::user::linux::seccomp::{RET_ALLOW, RET_TRACE};
use crate::user::linux::signal::deliver::{Dest, send_signal};
use crate::user::linux::signal::{SIGCHLD, SIGKILL, SIGSTOP, SIGTERM, SIGTRAP, SigInfo, code};

/// A thread's clone flags.
const THREAD: u64 = 0x100 | 0x200 | 0x400 | 0x800 | 0x1_0000;
const CLONE_PTRACE: u64 = 0x2000;
const CLONE_UNTRACED: u64 = 0x80_0000;

/// Makes thread 0 traced, running, with `options`.
fn tracee(h: &mut Harness, seized: bool, options: u64) -> Tracer {
    let (mine, theirs) = Link::pair().unwrap();
    h.proc.state.parent_link = Some(mine);
    let tracer = h.proc.state.ppid;
    h.proc.threads[0].ptrace = Some(Traced::new(tracer, LinkId::Parent, seized, options));
    Tracer { link: theirs }
}

fn messages(tr: &mut Tracer) -> Vec<Msg> {
    tr.link.recv()
}

/// The stop thread `idx` is in: exit code, kind, message.
fn stop(h: &Harness, idx: usize) -> (i32, StopKind, u64) {
    let tr = h.proc.threads[idx].ptrace.as_ref().unwrap();
    let s = tr.stop.as_ref().expect("stopped");
    (s.code, s.kind, tr.message)
}

/// A thread of thread 0 made with `flags` as the scheduler would run the
/// call; returns its TID.
fn spawn(h: &mut Harness, flags: u64) -> i32 {
    let nr = h.abi().number(Sysno::Clone).unwrap();
    h.proc.enter_syscall(0, nr, [flags, 0, 0, 0, 0, 0]);
    let t = &h.proc.threads[0];
    t.cpu.syscall_return_value() as i32
}

#[test]
fn clone_traces_the_new_thread_as_its_maker_is() {
    each_abi(|abi| {
        for seized in [false, true] {
            let mut h = Harness::new(abi);
            let mut tr = tracee(&mut h, seized, opt::TRACECLONE);
            let tid = spawn(&mut h, THREAD);
            // The maker stops for the event, the new TID its message.
            assert!(parked(&h.proc.threads[0]));
            assert_eq!(
                stop(&h, 0),
                (SIGTRAP | (EVENT_CLONE << 8), StopKind::Event, tid as u64)
            );
            // The tracer heard of the thread first.
            let got = messages(&mut tr);
            let me = h.proc.threads[0].tid;
            assert_eq!(
                got[0],
                Msg::Traced {
                    tid,
                    parent: me,
                    seized
                }
            );
            // The new thread: traced, SIGSTOP pending (a trap when seized).
            let i = h.index_of(tid);
            let t = &h.proc.threads[i];
            let child = t.ptrace.as_ref().unwrap();
            assert_eq!((child.seized, child.options), (seized, opt::TRACECLONE));
            assert_eq!(child.trap_stop, seized);
            assert_eq!(t.pending.contains(SIGSTOP), !seized);
            h.proc.deliver_signals(i);
            let s = h.proc.threads[i]
                .ptrace
                .as_ref()
                .unwrap()
                .stop
                .clone()
                .unwrap();
            if seized {
                assert_eq!(s.code, SIGTRAP | (128 << 8), "PTRACE_EVENT_STOP");
            } else {
                let info = s.info.unwrap();
                assert_eq!((s.code, info.code, info.pid()), (SIGSTOP, code::SI_USER, 0));
            }
        }
        // Without the option or with CLONE_UNTRACED: untraced, no event;
        // CLONE_PTRACE alone: traced, no event.
        for (options, extra, traced) in [
            (0, 0, false),
            (opt::TRACECLONE, CLONE_UNTRACED, false),
            (0, CLONE_PTRACE, true),
        ] {
            let mut h = Harness::new(abi);
            let _tr = tracee(&mut h, false, options);
            let tid = spawn(&mut h, THREAD | extra);
            assert!(!parked(&h.proc.threads[0]));
            let i = h.index_of(tid);
            assert_eq!(h.proc.threads[i].ptrace.is_some(), traced);
        }
    });
}

#[test]
fn exit_stops_a_thread_before_it_ends() {
    each_abi(|abi| {
        // exit(3) of a second thread: the message is the exit code.
        let mut h = Harness::new(abi);
        let mut tr = tracee(&mut h, false, opt::TRACEEXIT | opt::TRACECLONE);
        let tid = spawn(&mut h, THREAD);
        assert_eq!(resume(&mut h, &mut tr, req::CONT, 0), 0);
        let i = h.index_of(tid);
        let nr = h.abi().number(Sysno::Exit).unwrap();
        h.proc.enter_syscall(i, nr, [3, 0, 0, 0, 0, 0]);
        assert_eq!(
            stop(&h, i),
            (SIGTRAP | (EVENT_EXIT << 8), StopKind::Exiting, 0x300)
        );
        messages(&mut tr);
        assert_eq!(ask_on(&mut h, &mut tr, tid, req::CONT, 0, 0, &[]).0, 0);
        let tid_of = |h: &Harness| h.proc.threads.iter().any(|t| t.tid == tid);
        let i = h.index_of(tid);
        h.proc.resume_in_call(i);
        assert!(!tid_of(&h), "gone once resumed");
        let got = messages(&mut tr);
        assert!(
            got.contains(&Msg::Gone {
                tid,
                status: Some(0x300)
            }),
            "{got:?}"
        );
    });
}

#[test]
fn a_group_exit_ends_the_other_threads_then_stops() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let mut tr = tracee(&mut h, false, opt::TRACEEXIT);
        let nr = h.abi().number(Sysno::Clone).unwrap();
        let other = h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]) as i32;
        let _ = nr;
        let tracer = h.proc.state.ppid;
        let i = h.index_of(other);
        h.proc.threads[i].ptrace = Some(Traced::new(tracer, LinkId::Parent, false, opt::TRACEEXIT));
        let nr = h.abi().number(Sysno::ExitGroup).unwrap();
        h.proc.enter_syscall(0, nr, [5, 0, 0, 0, 0, 0]);
        // The other thread is gone (reported with the group's status),
        // and did not stop; this one stops.
        assert!(h.proc.threads.iter().all(|t| t.tid != other));
        let got = messages(&mut tr);
        assert!(
            got.contains(&Msg::Gone {
                tid: other,
                status: Some(0x500)
            }),
            "{got:?}"
        );
        assert_eq!(
            stop(&h, 0),
            (SIGTRAP | (EVENT_EXIT << 8), StopKind::Exiting, 0x500)
        );
        assert!(h.proc.state.exit.is_none());
        assert_eq!(ask(&mut h, &mut tr, req::CONT, 0, 0, &[]).0, 0);
        h.proc.resume_in_call(0);
        assert_eq!(h.proc.state.exit, Some(ExitStatus::Exited(5)));
    });
}

#[test]
fn a_fatal_signal_stops_before_the_process_dies_but_sigkill_does_not() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let mut tr = tracee(&mut h, false, opt::TRACEEXIT);
        let me = h.proc.state.pid;
        let mut th = Threads::split(&mut h.proc.threads, None);
        let info = SigInfo::kill(SIGTERM, code::SI_USER, me, 0);
        send_signal(&mut h.proc.state, &mut th, info, Dest::Process(me), false);
        h.proc.deliver_signals(0);
        // Its signal-delivery-stop first; let through, the exit event.
        assert_eq!(stop(&h, 0).1, StopKind::Signal);
        assert_eq!(ask(&mut h, &mut tr, req::CONT, 0, SIGTERM as u64, &[]).0, 0);
        h.proc.deliver_signals(0);
        assert_eq!(
            stop(&h, 0),
            (
                SIGTRAP | (EVENT_EXIT << 8),
                StopKind::Exiting,
                SIGTERM as u64
            )
        );
        assert!(h.proc.state.exit.is_none());
        assert_eq!(ask(&mut h, &mut tr, req::CONT, 0, 0, &[]).0, 0);
        h.proc.resume_in_call(0);
        let Some(ExitStatus::Signaled { info, .. }) = h.proc.state.exit else {
            panic!("dies of SIGTERM");
        };
        assert_eq!(info.signo, SIGTERM);
        // SIGKILL: no stop.
        let mut h = Harness::new(abi);
        let _tr = tracee(&mut h, false, opt::TRACEEXIT);
        let mut th = Threads::split(&mut h.proc.threads, None);
        send_signal(
            &mut h.proc.state,
            &mut th,
            SigInfo::kernel(SIGKILL),
            Dest::Process(me),
            false,
        );
        h.proc.deliver_signals(0);
        assert!(!parked(&h.proc.threads[0]));
        assert!(h.proc.state.exit.is_some());
    });
}

#[test]
fn seccomp_trace_stops_for_a_tracer_that_asked() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        nnp(&mut h);
        let prog = on(&h, Sysno::Getpid, RET_TRACE | 42);
        let at = h.scratch;
        let fp = fprog(&h, at, &prog);
        h.ok(Sysno::Seccomp, &[1, 0, fp]);
        // No tracer asking: ENOSYS. (The number register is set as a real
        // call's would be: RISC-V reads its number from a7.)
        let getpid = h.abi().number(Sysno::Getpid).unwrap();
        h.proc.threads[0].cpu.set_syscall_number(getpid);
        let mut tr = tracee(&mut h, false, 0);
        h.proc.enter_syscall(0, getpid, [0; 6]);
        assert_eq!(h.result(0), -(ENOSYS as i64));
        // PTRACE_O_TRACESECCOMP: the entry stop, then the seccomp stop.
        h.proc.threads[0].ptrace.as_mut().unwrap().options = opt::TRACESECCOMP | opt::TRACESYSGOOD;
        h.proc.threads[0].ptrace.as_mut().unwrap().mode.syscall = true;
        h.proc.threads[0].cpu.set_syscall_number(getpid);
        h.proc.enter_syscall(0, getpid, [0; 6]);
        assert_eq!(stop(&h, 0).1, StopKind::Entry { emu: false });
        assert_eq!(ask(&mut h, &mut tr, req::SYSCALL, 0, 0, &[]).0, 0);
        h.proc.resume_in_call(0);
        assert_eq!(
            stop(&h, 0),
            (SIGTRAP | (EVENT_SECCOMP << 8), StopKind::Seccomp, 42),
            "{abi:?}"
        );
        let (size, b) = ask(&mut h, &mut tr, req::GET_SYSCALL_INFO, 88, 0, &[]);
        assert_eq!((size, b[0]), (84, call::INFO_SECCOMP));
        assert_eq!(u32::from_le_bytes(b[80..84].try_into().unwrap()), 42);
        // Resumed: looked at again, RET_TRACE now allows it; then its exit
        // stop.
        assert_eq!(ask(&mut h, &mut tr, req::SYSCALL, 0, 0, &[]).0, 0);
        h.proc.resume_in_call(0);
        assert_eq!(h.result(0), h.proc.state.pid as i64);
        assert_eq!(stop(&h, 0).1, StopKind::Exit);
        // Skipped: the tracer makes the number -1 at the seccomp stop.
        assert_eq!(resume(&mut h, &mut tr, req::CONT, 0), 0);
        h.proc.threads[0].ptrace.as_mut().unwrap().mode.syscall = false;
        h.proc.threads[0].cpu.set_syscall_number(getpid);
        let x0 = h.result(0);
        h.proc.enter_syscall(0, getpid, [0; 6]);
        assert_eq!(stop(&h, 0).1, StopKind::Seccomp);
        // The entry view, with no entry stop before: x86-64's rax and
        // RISC-V's a0 are -ENOSYS, AArch64's x0 is left as it was.
        let entry = if abi == LinuxAbi::Aarch64 {
            x0
        } else {
            -(ENOSYS as i64)
        };
        assert_eq!(h.result(0), entry);
        let (_, mut b) = ask(&mut h, &mut tr, req::GET_SYSCALL_INFO, 88, 0, &[]);
        b[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(ask(&mut h, &mut tr, req::SET_SYSCALL_INFO, 88, 0, &b).0, 0);
        h.proc.threads[0].cpu.set_syscall_result(7);
        assert_eq!(ask(&mut h, &mut tr, req::CONT, 0, 0, &[]).0, 0);
        h.proc.resume_in_call(0);
        assert_eq!(h.result(0), 7, "not made: the result the tracer left");
        let _ = RET_ALLOW;
    });
}

#[test]
fn a_tracer_reaps_the_traced_threads_that_exited() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let (mine, theirs) = Link::pair().unwrap();
    h.proc.state.parent_link = Some(mine);
    let parent = h.proc.state.ppid;
    let me = h.proc.threads[0].tid;
    h.proc.state.tracees.add(parent, me, LinkId::Parent, false);
    h.proc.state.sigactions[(SIGCHLD - 1) as usize].handler = 0x40_1000;
    // A thread the tracee made, then its exit.
    assert!(theirs.send(&Msg::Traced {
        tid: parent + 1,
        parent,
        seized: false
    }));
    assert!(theirs.send(&Msg::Gone {
        tid: parent + 1,
        status: Some(0x700)
    }));
    while h
        .proc
        .state
        .tracees
        .get(parent + 1)
        .is_none_or(|t| t.exited.is_none())
    {
        h.proc.collect_async(None);
    }
    let chld = h
        .proc
        .state
        .shared_pending
        .records()
        .find(|i| i.signo == SIGCHLD)
        .copied();
    assert_eq!(
        chld.map(|i| (i.code, i.pid())),
        Some((code::CLD_EXITED, parent + 1))
    );
    // wait4(tid, __WALL) reaps it.
    let st = h.scratch;
    let wall = 0x4000_0000u64;
    let got = h.call(Sysno::Wait4, &[(parent + 1) as u64, st, wall, 0]);
    assert_eq!(got, (parent + 1) as i64);
    let mut b = [0u8; 4];
    h.proc.state.space.read_raw(st, &mut b).unwrap();
    assert_eq!(i32::from_le_bytes(b), 0x700);
    assert!(h.proc.state.tracees.get(parent + 1).is_none());
}

/// SECCOMP_RET_TRAP rolls the result register back (syscall_rollback),
/// which a traced thread's entry view had replaced.
#[test]
fn seccomp_trap_rolls_a_traced_call_back() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        nnp(&mut h);
        let trap = 0x0003_0000;
        let prog = on(&h, Sysno::Getpid, trap);
        let at = h.scratch;
        let fp = fprog(&h, at, &prog);
        h.ok(Sysno::Seccomp, &[1, 0, fp]);
        let _tr = tracee(&mut h, false, 0);
        let getpid = h.abi().number(Sysno::Getpid).unwrap();
        h.proc.threads[0].cpu.set_syscall_number(getpid);
        h.proc.enter_syscall(0, getpid, [0x55, 0, 0, 0, 0, 0]);
        // x86-64: orig_ax, the number; the others: the first argument.
        let back = if abi == LinuxAbi::X86_64 {
            getpid
        } else {
            0x55
        };
        assert_eq!(h.result(0) as u64, back);
        assert!(
            h.proc.threads[0]
                .pending
                .contains(crate::user::linux::signal::SIGSYS)
        );
    });
}

/// A thread reaped after its group began to exit reports the group's
/// status (wait_task_zombie).
#[test]
fn threads_reaped_after_a_group_exit_report_its_status() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let (mine, theirs) = Link::pair().unwrap();
    h.proc.state.parent_link = Some(mine);
    let parent = h.proc.state.ppid;
    let me = h.proc.threads[0].tid;
    h.proc.state.tracees.add(parent, me, LinkId::Parent, false);
    assert!(theirs.send(&Msg::Traced {
        tid: parent + 1,
        parent,
        seized: false
    }));
    assert!(theirs.send(&Msg::Gone {
        tid: parent + 1,
        status: Some(0)
    }));
    assert!(theirs.send(&Msg::GroupExit { status: 0x300 }));
    while h
        .proc
        .state
        .tracees
        .get(parent + 1)
        .is_none_or(|t| t.exited != Some(0x300))
    {
        h.proc.collect_async(None);
    }
    let st = h.scratch;
    let got = h.call(Sysno::Wait4, &[(parent + 1) as u64, st, 0x4000_0000, 0]);
    assert_eq!(got, (parent + 1) as i64);
    let mut b = [0u8; 4];
    h.proc.state.space.read_raw(st, &mut b).unwrap();
    assert_eq!(i32::from_le_bytes(b), 0x300);
}
