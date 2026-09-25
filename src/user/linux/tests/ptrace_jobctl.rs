//! A traced process's job control against `kernel/signal.c` and
//! `kernel/ptrace.c` (Linux 6.19), on every ABI: a group stop as a seized
//! thread reports it (`PTRACE_EVENT_STOP` with the stop's signal and
//! siginfo) and as an attached one does (the signal, no siginfo), the
//! tracer's `SIGCHLD` for it (`CLD_STOPPED` with the group's signal) and
//! for other stops (`CLD_TRAPPED`), the other traced threads joining it,
//! `PTRACE_INTERRUPT` (a running thread traps with `SIGTRAP`, a sleeping
//! one's call is interrupted and restarted, a stopped one traps again after
//! its stop, attached threads refuse it), `PTRACE_LISTEN` (only in a
//! `PTRACE_EVENT_STOP` trap and seized; the tracer stops seeing the stop;
//! `SIGCONT` and `PTRACE_INTERRUPT` trap it again), and `SIGCONT` telling
//! every seized thread.

use super::harness::{Harness, each_abi};
use super::ptrace_stops::{Tracer, ask, resume};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::process::Threads;
use crate::user::linux::ptrace::tracee::{parked, trap_notify};
use crate::user::linux::ptrace::{EVENT_STOP, Link, LinkId, Msg, StopKind, Traced, req};
use crate::user::linux::signal::deliver::{Dest, recalc_sigpending, send_signal};
use crate::user::linux::signal::{SIGCHLD, SIGCONT, SIGSTOP, SIGTRAP, SigInfo, code};

/// `CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
/// CLONE_SYSVSEM`: a thread.
const THREAD: u64 = 0x100 | 0x200 | 0x400 | 0x800 | 0x1_0000 | 0x4_0000;

fn e(errno: i32) -> i64 {
    -(errno as i64)
}

/// Makes thread 0 traced along its parent link, seized or attached, and
/// running.
fn tracee(h: &mut Harness, seized: bool) -> Tracer {
    let (mine, theirs) = Link::pair().unwrap();
    h.proc.state.parent_link = Some(mine);
    let tracer = h.proc.state.ppid;
    h.proc.threads[0].ptrace = Some(Traced::new(tracer, LinkId::Parent, seized, 0));
    Tracer { link: theirs }
}

fn signal(h: &mut Harness, sig: i32) {
    let me = h.proc.state.pid;
    let mut th = Threads::split(&mut h.proc.threads, None);
    send_signal(
        &mut h.proc.state,
        &mut th,
        SigInfo::kernel(sig),
        Dest::Process(me),
        false,
    );
}

/// The stop thread 0 is in: its exit code, siginfo code, and kind.
fn stop(h: &Harness) -> (i32, Option<i32>, StopKind) {
    let s = h.proc.threads[0]
        .ptrace
        .as_ref()
        .unwrap()
        .stop
        .clone()
        .expect("stopped");
    (s.code, s.info.map(|i| i.code), s.kind)
}

/// The `Stop` messages the tracer received: `(code, why, status)`.
fn stops(tr: &mut Tracer) -> Vec<(i32, i32, i32)> {
    tr.link
        .recv()
        .into_iter()
        .filter_map(|m| match m {
            Msg::Stop {
                code, why, status, ..
            } => Some((code, why, status)),
            _ => None,
        })
        .collect()
}

/// Into a group stop: the signal-delivery-stop for `SIGSTOP`, then the
/// tracer lets it through.
fn group_stop(h: &mut Harness, tr: &mut Tracer) {
    signal(h, SIGSTOP);
    h.proc.deliver_signals(0);
    assert_eq!(stop(h).2, StopKind::Signal);
    let (ret, _) = ask(h, tr, req::CONT, 0, SIGSTOP as u64, &[]);
    assert_eq!(ret, 0);
    h.proc.deliver_signals(0);
}

#[test]
fn a_group_stop_as_a_seized_and_an_attached_thread_reports_it() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let mut tr = tracee(&mut h, true);
        // The signal-delivery-stop before it is CLD_TRAPPED.
        signal(&mut h, SIGSTOP);
        h.proc.deliver_signals(0);
        assert_eq!(stops(&mut tr), [(SIGSTOP, code::CLD_TRAPPED, SIGSTOP)]);
        assert_eq!(ask(&mut h, &mut tr, req::CONT, 0, SIGSTOP as u64, &[]).0, 0);
        h.proc.deliver_signals(0);
        let event = SIGSTOP | (EVENT_STOP << 8);
        assert_eq!(stop(&h), (event, Some(event), StopKind::Quiet));
        assert_eq!(h.proc.state.group_stop, Some(SIGSTOP));
        assert_eq!(stops(&mut tr), [(event, code::CLD_STOPPED, SIGSTOP)]);
        // Attached: the signal and no siginfo.
        let mut h = Harness::new(abi);
        let mut tr = tracee(&mut h, false);
        group_stop(&mut h, &mut tr);
        assert_eq!(stop(&h), (SIGSTOP, None, StopKind::Quiet));
        assert_eq!(
            stops(&mut tr).last(),
            Some(&(SIGSTOP, code::CLD_STOPPED, SIGSTOP))
        );
        let (ret, _) = ask(&mut h, &mut tr, req::GETSIGINFO, 0, 0, &[]);
        assert_eq!(ret, e(EINVAL));
    });
}

#[test]
fn the_other_traced_threads_join_a_group_stop() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let mut tr = tracee(&mut h, true);
        let args = [THREAD, 0, 0, 0, 0];
        let tid = h.ok(Sysno::Clone, &args) as i32;
        let seized = h.index_of(tid);
        let tracer = h.proc.state.ppid;
        h.proc.threads[seized].ptrace = Some(Traced::new(tracer, LinkId::Parent, true, 0));
        let untraced = h.ok(Sysno::Clone, &args) as i32;
        let untraced = h.index_of(untraced);
        group_stop(&mut h, &mut tr);
        let other = h.proc.threads[seized].ptrace.as_ref().unwrap();
        assert!(
            other.trap_notify && !other.trap_stop,
            "a seized thread is told"
        );
        assert!(h.proc.threads[seized].sigpending);
        assert!(h.proc.threads[untraced].ptrace.is_none());
        // An attached thread stops with the group.
        let mut h = Harness::new(abi);
        let mut tr = tracee(&mut h, false);
        let tid = h.ok(Sysno::Clone, &args) as i32;
        let i = h.index_of(tid);
        h.proc.threads[i].ptrace = Some(Traced::new(tracer, LinkId::Parent, false, 0));
        group_stop(&mut h, &mut tr);
        let other = h.proc.threads[i].ptrace.as_ref().unwrap();
        assert!(other.trap_stop && !other.trap_notify);
        h.proc.deliver_signals(i);
        let s = h.proc.threads[i]
            .ptrace
            .as_ref()
            .unwrap()
            .stop
            .clone()
            .unwrap();
        assert_eq!((s.code, s.info.is_none()), (SIGSTOP, true));
    });
}

#[test]
fn interrupt_traps_a_seized_thread_wherever_it_is() {
    each_abi(|abi| {
        // Running: a trap with SIGTRAP, reported as CLD_STOPPED.
        let mut h = Harness::new(abi);
        let mut tr = tracee(&mut h, true);
        assert_eq!(ask(&mut h, &mut tr, req::INTERRUPT, 0, 0, &[]).0, 0);
        assert!(h.proc.threads[0].sigpending, "TIF_SIGPENDING");
        let me = &h.proc.threads[0];
        assert!(
            recalc_sigpending(&h.proc.state, me),
            "kept while the trap is due"
        );
        h.proc.deliver_signals(0);
        let event = SIGTRAP | (EVENT_STOP << 8);
        assert_eq!(stop(&h), (event, Some(event), StopKind::Quiet));
        assert_eq!(stops(&mut tr).last(), Some(&(event, code::CLD_STOPPED, 0)));
        assert!(!h.proc.threads[0].ptrace.as_ref().unwrap().trap_stop);
        // Stopped: a trap again once resumed.
        assert_eq!(ask(&mut h, &mut tr, req::INTERRUPT, 0, 0, &[]).0, 0);
        assert!(parked(&h.proc.threads[0]));
        assert_eq!(resume(&mut h, &mut tr, req::CONT, 0), 0);
        assert!(parked(&h.proc.threads[0]), "trapped again");
        assert_eq!(stop(&h).0, event);
        // Attached threads have no PTRACE_INTERRUPT.
        let mut h = Harness::new(abi);
        let mut tr = tracee(&mut h, false);
        assert_eq!(ask(&mut h, &mut tr, req::INTERRUPT, 0, 0, &[]).0, e(EIO));
    });
}

#[test]
fn interrupt_ends_a_sleep_whose_call_restarts() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let fds = h.scratch;
        h.ok(Sysno::Pipe2, &[fds, 0]);
        let mut b = [0u8; 4];
        h.proc.state.space.read_raw(fds, &mut b).unwrap();
        let rd = u32::from_le_bytes(b) as u64;
        let mut tr = tracee(&mut h, true);
        let read = h.abi().number(Sysno::Read).unwrap();
        h.proc.threads[0].syscall =
            Some(crate::user::linux::signal::deliver::SyscallEntry { nr: read, arg0: rd });
        assert_eq!(h.start(0, Sysno::Read, &[rd, fds + 64, 4]), None, "sleeps");
        assert_eq!(ask(&mut h, &mut tr, req::INTERRUPT, 0, 0, &[]).0, 0);
        assert_eq!(h.proc.wake_sleepers(), 1);
        // The call ended with its restart code, then the trap.
        assert!(h.proc.threads[0].blocked.is_none());
        h.proc.deliver_signals(0);
        assert_eq!(stop(&h).0, SIGTRAP | (EVENT_STOP << 8));
        // Resumed: the call is made again (the PC back at it).
        let pc = h.proc.threads[0].cpu.pc();
        assert_eq!(resume(&mut h, &mut tr, req::CONT, 0), 0);
        let len = h.proc.threads[0].cpu.syscall_insn_len();
        assert_eq!(h.proc.threads[0].cpu.pc(), pc - len, "restarted");
    });
}

#[test]
fn listen_keeps_a_seized_thread_stopped_until_a_change() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let mut tr = tracee(&mut h, true);
        // Only in a PTRACE_EVENT_STOP trap: not at a signal-delivery-stop.
        signal(&mut h, SIGSTOP);
        h.proc.deliver_signals(0);
        assert_eq!(ask(&mut h, &mut tr, req::LISTEN, 0, 0, &[]).0, e(EIO));
        assert_eq!(ask(&mut h, &mut tr, req::CONT, 0, SIGSTOP as u64, &[]).0, 0);
        h.proc.deliver_signals(0);
        stops(&mut tr);
        // Listening: still stopped, and the tracer is told first.
        assert_eq!(ask(&mut h, &mut tr, req::LISTEN, 0, 0, &[]).0, 0);
        assert!(parked(&h.proc.threads[0]));
        assert!(h.proc.threads[0].ptrace.as_ref().unwrap().listening);
        // SIGCONT ends the group stop and traps it again, with SIGTRAP.
        signal(&mut h, SIGCONT);
        assert_eq!(h.proc.state.group_stop, None);
        assert!(!parked(&h.proc.threads[0]));
        h.proc.deliver_signals(0);
        let event = SIGTRAP | (EVENT_STOP << 8);
        assert_eq!(stop(&h).0, event);
        // Then SIGCONT's own signal-delivery-stop.
        assert_eq!(resume(&mut h, &mut tr, req::CONT, 0), 0);
        assert_eq!((stop(&h).0, stop(&h).2), (SIGCONT, StopKind::Signal));
        // PTRACE_INTERRUPT traps a listening thread again at once.
        assert_eq!(resume(&mut h, &mut tr, req::CONT, 0), 0);
        group_stop(&mut h, &mut tr);
        assert_eq!(ask(&mut h, &mut tr, req::LISTEN, 0, 0, &[]).0, 0);
        assert_eq!(ask(&mut h, &mut tr, req::INTERRUPT, 0, 0, &[]).0, 0);
        assert!(!parked(&h.proc.threads[0]));
        h.proc.deliver_signals(0);
        assert_eq!(
            stop(&h).0,
            SIGSTOP | (EVENT_STOP << 8),
            "still group-stopped"
        );
        // Attached threads cannot listen.
        let mut h = Harness::new(abi);
        let mut tr = tracee(&mut h, false);
        group_stop(&mut h, &mut tr);
        assert_eq!(ask(&mut h, &mut tr, req::LISTEN, 0, 0, &[]).0, e(EIO));
    });
}

#[test]
fn sigcont_tells_every_seized_thread() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let _tr = tracee(&mut h, true);
        signal(&mut h, SIGCONT);
        let tr = h.proc.threads[0].ptrace.as_ref().unwrap();
        assert!(tr.trap_notify, "even outside a group stop");
        // An attached thread is not told.
        h.proc.threads[0].ptrace.as_mut().unwrap().seized = false;
        h.proc.threads[0].ptrace.as_mut().unwrap().trap_notify = false;
        trap_notify(&mut h.proc.threads[0]);
        assert!(!h.proc.threads[0].ptrace.as_ref().unwrap().trap_notify);
    });
}

#[test]
fn the_tracer_learns_of_stops_and_listening() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let (mine, theirs) = Link::pair().unwrap();
    h.proc.state.parent_link = Some(mine);
    let parent = h.proc.state.ppid;
    let me = h.proc.threads[0].tid;
    h.proc.state.tracees.add(parent, me, LinkId::Parent, true);
    // A SIGCHLD handler, so the notification is queued.
    h.proc.state.sigactions[(SIGCHLD - 1) as usize].handler = 0x40_1000;
    let event = SIGSTOP | (EVENT_STOP << 8);
    assert!(theirs.send(&Msg::Stop {
        tid: parent,
        code: event,
        why: code::CLD_STOPPED,
        status: SIGSTOP,
        uid: 77,
    }));
    while h.proc.state.tracees.get(parent).unwrap().stopped.is_none() {
        h.proc.collect_async(None);
    }
    let chld = h
        .proc
        .state
        .shared_pending
        .records()
        .find(|i| i.signo == SIGCHLD);
    let chld = chld.expect("SIGCHLD");
    assert_eq!(
        (chld.code, chld.pid(), chld.uid()),
        (code::CLD_STOPPED, parent, 77)
    );
    assert!(theirs.send(&Msg::Listening { tid: parent }));
    while h.proc.state.tracees.get(parent).unwrap().stopped.is_some() {
        h.proc.collect_async(None);
    }
}

/// `kill(pid, SIGSTOP)` to a linked process travels along the link (a host
/// `SIGSTOP` would stop the host process, traced or not), and the receiver
/// takes it as a guest signal from the sender.
#[test]
fn sigstop_to_a_linked_process_goes_along_the_link() {
    let mut h = Harness::new(LinuxAbi::Aarch64);
    let (mine, mut theirs) = Link::pair().unwrap();
    h.proc.state.parent_link = Some(mine);
    h.proc.state.config.processes = true;
    // The "parent" is a throwaway host process: had the signal gone
    // through the host, it would have stopped that one.
    let mut stand_in = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    h.proc.state.ppid = stand_in.id() as i32;
    let parent = h.proc.state.ppid as u64;
    let ret = h.call(Sysno::Kill, &[parent, SIGSTOP as u64]);
    let _ = stand_in.kill();
    let _ = stand_in.wait();
    assert_eq!(ret, 0);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let got = loop {
        let m = theirs.recv();
        if !m.is_empty() || std::time::Instant::now() > deadline {
            break m;
        }
    };
    let (me, uid) = (h.proc.state.pid, h.proc.state.creds.0);
    assert_eq!(
        got,
        [Msg::Kill {
            sig: SIGSTOP,
            pid: me,
            uid
        }]
    );
    // Received: queued for the process with the sender's identity.
    assert!(theirs.send(&Msg::Kill {
        sig: SIGSTOP,
        pid: 4321,
        uid: 7,
    }));
    while !h.proc.state.shared_pending.contains(SIGSTOP) {
        h.proc.collect_async(None);
    }
    let info = *h.proc.state.shared_pending.records().next().unwrap();
    assert_eq!(
        (info.code, info.pid(), info.uid()),
        (code::SI_USER, 4321, 7)
    );
}
