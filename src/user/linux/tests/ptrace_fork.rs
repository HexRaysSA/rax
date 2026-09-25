//! A traced process's forks against `kernel/fork.c` and `kernel/ptrace.c`
//! (Linux 6.19): which fork is traced and reported (`kernel_clone`'s
//! event, `CLONE_PTRACE`, `CLONE_UNTRACED`), the forker passing its tracer
//! a link to the new process and stopping for the event, the new process
//! traced along that link from its first instruction, the `vfork` events on
//! either side of its sleep, and a tracer adopting and reaping the new
//! tracee.

use super::harness::{Harness, each_abi};
use super::ptrace_stops::{Tracer, ask};
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::ptrace::tracee::{self, ForkTrace, fork_trace, parked};
use crate::user::linux::ptrace::{
    EVENT_CLONE, EVENT_FORK, EVENT_STOP, EVENT_VFORK, EVENT_VFORK_DONE, Link, LinkId, Msg,
    StopKind, Traced, link_ids, link_to, opt, peer_pid, req,
};
use crate::user::linux::signal::{SIGCHLD, SIGSTOP, SIGTRAP};

/// Makes thread 0 traced by its parent, running, with `options`.
fn tracee(h: &mut Harness, seized: bool, options: u64) -> Tracer {
    let (mine, theirs) = Link::pair().unwrap();
    h.proc.state.parent_link = Some(mine);
    let tracer = h.proc.state.ppid;
    h.proc.threads[0].ptrace = Some(Traced::new(tracer, LinkId::Parent, seized, options));
    Tracer { link: theirs }
}

/// The stop thread `idx` is in: exit code, kind, message.
fn stop(h: &Harness, idx: usize) -> (i32, StopKind, u64) {
    let tr = h.proc.threads[idx].ptrace.as_ref().unwrap();
    let s = tr.stop.as_ref().expect("stopped");
    (s.code, s.kind, tr.message)
}

fn event(e: i32) -> i32 {
    SIGTRAP | (e << 8)
}

/// A fork's tracing as `fork_trace` would make it, with the link's ends
/// given: the tracer's end, then the new process's.
fn trace(
    event: Option<i32>,
    tracer: i32,
    seized: bool,
    options: u64,
    ends: (Link, Link),
) -> ForkTrace {
    ForkTrace {
        event,
        tracer,
        seized,
        options,
        ends,
    }
}

/// Writes a byte into pipe end `wr` (a call of thread 0's that does not
/// sleep, made while its read sleeps).
fn write_pipe(h: &mut Harness, wr: u64) {
    let at = h.scratch + 128;
    h.fill(at, 1, b'x');
    assert_eq!(h.ok(Sysno::Write, &[wr, at, 1]), 1);
}

#[test]
fn a_fork_is_traced_as_the_tracer_asked() {
    let sigchld = SIGCHLD as u64;
    let mut h = Harness::new(LinuxAbi::X86_64);
    // Untraced: never.
    let t = &h.proc.threads[0];
    assert!(
        fork_trace(t, false, false, true, sigchld)
            .unwrap()
            .is_none()
    );
    let all = opt::TRACEFORK | opt::TRACEVFORK | opt::TRACECLONE;
    let _tr = tracee(&mut h, true, all);
    // (vfork, untraced, CLONE_PTRACE, exit signal) -> the event, traced.
    for (vfork, untraced, ptrace, signal, want) in [
        (false, false, false, sigchld, Some(EVENT_FORK)),
        (true, false, false, sigchld, Some(EVENT_VFORK)),
        // An exit signal other than SIGCHLD: a clone.
        (false, false, false, 0, Some(EVENT_CLONE)),
        (true, false, false, 0, Some(EVENT_VFORK)),
    ] {
        let got = fork_trace(&h.proc.threads[0], vfork, untraced, ptrace, signal)
            .unwrap()
            .expect("traced");
        assert_eq!(got.event, want);
        let tracer = h.proc.state.ppid;
        assert_eq!((got.tracer, got.seized, got.options), (tracer, true, all));
    }
    // CLONE_UNTRACED drops the event, and the tracing unless CLONE_PTRACE.
    let t = &h.proc.threads[0];
    assert!(
        fork_trace(t, false, true, false, sigchld)
            .unwrap()
            .is_none()
    );
    let got = fork_trace(t, false, true, true, sigchld).unwrap().unwrap();
    assert_eq!(got.event, None);
    // Options not asked for: no event; CLONE_PTRACE alone traces.
    h.proc.threads[0].ptrace.as_mut().unwrap().options = opt::TRACEFORK;
    let t = &h.proc.threads[0];
    assert!(
        fork_trace(t, true, false, false, sigchld)
            .unwrap()
            .is_none()
    );
    assert!(fork_trace(t, false, false, false, 0).unwrap().is_none());
    let got = fork_trace(t, true, false, true, sigchld).unwrap().unwrap();
    assert_eq!(got.event, None);
}

#[test]
fn the_forker_passes_a_link_then_stops_for_its_event() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let mut tr = tracee(&mut h, false, opt::TRACEFORK);
        let tracer = h.proc.state.ppid;
        let me = h.proc.threads[0].tid;
        let (tracer_end, mut child_end) = Link::pair().unwrap();
        let (_, spare) = Link::pair().unwrap();
        let fork = trace(
            Some(EVENT_FORK),
            tracer,
            false,
            opt::TRACEFORK,
            (tracer_end, spare),
        );
        let (p, t) = (&mut h.proc.state, &mut h.proc.threads[0]);
        tracee::forker_traced(p, t, fork, 4242);
        // The tracer hears of the new tracee with the link's end.
        let got = loop {
            let m = tr.link.recv();
            if !m.is_empty() {
                break m;
            }
        };
        assert_eq!(
            got,
            vec![Msg::Adopt {
                tid: 4242,
                parent: me,
                seized: false
            }]
        );
        let theirs = Link::from_fd(tr.link.take_fd().expect("the link's end"));
        assert!(tr.link.take_fd().is_none());
        assert!(theirs.send(&Msg::Listening { tid: 4242 }));
        let heard = loop {
            let m = child_end.recv();
            if !m.is_empty() {
                break m;
            }
        };
        assert_eq!(heard, vec![Msg::Listening { tid: 4242 }]);
        // Then the forker stops for its event, the new PID the message.
        assert!(h.proc.call_event(0));
        assert!(parked(&h.proc.threads[0]));
        assert_eq!(stop(&h, 0), (event(EVENT_FORK), StopKind::Event, 4242));
        let tr = h.proc.threads[0].ptrace.as_ref().unwrap();
        assert!(tr.events.is_empty());
    });
}

#[test]
fn the_forked_process_is_traced_along_its_own_link() {
    each_abi(|abi| {
        for seized in [false, true] {
            let mut h = Harness::new(abi);
            let (mut tracer_end, child_end) = Link::pair().unwrap();
            let (spare, _) = Link::pair().unwrap();
            let tracer = h.proc.state.ppid + 7;
            let fork = trace(None, tracer, seized, opt::TRACEFORK, (spare, child_end));
            let (p, t) = (&mut h.proc.state, &mut h.proc.threads[0]);
            tracee::forked_traced(p, t, fork);
            let tr = h.proc.threads[0].ptrace.as_ref().unwrap();
            assert_eq!(
                (tr.tracer, tr.link, tr.seized, tr.options),
                (tracer, LinkId::Tracer, seized, opt::TRACEFORK)
            );
            let p = &h.proc.state;
            assert_eq!(peer_pid(p, LinkId::Tracer), tracer);
            assert_eq!(link_to(p, tracer), Some(LinkId::Tracer));
            assert!(link_ids(p).contains(&LinkId::Tracer));
            // Its first stop: SIGSTOP (ptrace_init_task), or seized, a trap.
            assert_eq!(h.proc.threads[0].pending.contains(SIGSTOP), !seized);
            h.proc.deliver_signals(0);
            let want = if seized { event(EVENT_STOP) } else { SIGSTOP };
            assert_eq!(stop(&h, 0).0, want);
            let got = loop {
                let m = tracer_end.recv();
                if !m.is_empty() {
                    break m;
                }
            };
            let tid = h.proc.threads[0].tid;
            assert!(
                matches!(got[0], Msg::Stop { tid: t, code, .. } if t == tid && code == want),
                "{got:?}"
            );
            // The tracer gone: the link dropped, the stopped thread
            // detached (once it takes its resumption, its record without a
            // tracer).
            drop(tracer_end);
            while h.proc.state.tracer_link.is_some() {
                h.proc.collect_async(None);
            }
            let tr = h.proc.threads[0].ptrace.as_ref();
            assert!(tr.is_none_or(|tr| tr.tracer < 0));
        }
    });
}

/// `vfork`'s event comes before its sleep and `PTRACE_EVENT_VFORK_DONE`
/// after (a pipe read standing for the sleep); a stopped sleeper is not
/// woken.
#[test]
fn vfork_stops_before_its_sleep_and_after() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let options = opt::TRACEVFORK | opt::TRACEVFORKDONE;
        let mut tr = tracee(&mut h, false, options);
        let fds = h.scratch;
        h.ok(Sysno::Pipe2, &[fds, 0]);
        let mut b = [0u8; 8];
        h.proc.state.space.read_raw(fds, &mut b).unwrap();
        let (rd, wr) = (
            u32::from_le_bytes(b[..4].try_into().unwrap()) as u64,
            u32::from_le_bytes(b[4..].try_into().unwrap()) as u64,
        );
        tracee::due_event(&mut h.proc.threads[0], EVENT_VFORK, 77);
        let buf = fds + 64;
        assert_eq!(h.start(0, Sysno::Read, &[rd, buf, 1]), None);
        assert_eq!(stop(&h, 0), (event(EVENT_VFORK), StopKind::Event, 77));
        // Ready, but stopped: it sleeps on.
        write_pipe(&mut h, wr);
        assert_eq!(h.proc.wake_sleepers(), 0);
        assert!(h.proc.threads[0].blocked.is_some());
        // Resumed: back to its sleep, which then ends.
        assert_eq!(ask(&mut h, &mut tr, req::CONT, 0, 0, &[]).0, 0);
        h.proc.resume_in_call(0);
        assert!(h.proc.threads[0].blocked.is_some() && !parked(&h.proc.threads[0]));
        tracee::due_event(&mut h.proc.threads[0], EVENT_VFORK_DONE, 77);
        assert_eq!(h.proc.wake_sleepers(), 1);
        assert_eq!(stop(&h, 0), (event(EVENT_VFORK_DONE), StopKind::Event, 77));
        assert_eq!(ask(&mut h, &mut tr, req::CONT, 0, 0, &[]).0, 0);
        h.proc.resume_in_call(0);
        assert_eq!(h.result(0), 1);
        // Both due at once (the vfork child gone before the sleep): in
        // order, then the call's result.
        let t = &mut h.proc.threads[0];
        tracee::due_event(t, EVENT_VFORK, 78);
        tracee::due_event(t, EVENT_VFORK_DONE, 78);
        let pid = h.proc.state.pid as i64;
        assert_eq!(h.start(0, Sysno::Getpid, &[]), Some(pid));
        assert_eq!(stop(&h, 0).0, event(EVENT_VFORK));
        assert_eq!(ask(&mut h, &mut tr, req::CONT, 0, 0, &[]).0, 0);
        h.proc.resume_in_call(0);
        assert_eq!(stop(&h, 0), (event(EVENT_VFORK_DONE), StopKind::Event, 78));
        assert_eq!(ask(&mut h, &mut tr, req::CONT, 0, 0, &[]).0, 0);
        h.proc.resume_in_call(0);
        assert!(!parked(&h.proc.threads[0]));
        assert_eq!(h.result(0), pid);
        // VFORK_DONE not asked for: no stop.
        h.proc.threads[0].ptrace.as_mut().unwrap().options = opt::TRACEVFORK;
        tracee::due_event(&mut h.proc.threads[0], EVENT_VFORK_DONE, 79);
        assert!(!h.proc.call_event(0));
    });
}

/// The tracer's side: the tracee's fork hands it a link to the new
/// process, traced by the thread tracing the forker; the new tracee's
/// stops come along it, and its exit is the tracer's to reap.
#[test]
fn a_tracer_adopts_a_forked_tracee_and_reaps_it() {
    let mut h = Harness::new(LinuxAbi::X86_64);
    let (mine, theirs) = Link::pair().unwrap();
    h.proc.state.parent_link = Some(mine);
    let forker = h.proc.state.ppid;
    let me = h.proc.threads[0].tid;
    h.proc.state.tracees.add(forker, me, LinkId::Parent, false);
    let g = forker + 5;
    let (tracer_end, child_end) = Link::pair().unwrap();
    let adopt = Msg::Adopt {
        tid: g,
        parent: forker,
        seized: false,
    };
    assert!(theirs.send_passing(&adopt, &tracer_end));
    drop(tracer_end);
    while h.proc.state.tracees.get(g).is_none() {
        h.proc.collect_async(None);
    }
    let rec = h.proc.state.tracees.get(g).unwrap();
    assert_eq!((rec.tracer, rec.link), (me, LinkId::Adopted(g)));
    assert_eq!(link_to(&h.proc.state, g), Some(LinkId::Adopted(g)));
    assert_eq!(peer_pid(&h.proc.state, LinkId::Adopted(g)), g);
    // Its SIGSTOP comes along the new link.
    assert!(child_end.send(&Msg::Stop {
        tid: g,
        code: SIGSTOP,
        why: crate::user::linux::signal::code::CLD_TRAPPED,
        status: SIGSTOP,
        uid: 0,
    }));
    while h.proc.state.tracees.get(g).unwrap().stopped.is_none() {
        h.proc.collect_async(None);
    }
    let st = h.scratch;
    let wall = 0x4000_0000u64;
    assert_eq!(h.call(Sysno::Wait4, &[g as u64, st, wall, 0]), g as i64);
    let mut b = [0u8; 4];
    h.proc.state.space.read_raw(st, &mut b).unwrap();
    assert_eq!(i32::from_le_bytes(b), (SIGSTOP << 8) | 0x7f);
    // Its exit, then the link's end: the record stays to be reaped; the
    // link goes.
    assert!(child_end.send(&Msg::Gone {
        tid: g,
        status: Some(0x700)
    }));
    drop(child_end);
    while h.proc.state.adopted.iter().any(|a| a.0 == g) {
        h.proc.collect_async(None);
    }
    assert_eq!(h.proc.state.tracees.get(g).unwrap().exited, Some(0x700));
    assert_eq!(h.call(Sysno::Wait4, &[g as u64, st, wall, 0]), g as i64);
    h.proc.state.space.read_raw(st, &mut b).unwrap();
    assert_eq!(i32::from_le_bytes(b), 0x700);
    assert!(h.proc.state.tracees.get(g).is_none());
    // A group exit reaches every link, an adopted one too.
    let (a, mut b2) = Link::pair().unwrap();
    h.proc.state.adopted.push((g + 1, a));
    tracee::group_exit(&mut h.proc.state, 0x100);
    let got = loop {
        let m = b2.recv();
        if !m.is_empty() {
            break m;
        }
    };
    assert_eq!(got, vec![Msg::GroupExit { status: 0x100 }]);
}
