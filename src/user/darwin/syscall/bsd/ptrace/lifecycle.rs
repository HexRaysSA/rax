//! Guest zombie ownership follows XNU's p_oppid handoff, independently of
//! host parentage. The engine pins its PID until its final guest reap.

use super::{
    channels::{self, ServerRoute},
    incoming::{self, Incoming},
    protocol::Message,
    *,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Report {
    pub status: i32,
    pub rusage: [u8; 144],
}

#[derive(Debug, Default)]
pub(super) struct Target {
    report: Option<Report>,
    route: Option<ServerRoute>,
    original_parent: Option<i32>,
    done: bool,
}

pub(super) fn observe(
    proc: &mut Proc,
    running: Option<&mut Thread>,
    pid: i32,
    report: Report,
    uid: u32,
    reparented: bool,
) {
    let Some(child) = proc.tracing.family.children.get_mut(&pid) else {
        return;
    };
    let belongs = child.shared_status.as_ref().map_or_else(
        || child.traced || reparented && child.original_parent == Some(child.owner_pid),
        |shared| shared.snapshot().2 == child.owner_pid,
    );
    if !belongs || child.registered_exit.is_some() {
        return;
    }
    child.registered_exit = Some(report);
    child.stop = None;
    child.traced = false;
    child.attach_stop_pending = false;
    crate::user::darwin::kevent::guest_exit(proc, pid, report.status);
    let origin = Origin {
        pid,
        uid,
        status: report.status,
        // reap_child_locked sends CLD_CONTINUED when returning a zombie.
        code: if reparented { 6 } else { 1 },
    };
    proc.post(WaitKey::Child);
    if proc.sigacts.nocldwait {
        consume_exit(proc, pid);
    } else if reparented {
        // This is reap_child_locked's explicit psignal, not an ordinary
        // SIGCONT notification (which does not post SIGCHLD).
        proc.sigacts.origin = origin;
        signal::psignal(proc, running, signal::SIGCHLD, origin);
    } else if signal::child_changed(proc, &origin) {
        signal::psignal(proc, running, signal::SIGCHLD, origin);
    }
}

pub(super) fn wait_status(status: &ExitStatus) -> i32 {
    match status {
        ExitStatus::Exited(code) => (code & 0xff) << 8,
        ExitStatus::Signaled { signo, core, .. } => (signo & 0x7f) | if *core { 0x80 } else { 0 },
        ExitStatus::Internal(_) => 125 << 8,
    }
}

fn send_report(proc: &mut Proc, route: ServerRoute, report: Report, reparented: bool) -> bool {
    channels::queue_reply(
        proc,
        route,
        Message::ExitReport {
            status: report.status,
            uid: proc.creds.0,
            rusage: report.rusage,
            reparented,
        }
        .encode(),
    )
}

/// Complete one reap_child_locked operation. A saved p_oppid returns the
/// zombie even when the original parent and tracer are the same process.
fn advance(proc: &mut Proc, old: ServerRoute, ack: Option<u64>) {
    let original = proc.tracing.registered_exit.original_parent.take();
    let next = original.filter(|pid| *pid > 0).and_then(|pid| {
        if old.pid(proc) == Some(pid) && ack.is_some() {
            Some(old)
        } else if proc.tracing.family.parent_pid == Some(pid)
            && ServerRoute::Parent.link(proc).is_some()
            && old != ServerRoute::Parent
        {
            Some(ServerRoute::Parent)
        } else {
            None
        }
    });
    let retained = next == Some(old);
    if let Some(id) = ack {
        let _ = channels::queue_reply(proc, old, Message::ReapReply { id, retained }.encode());
    }
    proc.tracing.original_parent = None;
    if let Some(parent) = original {
        proc.ppid = parent;
        if let Some(shared) = &proc.tracing.family.parent_status {
            shared.set_parent(0, parent, false);
        }
    }
    proc.tracing.registered_exit.route = next;
    if let Some(route) = next {
        let report = proc
            .tracing
            .registered_exit
            .report
            .expect("initialized zombie");
        if !send_report(proc, route, report, true) {
            proc.tracing.registered_exit.route = None;
            proc.tracing.registered_exit.done = true;
        }
    } else {
        proc.tracing.registered_exit.done = true;
    }
}

/// Called after guest exit. No guest instructions or new MIG operations run.
/// All server links remain drainable until the reap reply has left the engine.
pub(crate) fn exit_wait(proc: &mut Proc) -> Option<Vec<(i32, bool, bool)>> {
    if proc.tracing.registered_exit.report.is_none() {
        let route = channels::tracer(proc).filter(|route| route.link(proc).is_some())?;
        let status = wait_status(proc.exit.as_ref()?);
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: usage is writable and this samples this engine only.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
            return None;
        }
        let report = Report {
            status,
            rusage: super::super::wait::rusage_bytes(&usage),
        };
        proc.tracing.registered_exit = Target {
            report: Some(report),
            route: Some(route),
            original_parent: proc.tracing.original_parent,
            done: false,
        };
        record_exit(&proc.tracing, proc.exit.as_ref().unwrap());
        remote_mach::target_exited(proc);
        proc.tracing.tracer = None;
        proc.tracing.tracer_route = None;
        if !send_report(proc, route, report, false) {
            advance(proc, route, None);
            channels::disconnect(proc, route);
        }
    }
    for route in channels::routes(proc) {
        if !remote_mach::flush_responses_on(proc, route) {
            if proc.tracing.registered_exit.route == Some(route) {
                advance(proc, route, None);
            }
            channels::disconnect(proc, route);
            continue;
        }
        let Some(link) = route.link_mut(proc) else {
            continue;
        };
        let (messages, closed) = incoming::receive(link, false);
        for message in messages {
            match message {
                Incoming::Trace(Message::ReapAck { id })
                    if proc.tracing.registered_exit.route == Some(route) =>
                {
                    advance(proc, route, Some(id))
                }
                message => super::lifecycle_rpc::reject(proc, route, message),
            }
        }
        if closed {
            if proc.tracing.registered_exit.route == Some(route) {
                advance(proc, route, None);
            }
            channels::disconnect(proc, route);
        }
    }
    // A reply is a linearization barrier: the waiting process cannot return
    // before ownership has changed, and the exiting engine cannot drop it.
    let mut fds = Vec::new();
    for route in channels::routes(proc) {
        if route.link(proc).is_none() {
            continue;
        }
        if !remote_mach::flush_responses_on(proc, route) {
            if proc.tracing.registered_exit.route == Some(route) {
                advance(proc, route, None);
            }
            channels::disconnect(proc, route);
            continue;
        }
        if let Some(link) = route.link(proc) {
            fds.push((
                link.fd(),
                !proc.tracing.registered_exit.done,
                link.wants_write(),
            ));
        }
    }
    if proc.tracing.registered_exit.done && channels::output_done(proc) {
        None
    } else {
        Some(fds)
    }
}

pub(super) fn matches_wait4(pid: i32, requested: i32) -> bool {
    if requested == -1 || requested == pid {
        return true;
    }
    if requested > 0 {
        return false;
    }
    let group = if requested == 0 {
        unsafe { libc::getpgrp() }
    } else {
        -requested
    };
    unsafe { libc::getpgid(pid) == group }
}

pub(crate) fn peek_exit(state: &State, requested: i32) -> Option<(i32, Report)> {
    state.family.children.iter().find_map(|(&pid, child)| {
        matches_wait4(pid, requested)
            .then_some(child.registered_exit)
            .flatten()
            .map(|report| (pid, report))
    })
}

pub(crate) fn has_registered_wait(state: &State, requested: i32) -> bool {
    state.family.children.iter().any(|(&pid, child)| {
        (child.is_traced() || child.registered_exit.is_some() || super::reap::owns(state, pid))
            && matches_wait4(pid, requested)
    })
}

/// Automatic SA_NOCLDWAIT collection does not have a waiting guest thread.
/// Its acknowledgement uses the reserved sequence zero.
pub(crate) fn consume_exit(proc: &mut Proc, pid: i32) {
    super::reap::automatic(proc, pid);
    if let Some(child) = proc.tracing.family.children.get_mut(&pid) {
        child.registered_exit = None;
        if let Some(link) = &mut child.link {
            let _ = link.queue(&Message::ReapAck { id: 0 }.encode());
            let _ = link.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::darwin::{
        abi::DarwinAbi,
        process::{RunStatus, bounded_tests::process},
    };
    use std::sync::atomic::AtomicBool;

    #[test]
    fn registered_zombie_waits_for_consumption_and_preserves_status_after_peer_eof() {
        let mut target = process(DarwinAbi::Arm64);
        let mut tracer = process(DarwinAbi::Arm64);
        target.proc.pid = 1002;
        target.proc.ppid = 1001;
        tracer.proc.pid = 1001;
        let (incoming, outgoing) = transport::Link::pair().unwrap();
        let id = incoming.identity();
        target.proc.tracing.family.peers.incoming.insert(
            id,
            peers::Incoming {
                record: registry::Record {
                    pid: 1001,
                    uid: 501,
                    instance: [1; 16],
                },
                link: incoming,
                server: Default::default(),
            },
        );
        target.proc.tracing.tracer = Some(1001);
        target.proc.tracing.tracer_route = Some(ServerRoute::Registered(id));
        let mut child = Child::new(outgoing, 1001);
        child.registry_instance = Some([2; 16]);
        child.traced = true;
        tracer.proc.tracing.family.children.insert(1002, child);
        target.proc.exit_with(ExitStatus::Exited(42));
        assert_eq!(
            target.run_slice(8, &AtomicBool::new(false)),
            RunStatus::Blocked
        );
        pump(&mut tracer.proc, None);
        let report = peek_exit(&tracer.proc.tracing, 1002).unwrap().1;
        assert_eq!(report.status, 42 << 8);
        assert_eq!(peek_exit(&tracer.proc.tracing, -1), Some((1002, report)));
        assert!(has_registered_wait(&tracer.proc.tracing, 1002));
        assert_eq!(
            target.run_slice(8, &AtomicBool::new(false)),
            RunStatus::Blocked
        );
        consume_exit(&mut tracer.proc, 1002);
        assert!(has_registered_wait(&tracer.proc.tracing, 1002));
        assert_eq!(
            target.run_slice(8, &AtomicBool::new(false)),
            RunStatus::Complete(ExitStatus::Exited(42))
        );
        pump(&mut tracer.proc, None);
        super::super::reap::poll_automatic(&mut tracer.proc);
        assert!(!has_registered_wait(&tracer.proc.tracing, 1002));
    }

    #[test]
    fn a_disconnected_tracer_releases_an_already_exited_target_without_changing_its_status() {
        let mut target = process(DarwinAbi::X86_64);
        let (incoming, peer) = transport::Link::pair().unwrap();
        let id = incoming.identity();
        target.proc.tracing.family.peers.incoming.insert(
            id,
            peers::Incoming {
                record: registry::Record {
                    pid: 1001,
                    uid: 501,
                    instance: [1; 16],
                },
                link: incoming,
                server: Default::default(),
            },
        );
        target.proc.ppid = 1001;
        target.proc.tracing.tracer = Some(1001);
        target.proc.tracing.tracer_route = Some(ServerRoute::Registered(id));
        target.proc.exit_with(ExitStatus::Exited(7));
        assert!(exit_wait(&mut target.proc).is_some());
        drop(peer);
        assert!(exit_wait(&mut target.proc).is_none());
        assert_eq!(target.proc.exit, Some(ExitStatus::Exited(7)));
    }
    #[test]
    fn foreign_tracer_reap_returns_zombie_to_ancestral_parent_and_rejects_other_controller() {
        let mut original = process(DarwinAbi::Arm64);
        let mut target = process(DarwinAbi::Arm64);
        let mut tracer = process(DarwinAbi::Arm64);
        original.proc.pid = 1001;
        target.proc.pid = 1002;
        target.proc.ppid = 1003;
        tracer.proc.pid = 1003;
        let shared = std::sync::Arc::new(SharedStatus::new().unwrap());
        let (parent_link, child_link) = transport::Link::pair().unwrap();
        let mut child = Child::new(parent_link, 1001);
        child.shared_status = Some(shared.clone());
        original.proc.tracing.family.children.insert(1002, child);
        target.proc.tracing.family.parent = Some(child_link);
        target.proc.tracing.family.parent_pid = Some(1001);
        target.proc.tracing.family.parent_status = Some(shared.clone());
        shared.set_tracer(1001, Some(1003));
        let (incoming, outgoing) = transport::Link::pair().unwrap();
        let id = incoming.identity();
        target.proc.tracing.family.peers.incoming.insert(
            id,
            peers::Incoming {
                record: registry::Record {
                    pid: 1003,
                    uid: 501,
                    instance: [3; 16],
                },
                link: incoming,
                server: Default::default(),
            },
        );
        let mut child = Child::new(outgoing, 1003);
        child.registry_instance = Some([2; 16]);
        child.original_parent = Some(1001);
        child.traced = true;
        tracer.proc.tracing.family.children.insert(1002, child);
        target.proc.tracing.tracer = Some(1003);
        target.proc.tracing.tracer_route = Some(ServerRoute::Registered(id));
        target.proc.tracing.original_parent = Some(1001);
        target.proc.exit_with(ExitStatus::Exited(42));
        assert!(exit_wait(&mut target.proc).is_some());
        pump(&mut tracer.proc, None);
        assert!(peek_exit(&tracer.proc.tracing, 1002).is_some());
        assert!(peek_exit(&original.proc.tracing, 1002).is_none());
        assert!(foreign_child(&original.proc.tracing, 1001, 1002));
        assert_eq!(shared.snapshot(), (false, 1001, 1003));
        assert_eq!(shared.guest_exit(), Some(42 << 8));
        // A controller without zombie ownership cannot acknowledge its reap.
        let (other, mut other_peer) = transport::Link::pair().unwrap();
        let other_id = other.identity();
        target.proc.tracing.family.peers.incoming.insert(
            other_id,
            peers::Incoming {
                record: registry::Record {
                    pid: 1004,
                    uid: 501,
                    instance: [4; 16],
                },
                link: other,
                server: Default::default(),
            },
        );
        other_peer
            .queue(&Message::ReapAck { id: 77 }.encode())
            .unwrap();
        other_peer.flush().unwrap();
        assert!(exit_wait(&mut target.proc).is_some());
        assert_eq!(
            target.proc.tracing.registered_exit.route,
            Some(ServerRoute::Registered(id))
        );
        consume_exit(&mut tracer.proc, 1002);
        assert!(exit_wait(&mut target.proc).is_some());
        pump(&mut original.proc, None);
        assert_eq!(shared.snapshot(), (false, 0, 1001));
        assert!(!foreign_child(&original.proc.tracing, 1001, 1002));
        assert_eq!(
            peek_exit(&original.proc.tracing, 1002).unwrap().1.status,
            42 << 8
        );
        assert_eq!(original.proc.sigacts.origin.code, 6);
        consume_exit(&mut original.proc, 1002);
        assert!(exit_wait(&mut target.proc).is_none());
    }
    #[test]
    fn waitid_zero_pid_or_group_cannot_select_or_consume_a_current_group_zombie() {
        use crate::user::darwin::syscall::bsd::wait::{self, idtype, opt};
        let mut tracer = process(DarwinAbi::Arm64);
        let child_pid = unsafe { libc::getpid() };
        let (link, _peer) = transport::Link::pair().unwrap();
        let mut child = Child::new(link, tracer.proc.pid);
        child.registry_instance = Some([2; 16]);
        child.registered_exit = Some(Report {
            status: 42 << 8,
            rusage: [0; 144],
        });
        tracer.proc.tracing.family.children.insert(child_pid, child);
        assert!(
            peek_exit(&tracer.proc.tracing, 0).is_some(),
            "wait4 zero selects this group"
        );
        let (_, mut thread) = tracer.proc.threads.pop_first().unwrap();
        let mut ctx = Ctx {
            proc: &mut tracer.proc,
            thread: &mut thread,
            nr: 173,
            pc: 0,
        };
        for kind in [idtype::P_PID, idtype::P_PGID] {
            assert_eq!(
                wait::waitid(&mut ctx, kind, 0, 1, opt::WEXITED | opt::WNOHANG),
                Err(Errno::ECHILD)
            );
            assert!(peek_exit(&ctx.proc.tracing, child_pid).is_some());
        }
        assert_eq!(
            wait::waitid(
                &mut ctx,
                idtype::P_PID,
                child_pid as u32,
                1,
                opt::WEXITED | opt::WNOHANG
            ),
            Err(Errno::EFAULT)
        );
        assert!(peek_exit(&ctx.proc.tracing, child_pid).is_some());
    }
}
