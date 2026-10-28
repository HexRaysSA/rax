//! Caller routing is independent of guest parentage. A registry controller
//! must not borrow an ancestral parent's export namespace or reply backlog.

use super::Proc;
use super::remote_mach::ServerState;
use super::transport::{ConnectionId, Link};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ServerRoute {
    Parent,
    Registered(ConnectionId),
}

impl ServerRoute {
    pub fn pid(self, proc: &Proc) -> Option<i32> {
        match self {
            Self::Parent => Some(proc.tracing.family.parent_pid.unwrap_or(proc.ppid)),
            Self::Registered(id) => proc
                .tracing
                .family
                .peers
                .incoming
                .get(&id)
                .map(|peer| peer.record.pid),
        }
    }

    pub fn connection(self, proc: &Proc) -> Option<ConnectionId> {
        self.link(proc).map(Link::identity)
    }

    pub fn link(self, proc: &Proc) -> Option<&Link> {
        match self {
            Self::Parent => proc.tracing.family.parent.as_ref(),
            Self::Registered(id) => proc
                .tracing
                .family
                .peers
                .incoming
                .get(&id)
                .map(|peer| &peer.link),
        }
    }

    pub fn link_mut(self, proc: &mut Proc) -> Option<&mut Link> {
        match self {
            Self::Parent => proc.tracing.family.parent.as_mut(),
            Self::Registered(id) => proc
                .tracing
                .family
                .peers
                .incoming
                .get_mut(&id)
                .map(|peer| &mut peer.link),
        }
    }

    pub fn server(self, proc: &Proc) -> Option<&ServerState> {
        match self {
            Self::Parent => Some(&proc.tracing.family.mach.parent_server),
            Self::Registered(id) => proc
                .tracing
                .family
                .peers
                .incoming
                .get(&id)
                .map(|peer| &peer.server),
        }
    }

    pub fn server_mut(self, proc: &mut Proc) -> Option<&mut ServerState> {
        match self {
            Self::Parent => Some(&mut proc.tracing.family.mach.parent_server),
            Self::Registered(id) => proc
                .tracing
                .family
                .peers
                .incoming
                .get_mut(&id)
                .map(|peer| &mut peer.server),
        }
    }

    pub fn callbacks(self, proc: &Proc) -> Option<&super::remote_mach::callback::State> {
        match self {
            Self::Parent => Some(&proc.tracing.family.mach.callbacks),
            _ => self.server(proc).map(|server| &server.callbacks),
        }
    }
    pub fn callbacks_mut(
        self,
        proc: &mut Proc,
    ) -> Option<&mut super::remote_mach::callback::State> {
        match self {
            Self::Parent => Some(&mut proc.tracing.family.mach.callbacks),
            _ => self.server_mut(proc).map(|server| &mut server.callbacks),
        }
    }
    pub fn tokens_mut(self, proc: &mut Proc) -> Option<&mut super::remote_mach::token::State> {
        match self {
            Self::Parent => Some(&mut proc.tracing.family.mach.tokens),
            _ => self.server_mut(proc).map(|server| &mut server.tokens),
        }
    }
    pub fn suspension(self, proc: &Proc) -> Option<&super::remote_mach::suspension::State> {
        match self {
            Self::Parent => Some(&proc.tracing.family.mach.suspension),
            _ => self.server(proc).map(|server| &server.suspension),
        }
    }
    pub fn suspension_mut(
        self,
        proc: &mut Proc,
    ) -> Option<&mut super::remote_mach::suspension::State> {
        match self {
            Self::Parent => Some(&mut proc.tracing.family.mach.suspension),
            _ => self.server_mut(proc).map(|server| &mut server.suspension),
        }
    }
    /// Short-lived disjoint access for host I/O. No guest/MIG callback is
    /// invoked while these references are held.
    pub fn parts(self, proc: &mut Proc) -> Option<(&mut ServerState, &mut Link)> {
        let family = &mut proc.tracing.family;
        match self {
            Self::Parent => family
                .parent
                .as_mut()
                .map(|link| (&mut family.mach.parent_server, link)),
            Self::Registered(id) => family
                .peers
                .incoming
                .get_mut(&id)
                .map(|peer| (&mut peer.server, &mut peer.link)),
        }
    }
}

pub(super) fn routes(proc: &Proc) -> Vec<ServerRoute> {
    std::iter::once(ServerRoute::Parent)
        .chain(
            proc.tracing
                .family
                .peers
                .incoming
                .keys()
                .copied()
                .map(ServerRoute::Registered),
        )
        .collect()
}

pub(super) fn callback_route(
    proc: &Proc,
    port: &crate::user::darwin::mach::ipc::Port,
) -> Option<ServerRoute> {
    routes(proc).into_iter().find(|route| {
        route
            .callbacks(proc)
            .is_some_and(|callbacks| callbacks.proxy_identity(port).is_some())
    })
}

pub(super) fn trace_me_route(proc: &Proc) -> Option<ServerRoute> {
    tracer(proc)
        .filter(|route| route.link(proc).is_some())
        .or_else(|| {
            ServerRoute::Parent
                .link(proc)
                .is_some()
                .then_some(ServerRoute::Parent)
        })
}

pub(super) fn tracer(proc: &Proc) -> Option<ServerRoute> {
    proc.tracing.tracer_route.or_else(|| {
        (proc.tracing.tracer == ServerRoute::Parent.pid(proc) && proc.tracing.tracer.is_some())
            .then_some(ServerRoute::Parent)
    })
}

pub(super) fn queue_reply(proc: &mut Proc, route: ServerRoute, bytes: Vec<u8>) -> bool {
    let queued = super::remote_mach::queue_control_on(proc, route, bytes);
    proc.tracing.output_barrier |= queued;
    queued
}

pub(super) fn disconnect(proc: &mut Proc, route: ServerRoute) {
    let controls = tracer(proc) == Some(route);
    match route {
        ServerRoute::Parent => {
            proc.tracing.family.parent = None;
            super::remote_mach::parent_died(proc);
        }
        ServerRoute::Registered(id) => {
            super::remote_mach::target::disconnected(proc, route);
            proc.tracing.family.peers.incoming.remove(&id);
        }
    }
    if controls {
        tracer_died(proc);
    } else {
        super::job_control::orphaned(proc);
    }
}

pub(super) fn tracer_died(proc: &mut Proc) {
    let pc = proc
        .tracing
        .stopped
        .and_then(|stop| proc.threads.get(&stop.thread))
        .map_or(0, |thread| thread.cpu.pc());
    proc.tracing.tracer = None;
    proc.tracing.tracer_route = None;
    proc.tracing.original_parent = None;
    if let Some(shared) = &proc.tracing.family.parent_status {
        shared.set_trace(0, false);
    }
    proc.tracing.stopped = None;
    proc.tracing.sigwait = None;
    proc.tracing.sigwaiters.clear();
    proc.tracing.attached_job_stop = false;
    proc.tracing.trace_update = None;
    proc.tracing.reserved_update = None;
    proc.tracing.verdict = None;
    proc.tracing.soft_override = None;
    proc.tracing.pending_kill = false;
    proc.tracing.stepping = None;
    if proc.exit.is_none() {
        proc.exit_with(super::ExitStatus::Signaled {
            signo: super::signal::SIGKILL,
            core: false,
            pc,
        });
    }
}

pub(super) fn output_done(proc: &Proc) -> bool {
    let parent = ServerRoute::Parent.link(proc).is_none_or(|link| {
        !link.wants_write() && super::remote_mach::output_empty(&proc.tracing.family.mach)
    });
    parent
        && proc.tracing.family.peers.incoming.values().all(|peer| {
            !peer.link.wants_write() && super::remote_mach::server_output_empty(&peer.server)
        })
}

#[cfg(test)]
mod tests {
    use super::super::{peers::Incoming, registry::Record, remote_mach, transport};
    use super::*;
    use crate::user::darwin::abi::DarwinAbi;
    use crate::user::darwin::process::{DarwinProcess, bounded_tests::process};

    fn connected() -> (DarwinProcess, Link, Link, ServerRoute) {
        let mut process = process(DarwinAbi::Arm64);
        process.proc.pid = 1002;
        process.proc.ppid = 1001;
        let (parent, parent_peer) = transport::Link::pair().unwrap();
        process.proc.tracing.family.parent = Some(parent);
        process.proc.tracing.family.parent_pid = Some(1001);
        let (registered, registered_peer) = transport::Link::pair().unwrap();
        let id = registered.identity();
        process.proc.tracing.family.peers.incoming.insert(
            id,
            Incoming {
                record: Record {
                    pid: 1003,
                    uid: 501,
                    instance: [2; 16],
                },
                link: registered,
                server: Default::default(),
            },
        );
        (
            process,
            parent_peer,
            registered_peer,
            ServerRoute::Registered(id),
        )
    }

    #[test]
    fn parent_and_registered_controller_have_independent_ordered_reply_queues() {
        let (mut process, mut parent, mut controller, registered) = connected();
        for (route, bytes) in [
            (ServerRoute::Parent, b"parent-first".as_slice()),
            (registered, b"controller"),
            (ServerRoute::Parent, b"parent-second"),
        ] {
            assert!(remote_mach::queue_control_on(
                &mut process.proc,
                route,
                bytes.to_vec()
            ));
        }
        let (frames, closed) = parent.receive().unwrap();
        assert!(!closed);
        assert_eq!(
            frames,
            vec![b"parent-first".to_vec(), b"parent-second".to_vec()]
        );
        let (frames, closed) = controller.receive().unwrap();
        assert!(!closed);
        assert_eq!(frames, vec![b"controller".to_vec()]);
        process.proc.tracing.family.mach.parent_server.allowed = true;
        assert!(!registered.server(&process.proc).unwrap().allowed);
    }

    #[test]
    fn a_closed_controller_does_not_break_parent_output_or_change_parent_identity() {
        let (mut process, mut parent, controller, registered) = connected();
        process.proc.ppid = 1003;
        process.proc.tracing.tracer = Some(1003);
        process.proc.tracing.tracer_route = Some(registered);
        assert_eq!(ServerRoute::Parent.pid(&process.proc), Some(1001));
        assert_eq!(tracer(&process.proc), Some(registered));
        drop(controller);
        assert!(!remote_mach::queue_control_on(
            &mut process.proc,
            registered,
            b"closed".to_vec()
        ));
        assert!(remote_mach::queue_control_on(
            &mut process.proc,
            ServerRoute::Parent,
            b"alive".to_vec()
        ));
        assert_eq!(parent.receive().unwrap().0, vec![b"alive".to_vec()]);
    }
    #[test]
    fn registered_control_does_not_transfer_to_the_original_parent() {
        use super::super::{
            TraceStop,
            protocol::{Message, ResumeMode},
            signal, trace_control,
        };
        let (mut process, mut parent, mut controller, route) = connected();
        let tid = *process.proc.threads.keys().next().unwrap();
        process.proc.ppid = 1003;
        process.proc.tracing.tracer = Some(1003);
        process.proc.tracing.tracer_route = Some(route);
        process.proc.tracing.original_parent = Some(1001);
        process.proc.tracing.stopped = Some(TraceStop {
            thread: tid,
            signal: signal::SIGSTOP,
        });
        let request = Message::Resume {
            id: 7,
            signal: 0,
            mode: ResumeMode::Detach,
            uid: 501,
        };
        trace_control::dispatch(&mut process.proc, None, ServerRoute::Parent, request);
        assert!(process.proc.tracing.stopped.is_some());
        assert_eq!(
            Message::decode(&parent.receive().unwrap().0[0]).unwrap(),
            Message::Reply {
                id: 7,
                errno: super::super::Errno::EBUSY.0
            }
        );
        assert!(controller.receive().unwrap().0.is_empty());
        trace_control::dispatch(&mut process.proc, None, route, request);
        assert_eq!(
            Message::decode(&controller.receive().unwrap().0[0]).unwrap(),
            Message::Reply { id: 7, errno: 0 }
        );
        assert_eq!(process.proc.ppid, 1001);
        assert_eq!(tracer(&process.proc), None);
        assert!(process.proc.tracing.stopped.is_none());
    }

    #[test]
    fn signal_stops_and_trace_me_use_the_registered_tracer() {
        use super::super::{job_control, protocol::Message, signal, stop_for_signal};
        let (mut process, mut parent, mut controller, route) = connected();
        let tid = *process.proc.threads.keys().next().unwrap();
        process.proc.ppid = 1003;
        process.proc.tracing.tracer = Some(1003);
        process.proc.tracing.tracer_route = Some(route);
        assert!(stop_for_signal(&mut process.proc, tid, signal::SIGTRAP, 0));
        assert!(matches!(
            Message::decode(&controller.receive().unwrap().0[0]).unwrap(),
            Message::Stop {
                signal: signal::SIGTRAP,
                ..
            }
        ));
        assert!(parent.receive().unwrap().0.is_empty());
        job_control::queue_trace_me(&mut process.proc).unwrap();
        assert_eq!(
            Message::decode(&controller.receive().unwrap().0[0]).unwrap(),
            Message::TraceMe
        );
        assert!(parent.receive().unwrap().0.is_empty());
    }

    #[test]
    fn original_parent_disconnect_preserves_an_independent_tracer_but_its_death_kills() {
        let (mut process, parent, controller, route) = connected();
        process.proc.ppid = 1003;
        process.proc.tracing.tracer = Some(1003);
        process.proc.tracing.tracer_route = Some(route);
        drop(parent);
        super::super::pump(&mut process.proc, None);
        assert_eq!(tracer(&process.proc), Some(route));
        assert!(process.proc.exit.is_none());
        drop(controller);
        super::super::pump(&mut process.proc, None);
        assert!(matches!(
            process.proc.exit,
            Some(super::super::ExitStatus::Signaled {
                signo: super::super::signal::SIGKILL,
                ..
            })
        ));
        assert_eq!(tracer(&process.proc), None);
    }
    #[test]
    fn original_parent_retains_posix_signal_permission_without_tracer_control() {
        use super::super::{SharedStatus, protocol::Message, signal, trace_control};
        let (mut process, _parent, _controller, route) = connected();
        process.proc.creds = (501, 501, 20, 20);
        process.proc.ppid = 1003;
        process.proc.tracing.tracer = Some(1003);
        process.proc.tracing.tracer_route = Some(route);
        let shared = std::sync::Arc::new(SharedStatus::new().unwrap());
        shared.set_parent_credentials((501, 501));
        process.proc.tracing.family.parent_status = Some(shared.clone());
        let pending = |process: &DarwinProcess| {
            process
                .proc
                .threads
                .values()
                .any(|thread| thread.sig.pending & signal::bit(signal::SIGUSR1) != 0)
        };
        trace_control::dispatch(
            &mut process.proc,
            None,
            ServerRoute::Parent,
            Message::Signal {
                signal: signal::SIGUSR1,
                sender: 9999,
                uid: 501,
            },
        );
        assert!(!pending(&process));
        shared.set_parent_credentials((502, 502));
        trace_control::dispatch(
            &mut process.proc,
            None,
            ServerRoute::Parent,
            Message::Signal {
                signal: signal::SIGUSR1,
                sender: 1001,
                uid: 502,
            },
        );
        assert!(!pending(&process));
        shared.set_parent_credentials((501, 501));
        trace_control::dispatch(
            &mut process.proc,
            None,
            ServerRoute::Parent,
            Message::Signal {
                signal: signal::SIGUSR1,
                sender: 1001,
                uid: 501,
            },
        );
        assert!(pending(&process));
        assert_eq!(tracer(&process.proc), Some(route));
    }
    #[test]
    fn registered_signing_projection_tracks_updates_and_rejects_prior_image_epoch() {
        use super::super::{
            Child, known_child_codesign, observation, peers, protocol::Message, pump,
        };
        let (mut target, _parent, controller, route) = connected();
        let mut tracer = process(DarwinAbi::Arm64);
        tracer.proc.pid = 1003;
        let mut child = Child::new(controller, 1003);
        child.registry_instance = Some([2; 16]);
        child.registry_epoch = 1;
        tracer
            .proc
            .tracing
            .family
            .children
            .insert(target.proc.pid, child);
        observation::sync_codesign(&mut target.proc);
        pump(&mut tracer.proc, None);
        assert_eq!(
            known_child_codesign(&tracer.proc.tracing, target.proc.pid),
            None
        );
        crate::user::darwin::codesign::prepare_trace_me(&mut target.proc);
        target.proc.codesign.as_mut().unwrap().flags = 0x3200_0025;
        observation::sync_codesign(&mut target.proc);
        pump(&mut tracer.proc, None);
        assert_eq!(
            known_child_codesign(&tracer.proc.tracing, target.proc.pid),
            Some(0x3200_0025)
        );
        peers::advance_image(&mut target.proc);
        pump(&mut tracer.proc, None);
        assert_eq!(
            known_child_codesign(&tracer.proc.tracing, target.proc.pid),
            None
        );
        assert!(queue_reply(
            &mut target.proc,
            route,
            Message::CodeFlags {
                epoch: 1,
                flags: Some(0xdead_beef)
            }
            .encode()
        ));
        pump(&mut tracer.proc, None);
        assert_eq!(
            known_child_codesign(&tracer.proc.tracing, target.proc.pid),
            None
        );
        observation::sync_codesign(&mut target.proc);
        pump(&mut tracer.proc, None);
        assert_eq!(
            known_child_codesign(&tracer.proc.tracing, target.proc.pid),
            Some(0x3200_0025)
        );
    }
}
