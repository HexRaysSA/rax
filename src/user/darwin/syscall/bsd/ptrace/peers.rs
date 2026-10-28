//! Registry setup owns no tracing authority. A connected peer becomes a
//! candidate controller/target; the tracing and Mach handlers still enforce
//! their own state, credential, and capability checks.

use super::registry::{Direction, Event, Record, Registry};
use super::transport::{ConnectionId, Link};
use super::{Child, Errno, Proc, Thread};
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::wait::{Wait, WaitKey};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

const MAX_INCOMING: usize = 32;

#[derive(Debug)]
pub(super) struct Incoming {
    pub record: Record,
    pub link: Link,
    pub server: super::remote_mach::ServerState,
}

#[derive(Debug)]
struct Discovery {
    pid: i32,
    pc: u64,
    call: i64,
    result: Option<i32>,
}

#[derive(Debug, Default)]
pub(super) struct State {
    initialized: bool,
    image_epoch: u64,
    wake_signals: BTreeSet<i32>,
    registry: Option<Registry>,
    failure: Option<Errno>,
    pub incoming: BTreeMap<ConnectionId, Incoming>,
    waiting: BTreeMap<u64, Discovery>,
}

fn discovery_error(error: &std::io::Error) -> Errno {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => Errno::EPERM,
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => Errno::ESRCH,
        _ => Errno::from_io(error),
    }
}

/// Called only for an active image, never while constructing an uncommitted
/// spawn/exec candidate. Closed embeddings do not publish host endpoints.
pub(super) fn publish(proc: &mut Proc) {
    let state = &mut proc.tracing.family.peers;
    if state.initialized || !proc.config.host_services || proc.pid != unsafe { libc::getpid() } {
        return;
    }
    state.initialized = true;
    state.image_epoch = 1;
    match Registry::host() {
        Ok(registry) => state.registry = Some(registry),
        Err(error) => state.failure = Some(discovery_error(&error)),
    }
}

pub(super) fn wait_fds(state: &super::State) -> Vec<(i32, bool, bool)> {
    let peers = &state.family.peers;
    let mut fds = peers
        .registry
        .as_ref()
        .map_or_else(Vec::new, Registry::wait_fds);
    if peers.incoming.len() >= MAX_INCOMING {
        if let Some(listener) = fds.first_mut() {
            listener.1 = false;
        }
    }
    fds.extend(peers.incoming.values().map(|peer| {
        (
            peer.link.fd(),
            state.exit_after_reply.is_none()
                && super::remote_mach::server_can_receive(&peer.server),
            peer.link.wants_write() || !super::remote_mach::server_output_empty(&peer.server),
        )
    }));
    fds
}

pub(super) fn deadline(state: &super::State) -> Option<Instant> {
    state
        .family
        .peers
        .registry
        .as_ref()
        .and_then(Registry::deadline)
}

/// Discovery is restarted with the original syscall; each waiter receives
/// its own completion even when several threads share one setup attempt.
pub(super) fn ensure(ctx: &mut Ctx<'_>, pid: i32) -> Result<bool, Errno> {
    publish(ctx.proc);
    let state = &mut ctx.proc.tracing.family.peers;
    if let Some(old) = state.waiting.get(&ctx.thread.tid) {
        if old.pid != pid || old.pc != ctx.pc || old.call != ctx.nr {
            state.waiting.remove(&ctx.thread.tid);
        }
    }
    if let Some(errno) = state
        .waiting
        .get(&ctx.thread.tid)
        .and_then(|wait| wait.result)
    {
        state.waiting.remove(&ctx.thread.tid);
        return if errno == 0 {
            Ok(true)
        } else {
            Err(Errno(errno))
        };
    }
    if ctx
        .proc
        .tracing
        .family
        .children
        .get(&pid)
        .is_some_and(|child| child.link.is_some())
    {
        return Ok(true);
    }
    let state = &mut ctx.proc.tracing.family.peers;
    let Some(registry) = &mut state.registry else {
        return state.failure.map_or(Ok(false), Err);
    };
    if !state.waiting.contains_key(&ctx.thread.tid) {
        match registry.connect(pid, Instant::now()) {
            Ok(()) => {}
            // The target may be a native host process outside this registry;
            // preserve the caller's existing non-guest-target error path.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(discovery_error(&error)),
        }
        state.waiting.insert(
            ctx.thread.tid,
            Discovery {
                pid,
                pc: ctx.pc,
                call: ctx.nr,
                result: None,
            },
        );
    }
    let until = registry.deadline();
    crate::user::darwin::syscall::sleep(
        ctx,
        Wait {
            keys: vec![WaitKey::Child],
            deadline: until,
            interruptible: false,
            ..Default::default()
        },
    )
    .map(|_| false)
}

fn complete(proc: &mut Proc, pid: i32, errno: i32) {
    for wait in proc
        .tracing
        .family
        .peers
        .waiting
        .values_mut()
        .filter(|wait| wait.pid == pid)
    {
        if wait.result.is_none() {
            wait.result = Some(errno);
        }
    }
    proc.post(WaitKey::Child);
}

fn event(proc: &mut Proc, event: Event) {
    match event {
        Event::Wake { peer } => {
            let caught = proc.sigacts.catch & super::signal::bit(super::signal::SIGCONT) != 0
                || (proc.tracing.job_stopped.is_some() && !proc.tracing.native_host_stop);
            if caught {
                let signals = &mut proc.tracing.family.peers.wake_signals;
                // At most 32 established and 32 setup peers are admitted.
                // An excess of unreconciled wake origins is an engine bound.
                if signals.len() == 64 && !signals.contains(&peer.pid) {
                    proc.exit_with(super::ExitStatus::Internal(
                        "pending registry wakes exhausted".into(),
                    ));
                    return;
                }
                signals.insert(peer.pid);
            }
            super::job_control::registry_woke(proc);
        }
        Event::Connected {
            peer,
            direction: Direction::Incoming,
            link,
        } => {
            let incoming = &mut proc.tracing.family.peers.incoming;
            if incoming.len() < MAX_INCOMING {
                let id = link.identity();
                incoming.insert(
                    id,
                    Incoming {
                        record: peer,
                        link,
                        server: Default::default(),
                    },
                );
                let route = super::channels::ServerRoute::Registered(id);
                let epoch = image_epoch(proc);
                if !super::remote_mach::queue_control_on(
                    proc,
                    route,
                    super::protocol::Message::ImageEpoch { epoch }.encode(),
                ) {
                    super::channels::disconnect(proc, route);
                }
                super::observation::sync_codesign(proc);
            }
        }
        Event::Connected {
            peer,
            direction: Direction::Outgoing,
            link,
        } => {
            let result = if proc.tracing.family.children.contains_key(&peer.pid) {
                // An outstanding old process/connection must be retired before
                // admitting a replacement; never overwrite its rights by PID.
                Errno::ESRCH.0
            } else {
                let mut child = Child::new(link, proc.pid);
                child.registry_instance = Some(peer.instance);
                proc.tracing.family.children.insert(peer.pid, child);
                0
            };
            complete(proc, peer.pid, result);
        }
        Event::Failed {
            pid,
            direction: Direction::Outgoing,
            error,
        } => complete(proc, pid, discovery_error(&error).0),
        Event::Failed {
            direction: Direction::Incoming,
            ..
        } => {}
    }
}

pub(super) fn pump(proc: &mut Proc, running: Option<&Thread>) {
    publish(proc);
    let stale: Vec<_> = proc
        .tracing
        .family
        .peers
        .waiting
        .iter()
        .filter_map(|(&tid, wait)| {
            let thread = running
                .filter(|thread| thread.tid == tid)
                .or_else(|| proc.threads.get(&tid));
            (!thread.is_some_and(|thread| {
                !thread.exited
                    && thread
                        .resume
                        .is_some_and(|resume| resume.pc == wait.pc && resume.call == wait.call)
            }))
            .then_some(tid)
        })
        .collect();
    for tid in stale {
        let peers = &mut proc.tracing.family.peers;
        if let Some(wait) = peers.waiting.remove(&tid) {
            if !peers
                .waiting
                .values()
                .any(|other| other.pid == wait.pid && other.result.is_none())
            {
                if let Some(registry) = &mut peers.registry {
                    registry.cancel_outgoing(wait.pid);
                }
            }
        }
    }
    poll(proc);
}

/// Setup-only polling is also safe while a scheduler thread is borrowed by
/// the signal path. It must not reap that temporarily absent thread's waiter.
pub(crate) fn poll(proc: &mut Proc) {
    publish(proc);
    let peers = &mut proc.tracing.family.peers;
    let slots = MAX_INCOMING.saturating_sub(peers.incoming.len());
    let events = peers
        .registry
        .as_mut()
        .map_or_else(Vec::new, |registry| registry.pump(Instant::now(), slots));
    for message in events {
        event(proc, message);
    }
}

pub(super) fn before_exec(state: &mut super::State) {
    let peers = &mut state.family.peers;
    if let Some(registry) = &mut peers.registry {
        for wait in peers.waiting.values() {
            registry.cancel_outgoing(wait.pid);
        }
    }
    peers.waiting.clear();
    peers.wake_signals.clear();
}

pub(super) fn image_epoch(proc: &Proc) -> u64 {
    proc.tracing.family.peers.image_epoch.max(1)
}

pub(super) fn advance_image(proc: &mut Proc) {
    let next = image_epoch(proc).checked_add(1);
    let routes: Vec<_> = proc
        .tracing
        .family
        .peers
        .incoming
        .keys()
        .copied()
        .map(super::channels::ServerRoute::Registered)
        .collect();
    let Some(epoch) = next else {
        for route in routes {
            super::channels::disconnect(proc, route);
        }
        return;
    };
    proc.tracing.family.peers.image_epoch = epoch;
    for route in routes {
        if let Some(server) = route.server_mut(proc) {
            server.code_flags = None;
        }
        if !super::remote_mach::queue_control_on(
            proc,
            route,
            super::protocol::Message::ImageEpoch { epoch }.encode(),
        ) {
            super::channels::disconnect(proc, route);
        }
    }
}

pub(super) fn has_controller(proc: &Proc) -> bool {
    !proc.tracing.family.peers.incoming.is_empty()
        || proc
            .tracing
            .family
            .peers
            .registry
            .as_ref()
            .is_some_and(Registry::has_incoming_wake)
}

pub(super) fn forget_host_wakes(state: &mut super::State) {
    state.family.peers.wake_signals.clear();
}

pub(crate) fn consume_host_wake(state: &mut super::State, sender: i32) -> bool {
    state.family.peers.wake_signals.remove(&sender)
}

pub(crate) fn finalize(state: &mut super::State) {
    state.family.peers.registry = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::darwin::abi::DarwinAbi;
    use crate::user::darwin::process::bounded_tests::process;

    #[test]
    fn a_registered_target_has_an_owned_connection_and_separate_process_instance() {
        let mut caller = process(DarwinAbi::Arm64);
        caller.proc.pid = 1001;
        let (link, _peer) = Link::pair().unwrap();
        let id = link.identity();
        let record = Record {
            pid: 1002,
            uid: 501,
            instance: [7; 16],
        };
        for tid in [10, 11] {
            caller.proc.tracing.family.peers.waiting.insert(
                tid,
                Discovery {
                    pid: 1002,
                    pc: 4,
                    call: 26,
                    result: None,
                },
            );
        }
        event(
            &mut caller.proc,
            Event::Connected {
                peer: record,
                direction: Direction::Outgoing,
                link,
            },
        );
        let child = &caller.proc.tracing.family.children[&1002];
        assert_eq!(child.owner_pid, 1001);
        assert_eq!(child.registry_instance, Some([7; 16]));
        assert_eq!(child.link.as_ref().unwrap().identity(), id);
        assert!(
            caller
                .proc
                .tracing
                .family
                .peers
                .waiting
                .values()
                .all(|wait| wait.result == Some(0))
        );
        let (replacement, _peer) = Link::pair().unwrap();
        event(
            &mut caller.proc,
            Event::Connected {
                peer: Record {
                    instance: [8; 16],
                    ..record
                },
                direction: Direction::Outgoing,
                link: replacement,
            },
        );
        assert_eq!(
            caller.proc.tracing.family.children[&1002]
                .link
                .as_ref()
                .unwrap()
                .identity(),
            id
        );
    }
}
