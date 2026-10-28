//! Connection-scoped hidden legacy resume rights. Raw port names never cross
//! the link. A target retains one physical send for the caller's coalesced
//! urefs; generation checks prevent an old release from consuming a new send.

use super::super::channels::ServerRoute;
use std::{collections::BTreeMap, io, sync::Arc};

use crate::user::darwin::{
    mach::{
        ipc::{KObject, Port, Right},
        kr, msg,
    },
    mig::{ids, suspension::LegacyEffect},
    process::Proc,
    syscall::mach::kmsg,
};

const REPLY: u8 = 0x8d;
const RELEASE: u8 = 0x8e;
const DEAD: u8 = 0x8f;
const TRACE_RESUME: u8 = 0x90;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super) enum Packet {
    TraceResume {
        id: u64,
        token: u64,
        result: i32,
    },
    Reply {
        sequence: u64,
        token: u64,
        generation: u64,
        result: i32,
        suspend: bool,
    },
    Release {
        token: u64,
        generation: u64,
    },
    Dead {
        token: u64,
        generation: u64,
    },
}

pub(in super::super) fn is_tag(tag: u8) -> bool {
    matches!(tag, REPLY | RELEASE | DEAD | TRACE_RESUME)
}

impl Packet {
    pub(in super::super) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(30);
        match *self {
            Self::TraceResume { id, token, result } => {
                bytes.push(TRACE_RESUME);
                bytes.extend_from_slice(&id.to_le_bytes());
                bytes.extend_from_slice(&token.to_le_bytes());
                bytes.extend_from_slice(&result.to_le_bytes());
            }
            Self::Reply {
                sequence,
                token,
                generation,
                result,
                suspend,
            } => {
                bytes.push(REPLY);
                for word in [sequence, token, generation] {
                    bytes.extend_from_slice(&word.to_le_bytes());
                }
                bytes.extend_from_slice(&result.to_le_bytes());
                bytes.push(u8::from(suspend));
            }
            Self::Release { token, generation } | Self::Dead { token, generation } => {
                bytes.push(if matches!(self, Self::Release { .. }) {
                    RELEASE
                } else {
                    DEAD
                });
                bytes.extend_from_slice(&token.to_le_bytes());
                bytes.extend_from_slice(&generation.to_le_bytes());
            }
        }
        bytes
    }

    pub(in super::super) fn decode(bytes: &[u8]) -> io::Result<Self> {
        let bad = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid legacy suspension frame",
            )
        };
        let word = |start: usize| u64::from_le_bytes(bytes[start..start + 8].try_into().unwrap());
        match bytes.first().copied() {
            Some(TRACE_RESUME) if bytes.len() == 21 => Ok(Self::TraceResume {
                id: word(1),
                token: word(9),
                result: i32::from_le_bytes(bytes[17..21].try_into().unwrap()),
            }),
            Some(REPLY) if bytes.len() == 30 && bytes[29] <= 1 => {
                let result = i32::from_le_bytes(bytes[25..29].try_into().unwrap());
                let suspend = bytes[29] != 0;
                let token = word(9);
                if suspend && (token == 0 || result != 0) {
                    return Err(bad());
                }
                Ok(Self::Reply {
                    sequence: word(1),
                    token,
                    generation: word(17),
                    result,
                    suspend,
                })
            }
            Some(tag @ (RELEASE | DEAD)) if bytes.len() == 17 && word(1) != 0 => {
                let (token, generation) = (word(1), word(9));
                Ok(if tag == RELEASE {
                    Self::Release { token, generation }
                } else {
                    Self::Dead { token, generation }
                })
            }
            _ => Err(bad()),
        }
    }
}

#[derive(Debug)]
struct Export {
    token: u64,
    generation: u64,
    right: Right,
}

#[derive(Debug)]
struct Proxy {
    port: Arc<Port>,
    generation: u64,
}

#[derive(Debug, Default)]
pub(in super::super) struct State {
    export: Option<Export>,
    proxies: BTreeMap<(i32, u64), Proxy>,
}

/// Keep the transferred send until a matching caller last-send or disconnect.
/// Repeated suspends coalesce physical sends, without changing hold counts.
pub(super) fn response(proc: &mut Proc, sequence: u64, effect: LegacyEffect) -> Packet {
    response_on(proc, ServerRoute::Parent, sequence, effect)
}

pub(super) fn response_on(
    proc: &mut Proc,
    route: ServerRoute,
    sequence: u64,
    effect: LegacyEffect,
) -> Packet {
    match effect {
        LegacyEffect::Suspend(right) => {
            let token = right.port().expect("legacy send").id;
            let previous = route
                .suspension_mut(proc)
                .expect("connected controller")
                .export
                .replace(Export {
                    token,
                    generation: sequence,
                    right,
                });
            if let Some(previous) = previous {
                kmsg::release(proc, [previous.right]);
            }
            Packet::Reply {
                sequence,
                token,
                generation: sequence,
                result: 0,
                suspend: true,
            }
        }
        LegacyEffect::Resume { port, result } => Packet::Reply {
            sequence,
            token: port.map_or(0, |port| port.id),
            generation: 0,
            result,
            suspend: false,
        },
    }
}

fn child_control(proc: &mut Proc, pid: i32, packet: Packet) {
    super::callback_runtime::child_bytes(proc, pid, packet.encode());
}

/// Target-side generation-checked no-senders transition.
pub(in super::super) fn from_parent(proc: &mut Proc, packet: Packet) {
    from_controller(proc, ServerRoute::Parent, packet);
}

pub(in super::super) fn from_controller(proc: &mut Proc, route: ServerRoute, packet: Packet) {
    if let Packet::Release { token, generation } = packet {
        let Some(state) = route.suspension_mut(proc) else {
            return;
        };
        if state
            .export
            .as_ref()
            .is_some_and(|held| held.token == token && held.generation == generation)
        {
            let export = state.export.take().unwrap();
            kmsg::release(proc, [export.right]);
        }
    }
}

pub(in super::super) fn from_child(proc: &mut Proc, pid: i32, packet: Packet) {
    if let Packet::TraceResume { id, token, result } = packet {
        let call = proc.tracing.pending.values_mut().find(|call| {
            call.pid == pid
                && call.id == id
                && call.errno.is_none()
                && !call.resume_effect
                && matches!(
                    call.kind,
                    super::super::CallKind::Attach | super::super::CallKind::Resume { .. }
                )
        });
        if let Some(call) = call {
            call.resume_effect = true;
            let port = proc
                .tracing
                .family
                .mach
                .suspension
                .proxies
                .get(&(pid, token))
                .map(|proxy| proxy.port.clone());
            let _ = crate::user::darwin::mig::suspension::finish_local(
                proc,
                LegacyEffect::Resume { port, result },
            );
        }
        return;
    }
    if let Packet::Dead { token, generation } = packet {
        let state = &mut proc.tracing.family.mach.suspension;
        if state
            .proxies
            .get(&(pid, token))
            .is_some_and(|proxy| proxy.generation == generation)
        {
            let proxy = state.proxies.remove(&(pid, token)).unwrap();
            kmsg::destroy_receive(proc, &proxy.port);
        }
        return;
    }
    let Packet::Reply {
        sequence,
        token,
        generation,
        result,
        suspend,
    } = packet
    else {
        return;
    };
    let state = &mut proc.tracing.family.mach;
    let request_id = if suspend {
        ids::task::TASK_SUSPEND
    } else {
        ids::task::TASK_RESUME
    };
    if !state
        .pending
        .get(&sequence)
        .is_some_and(|pending| pending.pid == pid && pending.request_id == request_id)
    {
        return;
    }
    let pending = state.pending.remove(&sequence).unwrap();
    let valid = !pending.canceled && state.peers.contains_key(&(pid, pending.instance));
    if !valid {
        if suspend {
            // Exports coalesce physical sends. A registered send can survive
            // caller exec while this old image's additional uref is discarded.
            let retained = state
                .suspension
                .proxies
                .get_mut(&(pid, token))
                .is_some_and(|proxy| {
                    proxy.generation = generation;
                    proxy.port.state.lock().unwrap().srights != 0
                });
            if !retained {
                child_control(proc, pid, Packet::Release { token, generation });
            }
        }
        super::fail_pending(proc, pending, kr::KERN_TERMINATED);
        return;
    }
    let effect = if suspend {
        let proxy = state
            .suspension
            .proxies
            .entry((pid, token))
            .or_insert_with(|| Proxy {
                port: Port::new(KObject::TaskResume(None)),
                generation,
            });
        proxy.generation = generation;
        proxy.port.state.lock().unwrap().srights += 1;
        LegacyEffect::Suspend(Right::Send(proxy.port.clone()))
    } else {
        LegacyEffect::Resume {
            port: state
                .suspension
                .proxies
                .get(&(pid, token))
                .map(|proxy| proxy.port.clone()),
            result,
        }
    };
    let result = crate::user::darwin::mig::suspension::finish_local(proc, effect)
        .err()
        .unwrap_or(0);
    let mut body = msg::NDR_RECORD.to_vec();
    body.extend_from_slice(&result.to_le_bytes());
    super::enqueue_reply(proc, pending, 0, body, Vec::new());
}

/// BSD ptrace calls task_resume in the tracer's context. Release the target
/// hold now, and serialize the caller-space uref effect before its BSD reply.
pub(in super::super) fn trace_resume(proc: &mut Proc, id: u64) {
    trace_resume_on(proc, super::super::channels::ServerRoute::Parent, id);
}

pub(in super::super) fn trace_resume_on(
    proc: &mut Proc,
    route: super::super::channels::ServerRoute,
    id: u64,
) {
    let result = proc
        .task
        .suspension
        .release(crate::user::darwin::mach::suspend::Hold::Legacy)
        .err()
        .unwrap_or(0);
    let token = proc
        .task
        .suspension
        .resume
        .as_ref()
        .map_or(0, |port| port.id);
    if token != 0
        && !super::queue_control_on(
            proc,
            route,
            Packet::TraceResume { id, token, result }.encode(),
        )
    {
        if let Some(server) = route.server_mut(proc) {
            server.failed = true;
        }
    }
}

pub(super) fn last_send(proc: &mut Proc, port: &Port) {
    let control =
        proc.tracing
            .family
            .mach
            .suspension
            .proxies
            .iter()
            .find_map(|(&(pid, token), proxy)| {
                (proxy.port.id == port.id).then_some((pid, token, proxy.generation))
            });
    if let Some((pid, token, generation)) = control {
        child_control(proc, pid, Packet::Release { token, generation });
    }
}

pub(super) fn route(proc: &Proc, port: &Port) -> Option<(i32, u64)> {
    proc.tracing
        .family
        .mach
        .suspension
        .proxies
        .iter()
        .find_map(|(&key, proxy)| (proxy.port.id == port.id).then_some(key))
}

pub(super) fn copy_resume_send(proc: &mut Proc, token: u64) -> Option<Right> {
    copy_resume_send_on(proc, ServerRoute::Parent, token)
}

pub(super) fn copy_resume_send_on(
    proc: &mut Proc,
    route: ServerRoute,
    token: u64,
) -> Option<Right> {
    let export = route.suspension(proc)?.export.as_ref()?;
    if export.token != token {
        return None;
    }
    let port = export.right.port()?.clone();
    port.state.lock().unwrap().srights += 1;
    Some(Right::Send(port))
}

pub(super) fn take_peer_ports(proc: &mut Proc, pid: i32) -> Vec<Arc<Port>> {
    let keys: Vec<_> = proc
        .tracing
        .family
        .mach
        .suspension
        .proxies
        .keys()
        .filter(|(peer, _)| *peer == pid)
        .copied()
        .collect();
    let mut ports = Vec::new();
    for key in keys {
        let proxy = proc
            .tracing
            .family
            .mach
            .suspension
            .proxies
            .remove(&key)
            .unwrap();
        ports.push(proxy.port);
    }
    ports
}

pub(super) fn peer_died(proc: &mut Proc, pid: i32) {
    for port in take_peer_ports(proc, pid) {
        kmsg::destroy_receive(proc, &port);
    }
}

pub(super) fn parent_died(proc: &mut Proc) {
    controller_died(proc, ServerRoute::Parent);
}

pub(in super::super) fn controller_died(proc: &mut Proc, route: ServerRoute) {
    if let Some(export) = route
        .suspension_mut(proc)
        .and_then(|state| state.export.take())
    {
        kmsg::release(proc, [export.right]);
    }
}

pub(super) fn before_exec(proc: &mut Proc) {
    use crate::user::darwin::mach::exception::Handler;
    // Use the exec projection itself so retained special ports and future
    // changes to task inheritance cannot silently diverge from this count.
    let carried = crate::user::darwin::exec::exec_task(&proc.task);
    let keys: Vec<_> = proc
        .tracing
        .family
        .mach
        .suspension
        .proxies
        .keys()
        .copied()
        .collect();
    for (pid, token) in keys {
        let Some(proxy) = proc
            .tracing
            .family
            .mach
            .suspension
            .proxies
            .get(&(pid, token))
        else {
            continue;
        };
        let port = proxy.port.clone();
        let generation = proxy.generation;
        let registered = carried
            .registered
            .iter()
            .filter(|handler| matches!(handler, Handler::Port(held) if held.id == port.id))
            .count();
        let special = carried
            .special
            .iter()
            .flatten()
            .filter(|held| held.id == port.id)
            .count();
        let actions = carried
            .exc
            .iter()
            .filter(|action| action.port.as_ref().is_some_and(|held| held.id == port.id))
            .count();
        // Task arrays are fixed-size. Connection-owned borrowed sends remain
        // live until the target releases them, including rejected handlers.
        let retained = (registered + special + actions) as u32
            + proc
                .tracing
                .family
                .mach
                .callbacks
                .relay_export_count(port.id);
        port.state.lock().unwrap().srights = retained;
        if retained == 0 {
            proc.tracing
                .family
                .mach
                .suspension
                .proxies
                .remove(&(pid, token));
            child_control(proc, pid, Packet::Release { token, generation });
            kmsg::destroy_receive(proc, &port);
        }
    }
}

pub(super) fn target_will_exec(proc: &mut Proc) {
    for route in super::super::channels::routes(proc) {
        if let Some(export) = route
            .suspension_mut(proc)
            .and_then(|state| state.export.take())
        {
            if !super::queue_control_on(
                proc,
                route,
                Packet::Dead {
                    token: export.token,
                    generation: export.generation,
                }
                .encode(),
            ) {
                super::target::fail(proc, route);
            }
            kmsg::release(proc, [export.right]);
        }
    }
    if let Some(port) = proc.task.suspension.resume.clone() {
        kmsg::destroy_receive(proc, &port);
    }
}
