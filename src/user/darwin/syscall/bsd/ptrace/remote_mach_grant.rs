//! Authenticated task acquisition before BSD attach. The target holds its
//! task send before acknowledging; a canceled caller releases that grant.

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use super::{Object, Peer, RemotePort};
use crate::user::darwin::mach::ipc::{KObject, MACH_PORT_NULL, Port, Right};
use crate::user::darwin::mach::kr;
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::{Ctx, mach};
use crate::user::darwin::wait::{Wait, WaitKey};

#[cfg(test)]
#[path = "remote_mach_grant_tests.rs"]
mod tests;

const REQUEST: u8 = 0x91;
const REPLY: u8 = 0x92;

pub(in super::super) fn is_tag(tag: u8) -> bool {
    matches!(tag, REQUEST | REPLY)
}

#[derive(Debug, Default)]
pub(in super::super) struct State {
    pending: BTreeMap<u64, Pending>,
    abandoned: BTreeMap<u64, Pending>,
}

impl State {
    pub(super) fn len(&self) -> usize {
        self.pending.len().saturating_add(self.abandoned.len())
    }

    pub(super) fn uses_instance(&self, pid: i32, instance: u64) -> bool {
        self.pending
            .values()
            .chain(self.abandoned.values())
            .any(|p| p.pid == pid && p.instance == instance)
    }
}

#[derive(Debug)]
struct Pending {
    sequence: u64,
    pid: i32,
    instance: u64,
    epoch: u64,
    pc: u64,
    result: Option<(i32, Option<Arc<Port>>)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) enum Packet {
    Request {
        sequence: u64,
        instance: u64,
        epoch: u64,
        creds: (u32, u32, u32, u32),
    },
    Reply {
        sequence: u64,
        instance: u64,
        epoch: u64,
        result: i32,
    },
}

impl Packet {
    fn encode(&self) -> Vec<u8> {
        let (tag, sequence, instance, epoch) = match self {
            Self::Request {
                sequence,
                instance,
                epoch,
                ..
            } => (REQUEST, sequence, instance, epoch),
            Self::Reply {
                sequence,
                instance,
                epoch,
                ..
            } => (REPLY, sequence, instance, epoch),
        };
        let mut bytes = vec![tag];
        for value in [sequence, instance, epoch] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        match self {
            Self::Request { creds, .. } => {
                for value in [creds.0, creds.1, creds.2, creds.3] {
                    bytes.extend_from_slice(&value.to_le_bytes());
                }
            }
            Self::Reply { result, .. } => bytes.extend_from_slice(&result.to_le_bytes()),
        }
        bytes
    }

    pub(in super::super) fn decode(bytes: &[u8]) -> io::Result<Self> {
        let invalid = || io::Error::from(io::ErrorKind::InvalidData);
        if !matches!(
            (bytes.first(), bytes.len()),
            (Some(&REQUEST), 41) | (Some(&REPLY), 29)
        ) {
            return Err(invalid());
        }
        let u64_at = |i| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
        let u32_at = |i| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        let (sequence, instance, epoch) = (u64_at(1), u64_at(9), u64_at(17));
        if instance == 0
            || instance & super::TARGET_INSTANCE_BIT != 0
            || epoch == 0
            || sequence & super::TARGET_GENERATION_BIT != 0
        {
            return Err(invalid());
        }
        Ok(if bytes[0] == REQUEST {
            Self::Request {
                sequence,
                instance,
                epoch,
                creds: (u32_at(25), u32_at(29), u32_at(33), u32_at(37)),
            }
        } else {
            Self::Reply {
                sequence,
                instance,
                epoch,
                result: u32_at(25) as i32,
            }
        })
    }
}

fn wait(ctx: &mut Ctx<'_>) -> i32 {
    mach::sleep(
        ctx,
        Wait {
            keys: vec![WaitKey::Child],
            interruptible: false,
            ..Default::default()
        },
    )
}

/// Each pending successful reply owns one real send reference until IPC
/// copyout or cancellation. Pending calls on one image share port identity.
pub(in super::super) fn task_for_pid(ctx: &mut Ctx<'_>, pid: i32, output: u64) -> i32 {
    let tid = ctx.thread.tid;
    if let Some(pending) = ctx.proc.tracing.family.mach.grants.pending.get(&tid) {
        if pending.pid == pid && pending.pc == ctx.pc {
            if pending.result.is_none() {
                return wait(ctx);
            }
            let pending = ctx
                .proc
                .tracing
                .family
                .mach
                .grants
                .pending
                .remove(&tid)
                .unwrap();
            let (result, port) = pending.result.unwrap();
            let name = if let Some(port) = port {
                match ctx.proc.ipc.insert(Right::Send(port.clone())) {
                    Ok(name) => name,
                    Err(_) => {
                        mach::kmsg::release_send(ctx.proc, &port);
                        MACH_PORT_NULL
                    }
                }
            } else {
                MACH_PORT_NULL
            };
            let _ = ctx.write_u32(output, name);
            return result;
        }
        cancel(ctx.proc, tid);
    }
    if !ctx.proc.tracing.family.children.contains_key(&pid) {
        match super::super::peers::ensure(ctx, pid) {
            Ok(true) => {}
            Err(error) if error == crate::user::darwin::abi::Errno::ERESTART => {
                return mach::RESTART;
            }
            _ => {
                let _ = ctx.write_u32(output, MACH_PORT_NULL);
                return kr::KERN_FAILURE;
            }
        }
    }
    if ctx
        .proc
        .tracing
        .family
        .children
        .get(&pid)
        .is_some_and(|child| {
            child.registry_instance.is_some() && child.registry_epoch == 0 && child.link.is_some()
        })
    {
        return wait(ctx);
    }
    let effective = (ctx.proc.creds.1, ctx.proc.creds.3);
    let represented_identity = ctx.thread.assumed.is_none_or(|ids| ids == effective);
    let epoch = ctx
        .proc
        .tracing
        .family
        .children
        .get(&pid)
        .filter(|child| child.link.is_some())
        .and_then(|child| {
            child
                .shared_status
                .as_ref()
                .map(|shared| shared.image_epoch())
                .or_else(|| child.registry_instance.map(|_| child.registry_epoch))
        });
    let Some(epoch) = epoch.filter(|epoch| *epoch != 0 && represented_identity) else {
        let _ = ctx.write_u32(output, MACH_PORT_NULL);
        return kr::KERN_FAILURE;
    };
    let state = &mut ctx.proc.tracing.family.mach;
    let existing = state
        .peers
        .iter()
        .find(|((p, _), peer)| *p == pid && peer.epoch == epoch && !peer.task.is_dead())
        .map(|((_, instance), _)| *instance)
        .or_else(|| {
            state
                .grants
                .pending
                .values()
                .find(|pending| pending.pid == pid && pending.epoch == epoch)
                .map(|pending| pending.instance)
        });
    let Some(instance) = existing.or_else(|| super::allocate_instance(state, pid)) else {
        let _ = ctx.write_u32(output, MACH_PORT_NULL);
        return kr::KERN_RESOURCE_SHORTAGE;
    };
    let mut sequence = state.next_sequence & !super::TARGET_GENERATION_BIT;
    while state.pending.contains_key(&sequence)
        || state.grants.abandoned.contains_key(&sequence)
        || state
            .grants
            .pending
            .values()
            .any(|pending| pending.sequence == sequence)
    {
        sequence = sequence.wrapping_add(1) & !super::TARGET_GENERATION_BIT;
    }
    state.next_sequence = sequence.wrapping_add(1) & !super::TARGET_GENERATION_BIT;
    state.grants.pending.insert(
        tid,
        Pending {
            sequence,
            pid,
            instance,
            epoch,
            pc: ctx.pc,
            result: None,
        },
    );
    let bytes = Packet::Request {
        sequence,
        instance,
        epoch,
        creds: ctx.proc.creds,
    }
    .encode();
    super::callback_runtime::child_bytes(ctx.proc, pid, bytes);
    wait(ctx)
}

pub(in super::super) fn from_parent(proc: &mut Proc, packet: Packet) {
    let Packet::Request {
        sequence,
        instance,
        epoch,
        creds,
    } = packet
    else {
        return;
    };
    from_controller(
        proc,
        super::super::channels::ServerRoute::Parent,
        Packet::Request {
            sequence,
            instance,
            epoch,
            creds,
        },
    );
}

pub(in super::super) fn from_controller(
    proc: &mut Proc,
    route: super::super::channels::ServerRoute,
    packet: Packet,
) {
    let Packet::Request {
        sequence,
        instance,
        epoch,
        creds,
    } = packet
    else {
        return;
    };
    let observed = crate::user::darwin::codesign::prepare_trace_me(proc);
    serve_on(
        proc,
        route,
        sequence,
        instance,
        epoch,
        creds,
        observed.is_some(),
    );
}

/// This admits the observed ordinary same-credential/get-task-allow case.
/// Saved IDs, supplementary groups, taskgated, and general MAC policy remain
/// outside the represented credentials; failure does not grant a capability.
fn serve(
    proc: &mut Proc,
    sequence: u64,
    instance: u64,
    epoch: u64,
    creds: (u32, u32, u32, u32),
    observed: bool,
) {
    serve_on(
        proc,
        super::super::channels::ServerRoute::Parent,
        sequence,
        instance,
        epoch,
        creds,
        observed,
    );
}

fn serve_on(
    proc: &mut Proc,
    route: super::super::channels::ServerRoute,
    sequence: u64,
    instance: u64,
    epoch: u64,
    creds: (u32, u32, u32, u32),
    observed: bool,
) {
    use crate::user::darwin::codesign::cs;
    let principal = match route {
        super::super::channels::ServerRoute::Parent => proc
            .tracing
            .family
            .parent_status
            .as_ref()
            .is_some_and(|shared| shared.parent_credentials() == Some((creds.0, creds.1))),
        super::super::channels::ServerRoute::Registered(id) => proc
            .tracing
            .family
            .peers
            .incoming
            .get(&id)
            .is_some_and(|peer| peer.record.uid == creds.0),
    };
    let allowed = proc.exit.is_none()
        && observed
        && creds.0 == creds.1
        && creds == proc.creds
        && principal
        && super::target::epoch(proc, route) == Some(epoch)
        && proc.codesign.as_ref().is_some_and(|signing| {
            signing.flags & cs::GET_TASK_ALLOW != 0 && signing.flags & cs::PLATFORM_BINARY == 0
        });
    let result = if allowed {
        route.server_mut(proc).expect("connected server").allowed = true;
        super::target::acquire(proc, route, sequence, instance, epoch, Object::Task);
        kr::KERN_SUCCESS
    } else {
        kr::KERN_FAILURE
    };
    if !super::queue_control_on(
        proc,
        route,
        Packet::Reply {
            sequence,
            instance,
            epoch,
            result,
        }
        .encode(),
    ) {
        super::target::fail(proc, route);
    } else {
        proc.tracing.output_barrier = true;
    }
}

pub(in super::super) fn from_child(proc: &mut Proc, pid: i32, packet: Packet) {
    let Packet::Reply {
        sequence,
        instance,
        epoch,
        result,
    } = packet
    else {
        return;
    };
    let tid = proc
        .tracing
        .family
        .mach
        .grants
        .pending
        .iter()
        .find(|(_, p)| {
            p.pid == pid && p.sequence == sequence && p.instance == instance && p.epoch == epoch
        })
        .map(|(&tid, _)| tid);
    let Some(tid) = tid else {
        let abandoned = proc.tracing.family.mach.grants.abandoned.get(&sequence);
        if abandoned.is_some_and(|p| p.pid == pid && p.instance == instance && p.epoch == epoch) {
            proc.tracing.family.mach.grants.abandoned.remove(&sequence);
            if result == kr::KERN_SUCCESS {
                // A later grant can refresh the export shared with an earlier
                // successful call. Preserve that export while any send lives.
                let state = &mut proc.tracing.family.mach;
                let live = state
                    .peers
                    .get(&(pid, instance))
                    .filter(|peer| {
                        peer.epoch == epoch
                            && !peer.task.is_dead()
                            && peer.task.state.lock().unwrap().srights != 0
                    })
                    .map(|peer| peer.task.id);
                if let Some(id) = live {
                    if let Some(remote) = state.ports.get_mut(&id) {
                        remote.generation = sequence;
                        remote.pending_release = false;
                    }
                } else {
                    release_grant(proc, pid, instance, sequence);
                }
            }
        }
        return;
    };
    let pending = &proc.tracing.family.mach.grants.pending[&tid];
    if pending.result.is_some() {
        return;
    }
    let port = if result == kr::KERN_SUCCESS {
        let state = &mut proc.tracing.family.mach;
        let peer = state.peers.entry((pid, instance)).or_insert_with(|| Peer {
            task: Port::new(KObject::Task),
            threads: BTreeMap::new(),
            epoch,
        });
        let port = peer.task.clone();
        port.state.lock().unwrap().srights += 1;
        state.ports.insert(
            port.id,
            RemotePort {
                pid,
                instance,
                object: Object::Task,
                generation: sequence,
                pending_release: false,
            },
        );
        Some(port)
    } else {
        None
    };
    proc.tracing
        .family
        .mach
        .grants
        .pending
        .get_mut(&tid)
        .unwrap()
        .result = Some((result, port));
    proc.post(WaitKey::Child);
}

fn release_grant(proc: &mut Proc, pid: i32, instance: u64, generation: u64) {
    if let Ok(bytes) = (super::Message::Release {
        generation,
        instance,
        object: Object::Task,
    })
    .encode()
    {
        super::callback_runtime::child_bytes(proc, pid, bytes);
    }
}

fn cancel(proc: &mut Proc, tid: u64) {
    let Some(mut pending) = proc.tracing.family.mach.grants.pending.remove(&tid) else {
        return;
    };
    match pending.result.take() {
        Some((_, Some(port))) => mach::kmsg::release_send(proc, &port),
        Some((_, None)) => {}
        None => {
            proc.tracing
                .family
                .mach
                .grants
                .abandoned
                .insert(pending.sequence, pending);
        }
    }
}

/// Kernel termination can remove a thread while its noninterruptible trap
/// is waiting. Keep only the wire identity needed to release a late grant.
pub(in super::super) fn reap(
    proc: &mut Proc,
    running: Option<&crate::user::darwin::process::Thread>,
) {
    let dead: Vec<_> = proc
        .tracing
        .family
        .mach
        .grants
        .pending
        .keys()
        .copied()
        .filter(|tid| {
            !running.is_some_and(|t| t.tid == *tid && !t.exited)
                && !proc.threads.get(tid).is_some_and(|t| !t.exited)
        })
        .collect();
    for tid in dead {
        cancel(proc, tid);
    }
}

pub(in super::super) fn before_exec(proc: &mut Proc) {
    let tids: Vec<_> = proc
        .tracing
        .family
        .mach
        .grants
        .pending
        .keys()
        .copied()
        .collect();
    for tid in tids {
        cancel(proc, tid);
    }
}

pub(in super::super) fn peer_died(proc: &mut Proc, pid: i32) {
    proc.tracing
        .family
        .mach
        .grants
        .abandoned
        .retain(|_, p| p.pid != pid);
    let tids: Vec<_> = proc
        .tracing
        .family
        .mach
        .grants
        .pending
        .iter()
        .filter_map(|(&tid, pending)| (pending.pid == pid).then_some(tid))
        .collect();
    for tid in tids {
        let pending = proc
            .tracing
            .family
            .mach
            .grants
            .pending
            .get_mut(&tid)
            .unwrap();
        let old = pending.result.replace((kr::KERN_FAILURE, None));
        if let Some((_, Some(port))) = old {
            mach::kmsg::release_send(proc, &port);
        }
    }
    proc.post(WaitKey::Child);
}
