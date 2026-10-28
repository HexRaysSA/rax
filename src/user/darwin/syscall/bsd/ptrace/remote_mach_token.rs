//! Suspension tokens retain individual send-once rights across a family link.

use super::super::channels::ServerRoute;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::user::darwin::mach::{
    ipc::{KObject, Port, Right, disp},
    kr,
    msg::{self, Item, Sender, bits, desc},
};
use crate::user::darwin::mig::ids;
use crate::user::darwin::process::{Proc, Thread};
use crate::user::darwin::syscall::{Ctx, mach::kmsg};

#[path = "remote_mach_token_wire.rs"]
mod wire;
pub(in super::super) use wire::{Packet, is_tag};

#[derive(Debug)]
struct Proxy {
    pid: i32,
    token: u64,
    port: Arc<Port>,
}

#[derive(Debug)]
struct Pending {
    pid: i32,
    reply: Right,
    reply_type: u32,
    id: i32,
    canceled: bool,
}

#[derive(Debug, Default)]
pub(in super::super) struct State {
    exports: BTreeMap<u64, Right>,
    proxies: BTreeMap<u64, Proxy>,
    pending: BTreeMap<u64, Pending>,
    next_token: u64,
}

pub(in super::super) fn is_proxy(proc: &Proc, port: &Port) -> bool {
    proc.tracing
        .family
        .mach
        .tokens
        .proxies
        .contains_key(&port.id)
        || super::suspension::route(proc, port).is_some()
}

/// Retain the actual send-once right before acknowledging its proxy. Every
/// token has its own wire identity even though XNU uses one resume port.
pub(super) fn capture(
    proc: &mut Proc,
    sequence: u64,
    instance: u64,
    reply: &mut msg::Message,
) -> Option<Packet> {
    capture_on(proc, ServerRoute::Parent, sequence, instance, reply)
}

pub(super) fn capture_on(
    proc: &mut Proc,
    route: ServerRoute,
    sequence: u64,
    instance: u64,
    reply: &mut msg::Message,
) -> Option<Packet> {
    let [
        (
            4,
            Item::Port {
                right: Some(Right::SendOnce(port)),
                disp: disp::MOVE_SEND_ONCE,
            },
        ),
    ] = reply.items.as_slice()
    else {
        return None;
    };
    if !crate::user::darwin::mach::suspend::is_resume_port(proc, port) {
        return None;
    }
    let state = route.tokens_mut(proc)?;
    let mut token = state.next_token.max(1);
    while state.exports.contains_key(&token) {
        token = token.wrapping_add(1).max(1);
    }
    state.next_token = token.wrapping_add(1).max(1);
    let (
        _,
        Item::Port {
            right: Some(right), ..
        },
    ) = reply.items.remove(0)
    else {
        unreachable!()
    };
    state.exports.insert(token, right);
    Some(Packet::Offer {
        sequence,
        instance,
        token,
    })
}

pub(super) fn discard_offer(proc: &mut Proc, packet: Packet) {
    discard_offer_on(proc, ServerRoute::Parent, packet);
}

pub(super) fn discard_offer_on(proc: &mut Proc, route: ServerRoute, packet: Packet) {
    if let Packet::Offer { token, .. } = packet {
        let right = route
            .tokens_mut(proc)
            .and_then(|state| state.exports.remove(&token));
        kmsg::release(proc, right);
    }
}

fn child(proc: &mut Proc, pid: i32, packet: Packet) {
    super::callback_runtime::child_bytes(proc, pid, packet.encode());
}

fn parent(proc: &mut Proc, packet: Packet) {
    parent_on(proc, ServerRoute::Parent, packet);
}

fn parent_on(proc: &mut Proc, route: ServerRoute, packet: Packet) {
    if !super::queue_control_on(proc, route, packet.encode()) {
        super::target::fail(proc, route);
    } else {
        proc.tracing.output_barrier = true;
    }
}

/// Abandonment releases one normal hold. Taking a destination out of the
/// space and using it for an RPC takes the separate `deliver` path.
pub(in super::super) fn release(proc: &mut Proc, port: &Port) -> bool {
    let Some(proxy) = proc.tracing.family.mach.tokens.proxies.remove(&port.id) else {
        return false;
    };
    {
        let mut state = port.state.lock().unwrap();
        state.sorights = state.sorights.saturating_sub(1);
    }
    child(proc, proxy.pid, Packet::Drop { token: proxy.token });
    true
}

pub(in super::super) fn deliver(proc: &mut Proc, mut request: msg::Message) {
    let Some(port) = request.dest.port().cloned() else {
        kmsg::destroy(proc, request);
        return;
    };
    let (pid, token, once) =
        if let Some(proxy) = proc.tracing.family.mach.tokens.proxies.remove(&port.id) {
            (proxy.pid, proxy.token, true)
        } else if let Some((pid, token)) = super::suspension::route(proc, &port) {
            (pid, token, false)
        } else {
            kmsg::destroy(proc, request);
            return;
        };
    let destination = std::mem::replace(&mut request.dest, Right::Dead);
    let mut body = std::mem::take(&mut request.body);
    if request.id == ids::task::TASK_RESUME2 && !body.is_empty() {
        // Every nonempty body fails this no-argument routine's size check.
        // Carry a representative bad size rather than abandoning the token
        // when a malformed RPC exceeds the private transport's frame limit.
        body.clear();
        body.extend_from_slice(&[0; 4]);
    } else if ids::name(request.id).is_none() {
        // An unknown routine is rejected before inspecting its body.
        body.clear();
    }
    let expects_reply = matches!(request.reply, Some(Right::Send(_) | Right::SendOnce(_)));
    if body.len() > super::MAX_FRAME - 30
        || (expects_reply && proc.tracing.family.mach.tokens.pending.len() >= 1024)
    {
        if once {
            child(proc, pid, Packet::Drop { token });
        }
        kmsg::consume_dest(proc, destination);
        super::reject(proc, request, kr::KERN_RESOURCE_SHORTAGE);
        return;
    }
    let state = &mut proc.tracing.family.mach;
    let mut sequence = state.next_sequence;
    while state.tokens.pending.contains_key(&sequence) {
        sequence = sequence.wrapping_add(1);
    }
    state.next_sequence = sequence.wrapping_add(1);
    if expects_reply {
        state.tokens.pending.insert(
            sequence,
            Pending {
                pid,
                reply: request.reply.take().unwrap(),
                reply_type: bits::local(request.bits),
                id: request.id,
                canceled: false,
            },
        );
    }
    let packet = Packet::Call {
        once,
        sequence,
        token,
        id: request.id,
        bits: request.bits,
        reply: expects_reply,
        body,
    };
    kmsg::destroy(proc, request);
    child(proc, pid, packet);
    // Keep the destination alive until its call is ordered ahead of any
    // legacy no-senders release triggered by consuming the final send.
    kmsg::consume_dest(proc, destination);
}

pub(in super::super) fn from_parent(proc: &mut Proc, running: Option<&mut Thread>, packet: Packet) {
    from_controller(proc, ServerRoute::Parent, running, packet);
}

pub(in super::super) fn from_controller(
    proc: &mut Proc,
    route: ServerRoute,
    running: Option<&mut Thread>,
    packet: Packet,
) {
    match packet {
        Packet::Drop { token } => {
            let right = route
                .tokens_mut(proc)
                .and_then(|state| state.exports.remove(&token));
            kmsg::release(proc, right);
        }
        Packet::Call {
            once,
            sequence,
            token,
            id,
            bits,
            reply,
            body,
        } => {
            let right = if once {
                route
                    .tokens_mut(proc)
                    .and_then(|state| state.exports.remove(&token))
            } else {
                super::suspension::copy_resume_send_on(proc, route, token)
            };
            let result = match right {
                Some(right) => serve(proc, running, right, id, bits, body),
                None => kr::KERN_INVALID_CAPABILITY,
            };
            if reply {
                parent_on(proc, route, Packet::Result { sequence, result });
            }
        }
        _ => {}
    }
}

fn serve(
    proc: &mut Proc,
    running: Option<&mut Thread>,
    right: Right,
    id: i32,
    flags: u32,
    body: Vec<u8>,
) -> i32 {
    let detached = if running.is_none() {
        proc.threads
            .iter()
            .find_map(|(&tid, t)| (!t.exited).then_some(tid))
    } else {
        None
    };
    let mut detached_thread = detached.and_then(|tid| proc.threads.remove(&tid));
    let thread = running.or(detached_thread.as_mut());
    let Some(thread) = thread else {
        kmsg::consume_dest(proc, right);
        return kr::KERN_TERMINATED;
    };
    let remote = if matches!(right, Right::SendOnce(_)) {
        disp::MOVE_SEND_ONCE
    } else {
        disp::MOVE_SEND
    };
    let target = right.port().unwrap().clone();
    let response = Port::new(KObject::None);
    response.state.lock().unwrap().sorights = 1;
    let request = msg::Message {
        bits: bits::set(remote, disp::MOVE_SEND_ONCE, 0, flags & bits::COMPLEX),
        dest: right,
        reply: Some(Right::SendOnce(response)),
        voucher: None,
        voucher_name: 0,
        id,
        body,
        items: Vec::new(),
        sender: Sender::KERNEL,
        aux: Vec::new(),
    };
    let pc = thread.cpu.pc();
    let reply = crate::user::darwin::mig::serve(
        &mut Ctx {
            proc,
            thread,
            nr: -1,
            pc,
        },
        &target,
        request,
    );
    if let Some(thread) = detached_thread {
        proc.threads.insert(thread.tid, thread);
    }
    let Some(mut reply) = reply else {
        return kr::MIG_NO_REPLY;
    };
    let result = if reply.body.len() == 12 && reply.bits & bits::COMPLEX == 0 {
        i32::from_le_bytes(reply.body[8..12].try_into().unwrap())
    } else {
        kr::MIG_TYPE_ERROR
    };
    let destination = std::mem::replace(&mut reply.dest, Right::Dead);
    kmsg::consume_dest(proc, destination);
    kmsg::destroy(proc, reply);
    result
}

pub(in super::super) fn from_child(proc: &mut Proc, pid: i32, packet: Packet) {
    match packet {
        Packet::Offer {
            sequence,
            instance,
            token,
        } => offer(proc, pid, sequence, instance, token),
        Packet::Result { sequence, result } => {
            if proc
                .tracing
                .family
                .mach
                .tokens
                .pending
                .get(&sequence)
                .is_some_and(|p| p.pid == pid)
            {
                let pending = proc
                    .tracing
                    .family
                    .mach
                    .tokens
                    .pending
                    .remove(&sequence)
                    .unwrap();
                finish(proc, pending, result);
            }
        }
        Packet::Dead { token } => {
            let key = proc
                .tracing
                .family
                .mach
                .tokens
                .proxies
                .iter()
                .find_map(|(&key, p)| (p.pid == pid && p.token == token).then_some(key));
            if let Some(key) = key {
                let proxy = proc
                    .tracing
                    .family
                    .mach
                    .tokens
                    .proxies
                    .remove(&key)
                    .unwrap();
                kmsg::destroy_receive(proc, &proxy.port);
            }
        }
        _ => {}
    }
}

fn offer(proc: &mut Proc, pid: i32, sequence: u64, instance: u64, token: u64) {
    let state = &mut proc.tracing.family.mach;
    if state
        .tokens
        .proxies
        .values()
        .any(|p| p.pid == pid && p.token == token)
    {
        return;
    }
    if !state.pending.get(&sequence).is_some_and(|p| {
        p.pid == pid && p.instance == instance && p.request_id == ids::task::TASK_SUSPEND2
    }) {
        child(proc, pid, Packet::Drop { token });
        return;
    }
    let pending = state.pending.remove(&sequence).unwrap();
    if pending.canceled || !state.peers.contains_key(&(pid, instance)) {
        child(proc, pid, Packet::Drop { token });
        super::fail_pending(proc, pending, kr::KERN_TERMINATED);
        return;
    }
    let port = Port::new(KObject::TaskResume(None));
    port.state.lock().unwrap().sorights = 1;
    state.tokens.proxies.insert(
        port.id,
        Proxy {
            pid,
            token,
            port: port.clone(),
        },
    );
    let mut body = 1u32.to_le_bytes().to_vec();
    body.resize(16, 0);
    body[14] = disp::MOVE_SEND_ONCE as u8;
    body[15] = desc::PORT;
    super::enqueue_reply(
        proc,
        pending,
        bits::COMPLEX,
        body,
        vec![(
            4,
            Item::Port {
                right: Some(Right::SendOnce(port)),
                disp: disp::MOVE_SEND_ONCE,
            },
        )],
    );
}

fn finish(proc: &mut Proc, pending: Pending, result: i32) {
    if pending.canceled {
        kmsg::release(proc, [pending.reply]);
        return;
    }
    let mut body = msg::NDR_RECORD.to_vec();
    body.extend_from_slice(&result.to_le_bytes());
    kmsg::enqueue(
        proc,
        msg::Message {
            bits: bits::set(pending.reply_type, 0, 0, 0),
            dest: pending.reply,
            reply: None,
            voucher: None,
            voucher_name: 0,
            id: pending.id.wrapping_add(100),
            body,
            items: Vec::new(),
            sender: Sender::KERNEL,
            aux: Vec::new(),
        },
    );
}

pub(super) fn before_exec(proc: &mut Proc) {
    let proxies = std::mem::take(&mut proc.tracing.family.mach.tokens.proxies);
    for proxy in proxies.into_values() {
        child(proc, proxy.pid, Packet::Drop { token: proxy.token });
        kmsg::destroy_receive(proc, &proxy.port);
    }
    let rights: Vec<_> = proc
        .tracing
        .family
        .mach
        .tokens
        .pending
        .values_mut()
        .map(|p| {
            p.canceled = true;
            std::mem::replace(&mut p.reply, Right::Dead)
        })
        .collect();
    kmsg::release(proc, rights);
}

pub(super) fn peer_died(proc: &mut Proc, pid: i32) {
    let mut ports = super::suspension::take_peer_ports(proc, pid);
    let keys: Vec<_> = proc
        .tracing
        .family
        .mach
        .tokens
        .proxies
        .iter()
        .filter_map(|(&key, p)| (p.pid == pid).then_some(key))
        .collect();
    for key in keys {
        let proxy = proc
            .tracing
            .family
            .mach
            .tokens
            .proxies
            .remove(&key)
            .unwrap();
        ports.push(proxy.port);
    }
    // Remove both routing kinds before destruction or reply failure can
    // re-enter delivery through another resume right.
    for port in ports {
        kmsg::destroy_receive(proc, &port);
    }
    let keys: Vec<_> = proc
        .tracing
        .family
        .mach
        .tokens
        .pending
        .iter()
        .filter_map(|(&key, p)| (p.pid == pid).then_some(key))
        .collect();
    for key in keys {
        let pending = proc
            .tracing
            .family
            .mach
            .tokens
            .pending
            .remove(&key)
            .unwrap();
        finish(proc, pending, kr::KERN_TERMINATED);
    }
}

pub(super) fn parent_died(proc: &mut Proc) {
    controller_died(proc, ServerRoute::Parent);
}

pub(in super::super) fn controller_died(proc: &mut Proc, route: ServerRoute) {
    let Some(state) = route.tokens_mut(proc) else {
        return;
    };
    let rights = std::mem::take(&mut state.exports);
    kmsg::release(proc, rights.into_values());
}

pub(super) fn target_will_exec(proc: &mut Proc) {
    for route in super::super::channels::routes(proc) {
        let Some(state) = route.tokens_mut(proc) else {
            continue;
        };
        let rights = std::mem::take(&mut state.exports);
        for (token, right) in rights {
            parent_on(proc, route, Packet::Dead { token });
            kmsg::release(proc, [right]);
        }
    }
}
