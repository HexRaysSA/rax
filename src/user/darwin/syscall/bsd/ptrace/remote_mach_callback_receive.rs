//! Copy a target's exception request into the handler owner's port space.

use std::collections::BTreeMap;

use super::super::callback_wire::{Message as Wire, Port as WirePort};
use super::super::{Object, Peer, RemotePort, TARGET_INSTANCE_BIT};
use crate::user::darwin::mach::{
    ipc::{KObject, Port, Right, disp},
    msg::{self, Item, Sender, bits, desc},
};
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::mach::kmsg;

/// Reject stale or malformed transfers before creating local rights. The
/// caller retains a rejected packet to cancel its target-owned reply/exports.
pub(in super::super) fn deliver(proc: &mut Proc, pid: i32, packet: Wire) -> Result<(), Wire> {
    let Wire::Deliver {
        instance,
        epoch,
        handler,
        reply,
        bits: flags,
        body,
        descriptors,
        ..
    } = &packet
    else {
        return Err(packet);
    };
    if packet.encode().is_err() {
        return Err(packet);
    }
    let Some(handler_port) = proc
        .tracing
        .family
        .mach
        .callbacks
        .handler_port(pid, *handler)
    else {
        return Err(packet);
    };
    // State-only RPCs carry no image-scoped rights. Their connection-scoped
    // send-once token controls lifetime, including through a relay's exec.
    let connected = proc.tracing.family.children.get(&pid).is_some_and(|child| {
        child.link.is_some()
            && (descriptors.is_empty()
                || child
                    .shared_status
                    .as_ref()
                    .map(|shared| shared.image_epoch())
                    .or_else(|| child.registry_instance.map(|_| child.registry_epoch))
                    == Some(*epoch))
    });
    if !connected {
        return Err(packet);
    }
    if descriptors.is_empty() {
        if *instance != 0 || flags & bits::COMPLEX != 0 {
            return Err(packet);
        }
    } else {
        if !matches!(
            descriptors.as_slice(),
            [
                super::super::callback_wire::Descriptor {
                    offset: 4,
                    port: WirePort::Thread { .. }
                },
                super::super::callback_wire::Descriptor {
                    offset: 16,
                    port: WirePort::Task { .. }
                },
            ]
        ) || flags & bits::COMPLEX == 0
            || body.get(..4) != Some(&2u32.to_le_bytes()[..])
        {
            return Err(packet);
        }
        for descriptor in descriptors {
            let offset = descriptor.offset as usize;
            let Some(raw) = body.get(offset..offset + 12) else {
                return Err(packet);
            };
            if raw[..10] != [0; 10] || raw[10] != disp::MOVE_SEND as u8 || raw[11] != desc::PORT {
                return Err(packet);
            }
        }
        match proc.tracing.family.mach.peers.get(&(pid, *instance)) {
            Some(peer) if peer.epoch == *epoch && !peer.task.is_dead() => {}
            None if instance & TARGET_INSTANCE_BIT != 0 => {}
            _ => return Err(packet),
        }
    }
    let Some(reply_right) = proc.tracing.family.mach.callbacks.proxy_reply(pid, *reply) else {
        return Err(packet);
    };
    let Wire::Deliver {
        instance,
        epoch,
        id,
        bits: flags,
        body,
        descriptors,
        ..
    } = packet
    else {
        unreachable!("validated delivery variant")
    };
    let state = &mut proc.tracing.family.mach;
    let mut items = Vec::with_capacity(descriptors.len());
    if !descriptors.is_empty() {
        let peer = state.peers.entry((pid, instance)).or_insert_with(|| Peer {
            task: Port::new(KObject::Task),
            threads: BTreeMap::new(),
            epoch,
        });
        for descriptor in descriptors {
            let (object, port, generation) = match descriptor.port {
                WirePort::Task { generation } => (Object::Task, peer.task.clone(), generation),
                WirePort::Thread { tid, generation } => {
                    let port = peer
                        .threads
                        .entry(tid)
                        .or_insert_with(|| Port::new(KObject::Thread(tid)))
                        .clone();
                    (Object::Thread(tid), port, generation)
                }
                WirePort::IdentityToken { .. } => unreachable!("validated identity descriptor"),
            };
            state.ports.insert(
                port.id,
                RemotePort {
                    pid,
                    instance,
                    object,
                    generation,
                    pending_release: false,
                },
            );
            port.state.lock().unwrap().srights += 1;
            items.push((
                descriptor.offset as usize,
                Item::Port {
                    right: Some(Right::Send(port)),
                    disp: disp::MOVE_SEND,
                },
            ));
        }
    }
    handler_port.state.lock().unwrap().srights += 1;
    kmsg::enqueue(
        proc,
        msg::Message {
            bits: bits::set(
                disp::MOVE_SEND,
                disp::MOVE_SEND_ONCE,
                0,
                flags & bits::COMPLEX,
            ),
            dest: Right::Send(handler_port),
            reply: Some(reply_right),
            voucher: None,
            voucher_name: 0,
            id,
            body,
            items,
            sender: Sender::KERNEL,
            aux: Vec::new(),
        },
    );
    Ok(())
}

/// Convert one send-once reply without sending a local proxy port name.
pub(in super::super) fn reply_packet(
    proc: &mut Proc,
    mut message: msg::Message,
) -> Result<(i32, Wire), msg::Message> {
    let Right::SendOnce(port) = &message.dest else {
        return Err(message);
    };
    let Some((pid, token)) = proc
        .tracing
        .family
        .mach
        .callbacks
        .proxy_reply_identity(port)
    else {
        return Err(message);
    };
    let packet = Wire::Reply {
        reply: token,
        id: message.id,
        bits: message.bits
            | if message.items.is_empty() {
                0
            } else {
                bits::COMPLEX
            },
        body: message.body.clone(),
    };
    if packet.encode().is_err() {
        return Err(message);
    }
    proc.tracing.family.mach.callbacks.take_proxy_reply(port);
    let destination = std::mem::replace(&mut message.dest, Right::Dead);
    kmsg::consume_dest(proc, destination);
    kmsg::destroy(proc, message);
    Ok((pid, packet))
}
