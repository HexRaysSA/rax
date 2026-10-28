//! Transfer an exception request to the process owning its handler.

use super::super::super::channels::{self, ServerRoute};
use super::super::callback_wire::{Descriptor, Message as Wire, Port as WirePort};
use super::super::{Export, Object, queue_control_on};
use crate::user::darwin::mach::{
    ipc::{KObject, Right, disp},
    msg::{self, Item, bits, desc},
};
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::mach::kmsg;

/// Serialize a kernel exception request. Until ownership has been validated,
/// failure returns the original message with every right still attached.
pub(in super::super) fn forward(
    proc: &mut Proc,
    mut message: msg::Message,
) -> Result<(), msg::Message> {
    let Some(destination) = message.dest.port() else {
        return Err(message);
    };
    let Some(route) = channels::callback_route(proc, destination) else {
        return Err(message);
    };
    let Some((handler, handler_generation, original_instance)) = route
        .callbacks(proc)
        .and_then(|callbacks| callbacks.proxy_identity(destination))
    else {
        return Err(message);
    };
    let Some(epoch) = super::super::target::epoch(proc, route).filter(|epoch| *epoch != 0) else {
        return Err(message);
    };
    let token = match &message.reply {
        Some(Right::SendOnce(port)) if !port.is_dead() => port.id,
        _ => return Err(message),
    };
    if message.voucher.is_some() || !message.aux.is_empty() || message.items.len() > 2 {
        return Err(message);
    }
    let mut objects = Vec::new();
    for (offset, item) in &message.items {
        let Item::Port {
            right: Some(Right::Send(port)),
            disp: disp::MOVE_SEND,
        } = item
        else {
            return Err(message);
        };
        let Some(descriptor) = offset
            .checked_add(12)
            .and_then(|end| message.body.get(*offset..end))
        else {
            return Err(message);
        };
        if descriptor[10] != disp::MOVE_SEND as u8 || descriptor[11] != desc::PORT {
            return Err(message);
        }
        let object = match port.kobject {
            KObject::Task if port.id == proc.task_port.id => Object::Task,
            KObject::Thread(tid) if tid != 0 => Object::Thread(tid),
            _ => return Err(message),
        };
        objects.push((*offset, object));
    }
    if objects.is_empty() {
        if message.bits & bits::COMPLEX != 0 {
            return Err(message);
        }
    } else if message.bits & bits::COMPLEX == 0
        || message.body.get(..4) != Some(&2u32.to_le_bytes()[..])
        || !matches!(
            objects.as_slice(),
            [(4, Object::Thread(_)), (16, Object::Task)]
        )
    {
        return Err(message);
    }
    let task_id = proc.task_port.id;
    let Some((exports, callbacks)) = super::super::target::callback_parts(proc, route) else {
        return Err(message);
    };
    let instance = if objects.is_empty() {
        0
    } else if exports.contains_key(&(original_instance, Object::Task)) {
        original_instance
    } else if let Some(instance) = exports.iter().find_map(|(&(instance, object), export)| {
        (object == Object::Task
            && export
                .right
                .port()
                .is_some_and(|port| port.id == task_id && !port.is_dead()))
        .then_some(instance)
    }) {
        instance
    } else {
        let Some(instance) = callbacks.target_instance(exports.len(), |candidate| {
            exports.keys().any(|(instance, _)| *instance == candidate)
        }) else {
            return Err(message);
        };
        instance
    };
    let state = &mut proc.tracing.family.mach;
    let mut serial = state.next_sequence & !super::super::TARGET_GENERATION_BIT;
    while state.pending.contains_key(&serial) {
        serial = serial.wrapping_add(1) & !super::super::TARGET_GENERATION_BIT;
    }
    state.next_sequence = serial.wrapping_add(1) & !super::super::TARGET_GENERATION_BIT;
    let generation = serial | super::super::TARGET_GENERATION_BIT;
    let mut descriptors = Vec::with_capacity(objects.len());
    for (offset, object) in &objects {
        let Ok(offset) = u32::try_from(*offset) else {
            return Err(message);
        };
        let port = match object {
            Object::Task => WirePort::Task { generation },
            Object::Thread(tid) => WirePort::Thread {
                tid: *tid,
                generation,
            },
        };
        descriptors.push(Descriptor { offset, port });
    }
    let packet = Wire::Deliver {
        instance,
        epoch,
        handler,
        generation: handler_generation,
        reply: token,
        id: message.id,
        bits: message.bits,
        body: message.body.clone(),
        descriptors,
    };
    let Ok(bytes) = packet.encode() else {
        return Err(message);
    };
    let reply = message.reply.take().expect("validated send-once reply");
    if let Err(reply) = route
        .callbacks_mut(proc)
        .expect("callback origin")
        .retain_reply(reply)
    {
        message.reply = Some(reply);
        return Err(message);
    }
    let mut spare = Vec::new();
    for ((_, item), (_, object)) in message.items.iter_mut().zip(objects) {
        let Item::Port { right, .. } = item else {
            unreachable!("validated port descriptor")
        };
        let right = right.take().expect("validated send right");
        if let Some(export) = route
            .server_mut(proc)
            .expect("callback origin")
            .exports
            .get_mut(&(instance, object))
        {
            export.generation = generation;
            spare.push(right);
        } else {
            route
                .server_mut(proc)
                .expect("callback origin")
                .exports
                .insert((instance, object), Export { generation, right });
        }
    }
    let destination = std::mem::replace(&mut message.dest, Right::Dead);
    kmsg::consume_dest(proc, destination);
    kmsg::destroy(proc, message);
    kmsg::release(proc, spare);
    if !queue_control_on(proc, route, bytes) {
        super::super::target::fail(proc, route);
    } else {
        proc.tracing.output_barrier = true;
    }
    Ok(())
}

/// Consume the retained target right when the handler replies or abandons it.
pub(in super::super) fn complete(proc: &mut Proc, packet: Wire) {
    complete_on(proc, ServerRoute::Parent, packet);
}

pub(in super::super) fn complete_on(proc: &mut Proc, route: ServerRoute, packet: Wire) {
    match packet {
        Wire::Reply {
            reply,
            id,
            bits: flags,
            body,
        } => {
            let Some(destination) = route
                .callbacks_mut(proc)
                .and_then(|callbacks| callbacks.take_reply(reply))
            else {
                return;
            };
            kmsg::enqueue(
                proc,
                msg::Message {
                    bits: bits::set(disp::MOVE_SEND_ONCE, 0, 0, flags & bits::COMPLEX),
                    dest: destination,
                    reply: None,
                    voucher: None,
                    voucher_name: 0,
                    id,
                    body,
                    items: Vec::new(),
                    sender: msg::Sender::KERNEL,
                    aux: Vec::new(),
                },
            );
        }
        Wire::Cancel { reply } => {
            let held = route
                .callbacks_mut(proc)
                .and_then(|callbacks| callbacks.take_reply(reply));
            kmsg::release(proc, held);
        }
        _ => {}
    }
}
