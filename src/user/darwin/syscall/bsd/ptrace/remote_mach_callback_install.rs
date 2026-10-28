//! Transfer a debugger-owned handler send into a connected target's action.

use super::{Pending, RemotePort, callback_wire};
use crate::user::darwin::mach::{
    ipc::{KObject, Right},
    kr,
    msg::{self, Item, bits},
};
use crate::user::darwin::process::{Proc, Thread};
use crate::user::darwin::syscall::{Ctx, mach::kmsg};

pub(super) fn deliver(ctx: &mut Ctx<'_>, mut request: msg::Message, remote: RemotePort) {
    let [
        (
            4,
            Item::Port {
                right: Some(Right::Send(port)),
                disp,
            },
        ),
    ] = request.items.as_slice()
    else {
        super::reject(ctx.proc, request, kr::MIG_TYPE_ERROR);
        return;
    };
    if port.is_dead() || super::super::channels::callback_route(ctx.proc, port).is_some() {
        super::reject(ctx.proc, request, kr::KERN_NOT_SUPPORTED);
        return;
    }
    let handler = port.id;
    let plain = port.kobject == KObject::None;
    let mut body = request.body.clone();
    if let Some(field) = body.get_mut(14) {
        *field = *disp as u8;
    }
    if let Some(name) = body.get_mut(4..8) {
        name.fill(0);
    }
    let expects_reply = matches!(request.reply, Some(Right::Send(_) | Right::SendOnce(_)));
    let state = &mut ctx.proc.tracing.family.mach;
    if expects_reply && state.pending.len() >= 1024 {
        super::reject(ctx.proc, request, kr::KERN_RESOURCE_SHORTAGE);
        return;
    }
    let mut sequence = state.next_sequence;
    while state.pending.contains_key(&sequence) {
        sequence = sequence.wrapping_add(1);
    }
    state.next_sequence = sequence.wrapping_add(1);
    let packet = callback_wire::Message::Install {
        sequence,
        instance: remote.instance,
        handler,
        generation: sequence,
        id: request.id,
        bits: request.bits,
        expects_reply,
        plain,
        body,
    };
    let Ok(bytes) = packet.encode() else {
        super::reject(ctx.proc, request, kr::KERN_RESOURCE_SHORTAGE);
        return;
    };
    if let Err(dead) = super::send_to_child(ctx.proc, remote.pid, &bytes, None) {
        if dead {
            super::child_link_failed(ctx.proc, remote.pid);
        }
        super::reject(
            ctx.proc,
            request,
            if dead {
                kr::KERN_TERMINATED
            } else {
                kr::KERN_RESOURCE_SHORTAGE
            },
        );
        return;
    }
    let Item::Port { right, .. } = &mut request.items[0].1 else {
        unreachable!("validated port item")
    };
    let right = right.take().expect("validated send right");
    match ctx
        .proc
        .tracing
        .family
        .mach
        .callbacks
        .retain_handler(remote.pid, handler, sequence, right)
    {
        Ok(spare) => kmsg::release(ctx.proc, spare),
        Err(right) => {
            kmsg::release(ctx.proc, [right]);
            super::child_link_failed(ctx.proc, remote.pid);
            super::reject(ctx.proc, request, kr::KERN_TERMINATED);
            return;
        }
    }
    match request.reply.take() {
        Some(reply @ (Right::Send(_) | Right::SendOnce(_))) => {
            ctx.proc.tracing.family.mach.pending.insert(
                sequence,
                Pending {
                    pid: remote.pid,
                    instance: remote.instance,
                    reply,
                    reply_type: bits::local(request.bits),
                    request_id: request.id,
                    overwrite: None,
                    canceled: false,
                },
            );
        }
        other => kmsg::release(ctx.proc, other),
    }
    kmsg::destroy(ctx.proc, request);
}

pub(super) fn serve(proc: &mut Proc, running: Option<&mut Thread>, packet: callback_wire::Message) {
    serve_on(
        proc,
        super::super::channels::ServerRoute::Parent,
        running,
        packet,
    );
}

pub(super) fn serve_on(
    proc: &mut Proc,
    route: super::super::channels::ServerRoute,
    running: Option<&mut Thread>,
    packet: callback_wire::Message,
) {
    let callback_wire::Message::Install {
        sequence,
        instance,
        handler,
        generation,
        id,
        bits,
        expects_reply,
        plain,
        body,
    } = packet
    else {
        return;
    };
    let Some(callbacks) = route.callbacks_mut(proc) else {
        return;
    };
    let proxy = callbacks.acquire_proxy(handler, generation, instance);
    let request = super::Message::Request {
        sequence,
        instance,
        object: super::Object::Task,
        id,
        bits,
        expects_reply,
        body,
        memory: None,
    };
    let reply = super::server::serve_with_handler_on(
        proc,
        route,
        running,
        request,
        Right::Send(proxy),
        plain,
    );
    if !super::server::queue_served_on(proc, route, expects_reply, reply) {
        super::target::fail(proc, route);
    }
}
