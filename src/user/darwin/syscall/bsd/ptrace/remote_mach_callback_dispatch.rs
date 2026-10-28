//! Direction-specific dispatch of reverse Mach messages and lifetime controls.

use super::super::{
    Object, callback,
    callback_wire::{Message, Port as WirePort},
};
use crate::user::darwin::mach::msg;
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::mach::kmsg;

/// Intercept a callback endpoint before a message enters its local queue.
/// An unrepresentable message consumes its rights, notifying the waiting
/// target of the abandoned reply rather than leaving an unreachable queue.
pub(crate) fn deliver_callback(proc: &mut Proc, message: msg::Message) -> Result<(), msg::Message> {
    let Some(port) = message.dest.port() else {
        return Err(message);
    };
    if proc
        .tracing
        .family
        .mach
        .callbacks
        .proxy_reply_identity(port)
        .is_some()
    {
        match callback::receive::reply_packet(proc, message) {
            Ok((pid, packet)) => super::child_control(proc, pid, packet),
            Err(message) => kmsg::destroy(proc, message),
        }
        return Ok(());
    }
    if super::super::super::channels::callback_route(proc, port).is_some() {
        if let Err(message) = callback::target::forward(proc, message) {
            kmsg::destroy(proc, message);
        }
        return Ok(());
    }
    Err(message)
}

pub(in super::super::super) fn from_parent(
    proc: &mut Proc,
    running: Option<&mut crate::user::darwin::process::Thread>,
    packet: Message,
) {
    from_controller(
        proc,
        super::super::super::channels::ServerRoute::Parent,
        running,
        packet,
    );
}

pub(in super::super::super) fn from_controller(
    proc: &mut Proc,
    route: super::super::super::channels::ServerRoute,
    running: Option<&mut crate::user::darwin::process::Thread>,
    packet: Message,
) {
    match packet {
        Message::Install { .. } => {
            super::super::callback_install::serve_on(proc, route, running, packet)
        }
        Message::Reply { .. } | Message::Cancel { .. } => {
            callback::target::complete_on(proc, route, packet)
        }
        Message::Dead {
            handler,
            generation,
        } => {
            if let Some(port) = route
                .callbacks_mut(proc)
                .and_then(|callbacks| callbacks.dead_proxy(handler, generation))
            {
                kmsg::destroy_receive(proc, &port);
            }
        }
        _ => {}
    }
}

pub(in super::super::super) fn from_child(proc: &mut Proc, pid: i32, packet: Message) {
    match packet {
        Message::PortsReply { .. } => super::super::callback_return::receive(proc, pid, packet),
        Message::Deliver { .. } => {
            if let Err(packet) = callback::receive::deliver(proc, pid, packet) {
                discard_delivery(proc, pid, packet);
            }
        }
        Message::Release {
            handler,
            generation,
        } => {
            let right = proc
                .tracing
                .family
                .mach
                .callbacks
                .release_handler(pid, handler, generation);
            kmsg::release(proc, right);
        }
        Message::Cancel { reply } => {
            if let Some(port) = proc
                .tracing
                .family
                .mach
                .callbacks
                .cancel_proxy_reply(pid, reply)
            {
                kmsg::destroy_receive(proc, &port);
            }
        }
        _ => {}
    }
}

/// Rejecting a delivery must return each transferred target capability and
/// abandon its send-once reply. Generations protect a subsequent reacquisition.
fn discard_delivery(proc: &mut Proc, pid: i32, packet: Message) {
    let Message::Deliver {
        instance,
        reply,
        descriptors,
        ..
    } = packet
    else {
        return;
    };
    super::child_control(proc, pid, Message::Cancel { reply });
    for descriptor in descriptors {
        let (object, generation) = match descriptor.port {
            WirePort::Task { generation } => (Object::Task, generation),
            WirePort::Thread { tid, generation } => (Object::Thread(tid), generation),
            WirePort::IdentityToken { .. } => continue,
        };
        // Exports are coalesced by object, not counted per message. A local
        // right from an earlier transfer still keeps this export alive.
        if let Some(remote) = proc.tracing.family.mach.ports.values_mut().find(|remote| {
            remote.pid == pid && remote.instance == instance && remote.object == object
        }) {
            remote.generation = generation;
            continue;
        }
        let bytes = super::super::Message::Release {
            instance,
            object,
            generation,
        }
        .encode();
        if let Ok(bytes) = bytes {
            proc.tracing
                .family
                .mach
                .callbacks
                .defer_to_child(pid, bytes);
        }
    }
    if !super::flush_child(proc, pid) {
        super::super::child_link_failed(proc, pid);
    }
}
