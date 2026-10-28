//! Ordered callback lifecycle controls and connection cleanup.

use super::super::channels::{self, ServerRoute};
use std::io;
use std::sync::Arc;

use super::callback_wire::Message;
use crate::user::darwin::mach::ipc::Port;
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::mach::kmsg;

#[path = "remote_mach_callback_dispatch.rs"]
mod dispatch;
pub(crate) use dispatch::deliver_callback;
pub(in super::super) use dispatch::{from_child, from_controller, from_parent};

pub(in super::super) fn wants_write(state: &super::State, pid: i32) -> bool {
    state.callbacks.has_outgoing(pid)
}

pub(in super::super) fn flush_pending(proc: &mut Proc) {
    let peers = proc.tracing.family.mach.callbacks.outgoing_peers();
    for pid in peers {
        if !flush_child(proc, pid) {
            super::child_link_failed(proc, pid);
        }
    }
}

fn parent_control(proc: &mut Proc, message: Message) {
    controller_control(proc, ServerRoute::Parent, message);
}

fn controller_control(proc: &mut Proc, route: ServerRoute, message: Message) {
    if message
        .encode()
        .ok()
        .is_none_or(|bytes| !super::queue_control_on(proc, route, bytes))
    {
        super::target::fail(proc, route);
    }
}

pub(in super::super) fn flush_child(proc: &mut Proc, pid: i32) -> bool {
    let family = &mut proc.tracing.family;
    let Some(link) = family
        .children
        .get_mut(&pid)
        .and_then(|child| child.link.as_mut())
    else {
        return false;
    };
    if link.flush().is_err() {
        return false;
    }
    while let Some(bytes) = family.mach.callbacks.front_outgoing(pid) {
        match link.queue(bytes) {
            Ok(()) => family.mach.callbacks.sent_outgoing(pid),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => return false,
        }
    }
    link.flush().is_ok()
}

fn child_control(proc: &mut Proc, pid: i32, message: Message) {
    let Ok(bytes) = message.encode() else {
        return;
    };
    child_bytes(proc, pid, bytes);
}

/// Share the connection FIFO with other capability lifetime controls. A
/// subsequent kernel RPC must not overtake a deferred last-send release.
pub(in super::super) fn child_bytes(proc: &mut Proc, pid: i32, bytes: Vec<u8>) {
    proc.tracing
        .family
        .mach
        .callbacks
        .defer_to_child(pid, bytes);
    if !flush_child(proc, pid) {
        super::child_link_failed(proc, pid);
    }
}

pub(in super::super) fn last_send(proc: &mut Proc, port: &Port) {
    let Some(route) = channels::callback_route(proc, port) else {
        return;
    };
    if let Some((handler, generation)) = route
        .callbacks_mut(proc)
        .and_then(|callbacks| callbacks.last_proxy_send(port))
    {
        controller_control(
            proc,
            route,
            Message::Release {
                handler,
                generation,
            },
        );
    }
}

/// Return true when a callback proxy consumed the abandoned send-once right.
pub(crate) fn release_callback_reply(proc: &mut Proc, port: &Arc<Port>) -> bool {
    let Some((pid, reply)) = proc.tracing.family.mach.callbacks.take_proxy_reply(port) else {
        return false;
    };
    {
        let mut state = port.state.lock().unwrap();
        state.sorights = state.sorights.saturating_sub(1);
    }
    child_control(proc, pid, Message::Cancel { reply });
    true
}

/// Called only after the receive right is marked dead, outside its lock.
pub(crate) fn callback_port_died(proc: &mut Proc, port: &Arc<Port>) {
    let exports = proc.tracing.family.mach.callbacks.dead_exports(port.id);
    for (pid, generation, right) in exports {
        child_control(
            proc,
            pid,
            Message::Dead {
                handler: port.id,
                generation,
            },
        );
        kmsg::release(proc, [right]);
    }
    for route in channels::routes(proc) {
        if let Some(held) = route
            .callbacks_mut(proc)
            .and_then(|callbacks| callbacks.take_reply(port.id))
        {
            controller_control(proc, route, Message::Cancel { reply: port.id });
            kmsg::release(proc, [held]);
        }
    }
}

pub(in super::super) fn peer_died(proc: &mut Proc, pid: i32) {
    let rights = proc.tracing.family.mach.callbacks.drop_peer(pid);
    let replies = proc.tracing.family.mach.callbacks.drop_peer_replies(pid);
    kmsg::release(proc, rights);
    for port in replies {
        kmsg::destroy_receive(proc, &port);
    }
}

pub(in super::super) fn parent_died(proc: &mut Proc) {
    controller_died(proc, super::super::channels::ServerRoute::Parent);
}

pub(in super::super) fn controller_died(
    proc: &mut Proc,
    route: super::super::channels::ServerRoute,
) {
    let Some(callbacks) = route.callbacks_mut(proc) else {
        return;
    };
    let proxies = callbacks.take_parent_proxies();
    let replies = callbacks.take_owned_replies();
    for port in proxies {
        kmsg::destroy_receive(proc, &port);
    }
    kmsg::release(proc, replies);
}

/// The old image loses its receive rights and outstanding RPCs. Exception
/// actions retain their handler sends across exec, so target proxies survive.
pub(in super::super) fn before_exec(proc: &mut Proc) {
    // A rejected handler may borrow a foreign kernel send. Only this
    // image's receive rights die; owning a send does not confer that right.
    let handlers = proc
        .tracing
        .family
        .mach
        .callbacks
        .local_handler_ports(&proc.ipc);
    for port in handlers {
        kmsg::destroy_receive(proc, &port);
    }
    let replies = proc.tracing.family.mach.callbacks.image_reply_proxy_ports();
    for port in replies {
        release_callback_reply(proc, &port);
        kmsg::destroy_receive(proc, &port);
    }
    for route in channels::routes(proc) {
        let Some(callbacks) = route.callbacks_mut(proc) else {
            continue;
        };
        let owned = callbacks.take_image_replies();
        for right in owned {
            if let Some(port) = right.port() {
                controller_control(proc, route, Message::Cancel { reply: port.id });
                kmsg::destroy_receive(proc, port);
            }
            kmsg::release(proc, [right]);
        }
        let proxies = route
            .callbacks(proc)
            .map_or_else(Vec::new, |callbacks| callbacks.handler_proxy_ports());
        for port in proxies {
            let inherited = proc
                .task
                .exc
                .iter()
                .filter(|action| {
                    action
                        .port
                        .as_ref()
                        .is_some_and(|handler| handler.id == port.id)
                })
                .count() as u32
                + proc
                    .tracing
                    .family
                    .mach
                    .callbacks
                    .relay_export_count(port.id);
            port.state.lock().unwrap().srights = inherited;
            if inherited == 0 {
                last_send(proc, &port);
            }
        }
    }
}
