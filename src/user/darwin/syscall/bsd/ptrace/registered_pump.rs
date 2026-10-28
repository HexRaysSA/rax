//! Bounded dispatch for authenticated independently launched callers.

use super::{
    channels::{self, ServerRoute},
    incoming::{self, Incoming},
    *,
};

pub(super) fn pump(proc: &mut Proc, mut running: Option<&mut Thread>) {
    let connections: Vec<_> = proc.tracing.family.peers.incoming.keys().copied().collect();
    for id in connections {
        let route = ServerRoute::Registered(id);
        for _ in 0..32 {
            let failed = route
                .server_mut(proc)
                .is_some_and(|server| std::mem::take(&mut server.failed));
            if failed || !remote_mach::flush_responses_on(proc, route) {
                channels::disconnect(proc, route);
                break;
            }
            if proc.tracing.exit_after_reply.is_some()
                || !route
                    .server(proc)
                    .is_some_and(remote_mach::server_can_receive)
            {
                break;
            }
            let Some(link) = route.link_mut(proc) else {
                break;
            };
            let (messages, closed) = incoming::receive(link, true);
            let empty = messages.is_empty();
            for message in messages {
                match message {
                    Incoming::Trace(message) => {
                        trace_control::dispatch(proc, running.as_deref_mut(), route, message)
                    }
                    Incoming::MachFailure(remote_mach::Message::Request {
                        sequence,
                        expects_reply,
                        ..
                    }) => {
                        if !remote_mach::failed_request_on(proc, route, sequence, expects_reply) {
                            channels::disconnect(proc, route);
                            break;
                        }
                    }
                    Incoming::Mach(message @ remote_mach::Message::Request { .. }) => {
                        let expects_reply = matches!(
                            &message,
                            remote_mach::Message::Request {
                                expects_reply: true,
                                ..
                            }
                        );
                        let reply = remote_mach::server::serve_on(
                            proc,
                            route,
                            running.as_deref_mut(),
                            message,
                        );
                        if !remote_mach::server::queue_served_on(proc, route, expects_reply, reply)
                        {
                            channels::disconnect(proc, route);
                            break;
                        }
                    }
                    Incoming::Mach(remote_mach::Message::Acquire {
                        generation,
                        instance,
                        epoch,
                        object,
                    }) => remote_mach::target::acquire(
                        proc, route, generation, instance, epoch, object,
                    ),
                    Incoming::Mach(remote_mach::Message::Release {
                        generation,
                        instance,
                        object,
                    }) => remote_mach::target::release(proc, route, generation, instance, object),
                    Incoming::Grant(packet) => {
                        remote_mach::grant::from_controller(proc, route, packet)
                    }
                    Incoming::Suspension(packet) => {
                        remote_mach::suspension::from_controller(proc, route, packet)
                    }
                    Incoming::Token(packet) => remote_mach::token::from_controller(
                        proc,
                        route,
                        running.as_deref_mut(),
                        packet,
                    ),
                    Incoming::Callback(packet) => remote_mach::callback_runtime::from_controller(
                        proc,
                        route,
                        running.as_deref_mut(),
                        packet,
                    ),
                    // A malformed/unexpected direction closes only its caller.
                    _ => {
                        channels::disconnect(proc, route);
                        break;
                    }
                }
            }
            if closed {
                channels::disconnect(proc, route);
            }
            if empty || closed || route.link(proc).is_none() {
                break;
            }
        }
    }
}
