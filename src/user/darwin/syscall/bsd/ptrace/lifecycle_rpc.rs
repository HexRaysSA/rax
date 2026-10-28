//! Complete requests received by a cooperative zombie without executing guest
//! work or acquiring new authority. Lifetime notices remain safe to discard
//! after the target exports have been retired.

use super::{
    Proc,
    channels::{self, ServerRoute},
    incoming::Incoming,
    protocol, remote_mach,
};
use crate::user::darwin::{
    abi::Errno,
    mach::{kr, msg::NDR_RECORD},
};

fn mach_failure(proc: &mut Proc, route: ServerRoute, sequence: u64, reply: bool) -> bool {
    if !reply {
        return true;
    }
    let mut body = NDR_RECORD.to_vec();
    body.extend_from_slice(&kr::KERN_TERMINATED.to_le_bytes());
    remote_mach::queue_response_on(
        proc,
        route,
        remote_mach::Message::Reply {
            sequence,
            bits: 0,
            body,
            threads: None,
            memory: None,
        },
    )
}

pub(super) fn reject(proc: &mut Proc, route: ServerRoute, message: Incoming) {
    let queued = match message {
        Incoming::Mach(remote_mach::Message::Request {
            sequence,
            expects_reply,
            ..
        })
        | Incoming::MachFailure(remote_mach::Message::Request {
            sequence,
            expects_reply,
            ..
        })
        | Incoming::Callback(remote_mach::callback_wire::Message::Install {
            sequence,
            expects_reply,
            ..
        }) => mach_failure(proc, route, sequence, expects_reply),
        Incoming::Mach(remote_mach::Message::Acquire {
            generation,
            instance,
            object,
            ..
        }) => remote_mach::queue_response_on(
            proc,
            route,
            remote_mach::Message::Dead {
                generation,
                instance,
                object,
            },
        ),
        Incoming::Grant(packet) => {
            // The ordinary grant server explicitly rejects proc.exit. It
            // retains the request's generation and epoch in its failure reply.
            remote_mach::grant::from_controller(proc, route, packet);
            true
        }
        Incoming::Token(remote_mach::token::Packet::Call {
            sequence, reply, ..
        }) => {
            !reply
                || remote_mach::queue_control_on(
                    proc,
                    route,
                    remote_mach::token::Packet::Result {
                        sequence,
                        result: kr::KERN_TERMINATED,
                    }
                    .encode(),
                )
        }
        Incoming::Trace(protocol::Message::Attach { id, .. }) => channels::queue_reply(
            proc,
            route,
            protocol::Message::AttachReply {
                id,
                errno: Errno::ESRCH.0,
                denied: false,
                original_parent: None,
            }
            .encode(),
        ),
        Incoming::Trace(
            protocol::Message::Resume { id, .. }
            | protocol::Message::CommitUpdate { id }
            | protocol::Message::CommitRemoteUpdate { id, .. },
        ) => channels::queue_reply(
            proc,
            route,
            protocol::Message::Reply {
                id,
                errno: Errno::ESRCH.0,
            }
            .encode(),
        ),
        _ => true,
    };
    if !queued {
        remote_mach::target::fail(proc, route);
    }
}
