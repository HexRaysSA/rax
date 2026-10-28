//! Decode each tracing-link frame without losing its position in wire order.

use super::{protocol, remote_mach, transport};

pub(super) enum Incoming {
    Trace(protocol::Message),
    Mach(remote_mach::Message),
    MachFailure(remote_mach::Message),
    Callback(remote_mach::callback_wire::Message),
    Suspension(remote_mach::suspension::Packet),
    Grant(remote_mach::grant::Packet),
    Token(remote_mach::token::Packet),
}

pub(super) fn receive(link: &mut transport::Link, one: bool) -> (Vec<Incoming>, bool) {
    let mut messages = Vec::new();
    if link.flush().is_err() {
        return (messages, true);
    }
    for _ in 0..if one { 1 } else { 32 } {
        match if one {
            link.receive_one_frame()
        } else {
            link.receive_frames()
        } {
            Ok((frames, closed)) => {
                let empty = frames.is_empty();
                for frame in frames {
                    let decoded = match frame.payload.first() {
                        Some(tag) if remote_mach::token::is_tag(*tag) && frame.fd.is_none() => {
                            remote_mach::token::Packet::decode(&frame.payload).map(Incoming::Token)
                        }
                        Some(tag) if remote_mach::grant::is_tag(*tag) && frame.fd.is_none() => {
                            remote_mach::grant::Packet::decode(&frame.payload).map(Incoming::Grant)
                        }
                        Some(tag)
                            if remote_mach::suspension::is_tag(*tag) && frame.fd.is_none() =>
                        {
                            remote_mach::suspension::Packet::decode(&frame.payload)
                                .map(Incoming::Suspension)
                        }
                        Some(
                            &remote_mach::REQUEST_TAG
                            | &remote_mach::REPLY_TAG
                            | &remote_mach::ACQUIRE_TAG
                            | &remote_mach::RELEASE_TAG
                            | &remote_mach::DEAD_TAG
                            | &remote_mach::BLOB_TAG,
                        ) => remote_mach::decode_frame(frame).map(|(message, failed)| {
                            if failed {
                                Incoming::MachFailure(message)
                            } else {
                                Incoming::Mach(message)
                            }
                        }),
                        Some(tag)
                            if remote_mach::callback_wire::is_tag(*tag) && frame.fd.is_none() =>
                        {
                            remote_mach::callback_wire::Message::decode(&frame.payload)
                                .map(Incoming::Callback)
                        }
                        _ if frame.fd.is_none() => {
                            protocol::Message::decode(&frame.payload).map(Incoming::Trace)
                        }
                        _ => Err(std::io::ErrorKind::InvalidData.into()),
                    };
                    match decoded {
                        Ok(message) => messages.push(message),
                        Err(_) => return (messages, true),
                    }
                }
                if closed || empty {
                    return (messages, closed);
                }
            }
            Err(_) => return (messages, true),
        }
    }
    (messages, false)
}
