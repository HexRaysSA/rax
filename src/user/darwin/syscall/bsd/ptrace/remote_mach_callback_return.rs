//! Return a handler capability to its original process without a guest name.

use super::callback_wire::{HandlerRef, Message as Wire};
use crate::user::darwin::mach::{
    ipc::{MACH_PORT_DEAD, Right, disp},
    msg::{self, Item},
};
use crate::user::darwin::process::Proc;

pub(super) fn encode(proc: &Proc, sequence: u64, reply: &msg::Message) -> Option<Wire> {
    encode_on(
        proc,
        super::super::channels::ServerRoute::Parent,
        sequence,
        reply,
    )
}

pub(super) fn encode_on(
    proc: &Proc,
    route: super::super::channels::ServerRoute,
    sequence: u64,
    reply: &msg::Message,
) -> Option<Wire> {
    super::exception::reply(&reply.body)?;
    if reply.items.len() != 32 {
        return None;
    }
    let mut body = reply.body.clone();
    let mut handlers = Vec::new();
    for (index, (offset, item)) in reply.items.iter().enumerate() {
        if *offset != 4 + index * 12 {
            return None;
        }
        let Item::Port {
            right,
            disp: disp::MOVE_SEND,
        } = item
        else {
            return None;
        };
        let marker = match right {
            None => 0,
            Some(Right::Dead) => MACH_PORT_DEAD,
            Some(Right::Send(port)) if port.is_dead() => MACH_PORT_DEAD,
            Some(Right::Send(port)) => {
                let (handler, generation, _) = route.callbacks(proc)?.proxy_identity(port)?;
                handlers.push(HandlerRef {
                    offset: *offset as u32,
                    handler,
                    generation,
                });
                0
            }
            _ => return None,
        };
        body[*offset..*offset + 4].copy_from_slice(&marker.to_le_bytes());
    }
    if handlers.is_empty() {
        return None;
    }
    Some(Wire::PortsReply {
        sequence,
        bits: reply.bits,
        body,
        handlers,
    })
}

pub(super) fn restore(
    proc: &mut Proc,
    pid: i32,
    body: &[u8],
    handlers: &[HandlerRef],
) -> Option<Vec<(usize, Item)>> {
    let mut items = super::exception::reply(body)?;
    let count = u32::from_le_bytes(body[396..400].try_into().ok()?) as usize;
    let mut resolved = Vec::with_capacity(handlers.len());
    let mut previous = None;
    for handler in handlers {
        let offset = handler.offset as usize;
        let index = offset.checked_sub(4)?;
        if index % 12 != 0
            || index / 12 >= count
            || previous.is_some_and(|old| old >= offset)
            || body.get(offset..offset + 4)? != [0; 4]
            || handler.handler == 0
        {
            return None;
        }
        previous = Some(offset);
        let port = proc
            .tracing
            .family
            .mach
            .callbacks
            .handler_port(pid, handler.handler);
        resolved.push((index / 12, port));
    }
    // No rights are created until every mapping has passed validation. If
    // the original receive right died while the reply travelled, copy out
    // a dead name, as local IPC does for an in-transit dead send right.
    for (index, port) in resolved {
        let right = if let Some(port) = port {
            port.state.lock().unwrap().srights += 1;
            Right::Send(port)
        } else {
            Right::Dead
        };
        items[index].1 = Item::Port {
            right: Some(right),
            disp: disp::MOVE_SEND,
        };
    }
    Some(items)
}

pub(super) fn receive(proc: &mut Proc, pid: i32, packet: Wire) {
    if let Wire::PortsReply {
        sequence,
        bits,
        body,
        handlers,
    } = packet
    {
        super::receive_reply_with_handlers(
            proc,
            pid,
            super::Message::Reply {
                sequence,
                bits,
                body,
                threads: None,
                memory: None,
            },
            Some(handlers),
        );
    }
}
