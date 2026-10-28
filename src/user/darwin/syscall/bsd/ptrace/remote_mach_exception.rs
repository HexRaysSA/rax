//! Exception-port actions without live transferred rights on a remote task.
//!
//! Null and dead-name ports carry no live cross-process rights. Live handlers
//! require reverse capability and reply-right transport.

use crate::user::darwin::mach::{
    ipc::{MACH_PORT_DEAD, Right, disp},
    msg::{self, Item, bits, desc},
};

pub(super) fn is_update(id: i32) -> bool {
    use crate::user::darwin::mig::ids::task;
    matches!(
        id,
        task::TASK_SET_EXCEPTION_PORTS | task::TASK_SWAP_EXCEPTION_PORTS
    )
}

pub(super) fn has_port_reply(id: i32) -> bool {
    use crate::user::darwin::mig::ids::task;
    matches!(
        id,
        task::TASK_GET_EXCEPTION_PORTS | task::TASK_SWAP_EXCEPTION_PORTS
    )
}

/// A swap must reject an unrepresentable result before installing its input.
/// Invalid requests continue to MIG so its validation order remains authoritative.
pub(super) fn swap_exports_live(proc: &crate::user::darwin::process::Proc, body: &[u8]) -> bool {
    swap_exports_live_on(proc, super::super::channels::ServerRoute::Parent, body)
}

pub(super) fn swap_exports_live_on(
    proc: &crate::user::darwin::process::Proc,
    route: super::super::channels::ServerRoute,
    body: &[u8],
) -> bool {
    use crate::user::darwin::mach::exception::{Handler, validate};
    if body.len() != 36
        || body[..4] != 1u32.to_le_bytes()
        || body[14] != disp::MOVE_SEND as u8
        || body[15] != desc::PORT
    {
        return false;
    }
    let word =
        |offset| u32::from_le_bytes(body[offset..offset + 4].try_into().expect("validated body"));
    let handler = match word(4) {
        0 => Handler::None,
        MACH_PORT_DEAD => Handler::Dead,
        _ => return false,
    };
    let mask = word(24);
    if validate(proc.abi, mask, &handler, word(28) as i32, word(32) as i32).is_err() {
        return false;
    }
    proc.task.exc.iter().enumerate().any(|(index, action)| {
        mask & (1u32 << index) != 0
            && action.port.as_ref().is_some_and(|port| {
                !port.is_dead()
                    && route
                        .callbacks(proc)
                        .and_then(|callbacks| callbacks.proxy_identity(port))
                        .is_none()
            })
    })
}

/// The copied-in disposition and kind of a handler without a live right.
pub(super) fn unbacked_handler(request: &msg::Message, id: i32) -> Option<(u32, bool)> {
    match request.items.as_slice() {
        [(4, Item::Port { right, disp })]
            if request.id == id
                && request.bits & bits::COMPLEX != 0
                && matches!(right, None | Some(Right::Dead)) =>
        {
            Some((*disp, matches!(right, Some(Right::Dead))))
        }
        _ => None,
    }
}

/// Reconstructs a null or dead handler after validating its descriptor.
/// MIG still validates the complete request, mask, and flavor.
pub(super) fn request(body: &[u8], request_bits: u32) -> Option<Vec<(usize, Item)>> {
    if request_bits & bits::COMPLEX == 0 || body.len() < 16 || body[15] != desc::PORT {
        return None;
    }
    let right = match u32::from_le_bytes(body[4..8].try_into().ok()?) {
        0 => None,
        MACH_PORT_DEAD => Some(Right::Dead),
        _ => return None,
    };
    Some(vec![(
        4,
        Item::Port {
            right,
            disp: u32::from(body[14]),
        },
    )])
}

/// Reconstructs 32 null or dead descriptors in a get reply. The count and
/// three variable arrays must fit exactly in the remaining message body.
pub(super) fn reply(body: &[u8]) -> Option<Vec<(usize, Item)>> {
    const DESCRIPTORS: usize = 32;
    const NDR: usize = 4 + DESCRIPTORS * 12;
    const ARRAYS: usize = NDR + 8;
    if body.len() < ARRAYS + 4
        || u32::from_le_bytes(body[0..4].try_into().ok()?) != DESCRIPTORS as u32
        || body[NDR..ARRAYS] != msg::NDR_RECORD
    {
        return None;
    }
    let count = u32::from_le_bytes(body[ARRAYS..ARRAYS + 4].try_into().ok()?) as usize;
    if count > DESCRIPTORS || body.len() != ARRAYS + 4 + count * 12 {
        return None;
    }
    let mut items = Vec::with_capacity(DESCRIPTORS);
    for index in 0..DESCRIPTORS {
        let offset = 4 + 12 * index;
        let descriptor = &body[offset..offset + 12];
        if descriptor[4..10] != [0; 6]
            || u32::from(descriptor[10]) != disp::MOVE_SEND
            || descriptor[11] != desc::PORT
        {
            return None;
        }
        let right = match u32::from_le_bytes(descriptor[..4].try_into().ok()?) {
            0 => None,
            MACH_PORT_DEAD => Some(Right::Dead),
            _ => return None,
        };
        items.push((
            offset,
            Item::Port {
                right,
                disp: disp::MOVE_SEND,
            },
        ));
    }
    Some(items)
}

/// Mark dead rights in the internal wire body without transmitting a name.
pub(super) fn normalize_reply(message: &mut msg::Message) -> bool {
    if reply(&message.body).is_none() || message.items.len() != 32 {
        return false;
    }
    for (index, (offset, item)) in message.items.iter().enumerate() {
        if *offset != 4 + index * 12 || message.body[*offset..*offset + 4] != [0; 4] {
            return false;
        }
        let name = match item {
            Item::Port {
                right: None,
                disp: disp::MOVE_SEND,
            } => 0,
            Item::Port {
                right: Some(Right::Dead),
                disp: disp::MOVE_SEND,
            } => MACH_PORT_DEAD,
            _ => return false,
        };
        message.body[*offset..*offset + 4].copy_from_slice(&name.to_le_bytes());
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_rejects_nonnull_or_malformed_descriptors_and_arrays() {
        let mut body = 32u32.to_le_bytes().to_vec();
        for _ in 0..32 {
            body.extend_from_slice(&[0; 12]);
            let end = body.len();
            body[end - 2] = disp::MOVE_SEND as u8;
        }
        body.extend_from_slice(&msg::NDR_RECORD);
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&[0; 12]);
        assert_eq!(reply(&body).unwrap().len(), 32);
        for (offset, value) in [(4, 1), (14, 19), (15, 1), (388, 1), (396, 33)] {
            let mut bad = body.clone();
            bad[offset] = value;
            assert!(reply(&bad).is_none(), "accepted mutation at {offset}");
        }
        body.pop();
        assert!(reply(&body).is_none());
    }

    #[test]
    fn dead_markers_round_trip_without_turning_live_ports_into_dead_names() {
        let mut body = 32u32.to_le_bytes().to_vec();
        for _ in 0..32 {
            body.extend_from_slice(&[0; 12]);
            let end = body.len();
            body[end - 2] = disp::MOVE_SEND as u8;
        }
        body.extend_from_slice(&msg::NDR_RECORD);
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&[0; 12]);
        let mut items = reply(&body).unwrap();
        items[0].1 = Item::Port {
            right: Some(Right::Dead),
            disp: disp::MOVE_SEND,
        };
        let mut message = msg::Message {
            bits: 0,
            dest: Right::Dead,
            reply: None,
            voucher: None,
            voucher_name: 0,
            id: 0,
            body,
            items,
            sender: msg::Sender::KERNEL,
            aux: Vec::new(),
        };
        assert!(normalize_reply(&mut message));
        assert_eq!(&message.body[4..8], &MACH_PORT_DEAD.to_le_bytes());
        let restored = reply(&message.body).unwrap();
        assert!(matches!(
            restored[0].1,
            Item::Port {
                right: Some(Right::Dead),
                ..
            }
        ));
        assert!(matches!(restored[1].1, Item::Port { right: None, .. }));
        message.body[4] = 1;
        assert!(reply(&message.body).is_none());
    }
}
