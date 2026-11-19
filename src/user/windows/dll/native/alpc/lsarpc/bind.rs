//! Local RPC transfer-syntax negotiation for the selected LSARPC endpoint.

use super::{Ctx, Flow, Mem, Object, probe_write};
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::hle::ApiResult;
use crate::user::windows::nt::status::*;

const CONTEXT_ATTRIBUTE: u32 = 0x2000_0000;
const BIND: u32 = 1;
const BIND_BYTES: usize = 72;
const NDR: u32 = 1;
const NDR64: u32 = 2;
const SYNTAX_MASK: u32 = 7;
const RPC_S_UNKNOWN_IF: u32 = 1717;
const RPC_S_PROTOCOL_ERROR: u32 = 1728;
const RPC_S_UNSUPPORTED_TRANS_SYN: u32 = 1730;
const FAULT: u32 = 2;
const FAULT_BYTES: usize = 20;
const LSARPC_INTERFACE: [u8; 20] = [
    0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
    0, 0, 0, 0,
];

// The virtual service has its own opaque client ID.
const SERVER_PROCESS: u32 = 0x4000_0008;
const SERVER_THREAD: u32 = SERVER_PROCESS + 4;

pub(in crate::user::windows::dll::native) fn exchange(
    c: &mut Ctx,
    handle: u64,
    [send_attributes, receive, length, receive_attributes]: [u64; 4],
    capacity: u64,
    request: &[u8],
) -> ApiResult {
    let Some(Object::LpcPort(endpoint)) = c.p.objects.get(handle) else {
        unreachable!("checked LSARPC port");
    };
    let peer = endpoint.lsarpc_peer().expect("checked LSARPC peer");
    let width = c.psize() as usize;
    let wow64 = width == 4;
    let header = if wow64 { 24 } else { 40 };
    let payload = &request[header..];
    if payload.len() < 4 || word(payload, 0) != BIND {
        return Err(c.unsupported(if peer.transfer_syntax.is_some() {
            "LSARPC account-lookup requests are outside the selected profile"
        } else {
            "LSARPC requests require a local RPC bind"
        }));
    }
    let request_type = u16::from_le_bytes([request[4], request[5]]);
    if payload.len() != BIND_BYTES
        || request[..2] != (BIND_BYTES as u16).to_le_bytes()
        || !matches!(request_type, 0 | 0x4000)
    {
        return Err(c.unsupported("LSARPC bind header is outside the selected profile"));
    }
    let negotiated = if payload[12..32] == LSARPC_INTERFACE {
        match word(payload, 32) & SYNTAX_MASK {
            1 | 5 => Ok(NDR),
            2 | 3 | 6 => Ok(NDR64),
            4 => Err(RPC_S_UNSUPPORTED_TRANS_SYN),
            _ => Err(RPC_S_PROTOCOL_ERROR),
        }
    } else {
        Err(RPC_S_UNKNOWN_IF)
    };
    let payload_bytes = if negotiated.is_ok() {
        BIND_BYTES
    } else {
        FAULT_BYTES
    };
    let total = header + payload_bytes;
    let short = capacity < total as u64;
    let Some(sequence) = peer.sequence.checked_add(1) else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let message_id = peer.message_id;
    let Some(next_id) = message_id.checked_add(2) else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let callback = message_id + 1;

    let cookie = if send_attributes != 0 {
        let masks = c.mem().bytes(send_attributes, 8)?;
        match word(&masks, 4) {
            0 => 0,
            CONTEXT_ATTRIBUTE if word(&masks, 0) == CONTEXT_ATTRIBUTE => {
                c.read_ptr(send_attributes + (8 + width) as u64)?
            }
            _ => {
                return Err(c.unsupported(
                    "LSARPC send message attributes are outside the selected profile",
                ));
            }
        }
    } else {
        0
    };
    let mut attributes = [0; 40];
    let sequence_offset = 8 + 2 * width;
    let attributes_bytes = if receive_attributes != 0 {
        match c.mem().u32(receive_attributes)? {
            0 => 8,
            CONTEXT_ATTRIBUTE => {
                put_word(&mut attributes, 4, CONTEXT_ATTRIBUTE);
                put_ptr(&mut attributes, 8, width, u64::from(peer.context));
                put_ptr(&mut attributes, 8 + width, width, cookie);
                put_word(&mut attributes, sequence_offset + 4, message_id);
                put_word(&mut attributes, sequence_offset + 8, callback);
                if wow64 { 28 } else { 40 }
            }
            _ => {
                return Err(c.unsupported(
                    "LSARPC receive message attributes are outside the selected profile",
                ));
            }
        }
    } else {
        0
    };

    if !wow64 && length != 0 {
        probe_write(c, length, width)?;
    }
    let aliases_send = send_attributes == receive_attributes;
    if attributes_bytes != 0 {
        if aliases_send {
            // A shared attribute allocation can expose the reply context even
            // if the subsequent message copy faults. Preserve its sequence.
            if attributes_bytes > 8 {
                let previous = c.mem().u32(receive_attributes + sequence_offset as u64)?;
                put_word(&mut attributes, sequence_offset, previous);
            }
            c.mem()
                .wr(receive_attributes + 4, &attributes[4..attributes_bytes])?;
        } else {
            probe_write(c, receive_attributes + 4, attributes_bytes - 4)?;
        }
    }
    if !short {
        let mut reply = [0; 40 + BIND_BYTES];
        reply[0..2].copy_from_slice(&(payload_bytes as u16).to_le_bytes());
        reply[2..4].copy_from_slice(&(total as u16).to_le_bytes());
        let kind = if negotiated.is_ok() { request_type } else { 0 };
        let kind = kind | 2 | if wow64 { 0x1000 } else { 0 };
        reply[4..6].copy_from_slice(&kind.to_le_bytes());
        put_ptr(&mut reply, 8, width, u64::from(SERVER_PROCESS));
        put_ptr(&mut reply, 8 + width, width, u64::from(SERVER_THREAD));
        put_word(&mut reply, 8 + 2 * width, message_id);
        put_word(&mut reply, header - width, callback);
        match negotiated {
            Ok(syntax) => {
                reply[header..total].copy_from_slice(payload);
                put_word(&mut reply, header + 8, 0);
                put_word(&mut reply, header + 32, syntax);
            }
            Err(status) => {
                put_word(&mut reply, header, FAULT);
                put_word(&mut reply, header + 8, status);
                reply[header + 16..total].copy_from_slice(&payload[16..20]);
            }
        }
        write_reply(c, receive, &reply[..total])?;
    }
    if attributes_bytes != 0 {
        if aliases_send {
            if attributes_bytes > 8 {
                c.mem()
                    .w32(receive_attributes + sequence_offset as u64, sequence)?;
            }
        } else {
            if attributes_bytes > 8 {
                put_word(&mut attributes, sequence_offset, sequence);
            }
            c.mem()
                .wr(receive_attributes + 4, &attributes[4..attributes_bytes])?;
        }
    }
    if length != 0 {
        let result = c.write_ptr(length, total as u64);
        if !wow64 {
            result?;
        }
    }

    let Some(Object::LpcPort(endpoint)) = c.p.objects.get_mut(handle) else {
        unreachable!("checked LSARPC port");
    };
    let peer = endpoint.lsarpc_peer_mut().expect("checked LSARPC peer");
    peer.sequence = sequence;
    if let Ok(syntax) = negotiated {
        peer.transfer_syntax = Some(syntax);
    }
    if short {
        // A reply discarded for lack of space consumes its message ID.
        peer.message_id = next_id;
    }
    Flow::ret(
        if short {
            STATUS_BUFFER_TOO_SMALL
        } else {
            STATUS_SUCCESS
        }
        .into(),
    )
}

// The kernel publishes an accessible prefix before a fault on a later page.
fn write_reply(
    c: &Ctx,
    mut address: u64,
    mut remaining: &[u8],
) -> Result<(), crate::user::windows::memory::MemFault> {
    while !remaining.is_empty() {
        let page_bytes = PAGE_SIZE - address % PAGE_SIZE;
        let (prefix, tail) = remaining.split_at(remaining.len().min(page_bytes as usize));
        c.mem().wr(address, prefix)?;
        address += prefix.len() as u64;
        remaining = tail;
    }
    Ok(())
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked RPC record"),
    )
}

fn put_word(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_ptr(bytes: &mut [u8], offset: usize, width: usize, value: u64) {
    bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
