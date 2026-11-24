//! Guest ALPC message and context publication for the local LSARPC endpoint.

use super::{Ctx, Flow, Mem, Object, probe_write};
use super::{bind, policy, policy_lookup};
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::hle::ApiResult;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::LsarpcInterface;

const CONTEXT_ATTRIBUTE: u32 = 0x2000_0000;
// The synchronous virtual endpoint does not apply the caller's scheduling ticket.
const WORK_ON_BEHALF_ATTRIBUTE: u32 = 0x0200_0000;
const RPC_ATTRIBUTES: u32 = 0x7e00_0000;
// The virtual service has its own opaque client ID.
const SERVER_PROCESS: u32 = 0x4000_0008;
const SERVER_THREAD: u32 = SERVER_PROCESS + 4;

pub(super) struct Response {
    pub(super) policy: policy::Change,
    pub(super) body: Vec<u8>,
    pub(super) request_type: u16,
    pub(super) transfer_syntax: Option<u32>,
}

pub(in crate::user::windows::dll::native) fn exchange(
    c: &mut Ctx,
    handle: u64,
    [send_attributes, receive, length, receive_attributes]: [u64; 4],
    capacity: u64,
    message_pointer_size: u64,
    request: &[u8],
) -> ApiResult {
    let association = c.p.objects.id(handle).expect("checked LSARPC handle");
    let Some(Object::LpcPort(endpoint)) = c.p.objects.obj(association) else {
        unreachable!("checked LSARPC port");
    };
    let peer = endpoint.lsarpc_peer().expect("checked LSARPC peer");
    let width = message_pointer_size as usize;
    let converted_message = width == 4;
    let converted_length = c.psize() == 4;
    let header = if converted_message { 24 } else { 40 };
    let payload = &request[header..];
    let request_type = u16::from_le_bytes([request[4], request[5]]);
    let valid_length = u16::from_le_bytes([request[0], request[1]]) as usize == payload.len();
    let response = match payload.get(..4).map(|_| word(payload, 0)) {
        Some(bind::BIND) if valid_length => bind::response(peer.interface, payload, request_type)
            .ok_or_else(|| {
            c.unsupported("LSARPC bind header is outside the selected profile")
        })?,
        Some(bind::BIND) => {
            return Err(c.unsupported("LSARPC bind header is outside the selected profile"));
        }
        _ if peer.transfer_syntax.is_none() => {
            return Err(c.unsupported("LSARPC requests require a local RPC bind"));
        }
        Some(policy::CALL) if valid_length && payload.len() >= 24 => {
            let operation = word(payload, 20);
            if request[6..8] != [0; 2] {
                return Err(c.unsupported(format!(
                    "LSARPC local RPC operation {operation} has a nonzero ALPC data info offset"
                )));
            }
            let response = match (peer.interface, peer.transfer_syntax) {
                (LsarpcInterface::Policy, Some(bind::NDR32)) => {
                    policy::response_ndr32(payload, request_type, association, &peer.policies)
                }
                (LsarpcInterface::Policy, Some(bind::NDR64)) => {
                    let names = c.p.native.as_ref().and_then(|runtime| {
                        runtime.object_namespace.privilege_display_names.as_deref()
                    });
                    policy::response(payload, request_type, association, &peer.policies, names)
                }
                (LsarpcInterface::PolicyLookup, Some(bind::NDR64)) => {
                    policy_lookup::response(c, payload, request_type, association, &peer.policies)
                }
                _ => None,
            };
            response.ok_or_else(|| {
                let endpoint = match peer.interface {
                    LsarpcInterface::Policy => "LSARPC",
                    LsarpcInterface::PolicyLookup => "lsapolicylookup",
                };
                c.unsupported(format!(
                    "{endpoint} local RPC operation {operation} is outside the selected profile"
                ))
            })?
        }
        _ => return Err(c.unsupported("LSARPC local RPC packet is outside the selected profile")),
    };
    let payload_bytes = response.body.len();
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
            valid
                if valid == CONTEXT_ATTRIBUTE
                    || (valid == (CONTEXT_ATTRIBUTE | WORK_ON_BEHALF_ATTRIBUTE)
                        && word(&masks, 0) == RPC_ATTRIBUTES) =>
            {
                let offset =
                    context_offset(word(&masks, 0), converted_message).ok_or_else(|| {
                        c.unsupported("LSARPC send context layout is outside the selected profile")
                    })?;
                c.mem().ptr(
                    send_attributes + (offset + width) as u64,
                    message_pointer_size,
                )?
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
    let mut receive_context = 8;
    let attributes_bytes = if receive_attributes != 0 {
        let allocated = c.mem().u32(receive_attributes)?;
        match allocated {
            0 => 8,
            _ => {
                receive_context =
                    context_offset(allocated, converted_message).ok_or_else(|| {
                        c.unsupported(
                            "LSARPC receive context layout is outside the selected profile",
                        )
                    })?;
                put_word(&mut attributes, 4, CONTEXT_ATTRIBUTE);
                put_ptr(&mut attributes, 8, width, u64::from(peer.context));
                put_ptr(&mut attributes, 8 + width, width, cookie);
                put_word(&mut attributes, sequence_offset + 4, message_id);
                put_word(&mut attributes, sequence_offset + 8, callback);
                if converted_message { 28 } else { 40 }
            }
        }
    } else {
        0
    };

    if !converted_length && length != 0 {
        probe_write(c, length, width)?;
    }
    let aliases_send = send_attributes == receive_attributes;
    if attributes_bytes != 0 {
        if aliases_send {
            // A shared attribute allocation can expose the reply context even
            // if the subsequent message copy faults. Preserve its sequence.
            if attributes_bytes > 8 {
                let previous = c
                    .mem()
                    .u32(receive_attributes + (receive_context + 2 * width) as u64)?;
                put_word(&mut attributes, sequence_offset, previous);
            }
            if receive_context != 8 {
                probe_attributes(c, receive_attributes, receive_context, attributes_bytes)?;
            }
            write_attributes(
                c,
                receive_attributes,
                receive_context,
                &attributes[..attributes_bytes],
            )?;
        } else {
            probe_attributes(c, receive_attributes, receive_context, attributes_bytes)?;
        }
    }
    if !short {
        if matches!(response.policy, policy::Change::Open(_)) {
            let Some(Object::LpcPort(endpoint)) = c.p.objects.obj_mut(association) else {
                unreachable!("checked LSARPC port");
            };
            // A partial message copy can expose some or all of a context. Even
            // on failure, another open must never reuse that identifier.
            endpoint
                .lsarpc_peer_mut()
                .expect("checked LSARPC peer")
                .policies
                .begin_reply();
        }
        let mut reply = vec![0; total];
        reply[0..2].copy_from_slice(&(payload_bytes as u16).to_le_bytes());
        reply[2..4].copy_from_slice(&(total as u16).to_le_bytes());
        let kind = response.request_type | 2 | if converted_message { 0x1000 } else { 0 };
        reply[4..6].copy_from_slice(&kind.to_le_bytes());
        put_ptr(&mut reply, 8, width, u64::from(SERVER_PROCESS));
        put_ptr(&mut reply, 8 + width, width, u64::from(SERVER_THREAD));
        put_word(&mut reply, 8 + 2 * width, message_id);
        put_word(&mut reply, header - width, callback);
        reply[header..].copy_from_slice(&response.body);
        write_reply(c, receive, &reply)?;
    }
    if attributes_bytes != 0 {
        if aliases_send {
            if attributes_bytes > 8 {
                c.mem().w32(
                    receive_attributes + (receive_context + 2 * width) as u64,
                    sequence,
                )?;
            }
        } else {
            if attributes_bytes > 8 {
                put_word(&mut attributes, sequence_offset, sequence);
            }
            write_attributes(
                c,
                receive_attributes,
                receive_context,
                &attributes[..attributes_bytes],
            )?;
        }
    }
    if length != 0 {
        let result = c.write_ptr(length, total as u64);
        if !converted_length {
            result?;
        }
    }

    let Some(Object::LpcPort(endpoint)) = c.p.objects.get_mut(handle) else {
        unreachable!("checked LSARPC port");
    };
    let peer = endpoint.lsarpc_peer_mut().expect("checked LSARPC peer");
    peer.sequence = sequence;
    if let Some(syntax) = response.transfer_syntax {
        peer.transfer_syntax = Some(syntax);
    }
    response.policy.publish(&mut peer.policies, !short);
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

// AlpcGetMessageAttribute gives context offset 8 for context-only buffers
// and skips the aligned view allocation in the installed caller's mask.
fn context_offset(allocated: u32, converted_message: bool) -> Option<usize> {
    match allocated {
        CONTEXT_ATTRIBUTE => Some(8),
        0x6000_0000 | RPC_ATTRIBUTES => Some(if converted_message { 24 } else { 40 }),
        _ => None,
    }
}

fn probe_attributes(
    c: &Ctx,
    address: u64,
    context_offset: usize,
    bytes: usize,
) -> Result<(), crate::user::windows::memory::MemFault> {
    if context_offset == 8 {
        probe_write(c, address + 4, bytes - 4)
    } else {
        probe_write(c, address + 4, 4)?;
        probe_write(c, address + context_offset as u64, bytes - 8)
    }
}

fn write_attributes(
    c: &Ctx,
    address: u64,
    context_offset: usize,
    bytes: &[u8],
) -> Result<(), crate::user::windows::memory::MemFault> {
    if context_offset == 8 {
        c.mem().wr(address + 4, &bytes[4..])
    } else {
        c.mem().wr(address + 4, &bytes[4..8])?;
        c.mem().wr(address + context_offset as u64, &bytes[8..])
    }
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

pub(super) fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked RPC record"),
    )
}

pub(super) fn put_word(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_ptr(bytes: &mut [u8], offset: usize, width: usize, value: u64) {
    bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
