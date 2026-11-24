//! Connection-local LSA policy context handles and privilege lookup (MS-LSAD).

use super::exchange::{Response, put_word, word};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{LsarpcPolicies, LsarpcPolicyContext, ObjId};
use crate::user::windows::security::privilege_names::{self, DisplayCatalog};

pub(super) const CALL: u32 = 0;
pub(super) const NDR32_CALL_CONTEXT: u32 = 0;
pub(super) const NDR64_CALL_CONTEXT: u32 = 1;

const CLOSE: u32 = 0;
const LOOKUP_PRIVILEGE_VALUE: u32 = 31;
const LOOKUP_PRIVILEGE_NAME: u32 = 32;
const LOOKUP_PRIVILEGE_DISPLAY_NAME: u32 = 33;
const OPEN: u32 = 130;
const REPLY: u32 = 3;
const RPC_HEADER_BYTES: usize = 24;
const INPUT_NDR32_NAME_AT: usize = 104;
const INPUT_NAME_AT: usize = 128;
const RESULT_NDR32_NAME_AT: usize = 48;
const RESULT_NAME_AT: usize = 72;
const CLOSE_NDR32_REPLY_BYTES: usize = 48;
const CLOSE_REPLY_BYTES: usize = 92;
const LOOKUP_NDR32_REPLY_BYTES: usize = 36;
const LOOKUP_REPLY_BYTES: usize = 80;
const OPEN_NDR32_BYTES: usize = 120;
const OPEN_NDR32_REPLY_BYTES: usize = 64;
const OPEN_BYTES: usize = 152;
const OPEN_REPLY_BYTES: usize = 136;
pub(super) const POLICY_LOOKUP_NAMES: u32 = 0x800;
const REVISION_V1: u32 = 1;
const STATUS_NO_SUCH_PRIVILEGE: u32 = 0xc000_0060;

#[derive(Default)]
pub(super) enum Change {
    #[default]
    None,
    Open(LsarpcPolicyContext),
    Close(LsarpcPolicyContext),
}

impl Change {
    pub(super) fn publish(self, contexts: &mut LsarpcPolicies, body_published: bool) {
        match self {
            Self::Open(context) if body_published => contexts.open(context),
            Self::Close(context) => contexts.close(context),
            _ => {}
        }
    }
}

pub(super) fn response(
    payload: &[u8],
    request_type: u16,
    association: ObjId,
    contexts: &LsarpcPolicies,
    display_names: Option<&DisplayCatalog>,
) -> Option<Response> {
    let mut response = match operation(payload, request_type, NDR64_CALL_CONTEXT)? {
        OPEN => open(payload, association, contexts)?,
        LOOKUP_PRIVILEGE_VALUE => lookup_value(payload, contexts)?,
        LOOKUP_PRIVILEGE_NAME => lookup_name(payload, contexts)?,
        LOOKUP_PRIVILEGE_DISPLAY_NAME => lookup_display_name(payload, contexts, display_names)?,
        CLOSE => close(payload, contexts)?,
        _ => return None,
    };
    echo_call_id(&mut response, payload);
    Some(response)
}

pub(super) fn response_ndr32(
    payload: &[u8],
    request_type: u16,
    association: ObjId,
    contexts: &LsarpcPolicies,
) -> Option<Response> {
    let mut response = match operation(payload, request_type, NDR32_CALL_CONTEXT)? {
        OPEN => open_ndr32(payload, association, contexts)?,
        LOOKUP_PRIVILEGE_VALUE => lookup_value_ndr32(payload, contexts)?,
        LOOKUP_PRIVILEGE_NAME => lookup_name_ndr32(payload, contexts)?,
        CLOSE => close_ndr32(payload, contexts)?,
        _ => return None,
    };
    echo_call_id(&mut response, payload);
    Some(response)
}

fn open_ndr32(payload: &[u8], association: ObjId, contexts: &LsarpcPolicies) -> Option<Response> {
    if payload.len() != OPEN_NDR32_BYTES || word(payload, 104) != word(payload, 108) {
        return None;
    }
    let desired = open_access_ndr32(payload)?;
    // The reply's scalar outputs and 20-byte context have the same offsets
    // as in the NDR64 stub, without its trailing transport padding.
    Some(open_reply(
        OPEN_NDR32_REPLY_BYTES,
        association,
        contexts,
        word(payload, 104),
        desired,
    ))
}

pub(super) fn open_access_ndr32(payload: &[u8]) -> Option<u32> {
    // The classic stub uses a 32-bit QoS referent and a 16-bit enum.
    if payload.len() < 104
        || payload[24..68].iter().any(|&byte| byte != 0)
        || word(payload, 68) != 24
        || payload[72..88].iter().any(|&byte| byte != 0)
        || word(payload, 88) == 0
        || word(payload, 92) != 12
        || u16::from_le_bytes([payload[96], payload[97]]) > 3
        || payload[98] > 1
        || payload[99] > 1
    {
        return None;
    }
    Some(word(payload, 100))
}

pub(super) fn operation(payload: &[u8], request_type: u16, context: u32) -> Option<u32> {
    if request_type != 0
        || payload.len() < RPC_HEADER_BYTES
        || qword(payload, 4) != 0
        || word(payload, 16) != context
    {
        return None;
    }
    Some(word(payload, 20))
}

pub(super) fn echo_call_id(response: &mut Response, request: &[u8]) {
    put_word(&mut response.body, 12, word(request, 12));
}

fn open(payload: &[u8], association: ObjId, contexts: &LsarpcPolicies) -> Option<Response> {
    if payload.len() != OPEN_BYTES || word(payload, 136) != word(payload, 140) {
        return None;
    }
    let desired = open_access(payload)?;
    Some(open_reply(
        OPEN_REPLY_BYTES,
        association,
        contexts,
        word(payload, 136),
        desired,
    ))
}

fn open_reply(
    size: usize,
    association: ObjId,
    contexts: &LsarpcPolicies,
    version: u32,
    desired: u32,
) -> Response {
    let context = match (version, desired) {
        (version, _) if version != REVISION_V1 => Err(STATUS_NOT_SUPPORTED),
        (_, 0) => Err(STATUS_INVALID_PARAMETER),
        (_, POLICY_LOOKUP_NAMES) => contexts
            .reserve(association)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES),
        _ => Err(STATUS_ACCESS_DENIED),
    };

    let mut response = reply(size);
    for offset in [24, 28, 32] {
        put_word(&mut response.body, offset, REVISION_V1);
    }
    // Report only capabilities implemented by the virtual policy service.
    match context {
        Ok(context) => {
            response.body[40..60].copy_from_slice(&context);
            response.policy = Change::Open(context);
        }
        Err(status) => put_word(&mut response.body, 60, status),
    }
    response
}

pub(super) fn open_access(payload: &[u8]) -> Option<u32> {
    // Inline NDR64 arguments.
    // The measured form has a NULL SystemName and object pointers, and a non-NULL QoS.
    if payload.len() < 136
        || payload[24..72].iter().any(|&b| b != 0)
        || word(payload, 72) != 48
        || payload[76..112].iter().any(|&b| b != 0)
        || qword(payload, 112) == 0
        || word(payload, 120) != 12
        || word(payload, 124) != 2
        || word(payload, 128) != 1
    {
        return None;
    }

    Some(word(payload, 132))
}

fn lookup_value(payload: &[u8], contexts: &LsarpcPolicies) -> Option<Response> {
    let (context, end) = lookup_name_input(payload)?;
    if end.next_multiple_of(8) != payload.len() {
        return None;
    }

    Some(lookup_value_reply(
        LOOKUP_REPLY_BYTES,
        context,
        &payload[INPUT_NAME_AT..end],
        contexts,
    ))
}

fn lookup_value_ndr32(payload: &[u8], contexts: &LsarpcPolicies) -> Option<Response> {
    if payload.len() < INPUT_NDR32_NAME_AT || payload[24..64].iter().any(|&byte| byte != 0) {
        return None;
    }
    let (length, maximum) = name_lengths(payload, 84)?;
    let end = INPUT_NDR32_NAME_AT + length;
    // The classic deferred WCHAR array uses three 32-bit counts.
    if end.next_multiple_of(4) != payload.len()
        || word(payload, 88) == 0
        || word(payload, 92) != (maximum / 2) as u32
        || word(payload, 96) != 0
        || word(payload, 100) != (length / 2) as u32
    {
        return None;
    }
    let context = payload[64..84].try_into().expect("checked context extent");
    Some(lookup_value_reply(
        LOOKUP_NDR32_REPLY_BYTES,
        context,
        &payload[INPUT_NDR32_NAME_AT..end],
        contexts,
    ))
}

fn lookup_value_reply(
    size: usize,
    context: LsarpcPolicyContext,
    name: &[u8],
    contexts: &LsarpcPolicies,
) -> Response {
    let mut response = reply(size);
    let status = if !contexts.contains(&context) {
        STATUS_INVALID_HANDLE
    } else {
        match decode_name(name) {
            Some(value) => {
                put_word(&mut response.body, 24, value);
                STATUS_SUCCESS
            }
            None => STATUS_NO_SUCH_PRIVILEGE,
        }
    };
    put_word(&mut response.body, 32, status);
    response
}

fn lookup_name_input(payload: &[u8]) -> Option<(LsarpcPolicyContext, usize)> {
    if payload.len() < INPUT_NAME_AT || payload[24..64].iter().any(|&b| b != 0) {
        return None;
    }

    let (length, maximum) = name_lengths(payload, 88)?;
    // RPC_UNICODE_STRING with a deferred conformant varying WCHAR array.
    if qword(payload, 96) == 0
        || qword(payload, 104) != (maximum / 2) as u64
        || qword(payload, 112) != 0
        || qword(payload, 120) != (length / 2) as u64
    {
        return None;
    }
    let context = payload[64..84].try_into().expect("checked context extent");
    Some((context, INPUT_NAME_AT + length))
}

fn name_lengths(payload: &[u8], offset: usize) -> Option<(usize, usize)> {
    let length = usize::from(u16::from_le_bytes([payload[offset], payload[offset + 1]]));
    let maximum = usize::from(u16::from_le_bytes([
        payload[offset + 2],
        payload[offset + 3],
    ]));
    (length % 2 == 0 && maximum % 2 == 0 && length <= maximum).then_some((length, maximum))
}

fn decode_name(bytes: &[u8]) -> Option<u32> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&units)
        .ok()
        .as_deref()
        .and_then(privilege_names::value)
}

fn privilege_name(payload: &[u8], contexts: &LsarpcPolicies) -> Option<Result<&'static str, u32>> {
    if payload.len() != 92 || payload[24..64].iter().any(|&b| b != 0) {
        return None;
    }
    let context = payload[64..84].try_into().expect("checked context extent");
    Some(if !contexts.contains(&context) {
        Err(STATUS_INVALID_HANDLE)
    } else {
        privilege_names::name(word(payload, 84), word(payload, 88)).ok_or(STATUS_NO_SUCH_PRIVILEGE)
    })
}

fn lookup_name(payload: &[u8], contexts: &LsarpcPolicies) -> Option<Response> {
    let name = match privilege_name(payload, contexts)? {
        Ok(name) => name,
        Err(status) => {
            let mut response = reply(40);
            put_word(&mut response.body, 32, status);
            return Some(response);
        }
    };

    let units: Vec<u16> = name.encode_utf16().collect();
    let end = RESULT_NAME_AT + 2 * units.len();
    let mut response = reply(end.next_multiple_of(4) + 8);
    put_name(&mut response.body, &units);
    Some(response)
}

fn lookup_name_ndr32(payload: &[u8], contexts: &LsarpcPolicies) -> Option<Response> {
    let name = match privilege_name(payload, contexts)? {
        Ok(name) => name,
        Err(status) => {
            let mut response = reply(32);
            put_word(&mut response.body, 28, status);
            return Some(response);
        }
    };
    let units: Vec<u16> = name.encode_utf16().collect();
    let length = (2 * units.len()) as u16;
    let end = RESULT_NDR32_NAME_AT + usize::from(length);
    let mut response = reply(end.next_multiple_of(4) + 4);
    let body = &mut response.body;
    // Classic NDR uses 32-bit unique pointers and deferred array counts.
    put_word(body, 24, 0x20000);
    body[28..30].copy_from_slice(&length.to_le_bytes());
    body[30..32].copy_from_slice(&(length + 2).to_le_bytes());
    put_word(body, 32, 0x20004);
    put_word(body, 36, units.len() as u32 + 1);
    put_word(body, 44, units.len() as u32);
    for (unit, bytes) in units
        .into_iter()
        .zip(body[RESULT_NDR32_NAME_AT..end].chunks_exact_mut(2))
    {
        bytes.copy_from_slice(&unit.to_le_bytes());
    }
    Some(response)
}

fn lookup_display_name(
    payload: &[u8],
    contexts: &LsarpcPolicies,
    names: Option<&DisplayCatalog>,
) -> Option<Response> {
    let (context, end) = lookup_name_input(payload)?;
    if end + 4 != payload.len() {
        return None;
    }
    if !contexts.contains(&context) {
        return Some(display_error(STATUS_INVALID_HANDLE));
    }
    let Some(value) = decode_name(&payload[INPUT_NAME_AT..end]) else {
        return Some(display_error(STATUS_NO_SUCH_PRIVILEGE));
    };

    let requested = [
        u16::from_le_bytes([payload[end], payload[end + 1]]),
        u16::from_le_bytes([payload[end + 2], payload[end + 3]]),
    ];
    let display = names?.get(value, requested)?;
    let end = RESULT_NAME_AT + 2 * display.units.len();
    let mut response = reply(end.next_multiple_of(4) + 40);
    put_name(&mut response.body, &display.units);
    response.body[end..end + 2].copy_from_slice(&display.language.to_le_bytes());
    Some(response)
}

fn display_error(status: u32) -> Response {
    let mut response = reply(72);
    put_word(&mut response.body, 36, status);
    response
}

fn put_name(body: &mut [u8], units: &[u16]) {
    // NDR64 unique pointer to an RPC_UNICODE_STRING with a deferred character array.
    // The counted data excludes the terminator, which contributes one to capacity.
    let chars = units.len() as u16;
    let length = chars * 2;
    put_word(body, 24, 0x20000);
    body[32..34].copy_from_slice(&length.to_le_bytes());
    body[34..36].copy_from_slice(&(length + 2).to_le_bytes());
    put_word(body, 40, 0x20000);
    put_word(body, 48, u32::from(chars) + 1);
    put_word(body, 64, u32::from(chars));
    for (unit, chunk) in units.iter().zip(body[RESULT_NAME_AT..].chunks_exact_mut(2)) {
        chunk.copy_from_slice(&unit.to_le_bytes());
    }
}

pub(super) fn close(payload: &[u8], contexts: &LsarpcPolicies) -> Option<Response> {
    close_with_size(payload, contexts, CLOSE_REPLY_BYTES)
}

pub(super) fn close_ndr32(payload: &[u8], contexts: &LsarpcPolicies) -> Option<Response> {
    close_with_size(payload, contexts, CLOSE_NDR32_REPLY_BYTES)
}

fn close_with_size(payload: &[u8], contexts: &LsarpcPolicies, size: usize) -> Option<Response> {
    if payload.len() != 84 || payload[24..64].iter().any(|&b| b != 0) {
        return None;
    }
    let context = payload[64..84].try_into().expect("checked context extent");
    let mut response = reply(size);
    if contexts.contains(&context) {
        response.policy = Change::Close(context);
    } else {
        put_word(&mut response.body, 44, STATUS_INVALID_HANDLE);
    }
    Some(response)
}

pub(super) fn reply(size: usize) -> Response {
    let mut body = vec![0; size];
    put_word(&mut body, 0, REPLY);
    Response {
        body,
        request_type: 0,
        transfer_syntax: None,
        policy: Change::None,
    }
}

fn qword(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("checked NDR64 record"),
    )
}
