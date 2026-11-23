//! Connection-local LSA policy context handles and privilege lookup (MS-LSAD).

use super::exchange::{Response, put_word, word};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{LsarpcPolicies, LsarpcPolicyContext, ObjId};
use crate::user::windows::security::privilege_names::{self, DisplayCatalog};

pub(super) const CALL: u32 = 0;

const CLOSE: u32 = 0;
const LOOKUP_PRIVILEGE_VALUE: u32 = 31;
const LOOKUP_PRIVILEGE_NAME: u32 = 32;
const LOOKUP_PRIVILEGE_DISPLAY_NAME: u32 = 33;
const OPEN: u32 = 130;
const REPLY: u32 = 3;
const RPC_HEADER_BYTES: usize = 24;
const INPUT_NAME_AT: usize = 128;
const RESULT_NAME_AT: usize = 72;
const CLOSE_REPLY_BYTES: usize = 92;
const LOOKUP_REPLY_BYTES: usize = 80;
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
    let mut response = match operation(payload, request_type)? {
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

pub(super) fn operation(payload: &[u8], request_type: u16) -> Option<u32> {
    if request_type != 0
        || payload.len() < RPC_HEADER_BYTES
        || qword(payload, 4) != 0
        || word(payload, 16) != 1
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
    let context = match (word(payload, 136), desired) {
        (version, _) if version != REVISION_V1 => Err(STATUS_NOT_SUPPORTED),
        (_, 0) => Err(STATUS_INVALID_PARAMETER),
        (_, POLICY_LOOKUP_NAMES) => contexts
            .reserve(association)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES),
        _ => Err(STATUS_ACCESS_DENIED),
    };

    let mut response = reply(OPEN_REPLY_BYTES);
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
    Some(response)
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

    let mut response = reply(LOOKUP_REPLY_BYTES);
    let status = if !contexts.contains(&context) {
        STATUS_INVALID_HANDLE
    } else {
        match decode_name(&payload[INPUT_NAME_AT..end]) {
            Some(value) => {
                put_word(&mut response.body, 24, value);
                STATUS_SUCCESS
            }
            None => STATUS_NO_SUCH_PRIVILEGE,
        }
    };
    put_word(&mut response.body, 32, status);
    Some(response)
}

fn lookup_name_input(payload: &[u8]) -> Option<(LsarpcPolicyContext, usize)> {
    if payload.len() < INPUT_NAME_AT || payload[24..64].iter().any(|&b| b != 0) {
        return None;
    }

    let length = usize::from(u16::from_le_bytes([payload[88], payload[89]]));
    let maximum = usize::from(u16::from_le_bytes([payload[90], payload[91]]));
    // RPC_UNICODE_STRING with a deferred conformant varying WCHAR array.
    if length % 2 != 0
        || maximum % 2 != 0
        || length > maximum
        || qword(payload, 96) == 0
        || qword(payload, 104) != (maximum / 2) as u64
        || qword(payload, 112) != 0
        || qword(payload, 120) != (length / 2) as u64
    {
        return None;
    }
    let context = payload[64..84].try_into().expect("checked context extent");
    Some((context, INPUT_NAME_AT + length))
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

fn lookup_name(payload: &[u8], contexts: &LsarpcPolicies) -> Option<Response> {
    if payload.len() != 92 || payload[24..64].iter().any(|&b| b != 0) {
        return None;
    }
    let context = payload[64..84].try_into().expect("checked context extent");
    let result = if !contexts.contains(&context) {
        Err(STATUS_INVALID_HANDLE)
    } else {
        let low = word(payload, 84);
        let high = word(payload, 88);
        privilege_names::name(low, high).ok_or(STATUS_NO_SUCH_PRIVILEGE)
    };
    let name = match result {
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
    if payload.len() != 84 || payload[24..64].iter().any(|&b| b != 0) {
        return None;
    }
    let context = payload[64..84].try_into().expect("checked context extent");
    let mut response = reply(CLOSE_REPLY_BYTES);
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
