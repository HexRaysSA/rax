//! Policy context calls on the local LSA Policy Lookup interface.

use super::exchange::{Response, put_word};
use super::policy::{self, Change, POLICY_LOOKUP_NAMES};
use super::translate;
use crate::user::windows::hle::Ctx;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{LsarpcPolicies, ObjId};

const OPEN: u32 = 0;
const CLOSE: u32 = 1;
const TRANSLATE_SIDS: u32 = 2;
const OPEN_REQUEST_BYTES: usize = 136;
const OPEN_REPLY_BYTES: usize = 92;
const CONTEXT_OFFSET: usize = 24;
const STATUS_OFFSET: usize = 44;

pub(super) fn response(
    c: &Ctx,
    payload: &[u8],
    request_type: u16,
    association: ObjId,
    contexts: &LsarpcPolicies,
) -> Option<Response> {
    let mut response = match policy::operation(payload, request_type)? {
        OPEN => open(payload, association, contexts)?,
        CLOSE => policy::close(payload, contexts)?,
        TRANSLATE_SIDS => translate_sid(c, payload, contexts)?,
        _ => return None,
    };
    policy::echo_call_id(&mut response, payload);
    Some(response)
}

fn translate_sid(c: &Ctx, payload: &[u8], contexts: &LsarpcPolicies) -> Option<Response> {
    let (context, sid) = translate::request(payload)?;
    if !contexts.contains(&context) {
        return None;
    }
    let account =
        c.p.native
            .as_ref()?
            .object_namespace
            .policy_lookup_account
            .as_ref()?;
    let subject = c.p.objects.primary_token_subject()?;
    if sid != account.user_sid || sid != subject.user {
        return None;
    }

    let mut response = policy::reply(24);
    translate::append_success(&mut response.body, account);
    Some(response)
}

fn open(payload: &[u8], association: ObjId, contexts: &LsarpcPolicies) -> Option<Response> {
    if payload.len() != OPEN_REQUEST_BYTES {
        return None;
    }
    let result = match policy::open_access(payload)? {
        0 => Err(STATUS_INVALID_PARAMETER),
        POLICY_LOOKUP_NAMES => contexts
            .reserve(association)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES),
        _ => Err(STATUS_ACCESS_DENIED),
    };
    let mut response = policy::reply(OPEN_REPLY_BYTES);
    match result {
        Ok(context) => {
            response.body[CONTEXT_OFFSET..STATUS_OFFSET].copy_from_slice(&context);
            response.policy = Change::Open(context);
        }
        Err(status) => put_word(&mut response.body, STATUS_OFFSET, status),
    }
    Some(response)
}
