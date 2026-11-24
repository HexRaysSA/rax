//! Policy context calls on the local LSA Policy Lookup interface.

use super::exchange::{Response, put_word};
use super::policy::{self, Change, POLICY_LOOKUP_NAMES};
use super::translate;
use crate::user::windows::hle::Ctx;
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::policy_lookup::Translation;
use crate::user::windows::objects::{LsarpcPolicies, LsarpcPolicyContext, ObjId};

const OPEN: u32 = 0;
const CLOSE: u32 = 1;
const TRANSLATE_SIDS: u32 = 2;
const OPEN_REQUEST_BYTES: usize = 136;
const OPEN_REPLY_BYTES: usize = 92;
const OPEN_NDR32_REQUEST_BYTES: usize = 104;
const OPEN_NDR32_REPLY_BYTES: usize = 48;
const CONTEXT_OFFSET: usize = 24;
const STATUS_OFFSET: usize = 44;

pub(super) fn response(
    c: &Ctx,
    payload: &[u8],
    request_type: u16,
    association: ObjId,
    contexts: &LsarpcPolicies,
) -> Option<Response> {
    let mut response = match policy::operation(payload, request_type, policy::NDR64_CALL_CONTEXT)? {
        OPEN => open(payload, association, contexts)?,
        CLOSE => policy::close(payload, contexts)?,
        TRANSLATE_SIDS => translate_sid(c, payload, contexts)?,
        _ => return None,
    };
    policy::echo_call_id(&mut response, payload);
    Some(response)
}

pub(super) fn response_ndr32(
    c: &Ctx,
    payload: &[u8],
    request_type: u16,
    association: ObjId,
    contexts: &LsarpcPolicies,
) -> Option<Response> {
    let mut response = match policy::operation(payload, request_type, policy::NDR32_CALL_CONTEXT)? {
        OPEN if payload.len() == OPEN_NDR32_REQUEST_BYTES => {
            let desired = policy::open_access_ndr32(payload)?;
            open_reply(OPEN_NDR32_REPLY_BYTES, desired, association, contexts)
        }
        TRANSLATE_SIDS => {
            let (context, sid) = translate::request_ndr32(payload)?;
            let mut response = policy::reply(24);
            translate::append_success_ndr32(&mut response.body, lookup(c, contexts, context, sid)?);
            response
        }
        _ => return None,
    };
    policy::echo_call_id(&mut response, payload);
    Some(response)
}

fn translate_sid(c: &Ctx, payload: &[u8], contexts: &LsarpcPolicies) -> Option<Response> {
    let (context, sid) = translate::request(payload)?;
    let mut response = policy::reply(24);
    translate::append_success(&mut response.body, lookup(c, contexts, context, sid)?);
    Some(response)
}

fn lookup<'a>(
    c: &'a Ctx,
    contexts: &LsarpcPolicies,
    context: LsarpcPolicyContext,
    sid: &[u8],
) -> Option<&'a Translation> {
    if !contexts.contains(&context) {
        return None;
    }
    let catalog =
        c.p.native
            .as_ref()?
            .object_namespace
            .policy_lookup_names
            .as_ref()?;
    let subject = c.p.objects.primary_token_subject()?;
    catalog.translate(&subject, sid)
}

fn open(payload: &[u8], association: ObjId, contexts: &LsarpcPolicies) -> Option<Response> {
    if payload.len() != OPEN_REQUEST_BYTES {
        return None;
    }
    let desired = policy::open_access(payload)?;
    Some(open_reply(OPEN_REPLY_BYTES, desired, association, contexts))
}

fn open_reply(
    size: usize,
    desired: u32,
    association: ObjId,
    contexts: &LsarpcPolicies,
) -> Response {
    let result = match desired {
        0 => Err(STATUS_INVALID_PARAMETER),
        POLICY_LOOKUP_NAMES => contexts
            .reserve(association)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES),
        _ => Err(STATUS_ACCESS_DENIED),
    };
    let mut response = policy::reply(size);
    match result {
        Ok(context) => {
            response.body[CONTEXT_OFFSET..STATUS_OFFSET].copy_from_slice(&context);
            response.policy = Change::Open(context);
        }
        Err(status) => put_word(&mut response.body, STATUS_OFFSET, status),
    }
    response
}
