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
const QUERY_INFORMATION: u32 = 5;
const ACCOUNT_DOMAIN_INFORMATION: u16 = 5;
const DNS_DOMAIN_INFORMATION: u16 = 12;
const POLICY_VIEW_LOCAL_INFORMATION: u32 = 0x1;
const OPEN_WITHOUT_QOS_BYTES: usize = 124;
const OPEN_REQUEST_BYTES: usize = 136;
const OPEN_REPLY_BYTES: usize = 92;
const OPEN_NDR32_WITHOUT_QOS_BYTES: usize = 96;
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
        OPEN if matches!(payload.len(), OPEN_WITHOUT_QOS_BYTES | OPEN_REQUEST_BYTES) => open_reply(
            OPEN_REPLY_BYTES,
            policy::open_access(payload)?,
            payload.len() == OPEN_WITHOUT_QOS_BYTES,
            association,
            contexts,
        ),
        CLOSE => policy::close(payload, contexts)?,
        TRANSLATE_SIDS => translate_sid(c, payload, contexts)?,
        QUERY_INFORMATION => query_policy(c, payload, contexts, false)?,
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
        OPEN if matches!(
            payload.len(),
            OPEN_NDR32_WITHOUT_QOS_BYTES | OPEN_NDR32_REQUEST_BYTES
        ) =>
        {
            open_reply(
                OPEN_NDR32_REPLY_BYTES,
                policy::open_access_ndr32(payload)?,
                payload.len() == OPEN_NDR32_WITHOUT_QOS_BYTES,
                association,
                contexts,
            )
        }
        CLOSE => policy::close_ndr32(payload, contexts)?,
        TRANSLATE_SIDS => {
            let (context, sid) = translate::request_ndr32(payload)?;
            let mut response = policy::reply(24);
            translate::append_success_ndr32(&mut response.body, lookup(c, contexts, context, sid)?);
            response
        }
        QUERY_INFORMATION => query_policy(c, payload, contexts, true)?,
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

fn query_policy(
    c: &Ctx,
    payload: &[u8],
    contexts: &LsarpcPolicies,
    classic: bool,
) -> Option<Response> {
    let request_size = if classic { 86 } else { 88 };
    if payload.len() != request_size
        || payload[24..64].iter().any(|&byte| byte != 0)
        || payload[86..].iter().any(|&byte| byte != 0)
    {
        return None;
    }
    let class = u16::from_le_bytes([payload[84], payload[85]]);
    if !matches!(class, ACCOUNT_DOMAIN_INFORMATION | DNS_DOMAIN_INFORMATION) {
        return None;
    }
    let context = payload[64..84].try_into().expect("checked context extent");
    let result_offset = if classic { 28 } else { 32 };
    let mut response = policy::reply(result_offset + 4);
    if !contexts.grants(&context, POLICY_VIEW_LOCAL_INFORMATION) {
        let status = if contexts.contains(&context) {
            STATUS_ACCESS_DENIED
        } else {
            STATUS_INVALID_HANDLE
        };
        put_word(&mut response.body, result_offset, status);
        return Some(response);
    }
    let policy =
        c.p.native
            .as_ref()?
            .object_namespace
            .domain_policy
            .as_ref()?;
    // The non-null out pointer precedes the information union discriminant.
    let body = &mut response.body;
    body.resize(if classic { 32 } else { 40 }, 0);
    put_word(body, 24, 0x20000);
    put_word(body, result_offset, u32::from(class));
    match (class, classic) {
        (ACCOUNT_DOMAIN_INFORMATION, _) => {
            translate::append_account_domain(body, policy.account_domain.as_ref()?, classic);
        }
        (_, true) => {
            translate::name_header_ndr32(body, &policy.dns_name);
            body.resize(76, 0); // DNS name, forest name, GUID, SID.
            translate::name_buffer_ndr32(body, &policy.dns_name);
        }
        (_, false) => {
            translate::name_header(body, &policy.dns_name);
            body.resize(112, 0); // DNS name, forest name, GUID, SID.
            translate::name_buffer(body, &policy.dns_name);
        }
    }
    body.resize(body.len().next_multiple_of(4) + 4, 0); // NTSTATUS.
    Some(response)
}

fn lookup<'a>(
    c: &'a Ctx,
    contexts: &LsarpcPolicies,
    context: LsarpcPolicyContext,
    sid: &[u8],
) -> Option<&'a Translation> {
    if !contexts.grants(&context, POLICY_LOOKUP_NAMES) {
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

fn open_reply(
    size: usize,
    desired: u32,
    without_qos: bool,
    association: ObjId,
    contexts: &LsarpcPolicies,
) -> Response {
    let allowed = POLICY_LOOKUP_NAMES
        | if without_qos {
            POLICY_VIEW_LOCAL_INFORMATION
        } else {
            0
        };
    let result = match desired {
        0 => Err(STATUS_INVALID_PARAMETER),
        access if access & !allowed == 0 => contexts
            .reserve(association)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES),
        _ => Err(STATUS_ACCESS_DENIED),
    };
    let mut response = policy::reply(size);
    match result {
        Ok(context) => {
            response.body[CONTEXT_OFFSET..STATUS_OFFSET].copy_from_slice(&context);
            response.policy = Change::Open(context, desired);
        }
        Err(status) => put_word(&mut response.body, STATUS_OFFSET, status),
    }
    response
}
