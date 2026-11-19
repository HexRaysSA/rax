//! The observed NDR64 request and successful reply for one primary account SID.

use crate::user::windows::object_namespace::policy_lookup::{Name, PrimaryAccount};
use crate::user::windows::objects::LsarpcPolicyContext;
use crate::user::windows::security;

const SID_AT: usize = 128;
const DOMAIN_LIMIT: u32 = 32;
const SID_TYPE_USER: u32 = 1;
const REVISION: u32 = 2;

fn read_u64(request: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(request[at..at + 8].try_into().expect("checked request"))
}

pub(super) fn request(payload: &[u8]) -> Option<(LsarpcPolicyContext, &[u8])> {
    if payload.len() < SID_AT
        || payload[24..64].iter().any(|&byte| byte != 0)
        || payload[84..88] != [0; 4]
        || read_u64(payload, 88) != 1
        || read_u64(payload, 96) == 0
        || read_u64(payload, 104) != 1
        || read_u64(payload, 112) == 0
    {
        return None;
    }
    let sid = security::sid(&payload[SID_AT..])?;
    let end = SID_AT + sid.len();
    let revision = end.next_multiple_of(8) + 24;
    if read_u64(payload, 120) != u64::from(sid[1])
        || payload.len() != revision + 4
        || payload[end..revision].iter().any(|&byte| byte != 0)
        || payload[revision..] != REVISION.to_le_bytes()
    {
        return None;
    }
    let context = payload[64..84].try_into().expect("checked context extent");
    Some((context, sid))
}

fn u32_field(body: &mut Vec<u8>, value: u32) {
    body.extend_from_slice(&value.to_le_bytes());
}

fn u64_field(body: &mut Vec<u8>, value: u64) {
    body.resize(body.len().next_multiple_of(8), 0);
    body.extend_from_slice(&value.to_le_bytes());
}

fn name_header(body: &mut Vec<u8>, name: &Name, referent: u64) {
    body.resize(body.len().next_multiple_of(8), 0);
    body.extend_from_slice(&(name.units.len() as u16 * 2).to_le_bytes());
    body.extend_from_slice(&(name.maximum_units * 2).to_le_bytes());
    u64_field(body, referent);
}

fn name_buffer(body: &mut Vec<u8>, name: &Name) {
    u64_field(body, u64::from(name.maximum_units));
    u64_field(body, 0);
    u64_field(body, name.units.len() as u64);
    for unit in &name.units {
        body.extend_from_slice(&unit.to_le_bytes());
    }
}

pub(super) fn append_success(body: &mut Vec<u8>, account: &PrimaryAccount) {
    // One referenced domain and its deferred name and SID.
    u64_field(body, 0x20000);
    u32_field(body, 1);
    u64_field(body, 0x20004);
    u32_field(body, DOMAIN_LIMIT);
    u64_field(body, 1);
    name_header(body, &account.domain, 0x20008);
    u64_field(body, 0x2000c);
    name_buffer(body, &account.domain);
    u64_field(body, u64::from(account.domain_sid[1]));
    body.extend_from_slice(&account.domain_sid);

    // One translated name, bound to the first referenced domain.
    u32_field(body, 1);
    u64_field(body, 0x20010);
    u64_field(body, 1);
    u32_field(body, SID_TYPE_USER);
    name_header(body, &account.account, 0x20014);
    u32_field(body, 0); // DomainIndex
    u32_field(body, 0); // Flags
    name_buffer(body, &account.account);
    body.resize(body.len().next_multiple_of(8), 0);
    u32_field(body, 1); // MappedCount
    u32_field(body, 0); // STATUS_SUCCESS
    body.resize(body.len() + 32, 0);
}
