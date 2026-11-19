//! Change only the selected guest token using the installed NT ABI.

use super::query::write_guard_result;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use crate::user::windows::security::Privilege;
use crate::user::windows::security::token::privileges::{
    Change, ENTRY_BYTES, HEADER_BYTES, record_bytes, sizes,
};

const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;

pub(super) fn privileges(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    write_guard_result(c, result)
}

fn checked(c: &mut Ctx) -> ApiResult {
    let (token, disable_all, input, capacity, previous, returned) = (
        c.ptr(0)?,
        c.u32(1)? as u8 != 0,
        c.ptr(2)?,
        c.u32(3)? as usize,
        c.ptr(4)?,
        c.ptr(5)?,
    );

    let requested = if disable_all {
        None
    } else {
        if input == 0 {
            return Flow::ret(STATUS_INVALID_PARAMETER.into());
        }
        let count = c.mem().u32(input)? as usize;
        let Some((_, data_bytes)) = sizes(count) else {
            return Flow::ret(STATUS_INVALID_PARAMETER.into());
        };
        let bytes = c
            .mem()
            .bytes(input + HEADER_BYTES as u64, data_bytes - HEADER_BYTES)?;
        Some(
            bytes
                .chunks_exact(ENTRY_BYTES)
                .map(|bytes| Privilege {
                    luid: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                    attributes: u32::from_le_bytes(bytes[8..].try_into().unwrap()),
                })
                .collect::<Vec<_>>(),
        )
    };

    if token == c.arch().ptr(u64::MAX) || token == c.arch().ptr(u64::MAX - 1) {
        return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
    }
    let Some(object) = c.p.objects.get(token) else {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    };
    let grants = TOKEN_ADJUST_PRIVILEGES | if previous != 0 { TOKEN_QUERY } else { 0 };
    let subject = match object {
        Object::PrimaryToken
        | Object::ImpersonationToken(_)
        | Object::GuestImpersonationToken { .. }
            if c.p.objects.access(token).unwrap_or(0) & grants != grants =>
        {
            return Flow::ret(STATUS_ACCESS_DENIED.into());
        }
        Object::PrimaryToken => {
            c.p.objects
                .primary_token_subject()
                .ok_or_else(|| c.unsupported("primary token privileges are not captured"))?
        }
        Object::ImpersonationToken(subject) | Object::GuestImpersonationToken { subject, .. } => {
            subject.clone()
        }
        Object::Opaque("Token") => {
            return Err(c.unsupported("opaque token has no guest privilege state"));
        }
        _ => return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into()),
    };

    let change = Change::plan(&subject.privileges, requested.as_deref());
    let previous_bytes = record_bytes(change.previous.len());
    if previous != 0 {
        // ReturnLength is published first, including when both pointers alias.
        // Keep each result within the caller's declared destination capacity.
        let required = if capacity < previous_bytes {
            change.required.max(previous_bytes)
        } else {
            change.required
        };
        c.mem().w32(returned, required as u32)?;
        if capacity < required {
            return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
        }
    }

    let modified = if change.changed && subject.statistics.is_some() {
        let Some(id) = c.p.objects.next_token_modified_id() else {
            return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
        };
        Some(id)
    } else {
        None
    };
    let publish = if previous != 0 {
        let mut frame = vec![0; previous_bytes];
        frame[..HEADER_BYTES].copy_from_slice(&(change.previous.len() as u32).to_le_bytes());
        for (record, entry) in frame[HEADER_BYTES..]
            .chunks_exact_mut(ENTRY_BYTES)
            .zip(&change.previous)
        {
            record[..8].copy_from_slice(&entry.luid.to_le_bytes());
            record[8..].copy_from_slice(&entry.attributes.to_le_bytes());
        }
        c.mem().wr(previous, &frame)
    } else {
        Ok(())
    };
    if change.changed {
        let mut subject = (*subject).clone();
        // After the adjustment pass, a previous-state store can fault. The
        // observed guard failure restores privilege bits but exposes ModifiedId.
        if publish.is_ok() {
            subject.privileges = change.privileges;
        }
        if let (Some(statistics), Some(id)) = (subject.statistics, modified) {
            subject.statistics =
                Some(statistics.with_privilege_change(subject.privileges.len() as u32, id));
        }
        if publish.is_ok() || modified.is_some() {
            c.p.objects.set_token_subject(token, subject);
        }
    }
    publish?;
    let status = if change.missing {
        STATUS_NOT_ALL_ASSIGNED
    } else {
        STATUS_SUCCESS
    };
    Flow::ret(status.into())
}
