//! Native key-body tags: capture first, then replace guest-owned object state.
use super::{Checked, finish, key, status};
use crate::user::windows::hle::{ApiResult, Ctx};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS, STATUS_SUCCESS,
};

pub(in super::super) fn set_key(c: &mut Ctx) -> ApiResult {
    let result = set_checked(c);
    finish(c, result)
}

fn set_checked(c: &mut Ctx) -> Checked<u32> {
    let (handle, class, input, length) = (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.u32(3)?);
    if class >= 7 {
        return status(STATUS_INVALID_INFO_CLASS);
    }
    if class != 5 {
        return Err(c
            .unsupported(&format!(
                "uncaptured registry key set information class {class}"
            ))
            .into());
    }
    if length != 4 {
        return status(STATUS_INFO_LENGTH_MISMATCH);
    }
    // Native controls admit unaligned/read-only input and consume a guard
    // before checking the handle. Only the captured low 16 bits replace tags.
    let tags = c.mem().u32(input)? as u16;
    key(c, handle, false)?;
    // Unlike querying tags, setting them needs no granted access bits. State
    // belongs to the key body, so duplicates share it and separate opens do not.
    if !c.p.objects.set_registry_tags(handle, tags) {
        return status(STATUS_INVALID_HANDLE);
    }
    Ok(STATUS_SUCCESS)
}
