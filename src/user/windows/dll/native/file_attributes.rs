//! Read-only metadata for authorized mapped files and selected installed DLLs.
//! Guest memory is captured locally; host adapters receive only resolved paths.

pub(super) mod attributes;
mod metadata;
pub(super) mod path;
#[cfg(unix)]
pub(super) mod posix;

use super::named_object::{Checked, finish, status};
use super::query::probe_write;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_DATATYPE_MISALIGNMENT, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};

pub(super) fn basic(c: &mut Ctx) -> ApiResult {
    query(c, false)
}

pub(super) fn full(c: &mut Ctx) -> ApiResult {
    query(c, true)
}

fn query(c: &mut Ctx, full: bool) -> ApiResult {
    let result = checked(c, full);
    finish(c, result)
}

fn checked(c: &mut Ctx, full: bool) -> Checked<u32> {
    let address = c.ptr(0)?;
    let output = c.ptr(1)?;
    let wow = c.arch() == WinArch::X86;
    let converted = if wow {
        Some(attributes::capture(c, address, true)?)
    } else {
        None
    };
    let bytes = if full {
        56
    } else if wow {
        36
    } else {
        40
    };
    if !wow && output % 8 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    probe_write(c, output, bytes)?;
    let attrs = match converted {
        Some(attrs) => attrs,
        None => attributes::capture(c, address, false)?,
    };
    let Some(attrs) = attrs else {
        return status(STATUS_INVALID_PARAMETER);
    };
    let name = attributes::validate(c, &attrs)?;
    let resolved = path::resolve(c, &attrs, name.as_deref())?;
    let info = metadata::query(c, &resolved, attrs.flags & 0x1000 != 0)?;
    let mut raw = [0u8; 56];
    for (field, value) in raw[..32].chunks_exact_mut(8).zip(info.times) {
        field.copy_from_slice(&value.to_le_bytes());
    }
    let attribute = if full {
        raw[32..40].copy_from_slice(&info.allocation.to_le_bytes());
        raw[40..48].copy_from_slice(&info.size.to_le_bytes());
        48
    } else {
        32
    };
    raw[attribute..attribute + 4].copy_from_slice(&info.attributes.to_le_bytes());
    c.mem().wr(output, &raw[..bytes])?;
    Ok(STATUS_SUCCESS)
}
