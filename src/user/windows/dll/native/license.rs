//! Read-only queries for selected installed Windows startup policies.

use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::policy::{self, APP_SERVER_MODE_NAME, DEVICE_FAMILY_NAME, Error};

pub(super) fn query_startup_value(c: &mut Ctx) -> ApiResult {
    let result = query(c);
    super::query::guard_result(c, result)
}

fn query(c: &mut Ctx) -> ApiResult {
    let Some(runtime) = c.p.native.as_ref() else {
        return Err(c.unsupported("NtQueryLicenseValue requires installed Windows inputs"));
    };
    let version = &runtime.version;
    if (version.major, version.minor, version.build) != (10, 0, 29708) {
        return Err(c.unsupported("unmeasured NtQueryLicenseValue profile"));
    }

    let (name, kind, data, capacity, required) =
        (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?, c.u32(3)?, c.ptr(4)?);
    if name == 0 || required == 0 || (data == 0 && capacity != 0) {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }

    const NAME_BYTES: usize = 2 * APP_SERVER_MODE_NAME.len();
    let mut descriptor = [0; 16];
    c.mem().rd(name, &mut descriptor)?;
    let length = usize::from(u16::from_le_bytes([descriptor[0], descriptor[1]]));
    let selected = [DEVICE_FAMILY_NAME, APP_SERVER_MODE_NAME]
        .into_iter()
        .find(|candidate| 2 * candidate.len() == length)
        .ok_or_else(|| c.unsupported("NtQueryLicenseValue startup name is not captured"))?;

    if selected == APP_SERVER_MODE_NAME
        && (c.arch() != WinArch::Arm64 || runtime.object_namespace.native_machine != Some(0xaa64))
    {
        return Err(c.unsupported("NtQueryLicenseValue AppServerMode profile is not captured"));
    }

    let buffer = u64::from_le_bytes(descriptor[8..].try_into().expect("UNICODE_STRING buffer"));
    let mut bytes = [0; NAME_BYTES];
    c.mem().rd(buffer, &mut bytes[..length])?;
    let units: Vec<_> = bytes[..length]
        .chunks_exact(2)
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
        .collect();
    if !units.iter().copied().eq(selected.encode_utf16()) {
        if !String::from_utf16(&units).is_ok_and(|name| name.eq_ignore_ascii_case(selected)) {
            return Err(c.unsupported("NtQueryLicenseValue startup name is not captured"));
        }
        if selected == DEVICE_FAMILY_NAME {
            c.mem().w32(required, 0)?;
        }
        return Flow::ret(STATUS_OBJECT_NAME_NOT_FOUND.into());
    }

    let catalog = runtime.policy_catalog.as_ref().map_err(|reason| {
        c.unsupported(format!("installed startup policy is unavailable: {reason}"))
    })?;
    let value = match policy::startup_dword(catalog, &units) {
        Ok(value) => value,
        Err(Error::Status(status)) => {
            if status == STATUS_OBJECT_NAME_NOT_FOUND && selected == DEVICE_FAMILY_NAME {
                c.mem().w32(required, 0)?;
            }
            return Flow::ret(status.into());
        }
        Err(Error::Unsupported(reason)) => return Err(c.unsupported(reason)),
    };
    let size = value.len() as u32;
    let fits = capacity >= size;
    super::query::probe_write(c, required, 4)?;
    if kind != 0 {
        super::query::probe_write(c, kind, 4)?;
    }
    if fits {
        super::query::probe_write(c, data, value.len())?;
    }
    c.mem().w32(required, size)?;
    if kind != 0 {
        c.mem().w32(kind, 4)?;
    }
    if !fits {
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    c.mem().wr(data, &value)?;
    Flow::ret(STATUS_SUCCESS.into())
}
