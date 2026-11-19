//! Basic information for the selected local account-lookup endpoint.

use super::lsarpc::PORT_FLAGS;
use crate::user::windows::arch::WinArch;
use crate::user::windows::dll::native::query::{
    WOW64_LENGTH_FAILURE, probe_destinations, return_length, write_guard_result,
};
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::rpc_security::READ_CONTROL;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};

const BASIC_INFORMATION: u32 = 0;
const INVALID_CLASS: u32 = u32::MAX;

pub(super) fn query(c: &mut Ctx) -> ApiResult {
    let result = query_checked(c);
    write_guard_result(c, result)
}

fn query_checked(c: &mut Ctx) -> ApiResult {
    let (handle, class, output, capacity, returned) =
        (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.u32(3)?, c.ptr(4)?);
    let build = c.p.native.as_ref().map(|runtime| runtime.version.build);
    if build != Some(29708) {
        return Err(c.unsupported(format!(
            "native ALPC information profile is unavailable on {} build {build:?}",
            c.arch()
        )));
    }
    let wow64 = c.arch() == WinArch::X86;
    if wow64 && class != BASIC_INFORMATION {
        return if class == INVALID_CLASS {
            Flow::ret(STATUS_INVALID_INFO_CLASS.into())
        } else {
            Err(c.unsupported(format!("ALPC information class {class}")))
        };
    }

    if output == 0 {
        return failure(c, returned, wow64, STATUS_INVALID_PARAMETER);
    }
    // Native64 probes the full advertised range and the length pointer before
    // resolving the port. WoW64 uses a private native record and probes neither.
    if !wow64 && let Some(status) = probe_destinations(c, output, capacity, returned)? {
        return Flow::ret(status.into());
    }
    let endpoint = match c.p.objects.get(handle) {
        Some(Object::LpcPort(endpoint)) => endpoint,
        Some(_) => return failure(c, returned, wow64, STATUS_OBJECT_TYPE_MISMATCH),
        None => {
            let status = match handle {
                0 => STATUS_INVALID_PARAMETER,
                pseudo
                    if pseudo == c.arch().ptr(CURRENT_PROCESS)
                        || pseudo == c.arch().ptr(CURRENT_THREAD) =>
                {
                    STATUS_OBJECT_TYPE_MISMATCH
                }
                _ => STATUS_INVALID_HANDLE,
            };
            return failure(c, returned, wow64, status);
        }
    };
    if c.p.objects.access(handle).unwrap_or(0) & READ_CONTROL == 0 {
        return failure(c, returned, wow64, STATUS_ACCESS_DENIED);
    }
    match class {
        BASIC_INFORMATION => {}
        INVALID_CLASS => return Flow::ret(STATUS_INVALID_PARAMETER.into()),
        _ => return Err(c.unsupported(format!("ALPC information class {class}"))),
    }

    let context = endpoint
        .lsarpc_context()
        .ok_or_else(|| c.unsupported("ALPC information for an unselected port"))?;
    let required = 8 + c.psize() as usize;
    let status = if (capacity as usize) < required {
        STATUS_INFO_LENGTH_MISMATCH
    } else {
        let mut record = [0; 16];
        record[..4].copy_from_slice(&PORT_FLAGS.to_le_bytes());
        record[4..8].copy_from_slice(&1u32.to_le_bytes());
        record[8..12].copy_from_slice(&context.to_le_bytes());
        c.mem().wr(output, &record[..required])?;
        STATUS_SUCCESS
    };
    return_length(c, returned, required as u32)?;
    Flow::ret(status.into())
}

fn failure(c: &Ctx, returned: u64, wow64: bool, status: u32) -> ApiResult {
    if wow64 {
        return_length(c, returned, WOW64_LENGTH_FAILURE)?;
    }
    Flow::ret(status.into())
}
