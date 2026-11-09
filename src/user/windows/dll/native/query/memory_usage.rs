//! Exact-size, pointer-width-independent memory telemetry with late ReturnLength.
use super::{guard_result, probe_write, return_length};
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT, STATUS_INFO_LENGTH_MISMATCH,
};

pub(super) fn information(c: &mut Ctx) -> ApiResult {
    information_with(c, |c| {
        c.p.vm
            .memory_usage()
            .map(|usage| usage.to_bytes())
            .map_err(|error| c.unsupported(format!("memory usage accounting: {error:?}")))
    })
}

pub(crate) fn information_with(
    c: &mut Ctx,
    snapshot: impl FnOnce(&Ctx) -> Result<[u8; 56], ApiErr>,
) -> ApiResult {
    let result = checked(c, snapshot);
    match guard_result(c, result) {
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        result => result,
    }
}

fn checked(c: &mut Ctx, snapshot: impl FnOnce(&Ctx) -> Result<[u8; 56], ApiErr>) -> ApiResult {
    let (class, output, bytes, returned) = (c.u32(0)?, c.ptr(1)?, c.u32(2)?, c.ptr(3)?);
    if class != 182 {
        return Err(c.unsupported(format!("memory usage query class {class}")));
    }
    if bytes != 0 {
        if output % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        probe_write(c, output, bytes as usize)?;
    }
    if returned != 0 {
        // Native ReturnLength permits unaligned DWORD storage, but probes its
        // whole span before either length failure or output publication.
        probe_write(c, returned, 4)?;
    }
    if bytes != 56 {
        return_length(c, returned, 56)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    let data = snapshot(c)?;
    c.mem().wr(output, &data)?;
    // Aliases observe this DWORD after the complete memory record.
    return_length(c, returned, 56)?;
    Flow::ret(0)
}
