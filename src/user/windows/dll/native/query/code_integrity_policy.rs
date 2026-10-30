//! Fixed policy record, with independently observed native and WoW64 copies.

use super::{ApiErr, ApiResult, Ctx, Flow, Mem, STATUS_INFO_LENGTH_MISMATCH, STATUS_NO_MEMORY};
use super::{STATUS_ACCESS_VIOLATION, return_length};

const BYTES: u32 = 32;

fn record(c: &Ctx) -> Result<[u8; 32], ApiErr> {
    let Some(runtime) = c.p.native.as_ref() else {
        return Err(
            c.unsupported("SystemCodeIntegrityPolicyInformation requires selected native inputs")
        );
    };
    runtime
        .code_integrity_policy
        .as_ref()
        .copied()
        .map_err(|reason| {
            c.unsupported(format!(
                "SystemCodeIntegrityPolicyInformation unavailable: {reason}"
            ))
        })
}

pub(super) fn query(c: &mut Ctx, output: u64, length: u32, returned: u64) -> ApiResult {
    // Native64 probes the entire declared output span and optional ULONG
    // before dispatch. Larger buffers retain every byte after this record.
    if length < BYTES {
        return_length(c, returned, BYTES)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    c.mem().wr(output, &record(c)?)?;
    return_length(c, returned, BYTES)?;
    Flow::ret(0)
}

pub(super) fn wow64(c: &mut Ctx, output: u64, length: u32, returned: u64) -> ApiResult {
    let result = wow64_copy(c, output, length, returned);
    super::write_guard_result(c, result)
}

fn wow64_copy(c: &mut Ctx, output: u64, length: u32, returned: u64) -> ApiResult {
    if output == 0 && length != 0 {
        return_length(c, returned, 0)?;
        return Flow::ret(STATUS_ACCESS_VIOLATION.into());
    }
    // Model the conversion workspace using the guest's configured budget.
    // Never allocate host memory proportional to an untrusted caller length.
    if u64::from(length) > c.p.cfg.arena_bytes.min(c.p.vm.high()) {
        return Flow::ret(STATUS_NO_MEMORY.into());
    }
    if length < BYTES {
        return_length(c, returned, BYTES)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    // WoW64 copies only 32 bytes, without native ULONG alignment or a probe
    // of the declared tail. A failed later ReturnLength store retains them.
    c.mem().wr(output, &record(c)?)?;
    return_length(c, returned, BYTES)?;
    Flow::ret(0)
}
