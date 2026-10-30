//! Opaque class189 bytes; native64 and WoW64 forward both caller destinations.

use super::{ApiErr, ApiResult, Ctx, Flow, Mem, STATUS_INFO_LENGTH_MISMATCH, return_length};
use std::sync::Arc;

fn record(c: &Ctx) -> Result<Arc<[u8]>, ApiErr> {
    let Some(runtime) = c.p.native.as_ref() else {
        return Err(c.unsupported(
            "SystemCodeIntegrityPoliciesFullInformation requires selected native inputs",
        ));
    };
    runtime
        .code_integrity_policies
        .as_ref()
        .cloned()
        .map_err(|reason| {
            c.unsupported(format!(
                "SystemCodeIntegrityPoliciesFullInformation unavailable: {reason}"
            ))
        })
}

pub(super) fn query(c: &mut Ctx, output: u64, length: u32, returned: u64) -> ApiResult {
    // All measured process ABIs probe the entire declared output span and
    // optional ReturnLength before class dispatch. There is no WoW64 conversion
    // workspace or copy-before-ReturnLength-probe path for this opaque class.
    let bytes = record(c)?;
    let required = u32::try_from(bytes.len())
        .map_err(|_| c.unsupported("captured code integrity policies exceed the ULONG length"))?;
    if length < required {
        return_length(c, returned, required)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    c.mem().wr(output, &bytes)?;
    return_length(c, returned, required)?;
    Flow::ret(0)
}
