use super::{ApiResult, Ctx, Flow, Mem, STATUS_INFO_LENGTH_MISMATCH, return_length};
use crate::user::windows::native::SECURE_BOOT_POLICY_BYTES;

pub(super) fn query(c: &mut Ctx, output: u64, length: u32, returned: u64) -> ApiResult {
    let Some(runtime) = c.p.native.as_ref() else {
        return Err(
            c.unsupported("SystemSecureBootPolicyInformation requires selected native inputs")
        );
    };
    if !runtime.supports_secure_boot_policy(c.arch()) {
        return Err(c.unsupported("SystemSecureBootPolicyInformation copy profile is unmeasured"));
    }
    let bytes = SECURE_BOOT_POLICY_BYTES as u32;
    if length < bytes {
        return_length(c, returned, bytes)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    let record = runtime.secure_boot_policy.as_ref().map_err(|reason| {
        c.unsupported(format!(
            "SystemSecureBootPolicyInformation unavailable: {reason}"
        ))
    })?;
    c.mem().wr(output, record)?;
    return_length(c, returned, bytes)?;
    Flow::ret(0)
}
