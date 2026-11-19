//! Class 52 reports policies configured by the guest process model.
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_DENIED, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_HANDLE,
    STATUS_OBJECT_TYPE_MISMATCH,
};
use crate::user::windows::objects::Object;

const DYNAMIC_CODE_POLICY: u32 = 2;
const SYSTEM_CALL_FILTER_POLICY: u32 = 11;

pub(super) fn query(c: &mut Ctx, process: u64, output: u64, length: u32) -> ApiResult {
    // The common process-query path already checked alignment and probed the
    // optional ReturnLength. This class never writes ReturnLength, on either
    // successful or failed queries, including aliases with the output record.
    // The outer query guard handler also visits a guarded flags destination
    // on another page, including READONLY|GUARD, as measured independently.
    if length != 8 {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    // Only the input policy word is captured before handle validation. A
    // readable selector may precede inaccessible output flags on another page.
    let policy = c.mem().u32(output)?;
    if process != c.arch().ptr(u64::MAX) {
        if process == c.arch().ptr(u64::MAX - 1) {
            return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
        }
        let Some(object) = c.p.objects.get(process) else {
            return Flow::ret(STATUS_INVALID_HANDLE.into());
        };
        let Object::Process { pid, .. } = object else {
            return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
        };
        if c.p.objects.access(process).unwrap_or(0) & (0x400 | 0x1000) == 0 {
            return Flow::ret(STATUS_ACCESS_DENIED.into());
        }
        if *pid != c.p.pid {
            return Err(c.unsupported("mitigation policy for an unmodeled peer process"));
        }
    }
    if !matches!(policy, DYNAMIC_CODE_POLICY | SYSTEM_CALL_FILTER_POLICY) {
        return Err(c.unsupported(format!("ProcessMitigationPolicy selector {policy}")));
    }
    // Guest creation permits dynamic code and installs the unfiltered native
    // service table. The model accepts no creation attribute or setter that
    // changes these two policies. Both selectors report the guest's own state.
    let flags = output.checked_add(4).ok_or(MemFault {
        addr: output,
        write: true,
    })?;
    c.mem().w32(flags, 0)?;
    Flow::ret(0)
}
