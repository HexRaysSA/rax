//! No-registration event validation in the dormant guest tracing namespace.
//!
//! Independent ARM64/x64/WoW64 observations are retained under
//! `docs/specifications/windows/native-trace-event/`. Guest tracing controllers
//! cannot enable sessions in the current kernel. A successful argument capture
//! therefore reports STATUS_WMI_ALREADY_DISABLED, including for registered
//! providers. No guest pointer or event is forwarded to host tracing.

use super::query::guard_result;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;

pub(super) fn event(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    guard_result(c, result)
}

fn checked(c: &mut Ctx) -> ApiResult {
    let flags = c.u32(1)?;
    // PHNT ETW_NT_TRACE_TYPE_MASK. Low-byte and high-word flags do not
    // change no-registration validation in any independently observed caller.
    let kind = flags & 0xff00;
    if kind == 0 || kind > 0x900 || (kind == 0x900 && c.arch() == WinArch::X86) {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if kind != 0x700 {
        return Err(c.unsupported(format!("NtTraceEvent flags {flags:#x}")));
    }
    let (provider, _field_size, fields) = (c.ptr(0)?, c.u32(2)?, c.ptr(3)?);
    if provider == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    // The native kernel checks both ULONG alignments before visiting fields,
    // and only reads the provider after the complete fixed fields record.
    if provider % 4 != 0 || fields % 4 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    // FieldSize is ignored for this mode, even zero and UINT32_MAX. Dormant
    // lookup does not dereference nested descriptors or their payload pointers.
    let _ = c.mem().bytes(fields, 120)?;
    let _ = c.mem().bytes(provider, 16)?;
    Flow::ret(STATUS_WMI_ALREADY_DISABLED.into())
}
