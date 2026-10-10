//! Hotpatch availability for the current kernel without admitted patching.
//! Class 9's disabled native64/WoW64 profile is experimentally recorded in
//! docs/specifications/windows/native-hotpatch-check. Mutating operations
//! remain explicit unsupported paths and never call a host NT service.
use super::query::{guard_result, probe_write};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
};

pub(super) fn manage(c: &mut Ctx) -> ApiResult {
    let result = check(c);
    match guard_result(c, result) {
        // Synthetic NTDLL imports share kernel status semantics with admitted
        // native service stubs; a query probe fault is not user-mode SEH.
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        result => result,
    }
}
fn check(c: &mut Ctx) -> ApiResult {
    let (class, info, length, returned) = (c.u32(0)?, c.ptr(1)?, c.u32(2)?, c.ptr(3)?);
    if class != 9 {
        return Err(c.unsupported(format!("hotpatch operation class {class}")));
    }
    let copied = if c.arch() == WinArch::X86 {
        // WoW64 rejects length before touching either pointer, then captures
        // input. Its copy-out occurs after the native kernel result even when
        // that result is an error; ReturnLength aliases are overwritten.
        if length != 8 {
            return Flow::ret(STATUS_INVALID_PARAMETER.into());
        }
        Some(c.mem().bytes(info, 8)?)
    } else {
        // Disabled native64 entry never touches or validates the information
        // buffer, length, Version or Flags. Do not copy a host enabled state.
        None
    };
    // Measured disabled profile requires this output, despite the optional
    // declaration in phnt. NULL and unwritable destinations return a fault.
    let kernel = write_returned(c, returned);
    // Consume a kernel guard fault before WoW64's unconditional copy-back.
    // A later copy-back fault supersedes that kernel status, as observed with
    // read-only information and a guarded ReturnLength destination.
    let kernel = guard_result(c, kernel);
    if let Some(data) = copied {
        c.mem().wr(info, &data)?;
    }
    kernel
}
fn write_returned(c: &Ctx, returned: u64) -> ApiResult {
    probe_write(c, returned, 4)?;
    c.mem().w32(returned, 0)?;
    Flow::ret(STATUS_NOT_SUPPORTED.into())
}
