//! Measured no-impersonation thread-token opening, from build29683 captures.
use super::query::write_guard_result;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

pub(super) fn open_thread(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    write_guard_result(c, result)
}

pub(super) fn open_thread_ex(c: &mut Ctx) -> ApiResult {
    let qualified = c.arch() == WinArch::Arm64
        && c.p.native.as_ref().is_some_and(|runtime| {
            let version = &runtime.version;
            (version.major, version.minor, version.build) == (10, 0, 29708)
                && runtime.object_namespace.native_machine == Some(0xaa64)
        });
    if !qualified {
        return Err(c.unsupported("unmeasured installed NtOpenThreadTokenEx profile"));
    }
    let (handle, _desired, _open_as_self, _attributes, _output) =
        (c.ptr(0)?, c.u32(1)?, c.u32(2)?, c.u32(3)?, c.ptr(4)?);
    // With no impersonation token, the qualified native ABI leaves the
    // caller's output alone, including when it points to null.
    Flow::ret(absent_thread_token(c, handle).into())
}

fn checked(c: &mut Ctx) -> ApiResult {
    let (handle, _desired, _self, output) = (c.ptr(0)?, c.u32(1)?, c.u32(2)?, c.ptr(3)?);
    let status = absent_thread_token(c, handle);
    if c.arch() == WinArch::X86 && output != 0 {
        // Captured WoW64 initializes the private native handle to zero and
        // copies it back even on kernel failure. Copy faults override status;
        // writable guards consume once; read-only guards remain armed.
        // Its null-output test skips this caller copy entirely.
        c.mem().w32(output, 0)?;
    }
    Flow::ret(status.into())
}
fn absent_thread_token(c: &Ctx, handle: u64) -> u32 {
    if handle == c.arch().ptr(u64::MAX) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if handle != c.arch().ptr(u64::MAX - 1) {
        match c.p.objects.get(handle) {
            None => return STATUS_INVALID_HANDLE,
            Some(Object::Thread { .. }) => {
                // Captured current/local/ended threads accept either query
                // information or query-limited-information, including aliases.
                if c.p.objects.access(handle).unwrap_or(0) & 0x840 == 0 {
                    return STATUS_ACCESS_DENIED;
                }
            }
            Some(_) => return STATUS_OBJECT_TYPE_MISMATCH,
        }
    }
    // This kernel personality has no thread-token attachment service.
    // Its new and ended threads have no impersonation token.
    // NtSetInformationThread class5 and impersonation-producing services
    // remain explicit unsupported boundaries, rather than changing this state.
    STATUS_NO_TOKEN
}
