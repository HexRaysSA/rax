//! Same-access duplication preserves the owned guest object, never a host HANDLE.
use super::query::{guard_result, probe_write};
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, Object};

pub(super) fn duplicate(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    guard_result(c, result)
}

fn process(c: &Ctx, handle: u64) -> Result<(), u32> {
    if handle == c.arch().ptr(CURRENT_PROCESS) {
        return Ok(());
    }
    match c.p.objects.get(handle) {
        Some(Object::Process { pid, .. }) if *pid == c.p.pid => {
            if c.p.objects.access(handle).unwrap_or(0) & 0x40 != 0 {
                Ok(())
            } else {
                Err(STATUS_ACCESS_DENIED)
            }
        }
        Some(Object::Process { .. }) => Err(STATUS_NOT_SUPPORTED),
        Some(_) => Err(STATUS_OBJECT_TYPE_MISMATCH),
        None => Err(STATUS_INVALID_HANDLE),
    }
}

fn checked(c: &mut Ctx) -> ApiResult {
    let (source_process, source, target_process, output, _desired, attributes, options) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.ptr(2)?,
        c.ptr(3)?,
        c.u32(4)?,
        c.u32(5)?,
        c.u32(6)?,
    );
    if options != 2 || attributes & !2 != 0 || output == 0 {
        return Err(c.unsupported("NtDuplicateObject options are not selected"));
    }
    for handle in [source_process, target_process] {
        if let Err(status) = process(c, handle) {
            if status == STATUS_NOT_SUPPORTED {
                return Err(c.unsupported("NtDuplicateObject foreign-process object ownership"));
            }
            return Flow::ret(status.into());
        }
    }
    if c.p.objects.get(source).is_none() {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    }
    probe_write(c, output, c.psize() as usize)?;
    let Some(duplicate) = c.p.objects.duplicate(source, attributes & 2 != 0) else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    if let Err(error) = c.write_ptr(output, duplicate.into()) {
        let _ = c.p.objects.close(duplicate.into());
        return Err(error.into());
    }
    Flow::ret(STATUS_SUCCESS.into())
}
