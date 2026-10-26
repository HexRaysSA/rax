//! Measured query validation and zero-before-copy publication on admitted builds.
use super::*;
use crate::user::mm::PAGE_SIZE;

pub(crate) fn query(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    match super::super::query::write_guard_result(c, result) {
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        result => result,
    }
}

fn checked(c: &mut Ctx) -> ApiResult {
    if !crate::user::windows::nls::supports_startup_profile(&c.p.cfg.version) {
        return Err(c.unsupported("NtGetMUIRegistryInfo native build profile is unmeasured"));
    }
    let (flags, size, output) = (c.u32(0)?, c.ptr(1)?, c.ptr(2)?);
    if flags & !0x0b == 0 && flags & 0x0a != 0 {
        return Err(
            c.unsupported("NtGetMUIRegistryInfo guest cache clear/commit is not implemented")
        );
    }
    if size == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    // The native entry captures the unaligned ULONG before validating flags
    // or the relationship between buffer presence and input length.
    let length = c.mem().u32(size)?;
    if flags & !0x0b != 0 || (output == 0) != (length == 0) {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let bytes = c.p.nls.as_ref().and_then(|nls| nls.mui()).ok_or_else(|| {
        c.unsupported("NtGetMUIRegistryInfo immutable query data was not selected")
    })?;
    let required = bytes.len() as u32;
    c.mem().w32(size, required)?;
    if output == 0 {
        return Flow::ret(STATUS_SUCCESS.into());
    }
    if length < required {
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    // The measured kernel first zeros the complete caller-supplied extent,
    // then copies the actual data. A fault can retain a zeroed prefix, even
    // when Data aliases DataSize. O(B) work, O(PAGE_SIZE) fixed scratch; a huge
    // requested length stops at the first inaccessible guest page.
    let zeros = [0u8; PAGE_SIZE as usize];
    let mut written = 0u64;
    while written < u64::from(length) {
        let address = output.checked_add(written).ok_or_else(|| {
            ApiErr::Fault(crate::user::windows::memory::MemFault {
                addr: output,
                write: true,
            })
        })?;
        let count = (PAGE_SIZE - address % PAGE_SIZE).min(u64::from(length) - written) as usize;
        c.mem().wr(address, &zeros[..count])?;
        written += count as u64;
    }
    c.mem().wr(output, &bytes)?;
    Flow::ret(STATUS_SUCCESS.into())
}
