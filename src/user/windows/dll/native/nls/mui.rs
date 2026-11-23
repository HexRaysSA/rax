//! Measured query validation and zero-before-copy publication on admitted builds.
use super::*;
use crate::user::mm::PAGE_SIZE;

pub(in super::super) fn ui_language_commitment(c: &mut Ctx) -> ApiResult {
    let status = c
        .p
        .nls
        .as_ref()
        .and_then(|nls| nls.ui_language_commitment)
        .ok_or_else(|| c.unsupported("installed UI-language commitment status is unavailable"))?;
    Flow::ret(status.into())
}

pub(in super::super) fn installed_ui_language(c: &mut Ctx) -> ApiResult {
    let language =
        c.p.nls
            .as_ref()
            .and_then(|nls| nls.installed_ui_language)
            .ok_or_else(|| c.unsupported("installed UI-language identifier is unavailable"))?;
    let output = c.ptr(0)?;
    // AddressSpace validates the whole word before writing either byte.
    // The observed WoW64 call accepts an unaligned LANGID.
    let result = c
        .mem()
        .w16(output, language.id)
        .map_err(ApiErr::from)
        .and_then(|()| Flow::ret(STATUS_SUCCESS.into()));
    if language.guard_before_write_access {
        fault_status(super::super::query::guard_result(c, result))
    } else {
        write_status(c, result)
    }
}

pub(crate) fn query(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    write_status(c, result)
}

fn write_status(c: &mut Ctx, result: ApiResult) -> ApiResult {
    fault_status(super::super::query::write_guard_result(c, result))
}

fn fault_status(result: ApiResult) -> ApiResult {
    match result {
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        result => result,
    }
}

fn checked(c: &mut Ctx) -> ApiResult {
    use crate::user::windows::nls;

    let version = &c.p.cfg.version;
    let machine = c.p.object_namespace.native_machine;
    let profile = nls::mui_profile(version, machine, c.arch())
        .ok_or_else(|| c.unsupported("NtGetMUIRegistryInfo native build profile is unmeasured"))?;
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
    if profile == nls::MuiProfile::ProbeDestination {
        // Validate the whole destination after publishing the requirement.
        // A fault leaves the destination as it was after size publication.
        super::super::query::probe_write(c, output, length as usize)?;
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
