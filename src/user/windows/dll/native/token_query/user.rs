//! SID_AND_ATTRIBUTES query results and the measured WoW64 conversion phases.
use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::hle::ApiErr;

pub(super) fn wow64_widening(class: u32) -> u32 {
    match class {
        TOKEN_USER | TOKEN_INTEGRITY_LEVEL => 8,
        class if DefaultsClass::from_raw(class).is_some() => 4,
        _ => 0,
    }
}

pub(super) fn preflight(
    c: &mut Ctx,
    output: u64,
    length: u32,
    returned: u64,
    widening: u32,
) -> Result<Option<u32>, ApiErr> {
    if output != 0 {
        // Native scratch widens the caller record before conversion. Reuse the
        // personality's no-paging-file budget; no host-sized allocation or
        // guest-visible scratch mapping is needed. Heap failure sets LastError.
        let capture = ((u64::from(length) + u64::from(widening) + 15) & !15) + 16;
        let charge = (capture + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if charge > c.p.vm.commit_limit() - c.p.vm.committed_bytes()
            || charge > c.p.vm.high() - c.p.vm.low()
        {
            c.set_last_error(8)?;
            return Ok(Some(STATUS_NO_MEMORY));
        }
    } else if length != 0 {
        // A NULL caller buffer bypasses scratch. Native output probing fails
        // before handle checks; the converter still narrows its zero
        // private required length. ReturnLength itself is optional in WoW64.
        if returned != 0 {
            c.mem().w32(returned, 0u32.wrapping_sub(widening))?;
        }
        return Ok(Some(STATUS_ACCESS_VIOLATION));
    }
    Ok(None)
}

pub(super) fn handle_error(c: &mut Ctx, class: u32, returned: u64, status: u32) -> ApiResult {
    let widening = wow64_widening(class);
    if c.arch() == WinArch::X86 && widening != 0 && returned != 0 {
        c.mem().w32(returned, 0u32.wrapping_sub(widening))?;
    }
    if c.arch() == WinArch::X86 && class == 10 && returned != 0 {
        c.mem().w32(returned, 0)?;
    }
    Flow::ret(status.into())
}

pub(super) fn publish(
    c: &mut Ctx,
    sid: &[u8],
    attributes: u32,
    output: u64,
    length: u32,
    returned: u64,
) -> ApiResult {
    let header = 2 * c.psize();
    // Subject selection validates a complete revision1 SID:8+4*N bytes,N<=15.
    // Required size is therefore24..84(native64) or16..76(WoW64), within u32.
    let required = header as u32 + sid.len() as u32;
    let wow = c.arch() == WinArch::X86;
    if !wow {
        c.mem().w32(returned, required)?;
    }
    if length < required {
        if wow && returned != 0 {
            c.mem().w32(returned, required)?;
        }
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    if wow {
        // The SID copy precedes both header stores. Its short-copy head/tail
        // stores share the existing native copy plan; a fault preserves progress.
        super::bno_copy::copy(c, output + header, sid)?;
    } else {
        c.mem().wr(output + header, sid)?;
    }
    c.write_ptr(output, output + header)?;
    c.mem().w32(output + c.psize(), attributes)?;
    // Native64 header padding remains untouched. WoW64 publishes length last,
    // so its overlapping DWORD wins over a converted pointer or attribute.
    if wow && returned != 0 {
        c.mem().w32(returned, required)?;
    }
    Flow::ret(STATUS_SUCCESS.into())
}
