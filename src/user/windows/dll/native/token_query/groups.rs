//! TOKEN_GROUPS publication from the modeled token's captured SID records.
use super::{Ctx, Flow, Mem, STATUS_BUFFER_TOO_SMALL, STATUS_SUCCESS, bno_copy};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::ApiResult;
use crate::user::windows::security::Group;

pub(super) fn publish(
    c: &mut Ctx,
    groups: &[Group],
    output: u64,
    length: u32,
    returned: u64,
) -> ApiResult {
    // The native capture admits at most 4096 complete SIDs of up to 68 bytes.
    if groups.len() > 4096 {
        return Err(c.unsupported("token group count exceeds the capture limit"));
    }
    let width = c.psize();
    let stride = 2 * width;
    let header = width + stride * groups.len() as u64;
    let payload = groups
        .iter()
        .map(|group| group.sid.len() as u64)
        .sum::<u64>();
    let required = (header + payload) as u32;
    // WoW64 reaches ReturnLength only after handle admission and requires a
    // writable DWORD. Native64 has already probed both caller destinations.
    c.mem().w32(returned, required)?;
    if length < required {
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }

    c.mem().w32(output, groups.len() as u32)?;
    let mut sid_address = output + header;
    let mut record = output + width;
    for group in groups {
        // The WoW64 converter copies each SID before publishing its record.
        // Preserve the reached stores when a later destination page faults.
        if c.arch() == WinArch::X86 {
            bno_copy::copy(c, sid_address, &group.sid)?;
        } else {
            c.mem().wr(sid_address, &group.sid)?;
        }
        c.write_ptr(record, sid_address)?;
        c.mem().w32(record + width, group.attributes)?;
        sid_address += group.sid.len() as u64;
        record += stride;
    }
    Flow::ret(STATUS_SUCCESS.into())
}
