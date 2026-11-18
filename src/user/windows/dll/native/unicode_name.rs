use crate::user::windows::hle::Ctx;
use crate::user::windows::memory::{Mem, MemFault};

/// Writes a counted name inline. Native64 leaves the header padding intact.
pub(super) fn write_inline(c: &Ctx, output: u64, name: &[u16]) -> Result<(), MemFault> {
    let bytes = (name.len() * 2) as u16;
    let buffer = output + 2 * c.psize();
    c.mem().w16(output, bytes)?;
    c.mem().w16(output + 2, bytes + 2)?;
    c.write_ptr(output + c.psize(), buffer)?;
    c.mem().put_wstr(buffer, name)
}
