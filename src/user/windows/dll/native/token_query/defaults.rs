//! Publish pointer-sized TOKEN_OWNER, TOKEN_PRIMARY_GROUP and TOKEN_DEFAULT_DACL records.

use super::{Ctx, Flow, Mem, STATUS_BUFFER_TOO_SMALL, STATUS_SUCCESS, bno_copy};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::ApiResult;

pub(super) fn publish(
    c: &mut Ctx,
    data: &[u8],
    output: u64,
    length: u32,
    returned: u64,
) -> ApiResult {
    let width = c.psize();
    // Capture bounds the payload to 64 KiB including the native header.
    let required = width as u32 + data.len() as u32;
    let wow = c.arch() == WinArch::X86;
    if !wow || (length < required && returned != 0) {
        c.mem().w32(returned, required)?;
    }
    if length < required {
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }

    let pointer = if data.is_empty() { 0 } else { output + width };
    c.write_ptr(output, pointer)?;
    if wow {
        // Publish the pointer before copying the payload so a later fault
        // preserves the pointer. The optional length store follows both.
        if !data.is_empty() {
            bno_copy::copy(c, pointer, data)?;
        }
        if returned != 0 {
            c.mem().w32(returned, required)?;
        }
    } else if !data.is_empty() {
        c.mem().wr(pointer, data)?;
    }
    Flow::ret(STATUS_SUCCESS.into())
}
