//! Native counted-string initialization for portable NTDLL.

use super::super::{
    hle::{ApiResult, Arg::Ptr, Conv::Stdcall, Ctx, Export, Flow},
    memory::Mem,
};

pub(super) static EXPORTS: &[Export] = &[Export::func(
    "RtlInitUnicodeString",
    Stdcall,
    &[Ptr, Ptr],
    init_unicode_string,
)];

fn init_unicode_string(c: &mut Ctx) -> ApiResult {
    let (output, source) = (c.ptr(0)?, c.ptr(1)?);
    let width = c.psize();
    // Windows publishes the cleared lengths and source pointer before
    // scanning. On x64/ARM64 this clears the four padding bytes as well.
    c.mem().wptr(output, width, 0)?;
    c.mem().wptr(output + width, width, source)?;
    if source != 0 {
        const MAX_LENGTH: usize = 0xfffc;
        let length = (c.mem().wstr(source, MAX_LENGTH / 2)?.len() * 2) as u16;
        c.mem().w16(output, length)?;
        c.mem().w16(output + 2, length + 2)?;
    }
    Flow::void()
}
