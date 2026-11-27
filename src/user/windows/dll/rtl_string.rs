//! Native counted-string operations for portable NTDLL.

use super::super::{
    hle::{
        ApiResult,
        Arg::{I32, Ptr},
        Conv::Stdcall,
        Ctx, Export, Flow,
    },
    memory::Mem,
};

pub(super) static EXPORTS: &[Export] = &[Export::func(
    "RtlInitUnicodeString",
    Stdcall,
    &[Ptr, Ptr],
    init_unicode_string,
)];

pub(super) static COMPARE_EXPORTS: &[Export] = &[Export::func(
    "RtlCompareUnicodeString",
    Stdcall,
    &[Ptr, Ptr, I32],
    compare_unicode_string,
)];

fn compare_unicode_string(c: &mut Ctx) -> ApiResult {
    let (left, right) = (c.ptr(0)?, c.ptr(1)?);
    let insensitive = c.u32(2)? as u8 != 0;
    let (a_len, b_len) = (c.mem().u16(left)? / 2, c.mem().u16(right)? / 2);
    let (a, b) = (
        c.read_ptr(left + c.psize())?,
        c.read_ptr(right + c.psize())?,
    );
    let upcase = c.p.registry.upcase_table();
    let fold = |unit: u16| {
        if insensitive {
            upcase.get(usize::from(unit)).copied().unwrap_or_else(|| {
                if unit <= 0x7f {
                    u16::from((unit as u8).to_ascii_uppercase())
                } else {
                    unit
                }
            })
        } else {
            unit
        }
    };
    for offset in 0..u64::from(a_len.min(b_len)) {
        let lhs = c.mem().u16(a.wrapping_add(2 * offset))?;
        let rhs = c.mem().u16(b.wrapping_add(2 * offset))?;
        if lhs != rhs {
            let delta = i32::from(fold(lhs)) - i32::from(fold(rhs));
            if delta != 0 {
                return Flow::ret(u64::from(delta as u32));
            }
        }
    }
    Flow::ret(u64::from((i32::from(a_len) - i32::from(b_len)) as u32))
}

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
