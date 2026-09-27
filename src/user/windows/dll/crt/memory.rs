//! Locale-independent CRT buffer operations on checked guest memory.
//!
//! Copy/fill preflight complete ranges before their first write, then use a
//! 256-byte buffer bounded by both guest pages. This is a personality fault
//! profile, not a claim about native optimized CRT fault/write ordering.
//! Searches/comparisons stop at the first result and never read beyond it.
//! Zero counts do not dereference pointers. Overlapping memcpy is undefined;
//! memmove implements both directions without allocation proportional to count.

use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::hle::{ApiErr, ApiResult, Arg::*, Conv::Cdecl, Ctx, Export, Flow};
use crate::user::windows::memory::{Mem, MemFault};

pub(crate) static MEMORY_EXPORTS: &[Export] = &[
    Export::func("memcpy", Cdecl, &[Ptr, Ptr, Ptr], copy_api),
    Export::func("memmove", Cdecl, &[Ptr, Ptr, Ptr], copy_api),
    Export::func("memset", Cdecl, &[Ptr, I32, Ptr], set_api),
    Export::func("memcmp", Cdecl, &[Ptr, Ptr, Ptr], compare_api),
    Export::func("memchr", Cdecl, &[Ptr, I32, Ptr], find_api),
];

/// Genuine stateless VCRUNTIME byte imports; no manufactured wide exports.
pub(crate) static VCRUNTIME_MEMORY_EXPORTS: &[Export] = &[
    Export::func("memcpy", Cdecl, &[Ptr, Ptr, Ptr], copy_api),
    Export::func("memmove", Cdecl, &[Ptr, Ptr, Ptr], copy_api),
    Export::func("memset", Cdecl, &[Ptr, I32, Ptr], set_api),
    Export::func("memcmp", Cdecl, &[Ptr, Ptr, Ptr], compare_api),
    Export::func("memchr", Cdecl, &[Ptr, I32, Ptr], find_api),
];

// Wide operations are public-header inline algorithms, not names admitted to
// a synthetic DLL. Unit-only descriptors exercise the checked raw-unit helpers.
#[cfg(test)]
static WIDE_HELPER_APIS: &[Export] = &[
    Export::func("wmemcpy", Cdecl, &[Ptr, Ptr, Ptr], copy_api),
    Export::func("wmemmove", Cdecl, &[Ptr, Ptr, Ptr], copy_api),
    Export::func("wmemset", Cdecl, &[Ptr, I32, Ptr], set_api),
    Export::func("wmemcmp", Cdecl, &[Ptr, Ptr, Ptr], compare_api),
    Export::func("wmemchr", Cdecl, &[Ptr, I32, Ptr], find_api),
];

fn fault(address: u64, write: bool) -> ApiErr {
    MemFault {
        addr: address,
        write,
    }
    .into()
}

/// No x86 pointer arithmetic silently wraps into an unrelated allocation.
pub(super) fn address(
    c: &Ctx,
    base: u64,
    index: u64,
    unit: u64,
    write: bool,
) -> Result<u64, ApiErr> {
    if !matches!(unit, 1 | 2) {
        return Err(ApiErr::Internal(
            "CRT character width must be 1 or 2 bytes".into(),
        ));
    }
    let max = c.arch().ptr(u64::MAX);
    let offset = index.checked_mul(unit).ok_or_else(|| fault(max, write))?;
    let at = base.checked_add(offset).ok_or_else(|| fault(max, write))?;
    let last = at.checked_add(unit - 1).ok_or_else(|| fault(max, write))?;
    if last > max {
        return Err(fault(max.saturating_add(1), write));
    }
    Ok(at)
}

pub(super) fn read_unit(c: &Ctx, base: u64, index: u64, unit: u64) -> Result<u16, ApiErr> {
    let at = address(c, base, index, unit, false)?;
    match unit {
        1 => Ok(u16::from(c.mem().u8(at)?)),
        2 => Ok(c.mem().u16(at)?),
        _ => Err(ApiErr::Internal(
            "CRT character width must be 1 or 2 bytes".into(),
        )),
    }
}

pub(super) fn write_unit(
    c: &Ctx,
    base: u64,
    index: u64,
    unit: u64,
    value: u16,
) -> Result<(), ApiErr> {
    let at = address(c, base, index, unit, true)?;
    match unit {
        1 => Ok(c.mem().w8(at, value as u8)?),
        2 => Ok(c.mem().w16(at, value)?),
        _ => Err(ApiErr::Internal(
            "CRT character width must be 1 or 2 bytes".into(),
        )),
    }
}

fn units(c: &Ctx) -> u64 {
    if c.api.name.starts_with('w') { 2 } else { 1 }
}

fn byte_count(c: &Ctx, count: u64, unit: u64, write: bool) -> Result<u64, ApiErr> {
    count
        .checked_mul(unit)
        .ok_or_else(|| fault(c.arch().ptr(u64::MAX), write))
}

fn probe(c: &Ctx, at: u64, bytes: u64, write: bool) -> Result<(), ApiErr> {
    if bytes == 0 {
        return Ok(());
    }
    // Checking the last accessed byte admits the top byte without forming an
    // unrepresentable one-past pointer. Guest mappings reject noncanonical VAs.
    address(c, at, bytes - 1, 1, write)?;
    let len = usize::try_from(bytes).map_err(|_| fault(at, write))?;
    c.mem()
        .probe(
            at,
            len,
            if write {
                MemoryAccessKind::Write
            } else {
                MemoryAccessKind::Read
            },
        )
        .map_err(|e| fault(e.address, write))
}

/// Nonoverlapping byte copy shared with strdup. Full preflight is bounded by
/// guest mappings, not a host allocation of `bytes` elements.
pub(super) fn copy(c: &Ctx, dest: u64, source: u64, bytes: u64) -> Result<(), ApiErr> {
    transfer(c, dest, source, bytes, false)
}

fn transfer(c: &Ctx, dest: u64, source: u64, bytes: u64, moving: bool) -> Result<(), ApiErr> {
    probe(c, source, bytes, false)?;
    probe(c, dest, bytes, true)?;
    let mut buf = [0u8; 256];
    let backwards = moving && dest > source && dest - source < bytes;
    let mut remaining = bytes;
    while remaining != 0 {
        let (from, to, count) = if backwards {
            let last_from = address(c, source, remaining - 1, 1, false)?;
            let last_to = address(c, dest, remaining - 1, 1, true)?;
            let count = remaining
                .min(buf.len() as u64)
                .min(last_from % PAGE_SIZE + 1)
                .min(last_to % PAGE_SIZE + 1);
            (last_from - count + 1, last_to - count + 1, count)
        } else {
            let done = bytes - remaining;
            let from = address(c, source, done, 1, false)?;
            let to = address(c, dest, done, 1, true)?;
            let count = remaining
                .min(buf.len() as u64)
                .min(PAGE_SIZE - from % PAGE_SIZE)
                .min(PAGE_SIZE - to % PAGE_SIZE);
            (from, to, count)
        };
        let count = count as usize;
        c.mem().rd(from, &mut buf[..count])?;
        c.mem().wr(to, &buf[..count])?;
        remaining -= count as u64;
    }
    Ok(())
}

fn copy_api(c: &mut Ctx) -> ApiResult {
    let (dest, source, count) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    let bytes = byte_count(c, count, units(c), false)?;
    transfer(
        c,
        dest,
        source,
        bytes,
        matches!(c.api.name, "memmove" | "wmemmove"),
    )?;
    Flow::ret(dest)
}

fn set_api(c: &mut Ctx) -> ApiResult {
    let (dest, value, count) = (c.ptr(0)?, c.u32(1)? as u16, c.ptr(2)?);
    let unit = units(c);
    let bytes = byte_count(c, count, unit, true)?;
    probe(c, dest, bytes, true)?;
    // Filling wide values a unit at a time also handles a wchar_t straddling
    // a page. No UTF-16 decoding or surrogate normalization is performed.
    if unit == 2 {
        for index in 0..count {
            write_unit(c, dest, index, unit, value)?;
        }
    } else {
        let buf = [value as u8; 256];
        let mut done = 0;
        while done != bytes {
            let at = address(c, dest, done, 1, true)?;
            let count = (bytes - done)
                .min(buf.len() as u64)
                .min(PAGE_SIZE - at % PAGE_SIZE);
            c.mem().wr(at, &buf[..count as usize])?;
            done += count;
        }
    }
    Flow::ret(dest)
}

fn compare_api(c: &mut Ctx) -> ApiResult {
    let (left, right, count) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    let unit = units(c);
    for index in 0..count {
        let a = read_unit(c, left, index, unit)?;
        let b = read_unit(c, right, index, unit)?;
        if a != b {
            return Flow::ret((i32::from(a) - i32::from(b)) as u32 as u64);
        }
    }
    Flow::ret(0)
}

fn find_api(c: &mut Ctx) -> ApiResult {
    let (source, value, count) = (c.ptr(0)?, c.u32(1)?, c.ptr(2)?);
    let unit = units(c);
    let value = if unit == 1 {
        value as u8 as u16
    } else {
        value as u16
    };
    for index in 0..count {
        if read_unit(c, source, index, unit)? == value {
            return Flow::ret(address(c, source, index, unit, false)?);
        }
    }
    Flow::ret(0)
}

#[cfg(test)]
#[path = "memory_tests.rs"]
mod tests;
