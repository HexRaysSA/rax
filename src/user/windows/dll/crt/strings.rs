//! Raw single-byte and Windows 16-bit wchar_t string operations.
//!
//! No locale, Unicode scalar decoding, or replacement of unpaired surrogates.
//! Units are accessed only when needed, including at page-end terminators.
//! Unterminated unbounded scans fault rather than return a truncated success.
//! Writes stream in increasing unit order; a later fault can leave a prefix
//! written. Native optimized fault-time partial completion is not claimed.

use super::memory::{address, read_unit, write_unit};
use crate::user::windows::hle::{ApiErr, ApiResult, Arg::*, Conv::Cdecl, Ctx, Export, Flow};
use crate::user::windows::memory::MemFault;

pub(crate) static STRING_EXPORTS: &[Export] = &[
    Export::func("strlen", Cdecl, &[Ptr], length_api),
    Export::func("wcslen", Cdecl, &[Ptr], length_api),
    Export::func("strcmp", Cdecl, &[Ptr, Ptr], compare_api),
    Export::func("wcscmp", Cdecl, &[Ptr, Ptr], compare_api),
    Export::func("strncmp", Cdecl, &[Ptr, Ptr, Ptr], compare_api),
    Export::func("wcsncmp", Cdecl, &[Ptr, Ptr, Ptr], compare_api),
    Export::func("strcpy", Cdecl, &[Ptr, Ptr], copy_api),
    Export::func("wcscpy", Cdecl, &[Ptr, Ptr], copy_api),
    Export::func("strncpy", Cdecl, &[Ptr, Ptr, Ptr], copy_api),
    Export::func("wcsncpy", Cdecl, &[Ptr, Ptr, Ptr], copy_api),
    Export::func("strcat", Cdecl, &[Ptr, Ptr], append_api),
    Export::func("wcscat", Cdecl, &[Ptr, Ptr], append_api),
    Export::func("strncat", Cdecl, &[Ptr, Ptr, Ptr], append_api),
    Export::func("wcsncat", Cdecl, &[Ptr, Ptr, Ptr], append_api),
    Export::func("strchr", Cdecl, &[Ptr, I32], find_api),
    Export::func("wcschr", Cdecl, &[Ptr, I32], find_api),
    Export::func("strrchr", Cdecl, &[Ptr, I32], find_api),
    Export::func("wcsrchr", Cdecl, &[Ptr, I32], find_api),
    Export::func("strstr", Cdecl, &[Ptr, Ptr], substring_api),
    Export::func("wcsstr", Cdecl, &[Ptr, Ptr], substring_api),
];

pub(crate) static NTDLL_STRING_EXPORTS: &[Export] =
    &[Export::func("_wcsicmp", Cdecl, &[Ptr, Ptr], compare_api)];

/// Bounded-length imports are admitted by UCRT, not augmented into MSVCRT.
pub(crate) static UCRT_STRING_EXPORTS: &[Export] = &[
    Export::func("strnlen", Cdecl, &[Ptr, Ptr], length_api),
    Export::func("wcsnlen", Cdecl, &[Ptr, Ptr], length_api),
];

pub(crate) static UCRT_SECURE_STRING_EXPORTS: &[Export] = &[Export::func(
    "wcscat_s",
    Cdecl,
    &[Ptr, Ptr, Ptr],
    wide_concat_secure,
)];

pub(crate) static UCRT_CASE_STRING_EXPORTS: &[Export] = &[Export::func(
    "_strnicmp",
    Cdecl,
    &[Ptr, Ptr, Ptr],
    compare_api,
)];

fn wide_concat_secure(c: &mut Ctx) -> ApiResult {
    let (dest, capacity, source) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    if dest == 0 || capacity == 0 {
        return concat_error(c, 22);
    }
    let end = string_len(c, dest, 2, Some(capacity))?;
    if source == 0 || end == capacity {
        write_unit(c, dest, 0, 2, 0)?;
        return concat_error(c, 22);
    }
    let available = capacity - end;
    let length = string_len(c, source, 2, Some(available))?;
    if length == available {
        write_unit(c, dest, 0, 2, 0)?;
        return concat_error(c, 34);
    }
    for index in 0..length {
        let value = read_unit(c, source, index, 2)?;
        write_unit(c, dest, end + index, 2, value)?;
    }
    write_unit(c, dest, end + length, 2, 0)?;
    Flow::ret(0)
}

fn concat_error(c: &mut Ctx, errno: u32) -> ApiResult {
    let kind = super::runtime(c)?;
    super::state::set_errno(c, kind, errno)?;
    super::invalid::invoke(
        c,
        kind,
        [0; 5],
        Box::new(move |_, _| Flow::ret(errno.into())),
    )
}

/// Stateless search names present in the genuine VCRUNTIME import inventory.
pub(crate) static VCRUNTIME_STRING_EXPORTS: &[Export] = &[
    Export::func("strchr", Cdecl, &[Ptr, I32], find_api),
    Export::func("wcschr", Cdecl, &[Ptr, I32], find_api),
    Export::func("strrchr", Cdecl, &[Ptr, I32], find_api),
    Export::func("wcsrchr", Cdecl, &[Ptr, I32], find_api),
    Export::func("strstr", Cdecl, &[Ptr, Ptr], substring_api),
    Export::func("wcsstr", Cdecl, &[Ptr, Ptr], substring_api),
];

fn units(c: &Ctx) -> u64 {
    if c.api.name.starts_with('w') { 2 } else { 1 }
}

fn advance(c: &Ctx, index: u64, write: bool) -> Result<u64, ApiErr> {
    index.checked_add(1).ok_or_else(|| {
        MemFault {
            addr: c.arch().ptr(u64::MAX),
            write,
        }
        .into()
    })
}

/// Returns raw units before NUL; a bounded scan returns the bound when no NUL
/// was encountered. Used by strdup without an O(length) host allocation.
pub(super) fn string_len(
    c: &Ctx,
    source: u64,
    unit: u64,
    bound: Option<u64>,
) -> Result<u64, ApiErr> {
    if !matches!(unit, 1 | 2) {
        return Err(ApiErr::Internal(
            "CRT character width must be 1 or 2 bytes".into(),
        ));
    }
    let mut index = 0;
    while bound.is_none_or(|n| index < n) {
        if read_unit(c, source, index, unit)? == 0 {
            return Ok(index);
        }
        index = advance(c, index, false)?;
    }
    Ok(index)
}

fn length_api(c: &mut Ctx) -> ApiResult {
    let source = c.ptr(0)?;
    let bound = if matches!(c.api.name, "strnlen" | "wcsnlen") {
        Some(c.ptr(1)?)
    } else {
        None
    };
    Flow::ret(string_len(c, source, units(c), bound)?)
}

fn compare_api(c: &mut Ctx) -> ApiResult {
    let (left, right) = (c.ptr(0)?, c.ptr(1)?);
    // The native NTDLL comparison folds only ASCII A through Z. It compares
    // all other UTF-16 units as stored, without visiting a process locale.
    // UCRT supports the C locale, which uses the same folding for bytes.
    let ignore_ascii_case = matches!(c.api.name, "_wcsicmp" | "_strnicmp");
    let bound = if matches!(c.api.name, "strncmp" | "wcsncmp" | "_strnicmp") {
        Some(c.ptr(2)?)
    } else {
        None
    };
    if c.api.name == "_strnicmp"
        && (left == 0 || right == 0 || bound.is_some_and(|n| n > i32::MAX as u64))
    {
        let kind = super::runtime(c)?;
        super::state::set_errno(c, kind, 22)?;
        return super::invalid::invoke(
            c,
            kind,
            [0; 5],
            Box::new(|_, _| Flow::ret(i32::MAX as u64)),
        );
    }
    let unit = if c.api.name == "_wcsicmp" {
        2
    } else {
        units(c)
    };
    let fold = |value: u16| {
        if ignore_ascii_case && (0x41..=0x5a).contains(&value) {
            value + 0x20
        } else {
            value
        }
    };
    let mut index = 0;
    while bound.is_none_or(|n| index < n) {
        let a = fold(read_unit(c, left, index, unit)?);
        let b = fold(read_unit(c, right, index, unit)?);
        if a != b {
            return Flow::ret((i32::from(a) - i32::from(b)) as u32 as u64);
        }
        if a == 0 {
            return Flow::ret(0);
        }
        index = advance(c, index, false)?;
    }
    Flow::ret(0)
}

fn copy_api(c: &mut Ctx) -> ApiResult {
    let (dest, source) = (c.ptr(0)?, c.ptr(1)?);
    let bounded = matches!(c.api.name, "strncpy" | "wcsncpy");
    let bound = if bounded { Some(c.ptr(2)?) } else { None };
    let unit = units(c);
    let mut index = 0;
    let mut padding = false;
    while bound.is_none_or(|n| index < n) {
        let value = if padding {
            0
        } else {
            read_unit(c, source, index, unit)?
        };
        write_unit(c, dest, index, unit, value)?;
        if value == 0 {
            if !bounded {
                return Flow::ret(dest);
            }
            padding = true;
        }
        index = advance(c, index, true)?;
    }
    Flow::ret(dest)
}

fn append_api(c: &mut Ctx) -> ApiResult {
    let (dest, source) = (c.ptr(0)?, c.ptr(1)?);
    let bound = if matches!(c.api.name, "strncat" | "wcsncat") {
        Some(c.ptr(2)?)
    } else {
        None
    };
    let unit = units(c);
    let end = string_len(c, dest, unit, None)?;
    let output = address(c, dest, end, unit, true)?;
    let mut index = 0;
    while bound.is_none_or(|n| index < n) {
        let value = read_unit(c, source, index, unit)?;
        write_unit(c, output, index, unit, value)?;
        if value == 0 {
            return Flow::ret(dest);
        }
        index = advance(c, index, true)?;
    }
    // Unlike strncpy, strncat writes a terminator even when source reaches n.
    write_unit(c, output, index, unit, 0)?;
    Flow::ret(dest)
}

fn find_api(c: &mut Ctx) -> ApiResult {
    let (source, value) = (c.ptr(0)?, c.u32(1)?);
    let unit = units(c);
    let value = if unit == 1 {
        value as u8 as u16
    } else {
        value as u16
    };
    let last = matches!(c.api.name, "strrchr" | "wcsrchr");
    let mut found = 0;
    let mut index = 0;
    loop {
        let current = read_unit(c, source, index, unit)?;
        if current == value {
            found = address(c, source, index, unit, false)?;
            if !last {
                return Flow::ret(found);
            }
        }
        if current == 0 {
            return Flow::ret(found);
        }
        index = advance(c, index, false)?;
    }
}

fn substring_api(c: &mut Ctx) -> ApiResult {
    let (haystack, needle) = (c.ptr(0)?, c.ptr(1)?);
    let unit = units(c);
    if read_unit(c, needle, 0, unit)? == 0 {
        return Flow::ret(haystack);
    }
    let mut start = 0;
    loop {
        let position = address(c, haystack, start, unit, false)?;
        let mut index = 0;
        loop {
            let n = read_unit(c, needle, index, unit)?;
            if n == 0 {
                return Flow::ret(position);
            }
            let h = read_unit(c, position, index, unit)?;
            if h == 0 {
                return Flow::ret(0);
            }
            if h != n {
                break;
            }
            index = advance(c, index, false)?;
        }
        start = advance(c, start, false)?;
    }
}

#[cfg(test)]
#[path = "strings_tests.rs"]
mod tests;
