//! Bounded UTF-16 operations used by the Win32 path and string contracts.

use super::super::hle::{ApiResult, Arg::*, Conv::Stdcall, Ctx, Export, Flow};
use super::super::memory::{Mem, MemFault};
use super::super::nt::error::ERROR_INVALID_PARAMETER;

pub(super) static EXPORTS: &[Export] = &[
    Export::func(
        "CompareStringOrdinal",
        Stdcall,
        &[Ptr, I32, Ptr, I32, I32],
        compare_ordinal,
    ),
    Export::func(
        "PathCchRemoveFileSpec",
        Stdcall,
        &[Ptr, Ptr],
        remove_file_spec,
    ),
    Export::func("IsDBCSLeadByte", Stdcall, &[I32], is_dbcs_lead_byte),
];

const PATHCCH_MAX_CCH: usize = 32_768;
const BACKSLASH: u16 = b'\\' as u16;
const E_INVALIDARG: u64 = 0x8007_0057;

fn is_dbcs_lead_byte(c: &mut Ctx) -> ApiResult {
    let _ = c.u32(0)?;
    // The portable ANSI code page is Windows-1252, a single-byte code page.
    Flow::bool(false)
}

fn compare_ordinal(c: &mut Ctx) -> ApiResult {
    use std::cmp::Ordering;

    let (left, right, ignore_case) = (c.ptr(0)?, c.ptr(2)?, c.u32(4)?);
    let (left_len, right_len) = (c.u32(1)? as i32, c.u32(3)? as i32);
    if left == 0 || right == 0 || left_len < -1 || right_len < -1 || ignore_case > 1 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let table = c.p.registry.upcase_table();
    let fold = |unit| {
        if ignore_case == 0 {
            return unit;
        }
        ordinal_uppercase(unit, &table)
    };
    let input = |ptr: u64, length: i32, offset: u64| -> Result<Option<u16>, MemFault> {
        if length >= 0 && offset / 2 == length as u64 {
            return Ok(None);
        }
        let addr = ptr.checked_add(offset).ok_or(MemFault {
            addr: u64::MAX,
            write: false,
        })?;
        let unit = c.mem().u16(addr)?;
        Ok((length >= 0 || unit != 0).then(|| fold(unit)))
    };
    let mut offset = 0;
    let order = loop {
        let left = input(left, left_len, offset)?;
        let right = input(right, right_len, offset)?;
        let order = left.cmp(&right);
        if order != Ordering::Equal || left.is_none() {
            break order;
        }
        offset += 2;
    };
    Flow::ret(match order {
        Ordering::Less => 1,
        Ordering::Equal => 2,
        Ordering::Greater => 3,
    })
}

pub(super) fn ordinal_uppercase(unit: u16, table: &[u16]) -> u16 {
    table.get(usize::from(unit)).copied().unwrap_or_else(|| {
        let Some(character) = char::from_u32(u32::from(unit)) else {
            return unit;
        };
        let mut upper = character.to_uppercase();
        let first = upper.next().unwrap_or(character);
        if upper.next().is_none() {
            u16::try_from(u32::from(first)).unwrap_or(unit)
        } else {
            unit
        }
    })
}

fn ascii_prefix(path: &[u16], prefix: &[u8]) -> bool {
    path.get(..prefix.len()).is_some_and(|head| {
        head.iter()
            .zip(prefix)
            .all(|(&unit, &byte)| u8::try_from(unit).is_ok_and(|u| u.eq_ignore_ascii_case(&byte)))
    })
}

fn unc_root(path: &[u16]) -> usize {
    let mut separators = path
        .iter()
        .enumerate()
        .filter(|&(_, &unit)| unit == BACKSLASH);
    separators.nth(1).map_or(path.len(), |(index, _)| index)
}

fn root_length(path: &[u16]) -> usize {
    if ascii_prefix(path, br"\\?\UNC\") {
        return 8 + unc_root(&path[8..]);
    }
    let prefix = if ascii_prefix(path, br"\\?\") || ascii_prefix(path, br"\\.\") {
        4
    } else if ascii_prefix(path, br"\\") {
        return 2 + unc_root(&path[2..]);
    } else {
        0
    };
    match &path[prefix..] {
        [letter, 58, BACKSLASH, ..]
            if u8::try_from(*letter).is_ok_and(|byte| byte.is_ascii_alphabetic()) =>
        {
            prefix + 3
        }
        [letter, 58, ..] if u8::try_from(*letter).is_ok_and(|byte| byte.is_ascii_alphabetic()) => {
            prefix + 2
        }
        [BACKSLASH, ..] => prefix + 1,
        tail if prefix != 0 => {
            prefix
                + tail
                    .iter()
                    .position(|&unit| unit == BACKSLASH)
                    .map_or(tail.len(), |i| i + 1)
        }
        _ => 0,
    }
}

fn remove_file_spec(c: &mut Ctx) -> ApiResult {
    let (address, capacity) = (c.ptr(0)?, c.ptr(1)?);
    if address == 0 || capacity == 0 || capacity > PATHCCH_MAX_CCH as u64 {
        return Flow::ret(E_INVALIDARG);
    }
    let path = c.mem().wstr(address, capacity as usize)?;
    if path.len() == capacity as usize {
        return Flow::ret(E_INVALIDARG);
    }
    let root = root_length(&path);
    if path.len() <= root {
        return Flow::ret(1); // S_FALSE
    }
    let end = path[root..]
        .iter()
        .rposition(|&unit| unit == BACKSLASH)
        .map_or(root, |i| root + i);
    c.mem().w16(address + end as u64 * 2, 0)?;
    Flow::ret(0) // S_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_length_preserves_dos_unc_and_extended_roots() {
        for (path, root) in [
            (r"relative\file", ""),
            (r"\file", r"\"),
            (r"C:file", "C:"),
            (r"C:\file", r"C:\"),
            (r"\\server\share\file", r"\\server\share"),
            (r"\\?\UNC\server\share\file", r"\\?\UNC\server\share"),
            (r"\\?\C:\file", r"\\?\C:\"),
        ] {
            let units: Vec<u16> = path.encode_utf16().collect();
            assert_eq!(
                String::from_utf16(&units[..root_length(&units)]).unwrap(),
                root
            );
        }
    }
}
