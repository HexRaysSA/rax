//! Wide Win32 registry APIs hosted by the portable KernelBase profile.
//! Real handles share key objects, access grants and view selection with NT.
use super::{
    Attributes, Checked, Failure, Name, key, open_resolved, probe_write, selected_value, status,
};
use crate::user::windows::hle::{ApiResult, Arg::Ptr, Conv::Stdcall, Ctx, Export, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::{error::ERROR_MORE_DATA, status::*, status_to_error};
use crate::user::windows::registry::{Key, MAX_NAME_UNITS};
use std::sync::Arc;

pub(in crate::user::windows::dll) static WIN32_REGISTRY_EXPORTS: &[Export] = &[
    Export::func("RegCloseKey", Stdcall, &[Ptr], close),
    Export::func("RegOpenKeyW", Stdcall, &[Ptr, Ptr, Ptr], open),
    Export::func(
        "RegQueryValueExW",
        Stdcall,
        &[Ptr, Ptr, Ptr, Ptr, Ptr, Ptr],
        query,
    ),
];

const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const KEY_QUERY_VALUE: u32 = 1;

fn result(outcome: Checked<u32>) -> ApiResult {
    match outcome {
        Ok(code) => Flow::ret(code.into()),
        Err(Failure::Status(code)) => Flow::ret(status_to_error(code).into()),
        Err(Failure::Api(error)) => Err(error),
    }
}

// The SDK casts these constants from signed LONG to ULONG_PTR. A truncated
// 64-bit handle with the same low word is not a predefined HKEY.
fn predefined(c: &Ctx, handle: u64) -> Option<u32> {
    let low = handle as u32;
    if c.arch().ptr(i64::from(low as i32) as u64) != handle {
        return None;
    }
    match low {
        0x8000_0000..=0x8000_0007 | 0x8000_0050 | 0x8000_0060 => Some(low),
        _ => None,
    }
}

fn wide_name(c: &Ctx, pointer: u64) -> Checked<Vec<u16>> {
    if pointer == 0 {
        return Ok(Vec::new());
    }
    let units = c.mem().wstr(pointer, MAX_NAME_UNITS + 1)?;
    if units.len() > MAX_NAME_UNITS {
        return status(STATUS_OBJECT_NAME_INVALID);
    }
    Ok(units)
}

fn open_from(c: &mut Ctx, parent: u64, subkey: Vec<u16>, access: u32) -> Checked<u32> {
    if subkey.first() == Some(&92) {
        return status(STATUS_OBJECT_PATH_SYNTAX_BAD);
    }
    let (root, units) = if let Some(hive) = predefined(c, parent) {
        // In built-in mode an unconfigured guest registry has no subkeys or values.
        if matches!(hive, 0x8000_0000..=0x8000_0003 | 0x8000_0005)
            && c.p.registry.upcase_table().is_empty()
        {
            return status(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let mut absolute: Vec<u16> = match hive {
            0x8000_0001 => {
                c.p.registry
                    .primary_hive_path()
                    .ok_or(Failure::Status(STATUS_NOT_SUPPORTED))?
                    .to_vec()
            }
            0x8000_0002 => crate::user::windows::registry::MACHINE_HIVE_KEY
                .encode_utf16()
                .collect(),
            0x8000_0003 => r"\Registry\User".encode_utf16().collect(),
            0x8000_0005 => r"\Registry\Machine\System\CurrentControlSet\Hardware Profiles\Current"
                .encode_utf16()
                .collect(),
            // The merged Classes hive and live performance providers require
            // data outside the captured ordinary registry roots.
            _ => return status(STATUS_NOT_SUPPORTED),
        };
        if !subkey.is_empty() {
            absolute.push(92);
            absolute.extend(subkey);
        }
        (0, absolute)
    } else {
        // RootDirectory == 0 means an absolute NT path. The Win32 API
        // requires a valid parent even when the supplied name is empty.
        key(c, parent, false)?;
        (parent, subkey)
    };
    let attrs = Attributes {
        root,
        name: Name { units, odd: false },
        flags: 0x40,
    };
    open_resolved(c, access, attrs, 0, false)
}

fn close(c: &mut Ctx) -> ApiResult {
    let handle = c.ptr(0)?;
    if predefined(c, handle).is_some() {
        return Flow::ret(0);
    }
    let outcome = key(c, handle, false).and_then(|_| {
        c.p.objects
            .close(handle)
            .map(|_| 0)
            .map_err(|_| Failure::Status(STATUS_INVALID_HANDLE))
    });
    result(outcome)
}

fn open(c: &mut Ctx) -> ApiResult {
    let outcome = open_checked(c);
    result(outcome)
}

fn open_checked(c: &mut Ctx) -> Checked<u32> {
    let (parent, pointer, out) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    if out == 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let subkey = wide_name(c, pointer)?;
    probe_write(c, out, c.psize() as usize)?;
    c.write_ptr(out, 0)?;
    if subkey.is_empty() {
        if predefined(c, parent).is_none() {
            key(c, parent, false)?;
        }
        c.write_ptr(out, parent)?;
        return Ok(0);
    }
    let handle = u64::from(open_from(c, parent, subkey, MAXIMUM_ALLOWED)?);
    if let Err(fault) = c.write_ptr(out, handle) {
        let _ = c.p.objects.close(handle);
        return Err(fault.into());
    }
    Ok(0)
}

fn query_key(c: &mut Ctx, handle: u64) -> Checked<Arc<Key>> {
    if predefined(c, handle).is_none() {
        return key(c, handle, true);
    }
    let transient = u64::from(open_from(c, handle, Vec::new(), KEY_QUERY_VALUE)?);
    let selected = key(c, transient, true);
    let _ = c.p.objects.close(transient);
    selected
}

fn query(c: &mut Ctx) -> ApiResult {
    let outcome = query_checked(c);
    result(outcome)
}

fn query_checked(c: &mut Ctx) -> Checked<u32> {
    let (handle, pointer, reserved) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    let (kind, data, size) = (c.ptr(3)?, c.ptr(4)?, c.ptr(5)?);
    if reserved != 0 || (data != 0 && size == 0) {
        return status(STATUS_INVALID_PARAMETER);
    }
    let selected = query_key(c, handle)?;
    let name = wide_name(c, pointer)?;
    let value = selected_value(c, &selected, &name)?;
    // Snapshot construction bounds value lengths to MAX_VALUE_BYTES.
    let required = value.data.len() as u32;
    let too_small = data != 0 && c.mem().u32(size)? < required;
    if kind != 0 {
        probe_write(c, kind, 4)?;
    }
    if size != 0 {
        probe_write(c, size, 4)?;
    }
    if data != 0 && !too_small {
        c.mem().wr(data, &value.data)?;
    }
    if kind != 0 {
        c.mem().w32(kind, value.kind)?;
    }
    if size != 0 {
        c.mem().w32(size, required)?;
    }
    Ok(if too_small { ERROR_MORE_DATA } else { 0 })
}

#[cfg(test)]
mod tests;
