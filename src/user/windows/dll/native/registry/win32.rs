//! Wide Win32 registry APIs hosted by the portable KernelBase profile.
//! Real handles share key objects, access grants and view selection with NT.
use super::{
    Attributes, Checked, Failure, Name, key, key_notify, open_resolved, probe_write,
    selected_value, status,
};
use crate::user::windows::hle::{
    ApiResult,
    Arg::{I32, Ptr},
    Conv::Stdcall,
    Ctx, Export, Flow,
};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::{
    error::{ERROR_DATATYPE_MISMATCH, ERROR_MORE_DATA, ERROR_UNSUPPORTED_TYPE},
    status::*,
    status_to_error,
};
use crate::user::windows::objects::{Object, RegistryCompletion};
use crate::user::windows::registry::{Key, MAX_NAME_UNITS};
use std::borrow::Cow;
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
    Export::func(
        "RegOpenKeyExW",
        Stdcall,
        &[Ptr, Ptr, I32, I32, Ptr],
        open_ex,
    ),
    Export::func(
        "RegGetValueW",
        Stdcall,
        &[Ptr, Ptr, Ptr, I32, Ptr, Ptr, Ptr],
        get_value,
    ),
    Export::func(
        "RegNotifyChangeKeyValue",
        Stdcall,
        &[Ptr, I32, I32, Ptr, I32],
        notify,
    ),
    Export::func(
        "RegOpenCurrentUser",
        Stdcall,
        &[I32, Ptr],
        open_current_user,
    ),
    Export::func(
        "RegOpenKeyExA",
        Stdcall,
        &[Ptr, Ptr, I32, I32, Ptr],
        open_ex,
    ),
];

pub(in crate::user::windows::dll) static WIN32_REGISTRY_ENUM_EXPORTS: &[Export] = &[Export::func(
    "RegEnumKeyExW",
    Stdcall,
    &[Ptr, I32, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr],
    enum_key,
)];

pub(in crate::user::windows::dll) static USER_CLASSES_EXPORTS: &[Export] = &[Export::func(
    "RegOpenUserClassesRoot",
    Stdcall,
    &[Ptr, I32, I32, Ptr],
    open_user_classes,
)];

const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const KEY_QUERY_VALUE: u32 = 1;
const KEY_ENUMERATE_SUB_KEYS: u32 = 8;
const RRF_RT_ANY: u32 = 0xffff;
const RRF_SUBKEY_WOW6464KEY: u32 = 0x10000;
const RRF_SUBKEY_WOW6432KEY: u32 = 0x20000;
const RRF_NOEXPAND: u32 = 0x1000_0000;
const RRF_ZEROONFAILURE: u32 = 0x2000_0000;

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

fn enum_key(c: &mut Ctx) -> ApiResult {
    let outcome = (|| -> Checked<u32> {
        let (handle, index, name, length, reserved, class, class_length, time) = (
            c.ptr(0)?,
            c.u32(1)?,
            c.ptr(2)?,
            c.ptr(3)?,
            c.ptr(4)?,
            c.ptr(5)?,
            c.ptr(6)?,
            c.ptr(7)?,
        );
        if reserved != 0 || name == 0 || length == 0 {
            return status(STATUS_INVALID_PARAMETER);
        }
        let key = key(c, handle, false)?;
        if c.p.objects.access(handle).unwrap_or(0) & KEY_ENUMERATE_SUB_KEYS == 0 {
            return status(STATUS_ACCESS_DENIED);
        }
        if class != 0 || class_length != 0 {
            return Err(c
                .unsupported("registry subkey class is not captured")
                .into());
        }
        let capacity = c.mem().u32(length)?;
        let children = key
            .child_metadata()
            .ok_or_else(|| c.unsupported("registry subkey enumeration is not captured"))?;
        let Some(child) = children.get(index as usize) else {
            return status(STATUS_NO_MORE_ENTRIES);
        };
        if capacity <= child.name.len() as u32 {
            return Ok(ERROR_MORE_DATA);
        }
        probe_write(c, name, (child.name.len() + 1) * 2)?;
        probe_write(c, length, 4)?;
        if time != 0 {
            probe_write(c, time, 8)?;
        }
        c.mem().put_wstr(name, &child.name)?;
        c.mem().w32(length, child.name.len() as u32)?;
        if time != 0 {
            c.mem().w64(time, child.last_write)?;
        }
        Ok(0)
    })();
    result(outcome)
}

fn open_from(c: &mut Ctx, parent: u64, subkey: Vec<u16>, access: u32) -> Checked<u32> {
    if subkey.first() == Some(&92) {
        return status(STATUS_OBJECT_PATH_SYNTAX_BAD);
    }
    let (root, units) = if let Some(hive) = predefined(c, parent) {
        // In built-in mode an unconfigured guest registry has no subkeys or values.
        if matches!(hive, 0x8000_0000..=0x8000_0003 | 0x8000_0005)
            && c.p.registry.upcase_table().is_empty()
            && !(hive == 0x8000_0002 && c.p.registry.is_portable_machine_subkey(&subkey))
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
    let (parent, pointer, out) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    let outcome = open_checked(c, parent, pointer, out, MAXIMUM_ALLOWED, true);
    result(outcome)
}

fn open_ex(c: &mut Ctx) -> ApiResult {
    let (parent, pointer, out) = (c.ptr(0)?, c.ptr(1)?, c.ptr(4)?);
    let options = c.u32(2)?;
    let access = c.u32(3)?;
    if options != 0 {
        return result(status(if options == 8 {
            STATUS_NOT_SUPPORTED // The guest snapshot has no registry link-source metadata.
        } else {
            STATUS_INVALID_PARAMETER
        }));
    }
    let outcome = open_checked(c, parent, pointer, out, access, false);
    result(outcome)
}

fn open_current_user(c: &mut Ctx) -> ApiResult {
    let (access, out) = (c.u32(0)?, c.ptr(1)?);
    let current_user = c.arch().ptr(0xffff_ffff_8000_0001);
    let outcome = (|| {
        if out == 0 {
            return status(STATUS_INVALID_PARAMETER);
        }
        probe_write(c, out, c.psize() as usize)?;
        c.write_ptr(out, 0)?;
        open_and_publish(c, current_user, Vec::new(), out, access)
    })();
    result(outcome)
}

fn open_user_classes(c: &mut Ctx) -> ApiResult {
    let outcome = (|| {
        let (token, options, out) = (c.ptr(0)?, c.u32(1)?, c.ptr(3)?);
        if token == 0 || options != 0 || out == 0 {
            return status(STATUS_INVALID_PARAMETER);
        }
        if !c.p.cfg.gameos || c.p.native.is_some() {
            return Err(c
                .unsupported("per-user registry classes hive is not captured")
                .into());
        }
        if token == c.arch().ptr(u64::MAX - 4) {
            return status(STATUS_NO_TOKEN);
        }
        if token != c.arch().ptr(u64::MAX - 3) && token != c.arch().ptr(u64::MAX - 5) {
            match c.p.objects.get(token) {
                Some(Object::PrimaryToken) if c.p.objects.access(token).unwrap_or(0) & 8 != 0 => {}
                Some(Object::PrimaryToken) => return status(STATUS_ACCESS_DENIED),
                Some(_) => return status(STATUS_OBJECT_TYPE_MISMATCH),
                None => return status(STATUS_INVALID_HANDLE),
            }
        }
        // The portable guest has no loaded user profile or SID_Classes hive.
        probe_write(c, out, c.psize() as usize)?;
        c.write_ptr(out, 0)?;
        status(STATUS_OBJECT_NAME_NOT_FOUND)
    })();
    result(outcome)
}

fn open_checked(
    c: &mut Ctx,
    parent: u64,
    pointer: u64,
    out: u64,
    access: u32,
    reuse_handle: bool,
) -> Checked<u32> {
    if out == 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let subkey = if c.api.name == "RegOpenKeyExA" && pointer != 0 {
        let bytes = c.mem().cstr(pointer, MAX_NAME_UNITS + 1)?;
        if bytes.len() > MAX_NAME_UNITS {
            return status(STATUS_OBJECT_NAME_INVALID);
        }
        crate::user::windows::dll::crt::startup::decode_process_ansi(&bytes)
    } else {
        wide_name(c, pointer)?
    };
    probe_write(c, out, c.psize() as usize)?;
    c.write_ptr(out, 0)?;
    if subkey.is_empty() && (reuse_handle || predefined(c, parent).is_some()) {
        if predefined(c, parent).is_none() {
            key(c, parent, false)?;
        }
        c.write_ptr(out, parent)?;
        return Ok(0);
    }
    open_and_publish(c, parent, subkey, out, access)
}

fn open_and_publish(
    c: &mut Ctx,
    parent: u64,
    subkey: Vec<u16>,
    out: u64,
    access: u32,
) -> Checked<u32> {
    let handle = u64::from(open_from(c, parent, subkey, access)?);
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

fn notify(c: &mut Ctx) -> ApiResult {
    let (handle, filter, event, asynchronous) = (c.ptr(0)?, c.u32(2)?, c.ptr(3)?, c.u32(4)? != 0);
    let agnostic = filter & key_notify::THREAD_AGNOSTIC != 0;
    if (agnostic && !asynchronous) || (asynchronous && event == 0) {
        return result(status(STATUS_INVALID_PARAMETER));
    }
    let key = match predefined(c, handle) {
        Some(0x8000_0000..=0x8000_0003 | 0x8000_0005) => None,
        Some(_) => return result(status(STATUS_INVALID_HANDLE)),
        None => Some(handle),
    };
    let completion = RegistryCompletion {
        owner: (!agnostic).then_some(c.t.tid),
        event: None,
        io: None,
        apc: None,
    };
    match key_notify::register(c, key, event, filter, asynchronous, completion) {
        Ok(Some(event)) if !asynchronous => {
            Flow::block(key_notify::wait_event(event), |_, _| Flow::ret(0))
        }
        Ok(_) => Flow::ret(0),
        Err(error) => result(Err(error)),
    }
}

fn get_value(c: &mut Ctx) -> ApiResult {
    let (data, size, flags) = (c.ptr(5)?, c.ptr(6)?, c.u32(3)?);
    if data != 0 && size == 0 {
        return result(status(STATUS_INVALID_PARAMETER));
    }
    let capacity = if data != 0 { c.mem().u32(size)? } else { 0 };
    let outcome = get_value_checked(c, flags, capacity);
    if flags & RRF_ZEROONFAILURE != 0
        && capacity != 0
        && matches!(&outcome, Ok(1..) | Err(Failure::Status(_)))
    {
        probe_write(c, data, capacity as usize)?;
        let zeros = [0; 4096];
        let mut remaining = u64::from(capacity);
        while remaining != 0 {
            let count = remaining.min(zeros.len() as u64);
            c.mem().wr(
                data + u64::from(capacity) - remaining,
                &zeros[..count as usize],
            )?;
            remaining -= count;
        }
    }
    result(outcome)
}

fn get_value_checked(c: &mut Ctx, flags: u32, capacity: u32) -> Checked<u32> {
    let handle = c.ptr(0)?;
    let types = flags & RRF_RT_ANY;
    let view = flags & (RRF_SUBKEY_WOW6464KEY | RRF_SUBKEY_WOW6432KEY);
    if handle == 0 || types == 0 || view == (RRF_SUBKEY_WOW6464KEY | RRF_SUBKEY_WOW6432KEY) {
        return status(STATUS_INVALID_PARAMETER);
    }
    let subkey = wide_name(c, c.ptr(1)?)?;
    let name = wide_name(c, c.ptr(2)?)?;
    let selected = if subkey.is_empty() {
        query_key(c, handle)?
    } else {
        if predefined(c, handle).is_none() {
            key(c, handle, true)?;
        }
        // The documented RRF view bits are eight positions above KEY_WOW64_*.
        let access = KEY_QUERY_VALUE | (view >> 8);
        let transient = u64::from(open_from(c, handle, subkey, access)?);
        let selected = key(c, transient, true);
        let _ = c.p.objects.close(transient);
        selected?
    };
    let value = selected_value(c, &selected, &name)?;
    let kind_flag = match value.kind {
        0..=4 => 1 << value.kind,
        7 => 0x20,
        11 => 0x40,
        _ => 0,
    };
    let expands = value.kind == 2 && flags & RRF_NOEXPAND == 0;
    let type_flag = if expands { 2 } else { kind_flag };
    if types != RRF_RT_ANY && types & type_flag == 0 {
        return Ok(ERROR_UNSUPPORTED_TYPE);
    }
    if value.kind == 3
        && ((types == 0x18 && value.data.len() != 4) || (types == 0x48 && value.data.len() != 8))
    {
        return Ok(ERROR_DATATYPE_MISMATCH);
    }
    if expands {
        return status(STATUS_NOT_SUPPORTED);
    }
    let mut bytes = Cow::Borrowed(value.data.as_slice());
    if matches!(value.kind, 1 | 2 | 7) {
        if bytes.len() % 2 != 0 {
            return Ok(ERROR_DATATYPE_MISMATCH);
        }
        let required_nulls = if value.kind == 7 { 2 } else { 1 };
        let trailing_nulls = bytes
            .rchunks_exact(2)
            .take(required_nulls)
            .take_while(|unit| *unit == [0, 0])
            .count();
        if trailing_nulls < required_nulls {
            let end = bytes.len() + 2 * (required_nulls - trailing_nulls);
            bytes.to_mut().resize(end, 0);
        }
    }
    let (kind, data, size) = (c.ptr(4)?, c.ptr(5)?, c.ptr(6)?);
    write_query(c, kind, data, size, capacity, value.kind, &bytes)
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
    let capacity = if data != 0 { c.mem().u32(size)? } else { 0 };
    write_query(c, kind, data, size, capacity, value.kind, &value.data)
}

fn write_query(
    c: &Ctx,
    kind: u64,
    data: u64,
    size: u64,
    capacity: u32,
    value_kind: u32,
    bytes: &[u8],
) -> Checked<u32> {
    // Snapshot construction bounds value lengths to MAX_VALUE_BYTES.
    let required = bytes.len() as u32;
    let too_small = data != 0 && capacity < required;
    if kind != 0 {
        probe_write(c, kind, 4)?;
    }
    if size != 0 {
        probe_write(c, size, 4)?;
    }
    if data != 0 && !too_small {
        c.mem().wr(data, bytes)?;
    }
    if kind != 0 {
        c.mem().w32(kind, value_kind)?;
    }
    if size != 0 {
        c.mem().w32(size, required)?;
    }
    Ok(if too_small { ERROR_MORE_DATA } else { 0 })
}

#[cfg(test)]
mod tests;
