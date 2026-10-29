//! Snapshot-backed runtime registry reads. Native64 and WoW64 capture/probe order
//! follows captured ARM64 and AMD64 kernel profiles under docs/specifications.
//! No guest path, access mask or handle reaches a host registry service.
use super::query::{guard_result, probe_write};
use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use crate::user::windows::registry::{Key, Lookup, RegistryView, Value};
use std::sync::Arc;

const READ_ACCESS: u32 = 0x0002_0019;
const MAX_CONVERSION_BYTES: usize = 16 << 20;

#[path = "registry/key_enumeration.rs"]
mod key_enumeration;
pub(super) use key_enumeration::enumerate_key;

#[path = "registry/key_query.rs"]
mod key_query;
pub(super) use key_query::query_key;

#[path = "registry/key_set.rs"]
mod key_set;
pub(super) use key_set::set_key;

enum Failure {
    Status(u32),
    Api(ApiErr),
}
type Checked<T> = Result<T, Failure>;
impl From<ApiErr> for Failure {
    fn from(error: ApiErr) -> Self {
        Self::Api(error)
    }
}
impl From<MemFault> for Failure {
    fn from(error: MemFault) -> Self {
        Self::Api(error.into())
    }
}
fn finish(c: &mut Ctx, result: Checked<u32>) -> ApiResult {
    let result = match result {
        Ok(status) | Err(Failure::Status(status)) => Flow::ret(status.into()),
        Err(Failure::Api(error)) => Err(error),
    };
    match guard_result(c, result) {
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        result => result,
    }
}
fn status<T>(value: u32) -> Checked<T> {
    Err(Failure::Status(value))
}

#[derive(Clone)]
struct Descriptor {
    length: usize,
    buffer: u64,
}
struct Name {
    units: Vec<u16>,
    odd: bool,
}
fn name(c: &Ctx, address: u64) -> Checked<Descriptor> {
    // UNICODE_STRING is captured byte-wise, including an unaligned descriptor.
    // MaximumLength is not consulted by the recorded query/open profile.
    let length = c.mem().u16(address)? as usize;
    let buffer = c.read_ptr(address + if c.psize() == 4 { 4 } else { 8 })?;
    Ok(Descriptor { length, buffer })
}
fn text(c: &Ctx, descriptor: Descriptor, wow_open: bool) -> Checked<Name> {
    let Descriptor { length, buffer } = descriptor;
    // Query thunks widen the descriptor, not its text. Native entry validates
    // odd Length before Buffer probing; WoW64 OBJECT_ATTRIBUTES conversion
    // instead copies name bytes before native open/output validation.
    if !wow_open && length % 2 != 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let bytes = c.mem().bytes(buffer, length)?;
    Ok(Name {
        units: bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect(),
        odd: length % 2 != 0,
    })
}
struct Attributes {
    root: u64,
    name: Name,
    flags: u32,
}
fn odd_open_name_status(c: &Ctx) -> Checked<u32> {
    let Some(native) = &c.p.native else {
        // The built-in personality retains its original ARM64-derived profile.
        return Ok(STATUS_INVALID_PARAMETER);
    };
    match (
        native.version.major,
        native.version.minor,
        native.version.build,
        native.object_namespace.native_machine,
    ) {
        (10, 0, 20348 | 26100, Some(0x8664)) => Ok(STATUS_OBJECT_NAME_INVALID),
        (10, 0, 29683 | 29695, Some(0xAA64)) => Ok(STATUS_INVALID_PARAMETER),
        _ => Err(c
            .unsupported("registry odd key-name kernel profile is not captured")
            .into()),
    }
}
fn attributes(c: &Ctx, address: u64) -> Checked<Attributes> {
    let wow = c.arch() == WinArch::X86;
    let size = if wow { 24 } else { 48 };
    if !wow && address % 8 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    if wow && c.mem().u32(address)? != size {
        return status(STATUS_INVALID_PARAMETER);
    }
    c.mem()
        .probe(address, size as usize, MemoryAccessKind::Read)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: false,
        })?;
    if c.mem().u32(address)? != size {
        return status(STATUS_INVALID_PARAMETER);
    }
    let offset = if wow { 4 } else { 8 };
    let root = c.read_ptr(address + offset)?;
    let object_name = c.read_ptr(address + offset + c.psize())?;
    let flags = c.mem().u32(address + offset + c.psize() * 2)?;
    let security = c.read_ptr(address + if wow { 16 } else { 32 })?;
    let qos = c.read_ptr(address + if wow { 20 } else { 40 })?;
    for (pointer, description) in [
        (security, "registry security descriptor"),
        (qos, "registry security QoS"),
    ] {
        if pointer != 0 {
            if !wow && pointer % 4 != 0 {
                return status(STATUS_DATATYPE_MISALIGNMENT);
            }
            // WoW64 captures pointed-to security structures before output.
            c.mem().u32(pointer)?;
            return Err(c.unsupported(description).into());
        }
    }
    let descriptor = name(c, object_name)?;
    if !wow && descriptor.length % 2 != 0 {
        return status(odd_open_name_status(c)?);
    }
    if !wow && descriptor.length != 0 && descriptor.length % 2 == 0 && descriptor.buffer % 2 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    Ok(Attributes {
        root,
        name: text(c, descriptor, wow)?,
        flags,
    })
}
fn key(c: &Ctx, handle: u64, query: bool) -> Checked<Arc<Key>> {
    if handle == c.arch().ptr(u64::MAX) || handle == c.arch().ptr(u64::MAX - 1) {
        return status(STATUS_OBJECT_TYPE_MISMATCH);
    }
    let Some(object) = c.p.objects.get(handle) else {
        return status(STATUS_INVALID_HANDLE);
    };
    let Object::Key(key) = object else {
        return status(STATUS_OBJECT_TYPE_MISMATCH);
    };
    if query && c.p.objects.access(handle).unwrap_or(0) & 1 == 0 {
        return status(STATUS_ACCESS_DENIED);
    }
    Ok(key.clone())
}
fn grant(c: &Ctx, access: u32) -> Checked<u32> {
    if c.arch() == WinArch::X86 && access & 0x300 == 0x300 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let access = access & !0x300; // View flags select snapshots; they are not granted rights.
    if access == 0 || access & !(READ_ACCESS | 0xA200_0000) != 0 {
        return status(STATUS_ACCESS_DENIED);
    }
    Ok(if access & 0xA200_0000 != 0 {
        READ_ACCESS
    } else {
        access
    })
}

fn open_grant(c: &Ctx, access: u32, options: u32, selected: &Key) -> Checked<u32> {
    if c.arch() == WinArch::X86 && access & 0x300 == 0x300 {
        return status(STATUS_INVALID_PARAMETER);
    }
    if options & 4 == 0 {
        if let Some(profile) = selected.captured_access() {
            return match profile.grant(access) {
                Ok(granted) => Ok(granted),
                Err(code) => status(code),
            };
        }
        return grant(c, access);
    }
    let subject =
        c.p.objects.primary_token_subject().ok_or_else(|| {
            c.unsupported("registry backup/restore token subject is not captured")
        })?;
    // The current thread-token attachment boundary keeps this the captured
    // primary subject. Native controls use a separately duplicated token.
    let enabled = |luid| {
        subject
            .privileges
            .iter()
            .any(|privilege| privilege.luid == luid && privilege.attributes & 2 != 0)
    };
    let granted =
        if enabled(17) { 0x0102_0019 } else { 0 } | if enabled(18) { 0x010F_0006 } else { 0 };
    if granted == 0 {
        status(STATUS_ACCESS_DENIED)
    } else {
        Ok(granted)
    }
}

#[path = "registry/key_tags.rs"]
mod key_tags;
use key_tags::RelativeOpen;

// Retained native parent graphs also exercise this common conversion policy.
#[cfg(test)]
fn command_reopen_tags(
    wow: bool,
    parent: u32,
    parent_view: RegistryView,
    requested: u32,
) -> Option<u32> {
    Some(RelativeOpen::new(wow, parent, requested)?.tags(
        false,
        parent_view == RegistryView::Wow32,
        false,
    ))
}

#[cfg(test)]
#[path = "registry/system_command_tests.rs"]
mod system_command_tests;

pub(super) fn open(c: &mut Ctx) -> ApiResult {
    let result = open_checked(c, 0);
    finish(c, result)
}
pub(super) fn open_ex(c: &mut Ctx) -> ApiResult {
    let options = c.u32(3)?;
    let result = open_checked(c, options);
    finish(c, result)
}
fn open_checked(c: &mut Ctx, options: u32) -> Checked<u32> {
    let (out, access, attrs) = (c.ptr(0)?, c.u32(1)?, c.ptr(2)?);
    let wow = c.arch() == WinArch::X86;
    if !wow && options & !0x1C != 0 {
        return status(STATUS_INVALID_PARAMETER_4);
    }
    let attrs = if wow {
        attributes(c, attrs)?
    } else {
        probe_write(c, out, c.psize() as usize)?;
        c.write_ptr(out, 0)?;
        attributes(c, attrs)?
    };
    if wow && out != 0 {
        probe_write(c, out, 4)?;
        c.write_ptr(out, 0)?;
    }
    let absolute = attrs.name.units.first() == Some(&(b'\\' as u16));
    if wow && attrs.root != 0 && absolute {
        return status(STATUS_OBJECT_PATH_SYNTAX_BAD);
    }
    if wow && access & 0x300 == 0x300 {
        return status(STATUS_INVALID_PARAMETER);
    }
    if wow && attrs.root != 0 {
        // The thunk resolves a relative root before native option validation.
        // Absolute syntax and contradictory views still precede this lookup.
        key(c, attrs.root, false)?;
    }
    if options & !0x1C != 0 {
        return status(STATUS_INVALID_PARAMETER_4);
    }
    if attrs.flags & !0x1FF2 != 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    if attrs.name.odd {
        return status(odd_open_name_status(c)?);
    }
    if attrs.flags & 0x100 != 0 {
        return Err(c
            .unsupported("registry link-source metadata is not captured")
            .into());
    }
    let views;
    let mut relative = None;
    let mut physical_wow = false;
    let mut control_set_alias = false;
    let selected = if attrs.root != 0 {
        // The compatibility thunk rejects an absolute rooted name before the
        // native object manager checks the root handle's validity/type.
        if wow && absolute {
            return status(STATUS_OBJECT_PATH_SYNTAX_BAD);
        }
        if absolute && c.p.objects.get(attrs.root).is_some() {
            return status(STATUS_OBJECT_PATH_SYNTAX_BAD);
        }
        let root = key(c, attrs.root, false)?;
        if absolute {
            return status(STATUS_OBJECT_PATH_SYNTAX_BAD);
        }
        if let Some(tags) = c.p.objects.registry_tags(attrs.root) {
            relative = Some(match RelativeOpen::new(wow, tags, access & 0x300) {
                Some(state) => state,
                None => return status(STATUS_INVALID_PARAMETER),
            });
        }
        physical_wow = root.redirected_view == Some(RegistryView::Wow32)
            && root.command_physical_name(&root.path);
        if root.is_machine_hive() {
            let folded = root.fold(&attrs.name.units);
            let mut parts = folded.split(|u| *u == 92).filter(|part| !part.is_empty());
            control_set_alias = parts
                .next()
                .is_some_and(|part| part.iter().copied().eq("SYSTEM".encode_utf16()))
                && parts.next().is_some_and(|part| {
                    part.iter().copied().eq("CURRENTCONTROLSET".encode_utf16())
                });
        }
        let selected = if let Some(catalog) = root.hive_views() {
            views = Some(catalog);
            let view = if wow {
                relative
                    .as_ref()
                    .ok_or_else(|| c.unsupported("parent key tags are not captured"))?
                    .view()
            } else {
                RegistryView::Native64
            };
            root.relative_in_view(&attrs.name.units, view)
        } else if wow
            && relative.as_ref().map_or(access & 0x200 != 0, |state| {
                state.view() == RegistryView::Wow32
            })
            && root.redirected_view == Some(RegistryView::Native64)
        {
            let captured = c.p.objects.registry_views(attrs.root).ok_or_else(|| {
                c.unsupported("AppModel relative registry views are not captured")
            })?;
            let selected = captured.relative(&root, &attrs.name.units, RegistryView::Wow32);
            views = Some(captured);
            selected
        } else {
            views = c.p.objects.registry_views(attrs.root);
            root.relative(&attrs.name.units)
        };
        match selected {
            Lookup::Present(key) => key,
            Lookup::Missing => return status(STATUS_OBJECT_NAME_NOT_FOUND),
            Lookup::MissingPath => return status(STATUS_OBJECT_PATH_NOT_FOUND),
            Lookup::Unselected => {
                return Err(c.unsupported("unsnapshotted registry subkey").into());
            }
        }
    } else {
        if !absolute {
            return status(STATUS_OBJECT_PATH_SYNTAX_BAD);
        }
        let view = if wow && access & 0x100 == 0 {
            RegistryView::Wow32
        } else {
            RegistryView::Native64
        };
        views = Some(c.p.registry.views.clone());
        match c.p.registry.lookup_view(&attrs.name.units, view) {
            Lookup::Present(key) => key,
            Lookup::Missing => return status(STATUS_OBJECT_NAME_NOT_FOUND),
            Lookup::MissingPath => return status(STATUS_OBJECT_PATH_NOT_FOUND),
            Lookup::Unselected => {
                return Err(c
                    .unsupported("registry key outside selected runtime snapshot")
                    .into());
            }
        }
    };
    // Native controls distinguish OBJ_OPENLINK above from OpenOptions bit8.
    // The admitted option alone retains the ordinary resolved-key behavior.
    // Relative opens consume key-body state. Absolute opens establish native
    // initial tags; contradictory WoW64 views were rejected before selection.
    let redirected = selected.redirected_view.is_some();
    let tags = if let Some(relative) = &relative {
        relative.tags(
            selected.is_machine_hive(),
            physical_wow || selected.command_physical_name(&attrs.name.units),
            control_set_alias,
        )
    } else if wow {
        let requested = access & 0x300;
        if selected.is_machine_hive() || selected.logical_hive_alias(&attrs.name.units) {
            requested
        } else if selected.command_physical_name(&attrs.name.units) {
            if requested == 0x100 { 0x100 } else { 0xE00 }
        } else {
            requested | if requested == 0x100 { 0 } else { 0x400 }
        }
    } else {
        0
    };
    let access = open_grant(c, access, options, &selected)?;
    // Redirected WoW64 key-body metadata is not inferred from the shared-key
    // formula. Keep it explicitly uncaptured until a present-root oracle exists.
    let id = if redirected && wow && selected.command_access().is_none() {
        c.p.objects.create_registry_key_metadata(selected, None)
    } else {
        c.p.objects.create_registry_key(selected, tags)
    };
    let Some(id) = id else {
        return status(STATUS_INSUFFICIENT_RESOURCES);
    };
    if redirected {
        if let Some(views) = views {
            c.p.objects.set_registry_views(id, views);
        }
    }
    let Some(handle) = c.p.objects.open_access(id, attrs.flags & 2 != 0, access) else {
        c.p.objects.release(id);
        return status(STATUS_INSUFFICIENT_RESOURCES);
    };
    if let Err(fault) = c.write_ptr(out, u64::from(handle)) {
        // The measured WoW64 NULL-output successful open leaks its handle.
        // A NULL output on an earlier failure skips copy-back entirely.
        if !wow || out != 0 {
            let _ = c.p.objects.close(u64::from(handle));
        }
        return Err(fault.into());
    }
    Ok(STATUS_SUCCESS)
}

pub(super) fn query(c: &mut Ctx) -> ApiResult {
    let result = query_checked(c);
    // query_checked may already have consumed the native guard before a
    // compatibility copy-out. finish only consumes a subsequent copy fault.
    finish(c, result)
}
fn query_checked(c: &mut Ctx) -> Checked<u32> {
    let (handle, address, class, out, length, returned) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.u32(2)?,
        c.ptr(3)?,
        c.u32(4)?,
        c.ptr(5)?,
    );
    let captured = if c.arch() == WinArch::X86 && address != 0 {
        Some(name(c, address)?)
    } else {
        None
    };
    let converted =
        c.arch() == WinArch::X86 && (out % 4 != 0 || matches!(class, 3 | 4) && out % 8 != 0);
    let mut scratch = if converted {
        if length as usize > MAX_CONVERSION_BYTES {
            return Err(c
                .unsupported("WoW64 registry conversion exceeds 16 MiB")
                .into());
        }
        // Host WoW64 copies undefined scratch tails and error bytes. A private
        // zero-initialized buffer preserves defined output without exposing
        // host allocator contents; those undefined bytes are not an oracle.
        Some(vec![0; length as usize])
    } else {
        None
    };
    let result = query_value(
        c,
        handle,
        address,
        captured,
        class,
        out,
        length,
        returned,
        scratch.as_deref_mut(),
    );
    if let Some(scratch) = scratch {
        let result = match result {
            Err(Failure::Api(ApiErr::Fault(fault))) if c.p.vm.take_guard(fault.addr) => {
                Ok(STATUS_GUARD_PAGE_VIOLATION)
            }
            result => result,
        };
        write_pages(c, out, &scratch)?;
        result
    } else {
        result
    }
}
#[allow(clippy::too_many_arguments)]
fn query_value(
    c: &Ctx,
    handle: u64,
    address: u64,
    captured: Option<Descriptor>,
    class: u32,
    out: u64,
    length: u32,
    returned: u64,
    scratch: Option<&mut [u8]>,
) -> Checked<u32> {
    if class > 4 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let key = key(c, handle, true)?;
    let descriptor = match captured {
        Some(name) => name,
        None => name(c, address)?,
    };
    let name = text(c, descriptor, false)?;
    let value = key
        .value(&name.units)
        .ok_or(Failure::Status(STATUS_OBJECT_NAME_NOT_FOUND))?;
    // Native64 probes ULONG alignment for every admitted class when Length
    // is nonzero, including a buffer too short for its fixed header.
    if scratch.is_none() && length != 0 && out % 4 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    let mut bytes = encode(value, class);
    probe_write(c, returned, 4)?;
    c.mem().w32(returned, bytes.len() as u32)?;
    let header = match class {
        0 | 2 => 12,
        1 | 3 => 20,
        4 => 8,
        _ => unreachable!(),
    };
    if length < header {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    let n = (length as usize).min(bytes.len());
    let name_bytes = value.name.len() * 2;
    if matches!(class, 0 | 1 | 3)
        && n > header as usize
        && n < header as usize + name_bytes
        && (n - header as usize) % 2 != 0
    {
        // Native Unicode-name copy retains complete WCHARs and zeroes the
        // leftover byte. Raw value data instead retains its byte prefix.
        bytes[n - 1] = 0;
    }
    if let Some(scratch) = scratch {
        scratch[..n].copy_from_slice(&bytes[..n]);
    } else {
        write_pages(c, out, &bytes[..n])?;
    }
    Ok(if n < bytes.len() {
        STATUS_BUFFER_OVERFLOW
    } else {
        STATUS_SUCCESS
    })
}
fn encode(value: &Value, class: u32) -> Vec<u8> {
    let name: Vec<u8> = value.name.iter().flat_map(|u| u.to_le_bytes()).collect();
    let mut result = Vec::new();
    let words: Vec<u32> = match class {
        0 => vec![0, value.kind, name.len() as u32],
        1 | 3 => vec![
            0,
            value.kind,
            ((20 + name.len() + 7) & !7) as u32,
            value.data.len() as u32,
            name.len() as u32,
        ],
        2 => vec![0, value.kind, value.data.len() as u32],
        4 => vec![value.kind, value.data.len() as u32],
        _ => unreachable!(),
    };
    for word in words {
        result.extend_from_slice(&word.to_le_bytes());
    }
    if matches!(class, 0 | 1 | 3) {
        result.extend_from_slice(&name);
    }
    if matches!(class, 1 | 3) {
        result.resize((result.len() + 7) & !7, 0);
    }
    if class != 0 {
        result.extend_from_slice(&value.data);
    }
    result
}
/// Copy only the defined prefix, in ascending page order. An inaccessible
/// later page preserves earlier writes, unlike AddressSpace::write's whole
/// range preflight. O(B + P) time and O(1) extra space for B bytes/P pages.
fn write_pages(c: &Ctx, mut address: u64, mut bytes: &[u8]) -> Result<(), MemFault> {
    while !bytes.is_empty() {
        let n = bytes.len().min((PAGE_SIZE - address % PAGE_SIZE) as usize);
        c.mem().wr(address, &bytes[..n])?;
        bytes = &bytes[n..];
        if !bytes.is_empty() {
            address = address.checked_add(n as u64).ok_or(MemFault {
                addr: u64::MAX,
                write: true,
            })?;
        }
    }
    Ok(())
}
