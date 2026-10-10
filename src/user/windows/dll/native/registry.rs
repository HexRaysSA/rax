//! Snapshot-backed runtime registry reads. Native64 and WoW64 capture/probe order
//! follows the build29683 observations retained under docs/specifications.
//! No guest path, access mask or handle reaches a host registry service.
use super::query::{guard_result, probe_write};
use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use crate::user::windows::registry::{Key, Value};
use std::sync::Arc;

const READ_ACCESS: u32 = 0x0002_0019;
const MAX_CONVERSION_BYTES: usize = 16 << 20;

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
    Ok(Attributes {
        root,
        name: text(c, name(c, object_name)?, wow)?,
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
    let access = access & !0x300; // Fixed SYSTEM keys are shared between views.
    if access == 0 || access & !(READ_ACCESS | 0xA200_0000) != 0 {
        return status(STATUS_ACCESS_DENIED);
    }
    Ok(if access & 0xA200_0000 != 0 {
        READ_ACCESS
    } else {
        access
    })
}

pub(super) fn open(c: &mut Ctx) -> ApiResult {
    let result = open_checked(c);
    finish(c, result)
}
fn open_checked(c: &mut Ctx) -> Checked<u32> {
    let (out, access, attrs) = (c.ptr(0)?, c.u32(1)?, c.ptr(2)?);
    let wow = c.arch() == WinArch::X86;
    let attrs = if wow {
        attributes(c, attrs)?
    } else {
        probe_write(c, out, c.psize() as usize)?;
        c.write_ptr(out, 0)?;
        attributes(c, attrs)?
    };
    if wow {
        probe_write(c, out, 4)?;
        c.write_ptr(out, 0)?;
    }
    if attrs.flags & !0x1EF2 != 0 || attrs.name.odd {
        return status(STATUS_INVALID_PARAMETER);
    }
    let absolute = attrs.name.units.first() == Some(&(b'\\' as u16));
    let selected = if attrs.root != 0 {
        // The compatibility thunk rejects an absolute rooted name before the
        // native object manager checks the root handle's validity/type.
        if wow && absolute {
            return status(STATUS_OBJECT_PATH_SYNTAX_BAD);
        }
        let root = key(c, attrs.root, false)?;
        if absolute {
            return status(STATUS_OBJECT_PATH_SYNTAX_BAD);
        }
        if attrs.name.units.is_empty() {
            root
        } else if root.children == 0 {
            return status(STATUS_OBJECT_NAME_NOT_FOUND);
        } else {
            return Err(c.unsupported("unsnapshotted registry subkey").into());
        }
    } else {
        if !absolute {
            return status(STATUS_OBJECT_PATH_SYNTAX_BAD);
        }
        c.p.registry.key(&attrs.name.units).ok_or_else(|| {
            Failure::Api(c.unsupported("registry key outside selected runtime snapshot"))
        })?
    };
    let access = grant(c, access)?;
    let Some(id) = c.p.objects.try_create(Object::Key(selected)) else {
        return status(STATUS_INSUFFICIENT_RESOURCES);
    };
    let Some(handle) = c.p.objects.open_access(id, attrs.flags & 2 != 0, access) else {
        c.p.objects.release(id);
        return status(STATUS_INSUFFICIENT_RESOURCES);
    };
    if let Err(fault) = c.write_ptr(out, u64::from(handle)) {
        let _ = c.p.objects.close(u64::from(handle));
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
