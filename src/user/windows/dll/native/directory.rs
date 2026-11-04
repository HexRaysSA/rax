//! Snapshot-backed directory/link/section opens with measured native/WoW64 capture order.
use super::query::{guard_result, probe_write, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::{Directory, LookupError};
use crate::user::windows::objects::Object;
use std::sync::Arc;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Directory,
    Link,
    Section,
}
impl Kind {
    fn valid_flags(self) -> u32 {
        if self == Self::Section {
            0x11FF2
        } else {
            0x1FF2
        }
    }
}
enum Failure {
    Status(u32),
    Api(ApiErr),
}
type Checked<T> = Result<T, Failure>;
impl From<MemFault> for Failure {
    fn from(f: MemFault) -> Self {
        Self::Api(f.into())
    }
}
impl From<ApiErr> for Failure {
    fn from(e: ApiErr) -> Self {
        Self::Api(e)
    }
}
fn status<T>(s: u32) -> Checked<T> {
    Err(Failure::Status(s))
}
fn finish(c: &mut Ctx, result: Checked<u32>) -> ApiResult {
    finish_with(c, result, false)
}
fn finish_with(c: &mut Ctx, result: Checked<u32>, write: bool) -> ApiResult {
    let result = match result {
        Ok(s) | Err(Failure::Status(s)) => Flow::ret(s.into()),
        Err(Failure::Api(e)) => Err(e),
    };
    let result = if write {
        write_guard_result(c, result)
    } else {
        guard_result(c, result)
    };
    match result {
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        r => r,
    }
}
struct Name {
    length: usize,
    buffer: u64,
}
struct Attributes {
    root: u64,
    name: Option<Name>,
    flags: u32,
    security: u64,
    qos: Option<Vec<u8>>,
}
fn name(c: &Ctx, address: u64, wow: bool) -> Checked<Option<Name>> {
    if address == 0 {
        return Ok(None);
    }
    let size = if c.psize() == 4 { 8 } else { 16 };
    if !wow {
        c.mem().bytes(address, size)?;
    }
    let length = c.mem().u16(address)? as usize;
    if wow {
        // The converter copies MaximumLength even though the NT open ignores it.
        c.mem().u16(address + 2)?;
    }
    Ok(Some(Name {
        length,
        buffer: c.read_ptr(address + if c.psize() == 4 { 4 } else { 8 })?,
    }))
}
fn capture(c: &mut Ctx, address: u64, wow: bool, kind: Kind) -> Checked<Option<Attributes>> {
    if address == 0 {
        return Ok(None);
    }
    let size = if wow { 24 } else { 48 };
    if !wow && address % 8 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    if wow && c.mem().u32(address)? != size {
        return status(STATUS_INVALID_PARAMETER);
    }
    if !wow {
        c.mem().bytes(address, size as usize)?;
    }
    if c.mem().u32(address)? != size {
        return status(STATUS_INVALID_PARAMETER);
    }
    let offset = if wow { 4 } else { 8 };
    let root = c.read_ptr(address + offset)?;
    let np = c.read_ptr(address + offset + c.psize())?;
    // WoW64 follows ObjectName before reading the remaining attributes fields.
    // A descriptor guard can therefore precede an attributes tail access fault.
    let converted_name = if wow { Some(name(c, np, true)?) } else { None };
    let flags = c.mem().u32(address + offset + c.psize() * 2)?;
    let security = c.read_ptr(address + if wow { 16 } else { 32 })?;
    let qp = c.read_ptr(address + if wow { 20 } else { 40 })?;
    // Native validates attributes before following any subordinate pointers.
    // WoW64 first converts its descriptors and pointed-to security/QoS headers.
    if !wow && flags & !kind.valid_flags() != 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let qos = if qp == 0 {
        None
    } else {
        if !wow && qp % 4 != 0 {
            return status(STATUS_DATATYPE_MISALIGNMENT);
        }
        Some(c.mem().bytes(qp, 12)?)
    };
    if security != 0 {
        if !wow && security % 4 != 0 {
            return status(STATUS_DATATYPE_MISALIGNMENT);
        }
        if wow {
            c.mem().bytes(security, 20)?;
        }
    }
    let name = match converted_name {
        Some(name) => name,
        None => name(c, np, false)?,
    };
    Ok(Some(Attributes {
        root,
        name,
        flags,
        security,
        qos,
    }))
}
fn root(c: &Ctx, handle: u64, absolute: bool) -> Checked<Arc<Directory>> {
    let pseudo = handle == c.arch().ptr(u64::MAX) || handle == c.arch().ptr(u64::MAX - 1);
    let object = c.p.objects.get(handle);
    if !pseudo && object.is_none() {
        return status(STATUS_INVALID_HANDLE);
    }
    if absolute {
        return status(STATUS_OBJECT_PATH_SYNTAX_BAD);
    }
    match object {
        Some(Object::Directory(d)) => Ok(d.clone()),
        _ => status(STATUS_OBJECT_TYPE_MISMATCH),
    }
}
fn open_object(c: &mut Ctx, access: u32, attrs: Option<Attributes>, kind: Kind) -> Checked<u32> {
    let link = kind == Kind::Link;
    let Some(attrs) = attrs else {
        return status(STATUS_INVALID_PARAMETER);
    };
    if attrs.flags & !kind.valid_flags() != 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    if let Some(qos) = attrs.qos {
        let length = u32::from_le_bytes(qos[..4].try_into().unwrap());
        let level = u32::from_le_bytes(qos[4..8].try_into().unwrap());
        if length != 12 || level != 2 || qos[8] != 0 || qos[9] != 0 {
            return Err(c
                .unsupported("NT directory security QoS outside captured initialization profile")
                .into());
        }
    }
    if attrs.security != 0 {
        if c.mem().u8(attrs.security)? != 1 {
            return status(STATUS_UNKNOWN_REVISION);
        }
        return Err(c
            .unsupported("NT directory security descriptor capture")
            .into());
    }
    let Some(name) = attrs.name else {
        return status(STATUS_OBJECT_PATH_SYNTAX_BAD);
    };
    // MaximumLength is ignored. Buffer alignment precedes the counted-string
    // length checks; an empty string neither aligns nor probes its Buffer.
    if name.length != 0 && name.buffer % 2 != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    if name.length % 2 != 0 || name.length >= 65534 {
        return status(STATUS_OBJECT_NAME_INVALID);
    }
    let bytes = c.mem().bytes(name.buffer, name.length)?;
    let units: Vec<_> = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    // An empty counted name opens the typed root object itself, including a
    // symbolic-link root. Nonempty link-root traversal remains a type error.
    let selected_link = if link && units.is_empty() {
        match c.p.objects.get(attrs.root) {
            Some(Object::SymbolicLink(l)) => Some(l.clone()),
            _ => None,
        }
    } else {
        None
    };
    // Section parsing follows an empty symbolic-link root. The selected
    // KnownDllPath targets use DOS grammar, which the object manager rejects.
    if kind == Kind::Section
        && units.is_empty()
        && let Some(Object::SymbolicLink(l)) = c.p.objects.get(attrs.root)
    {
        if attrs.flags & 0x1000 != 0 {
            return status(STATUS_REPARSE_POINT_ENCOUNTERED);
        }
        if l.target.first() != Some(&92) {
            return status(STATUS_OBJECT_NAME_INVALID);
        }
        return Err(c
            .unsupported("NT section symbolic-link root outside captured DOS-target profile")
            .into());
    }
    let root = if attrs.root == 0 || selected_link.is_some() {
        None
    } else {
        Some(root(c, attrs.root, units.first() == Some(&(b'\\' as u16)))?)
    };
    if link {
        let resource = match selected_link
            .map(Ok)
            .unwrap_or_else(|| c.p.object_namespace.lookup_link(root, &units, attrs.flags))
        {
            Ok(l) => l,
            Err(LookupError::Status(s)) => return status(s),
            Err(LookupError::Unselected) => {
                return Err(c
                    .unsupported("NT link outside selected installed namespace")
                    .into());
            }
        };
        if attrs.flags & 0x120 != 0 {
            return status(STATUS_INVALID_PARAMETER);
        }
        let grant = resource.grant(access, false).map_err(Failure::Status)?;
        return c
            .p
            .objects
            .open_symbolic_link(resource, attrs.flags & 2 != 0, grant)
            .ok_or(Failure::Status(STATUS_INSUFFICIENT_RESOURCES));
    }
    if kind == Kind::Section {
        let section = match c.p.object_namespace.lookup_installed_section(
            root,
            &units,
            attrs.flags,
            c.arch() == WinArch::X86,
        ) {
            Ok(s) => s,
            Err(LookupError::Status(s)) => return status(s),
            Err(LookupError::Unselected) => {
                return Err(c
                    .unsupported("NT section outside selected installed namespace")
                    .into());
            }
        };
        // OPENLINK rejection precedes authorization, while EXCLUSIVE rejection
        // follows it. Directory/link ordering remains independently captured.
        if attrs.flags & 0x100 != 0 {
            return status(STATUS_INVALID_PARAMETER);
        }
        let grant = section.grant(access, false).map_err(|error| match error {
            crate::user::windows::object_namespace::SectionGrantError::Status(status) => {
                Failure::Status(status)
            }
            crate::user::windows::object_namespace::SectionGrantError::Unavailable(reason) => {
                Failure::Api(c.unsupported(reason))
            }
        })?;
        if attrs.flags & 0x20 != 0 {
            return status(STATUS_INVALID_PARAMETER);
        }
        return c
            .p
            .objects
            .open_selected_section(section, attrs.flags & 2 != 0, grant)
            .ok_or(Failure::Status(STATUS_INSUFFICIENT_RESOURCES));
    }
    let directory = match c.p.object_namespace.lookup(root, &units, attrs.flags) {
        Ok(d) => d,
        Err(LookupError::Status(s)) => return status(s),
        Err(LookupError::Unselected) => {
            return Err(c
                .unsupported("NT directory outside selected installed namespace")
                .into());
        }
    };
    if attrs.flags & 0x120 != 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let grant = directory.grant(access, false).map_err(Failure::Status)?;
    let Some(h) =
        c.p.objects
            .open_directory(directory, attrs.flags & 2 != 0, grant)
    else {
        return status(STATUS_INSUFFICIENT_RESOURCES);
    };
    Ok(h)
}
/// The installed WoW64 converter redirects absolute system paths and expands
/// relative names against queryable root objects before calling the NT service.
/// Its faults precede the temporary output slot and caller-copy phase.
fn wow_redirect_probe(c: &mut Ctx, attrs: &Option<Attributes>) -> Checked<()> {
    let Some(attrs) = attrs else { return Ok(()) };
    let Some(name) = &attrs.name else {
        return Ok(());
    };
    if attrs.root != 0 {
        let root_bytes = match c.p.objects.get(attrs.root) {
            Some(Object::Directory(d)) => d.path.len() * 2,
            Some(Object::SymbolicLink(l)) => l.path.len() * 2,
            Some(Object::ImageSection(s)) => s.path.len() * 2,
            Some(Object::DataSection(s)) => s.path.len() * 2,
            Some(Object::FileSection(_)) => 0,
            // Native pseudo process/thread objects have an empty queried name.
            None if attrs.root == c.arch().ptr(u64::MAX)
                || attrs.root == c.arch().ptr(u64::MAX - 1) =>
            {
                0
            }
            _ => return Ok(()),
        };
        if root_bytes + name.length + 2 <= 65534 {
            c.mem().bytes(name.buffer, name.length)?;
        }
        return Ok(());
    }
    // Exact u16 arithmetic in the converter's temporary UNICODE_STRING capacity.
    if name.length > (name.length as u16).wrapping_add(26) as usize {
        return Ok(());
    }
    let prefix = &c.p.object_namespace.wow_system_prefix;
    if prefix.is_empty() || name.length < prefix.len() * 2 {
        return Ok(());
    }
    let insensitive = attrs.flags & 0x40 != 0;
    if insensitive {
        for (index, &unit) in prefix.iter().enumerate() {
            let actual = c.mem().u16(name.buffer + (index * 2) as u64)?;
            if !c.p.object_namespace.equal_unit(actual, unit, true) {
                return Ok(());
            }
        }
    } else {
        // The measured loaded caller reads a full initial 16-byte block for
        // case-sensitive prefix comparison, including unaligned crossings.
        // Case-insensitive comparison above instead short-circuits by WCHAR.
        let expected: Vec<_> = prefix.iter().flat_map(|u| u.to_le_bytes()).collect();
        let mut offset = 0;
        for width in [16, 8, 1] {
            while expected.len() - offset >= width {
                let actual = c.mem().bytes(name.buffer + offset as u64, width)?;
                if actual != expected[offset..offset + width] {
                    return Ok(());
                }
                offset += width;
            }
        }
    }
    Err(c
        .unsupported("WoW64 system-path redirection outside selected NT directories")
        .into())
}
fn publish(c: &mut Ctx, out: u64, result: Checked<u32>, kind: Kind) -> ApiResult {
    let caller_store = kind == Kind::Section && c.arch() == WinArch::X86;
    let (status, handle) = match result {
        Ok(h) => (0, Some(h)),
        Err(Failure::Status(s)) => (s, None),
        Err(Failure::Api(e)) => {
            let flow = finish(c, Err(Failure::Api(e)))?;
            let Flow::Ret(crate::user::windows::hle::Value::Int(s)) = flow else {
                return Ok(flow);
            };
            (s as u32, None)
        }
    };
    if let Err(fault) = probe_write(c, out, c.psize() as usize) {
        if let Some(h) = handle {
            let _ = c.p.objects.close(u64::from(h));
        }
        return finish_with(c, Err(fault.into()), caller_store);
    }
    if let Err(e) = c.write_ptr(out, handle.map_or(0, u64::from)) {
        if let Some(h) = handle {
            let _ = c.p.objects.close(u64::from(h));
        }
        return finish_with(c, Err(e.into()), caller_store);
    }
    Flow::ret(status.into())
}
pub(super) fn open(c: &mut Ctx) -> ApiResult {
    open_selected(c, Kind::Directory)
}
pub(super) fn open_link(c: &mut Ctx) -> ApiResult {
    open_selected(c, Kind::Link)
}
pub(super) fn open_section(c: &mut Ctx) -> ApiResult {
    open_selected(c, Kind::Section)
}
fn open_selected(c: &mut Ctx, kind: Kind) -> ApiResult {
    let (out, access, address) = (c.ptr(0)?, c.u32(1)?, c.ptr(2)?);
    let wow = c.arch() == WinArch::X86;
    if !wow {
        // Native64 passes the caller's pointer directly to the NT service.
        if let Err(e) = probe_write(c, out, c.psize() as usize) {
            return finish(c, Err(e.into()));
        }
    }
    let attrs = match capture(c, address, wow, kind) {
        Ok(a) => a,
        Err(e) => {
            if wow {
                return finish(c, Err(e));
            }
            return publish(c, out, Err(e), kind);
        }
    };
    if wow {
        if let Err(e) = wow_redirect_probe(c, &attrs) {
            return finish(c, Err(e));
        }
        // A NULL caller output selects a NULL native output, while non-NULL
        // callers use the converter's valid temporary HANDLE and later copy-out.
        if out == 0 {
            return finish(c, status(STATUS_ACCESS_VIOLATION));
        }
    }
    let result = open_object(c, access, attrs, kind);
    publish(c, out, result, kind)
}
