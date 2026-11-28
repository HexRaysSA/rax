//! Guest-owned pagefile sections with temporary names in selected directories.
//! No guest pointer, handle, name or argument is forwarded to a host NT call.
use super::named_object;
use super::object_create::{self, Attributes};
use super::query::{guard_result, probe_write};
use crate::user::mm::{PAGE_SIZE, SharedObject};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{GameOsPhysicalSection, Mem};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use std::sync::Arc;
mod file;
mod named;
pub(super) use named::open as open_named;

const KIND: &str = "pagefile section";
const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
const SEC_RESERVE: u32 = 0x0400_0000;
const SEC_PARTITION_OWNER_HANDLE: u32 = 0x0004_0000;
const SEC_64K_PAGES: u32 = 0x0008_0000;
const SEC_COMMIT: u32 = 0x0800_0000;
const SEC_IMAGE: u32 = 0x0100_0000;
const SEC_NOCACHE: u32 = 0x1000_0000;
const SEC_WRITECOMBINE: u32 = 0x4000_0000;
const OUTER_ALLOCATION_BITS: u32 = 0xDD6E_007F;
const SEC_LARGE_PAGES: u32 = 0x8000_0000;
const MAX_BACKING_BYTES: u64 = 64 << 20;

pub(super) fn create(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    guard_result(c, result)
}

pub(super) fn create_ex(c: &mut Ctx) -> ApiResult {
    let result = checked_ex(c);
    guard_result(c, result)
}

fn checked_ex(c: &mut Ctx) -> ApiResult {
    let parameters = c.ptr(7)?;
    let count = c.u32(8)?;
    if count == 0 && c.u32(5)? & SEC_PARTITION_OWNER_HANDLE == 0 {
        return checked(c);
    }
    let attributes = c.u32(5)?;
    if !super::super::gameos::enabled(c)
        || attributes != SEC_RESERVE | SEC_PARTITION_OWNER_HANDLE | SEC_64K_PAGES
        || count != 1
    {
        return Err(c.unsupported(format!(
            "NtCreateSectionEx allocation attributes {attributes:#x}, extended parameter count {count}"
        )));
    }
    let (out, access, object, maximum, protection, owner) = (
        c.ptr(0)?,
        c.u32(1)?,
        c.ptr(2)?,
        c.ptr(3)?,
        c.u32(4)?,
        c.ptr(6)?,
    );
    if object != 0 || access & !SECTION_ALL_ACCESS != 0 || protection != 4 {
        return Err(c.unsupported("NtCreateSectionEx physical section creation parameters"));
    }
    if parameters % 8 != 0 || maximum % 8 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    probe_write(c, out, c.psize() as usize)?;
    // XMem creates the partition's user-physical section using a zero
    // maximum size and a single {type: 1, flags: 1} record.
    if maximum == 0 || c.mem().u64(maximum)? != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER_4.into());
    }
    let record = c.mem().bytes(parameters, 16)?;
    if record[..8] != 1u64.to_le_bytes() || record[8..] != 1u64.to_le_bytes() {
        return Err(c.unsupported("NtCreateSectionEx physical section extended parameter"));
    }
    let partition_id = match c.p.objects.get(owner) {
        Some(Object::MemoryPartition { partition_id }) => *partition_id,
        Some(_) => return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into()),
        None => return Flow::ret(STATUS_INVALID_HANDLE.into()),
    };
    object_create::publish(
        c,
        out,
        false,
        access,
        Object::GameOsPhysicalSection(Arc::new(GameOsPhysicalSection { partition_id })),
    )
}
#[derive(Clone, Copy)]
struct Request {
    out: u64,
    access: u32,
    object: u64,
    maximum: u64,
    protection: u32,
    attributes: u32,
    file: u64,
}
fn checked(c: &mut Ctx) -> ApiResult {
    let request = Request {
        out: c.ptr(0)?,
        access: c.u32(1)?,
        object: c.ptr(2)?,
        maximum: c.ptr(3)?,
        protection: c.u32(4)?,
        attributes: c.u32(5)?,
        file: c.ptr(6)?,
    };
    let out = request.out;
    let wow = c.arch() == WinArch::X86;
    let converted = if wow {
        let result = if request.file == 0 {
            object_create::capture_fields(c, request.object)?
        } else {
            object_create::capture(c, request.object, KIND)?
        };
        let attrs = match result {
            Ok(attrs) => attrs,
            Err(code) => return Flow::ret(code.into()),
        };
        let name = if request.file == 0 {
            match capture_name(c, &attrs) {
                Ok(name) => name,
                Err(error) => return named::api_error(error),
            }
        } else {
            None
        };
        Some((attrs, name))
    } else {
        None
    };
    // WoW64 converts OBJECT_ATTRIBUTES before entering the native service.
    // Initial mode/PAGE syntax checks then precede the caller-buffer probes.
    // PAGE=0 is deferred to the later memory-manager validation, unlike other
    // invalid PAGE values; native-priority and valid-cross controls bind this.
    let attributes = request.attributes;
    let result = preflight_attributes(attributes).or_else(|| {
        (request.protection != 0 && !valid_section_protection(request.protection))
            .then_some(STATUS_INVALID_PAGE_PROTECTION)
    });
    if let Some(status) = result {
        let result = Flow::ret(status.into());
        if out != 0 {
            object_create::wow_failure(c, out, &result)?;
        }
        return result;
    }
    // WoW64 passes a private native HANDLE output and copies it to the caller
    // after the service, except its NULL destination is rejected up front.
    // In particular a maximum-size guard is visited before a late inaccessible
    // or guarded caller destination (independent v5 roles149/165).
    if !wow || out == 0 {
        probe_write(c, out, c.psize() as usize)?;
    }
    let result = construct(c, request, converted);
    if wow && matches!(&result, Err(ApiErr::Fault(fault)) if fault.write) {
        // Publication already attempted the caller copy and rolled back the
        // handle. Its store fault must not cause a second zero copy-back.
        return result;
    }
    // Faults after the WoW64 conversion/output probe occur inside the native
    // service. The wrapper copies its zero HANDLE back for these failures too.
    // Conversion and initial destination faults returned above retain their
    // distinct output/guard behavior.
    let result = guard_result(c, result);
    let result = if wow && matches!(result, Err(ApiErr::Fault(_))) {
        Flow::ret(STATUS_ACCESS_VIOLATION.into())
    } else {
        result
    };
    object_create::wow_failure(c, out, &result)?;
    result
}
fn valid_section_protection(protection: u32) -> bool {
    matches!(protection, 2 | 4 | 8 | 0x10 | 0x20 | 0x40 | 0x80)
}
fn preflight_attributes(attributes: u32) -> Option<u32> {
    let mode = attributes & (SEC_RESERVE | SEC_COMMIT | SEC_IMAGE);
    if attributes & !OUTER_ALLOCATION_BITS != 0
        || !matches!(mode, SEC_RESERVE | SEC_COMMIT | SEC_IMAGE)
        || (mode == SEC_IMAGE && attributes & !(SEC_IMAGE | SEC_NOCACHE | 0x7F) != 0)
    {
        return Some(STATUS_INVALID_PARAMETER_6);
    }
    None
}
fn capture_name(c: &Ctx, attrs: &Attributes) -> named_object::Checked<Option<Vec<u16>>> {
    if attrs.name == 0 {
        object_create::supported_attributes(c, attrs, KIND)?;
        return Ok(None);
    }
    if attrs.security != 0 {
        return Err(c
            .unsupported("NT named pagefile section explicit security descriptor")
            .into());
    }
    if attrs.qos != 0 {
        return Err(c
            .unsupported("NT named pagefile section security quality of service")
            .into());
    }
    named_object::attributes::capture_name(c, attrs.name, c.arch() == WinArch::X86)
}

fn construct(
    c: &mut Ctx,
    request: Request,
    converted: Option<(Attributes, Option<Vec<u16>>)>,
) -> ApiResult {
    let Request {
        out,
        access,
        object,
        maximum,
        protection,
        attributes,
        file,
    } = request;
    let size = if maximum == 0 {
        0
    } else {
        if maximum % 8 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        c.mem().u64(maximum)?
    };
    let mode = attributes & (SEC_RESERVE | SEC_COMMIT | SEC_IMAGE);
    if attributes & 0x0006_0000 != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if !valid_section_protection(protection) {
        return Flow::ret(STATUS_INVALID_PAGE_PROTECTION.into());
    }
    if mode == SEC_IMAGE && attributes & SEC_NOCACHE != 0 && protection != 2 {
        // SEC_IMAGE_NO_EXECUTE accepts PAGE_READONLY only. The independent
        // v11 matrix rejects every other PAGE before file-access validation.
        return Flow::ret(STATUS_INVALID_PAGE_PROTECTION.into());
    }
    // WC alone rejects executable sections after maximum-size capture.
    // With both cache flags, NOCACHE wins and the section reports no WC bit.
    if attributes & (SEC_NOCACHE | SEC_WRITECOMBINE) == SEC_WRITECOMBINE && protection & 0xF0 != 0 {
        return Flow::ret(STATUS_INVALID_PAGE_PROTECTION.into());
    }
    if attributes & 0x7E != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if file != 0 {
        return file::construct(c, request, converted.map(|(attrs, _)| attrs), size);
    }
    if mode == SEC_IMAGE {
        return Flow::ret(STATUS_INVALID_FILE_FOR_SECTION.into());
    }
    if mode == SEC_RESERVE && attributes & SEC_LARGE_PAGES != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER_6.into());
    }
    if size == 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER_4.into());
    }
    if (size as i64) < 0 {
        return Flow::ret(STATUS_SECTION_TOO_BIG.into());
    }
    let (attrs, name) = match converted {
        Some(pair) => pair,
        None => {
            let attrs = match object_create::capture_fields(c, object)? {
                Ok(attrs) => attrs,
                Err(code) => return Flow::ret(code.into()),
            };
            if attrs.flags & !0x11EF2 != 0 {
                return Flow::ret(STATUS_INVALID_PARAMETER.into());
            }
            let name = match capture_name(c, &attrs) {
                Ok(name) => name,
                Err(error) => return named::api_error(error),
            };
            (attrs, name)
        }
    };
    if attrs.flags & !0x11EF2 != 0 {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if attrs.root != 0 && attrs.name == 0 {
        return Err(c.unsupported("NT pagefile section root handle without a name"));
    }
    if attrs.flags & 0x10 != 0 {
        return Err(c.unsupported("NT pagefile section OBJ_PERMANENT lifetime"));
    }
    if attributes & SEC_LARGE_PAGES != 0 {
        return Err(c.unsupported("NtCreateSection large-page allocation contract"));
    }
    if attributes & 0x0068_0000 != 0 {
        return Err(
            c.unsupported("NtCreateSection based, 64K-page or no-change allocation contract")
        );
    }
    let grant = grant(c, access)?;
    if size > MAX_BACKING_BYTES {
        return Err(c.unsupported("NtCreateSection exceeds the 64 MiB backing bound"));
    }
    let inherit = attrs.flags & 2 != 0;
    let name = match named_object::resolve_name(
        c,
        attrs.root,
        name.as_deref(),
        attrs.flags,
        false,
        KIND,
    ) {
        Ok(name) => name,
        Err(error) => return named::api_error(error),
    };
    if let Some(name) = &name {
        match named::existing(c, name) {
            Ok(Some(id)) => {
                if attrs.flags & 0x80 == 0 {
                    return Flow::ret(STATUS_OBJECT_NAME_COLLISION.into());
                }
                return named::publish(c, out, inherit, grant, id, true);
            }
            Ok(None) => {}
            Err(error) => return named::api_error(error),
        }
        if let Err(error) = named::check_global_creation(c, name) {
            return named::api_error(error);
        }
    }
    let size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let attributes = if attributes & SEC_NOCACHE != 0 {
        attributes & !SEC_WRITECOMBINE
    } else {
        attributes
    };
    let shared = match SharedObject::anonymous(size) {
        Ok(s) => Arc::new(s),
        Err(_) => return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into()),
    };
    let mapping = Object::Mapping {
        file: None,
        size,
        protect: protection,
        attributes: attributes & !1,
        shared: Some(shared),
    };
    let Some(name) = name else {
        return object_create::publish(c, out, inherit, grant, mapping);
    };
    let Some((id, exists)) = c.p.objects.try_create_native_named(name, mapping) else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    debug_assert!(!exists);
    named::publish(c, out, inherit, grant, id, false)
}

fn grant(c: &Ctx, access: u32) -> Result<u32, ApiErr> {
    if access & 0x0100_0000 != 0 {
        return Err(c.unsupported("NT pagefile section ACCESS_SYSTEM_SECURITY privilege"));
    }
    let mut grant = access & 0x001F_001F;
    for (generic, specific) in [
        (0x8000_0000, 0x0002_0005),
        (0x4000_0000, 0x0002_0002),
        (0x2000_0000, 0x0002_0008),
        (0x1000_0000, SECTION_ALL_ACCESS),
        (0x0200_0000, SECTION_ALL_ACCESS),
    ] {
        if access & generic != 0 {
            grant |= specific;
        }
    }
    Ok(grant)
}
