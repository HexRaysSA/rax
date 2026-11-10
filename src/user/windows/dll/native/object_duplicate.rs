//! Duplicate guest handles without publishing a host HANDLE or foreign object.
use super::query::{guard_result, probe_write};
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, ObjId, Object};

const SAME_ACCESS: u32 = 2;
const SAME_ATTRIBUTES: u32 = 4;
const ALL_ACCESS: u32 = 0x001f_ffff;
const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

struct Request {
    source_process: u64,
    source: u64,
    target_process: u64,
    output: u64,
    desired: u32,
    attributes: u32,
    options: u32,
}

#[derive(Clone, Copy)]
enum Kind {
    Thread,
    Process,
    Event,
}

struct Source {
    object: ObjId,
    kind: Kind,
    access: u32,
    flags: u32,
}

enum Candidate {
    Owned(Source),
    Invalid,
    Unselected,
}

pub(super) fn duplicate(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    guard_result(c, result)
}

fn process(c: &Ctx, handle: u64) -> Result<(), u32> {
    if handle == c.arch().ptr(CURRENT_PROCESS) {
        return Ok(());
    }
    match c.p.objects.get(handle) {
        Some(Object::Process { pid, .. }) if *pid == c.p.pid => {
            if c.p.objects.access(handle).unwrap_or(0) & 0x40 != 0 {
                Ok(())
            } else {
                Err(STATUS_ACCESS_DENIED)
            }
        }
        Some(Object::Process { .. }) => Err(STATUS_NOT_SUPPORTED),
        Some(_) => Err(STATUS_OBJECT_TYPE_MISMATCH),
        None => Err(STATUS_INVALID_HANDLE),
    }
}

fn checked(c: &mut Ctx) -> ApiResult {
    let r = Request {
        source_process: c.ptr(0)?,
        source: c.ptr(1)?,
        target_process: c.ptr(2)?,
        output: c.ptr(3)?,
        desired: c.u32(4)?,
        attributes: c.u32(5)?,
        options: c.u32(6)?,
    };
    if c.p.native.as_ref().is_some_and(|native| {
        (
            native.version.major,
            native.version.minor,
            native.version.build,
        ) == (10, 0, 29704)
            && native.object_namespace.native_machine == Some(0xaa64)
    }) && matches!(r.options, 0 | 2 | 4 | 6 | 0x10)
        && r.attributes & !0x203 == 0
    {
        match source(c, r.source) {
            Candidate::Owned(source) => return nonclosing(c, &r, Some(source)),
            Candidate::Invalid => return nonclosing(c, &r, None),
            Candidate::Unselected => {}
        }
    }
    same_access(c, r)
}

fn source(c: &Ctx, handle: u64) -> Candidate {
    if handle == c.arch().ptr(CURRENT_THREAD) {
        return Candidate::Owned(Source {
            object: c.t.obj,
            kind: Kind::Thread,
            access: ALL_ACCESS,
            flags: 0,
        });
    }
    let objects = &c.p.objects;
    if handle == c.arch().ptr(CURRENT_PROCESS) {
        let own = objects.iter().find_map(|(id, object)| {
            matches!(object, Object::Process { pid, .. } if *pid == c.p.pid).then_some(id)
        });
        return own.map_or(Candidate::Unselected, |object| {
            Candidate::Owned(Source {
                object,
                kind: Kind::Process,
                access: ALL_ACCESS,
                flags: 0,
            })
        });
    }
    let Some(object) = objects.id(handle) else {
        return Candidate::Invalid;
    };
    let kind = match objects.obj(object) {
        Some(Object::Thread { .. })
            if object == c.t.obj || objects.thread_start(object).is_some() =>
        {
            Kind::Thread
        }
        Some(Object::Process { pid, .. }) if *pid == c.p.pid => Kind::Process,
        Some(Object::Event { .. }) => Kind::Event,
        _ => return Candidate::Unselected,
    };
    Candidate::Owned(Source {
        object,
        kind,
        access: objects.access(handle).expect("selected live handle"),
        flags: objects.flags(handle).expect("selected live handle"),
    })
}

fn failure(c: &Ctx, output: u64, status: u32) -> ApiResult {
    if output != 0 {
        c.write_ptr(output, 0)?;
    }
    Flow::ret(status.into())
}

/// This grant is local to the measured guest object class. It does not
/// authorize operations on a host token, security descriptor or handle.
fn grant(kind: Kind, desired: u32) -> Result<u32, u32> {
    if desired & 0x0ce0_0000 != 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    let desired = desired & !MAXIMUM_ALLOWED;
    if desired & ACCESS_SYSTEM_SECURITY != 0 && !matches!(kind, Kind::Event) {
        return Err(STATUS_PRIVILEGE_NOT_HELD);
    }
    Ok(match kind {
        Kind::Thread => crate::user::windows::security::thread::map_access(desired),
        Kind::Event => {
            super::object_create::map_access(desired) | (desired & ACCESS_SYSTEM_SECURITY)
        }
        Kind::Process => {
            let mut grant = desired & ALL_ACCESS;
            for (generic, rights) in [
                (0x8000_0000, 0x0002_1410),
                (0x4000_0000, 0x0002_3bea),
                (0x2000_0000, 0x0012_1001),
                (0x1000_0000, ALL_ACCESS),
            ] {
                if desired & generic != 0 {
                    grant |= rights;
                }
            }
            for (right, implied) in [(0x400, 0x1000), (0x200, 0x2000)] {
                if grant & right != 0 {
                    grant |= implied;
                }
            }
            grant
        }
    })
}

fn nonclosing(c: &mut Ctx, r: &Request, source: Option<Source>) -> ApiResult {
    // The native 29704 caller destination is optional and may be unaligned.
    // A reached output fault precedes handle validation, with no publication.
    if r.output != 0 {
        probe_write(c, r.output, c.psize() as usize)?;
    }
    if let Err(status) = process(c, r.source_process).and_then(|()| {
        if r.target_process == 0 {
            Err(STATUS_INVALID_PARAMETER)
        } else {
            process(c, r.target_process)
        }
    }) {
        if status == STATUS_NOT_SUPPORTED {
            return Err(c.unsupported("NtDuplicateObject foreign-process object ownership"));
        }
        return failure(c, r.output, status);
    }
    let Some(source) = source else {
        return failure(c, r.output, STATUS_INVALID_HANDLE);
    };
    let access = if r.options & SAME_ACCESS != 0 {
        source.access
    } else {
        match grant(source.kind, r.desired) {
            Ok(access) => access,
            Err(status) => return failure(c, r.output, status),
        }
    };
    let flags = if r.options & SAME_ATTRIBUTES != 0 {
        source.flags
    } else {
        // OBJ_PROTECT_CLOSE and OBJ_INHERIT have the opposite bit positions
        // to HANDLE_FLAG_PROTECT_FROM_CLOSE and HANDLE_FLAG_INHERIT.
        (r.attributes & 2) >> 1 | (r.attributes & 1) << 1
    };
    let Some(duplicate) =
        c.p.objects
            .open_access(source.object, flags & 1 != 0, access)
    else {
        return failure(c, r.output, STATUS_INSUFFICIENT_RESOURCES);
    };
    let duplicate = u64::from(duplicate);
    if r.output != 0
        && let Err(fault) = c.write_ptr(r.output, duplicate)
    {
        let _ = c.p.objects.close(duplicate);
        return Err(fault.into());
    }
    // Protection is installed only after a possible publication rollback.
    assert!(c.p.objects.set_flags(duplicate, 2, flags));
    Flow::ret(STATUS_SUCCESS.into())
}

fn same_access(c: &mut Ctx, r: Request) -> ApiResult {
    let Request {
        source_process,
        source,
        target_process,
        output,
        attributes,
        options,
        ..
    } = r;
    if options != 2 || attributes & !2 != 0 || output == 0 {
        return Err(c.unsupported("NtDuplicateObject options are not selected"));
    }
    for handle in [source_process, target_process] {
        if let Err(status) = process(c, handle) {
            if status == STATUS_NOT_SUPPORTED {
                return Err(c.unsupported("NtDuplicateObject foreign-process object ownership"));
            }
            return Flow::ret(status.into());
        }
    }
    if c.p.objects.get(source).is_none() {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    }
    probe_write(c, output, c.psize() as usize)?;
    let Some(duplicate) = c.p.objects.duplicate(source, attributes & 2 != 0) else {
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    if let Err(error) = c.write_ptr(output, duplicate.into()) {
        let _ = c.p.objects.close(duplicate.into());
        return Err(error.into());
    }
    Flow::ret(STATUS_SUCCESS.into())
}
