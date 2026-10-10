//! Events, recursive mutexes, and counting semaphores.

use super::*;

pub(super) const SYNCHRONIZE: u32 = 0x0010_0000;
const EVENT_ALL_ACCESS: u32 = 0x001F_0003;
const MUTEX_ALL_ACCESS: u32 = 0x001F_0001;
const SEMAPHORE_ALL_ACCESS: u32 = 0x001F_0003;
const MODIFY_STATE: u32 = 2;

#[derive(Clone, Copy)]
enum Kind {
    Event,
    Mutex,
    Semaphore,
}
impl Kind {
    fn matches(self, object: &Object) -> bool {
        matches!(
            (self, object),
            (Self::Event, Object::Event { .. })
                | (Self::Mutex, Object::Mutex { .. })
                | (Self::Semaphore, Object::Semaphore { .. })
        )
    }
    fn all_access(self) -> u32 {
        match self {
            Self::Event => EVENT_ALL_ACCESS,
            Self::Mutex => MUTEX_ALL_ACCESS,
            Self::Semaphore => SEMAPHORE_ALL_ACCESS,
        }
    }
}

/// Full UTF-16 scalar names, ASCII ANSI names, <=260 units plus NUL. Reject
/// code-page-dependent ANSI and unpaired UTF-16 rather than lossy aliases.
fn name(c: &Ctx, addr: u64, wide: bool) -> Checked<Option<String>> {
    if addr == 0 {
        return Ok(None);
    }
    let mut units = Vec::with_capacity(32);
    for index in 0..=260 {
        let size = if wide { 2 } else { 1 };
        let at = checked_add(c, addr, index * size, size)?;
        let unit = if wide {
            c.mem().u16(at)?
        } else {
            u16::from(c.mem().u8(at)?)
        };
        if unit == 0 {
            if units.is_empty() {
                return Err(ServiceError::Win32(ERROR_INVALID_NAME));
            }
            let value =
                String::from_utf16(&units).map_err(|_| ServiceError::Win32(ERROR_NOT_SUPPORTED))?;
            let remainder = value
                .strip_prefix("Global\\")
                .or_else(|| value.strip_prefix("Local\\"));
            if let Some(remainder) = remainder {
                if remainder.is_empty() || remainder.contains('\\') {
                    return Err(ServiceError::Win32(ERROR_INVALID_NAME));
                }
            } else if value.contains('\\') {
                // Private and system namespaces have no admitted implementation.
                return Err(ServiceError::Win32(ERROR_NOT_SUPPORTED));
            }
            return Ok(Some(value));
        }
        if index == 260 {
            return Err(ServiceError::Win32(ERROR_FILENAME_EXCED_RANGE));
        }
        if !wide && unit > 0x7F {
            return Err(ServiceError::Win32(ERROR_NOT_SUPPORTED));
        }
        units.push(unit);
    }
    unreachable!("bounded scan returns on index 260")
}

fn object(c: &Ctx, handle: u64, kind: Kind, access: u32) -> Checked<ObjId> {
    let id =
        c.p.objects
            .id(handle)
            .ok_or(ServiceError::Win32(ERROR_INVALID_HANDLE))?;
    if !c
        .p
        .objects
        .obj(id)
        .is_some_and(|object| kind.matches(object))
    {
        return Err(ServiceError::Win32(ERROR_INVALID_HANDLE));
    }
    let grant =
        c.p.objects
            .access(handle)
            .ok_or(ServiceError::Win32(ERROR_INVALID_HANDLE))?;
    if grant & access != access {
        return Err(ServiceError::Win32(ERROR_ACCESS_DENIED));
    }
    Ok(id)
}

fn create(c: &mut Ctx, attrs: u64, name: Option<String>, kind: Kind, new: Object) -> ApiResult {
    let existing = name.as_deref().and_then(|name| c.p.objects.by_name(name));
    if let Some(id) = existing
        && !c
            .p
            .objects
            .obj(id)
            .is_some_and(|object| kind.matches(object))
    {
        return c.fail(ERROR_INVALID_HANDLE, 0);
    }
    let inherit = match security(c, attrs, existing.is_some()) {
        Ok(value) => value,
        Err(error) => return failure(c, error, 0),
    };
    // LastError is an output too; validate before publishing any object/handle.
    writable(c, c.t.teb + offsets(c.arch()).teb_last_error, 4)?;
    let result = if let Some(name) = name.as_deref() {
        c.p.objects.try_create_named(name, new)
    } else {
        c.p.objects.try_create(new).map(|id| (id, false))
    };
    let Some((id, existed)) = result else {
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    };
    let Some(handle) = c.p.objects.open_access(id, inherit, kind.all_access()) else {
        if !existed {
            c.p.objects.release(id);
        }
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    };
    if let Err(fault) = c.set_last_error(if existed {
        ERROR_ALREADY_EXISTS
    } else {
        ERROR_SUCCESS
    }) {
        let _ = c.p.objects.close(u64::from(handle));
        return Err(fault.into());
    }
    Flow::ret(u64::from(handle))
}

fn create_event(c: &mut Ctx, wide: bool) -> ApiResult {
    let (attrs, manual, signaled, addr) = (c.ptr(0)?, c.bool(1)?, c.bool(2)?, c.ptr(3)?);
    let name = match name(c, addr, wide) {
        Ok(name) => name,
        Err(error) => return failure(c, error, 0),
    };
    create(
        c,
        attrs,
        name,
        Kind::Event,
        Object::Event {
            manual,
            signaled: i32::from(signaled),
        },
    )
}
pub(super) fn create_event_w(c: &mut Ctx) -> ApiResult {
    create_event(c, true)
}
pub(super) fn create_event_a(c: &mut Ctx) -> ApiResult {
    create_event(c, false)
}

fn create_mutex(c: &mut Ctx, wide: bool) -> ApiResult {
    let (attrs, owned, addr) = (c.ptr(0)?, c.bool(1)?, c.ptr(2)?);
    let name = match name(c, addr, wide) {
        Ok(name) => name,
        Err(error) => return failure(c, error, 0),
    };
    let owner = owned.then_some(c.t.tid);
    create(
        c,
        attrs,
        name,
        Kind::Mutex,
        Object::Mutex {
            owner,
            count: u32::from(owned),
            abandoned: false,
        },
    )
}
pub(super) fn create_mutex_w(c: &mut Ctx) -> ApiResult {
    create_mutex(c, true)
}
pub(super) fn create_mutex_a(c: &mut Ctx) -> ApiResult {
    create_mutex(c, false)
}

fn create_semaphore(c: &mut Ctx, wide: bool) -> ApiResult {
    let (attrs, count, max, addr) = (c.ptr(0)?, c.i32(1)?, c.i32(2)?, c.ptr(3)?);
    let name = match name(c, addr, wide) {
        Ok(name) => name,
        Err(error) => return failure(c, error, 0),
    };
    let existing = name.as_deref().and_then(|name| c.p.objects.by_name(name));
    // Win32 ignores both counts when an existing same-type name is opened.
    if existing.is_none() && (max <= 0 || count < 0 || count > max) {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    create(
        c,
        attrs,
        name,
        Kind::Semaphore,
        Object::Semaphore { count, max },
    )
}
pub(super) fn create_semaphore_w(c: &mut Ctx) -> ApiResult {
    create_semaphore(c, true)
}
pub(super) fn create_semaphore_a(c: &mut Ctx) -> ApiResult {
    create_semaphore(c, false)
}

fn desired_access(kind: Kind, access: u32) -> Checked<u32> {
    // Restricted, one-principal namespace: normal standard/type rights are
    // granted. No tokens, impersonation, SACL privilege or DACL is fabricated.
    // Exact GENERIC_* mappings and MAXIMUM_ALLOWED require a separate
    // token/security contract. Callers can request documented explicit bits.
    if access & 0xF300_0000 != 0 {
        return Err(ServiceError::Win32(ERROR_NOT_SUPPORTED));
    }
    if access & !kind.all_access() != 0 {
        return Err(ServiceError::Win32(ERROR_ACCESS_DENIED));
    }
    Ok(access)
}

fn open(c: &mut Ctx, wide: bool, kind: Kind) -> ApiResult {
    let (access, inherit, addr) = (c.u32(0)?, c.bool(1)?, c.ptr(2)?);
    let name = match name(c, addr, wide) {
        Ok(Some(name)) => name,
        Ok(None) => return c.fail(ERROR_INVALID_PARAMETER, 0),
        Err(error) => return failure(c, error, 0),
    };
    let Some(id) = c.p.objects.by_name(&name) else {
        return c.fail(ERROR_FILE_NOT_FOUND, 0);
    };
    if !c
        .p
        .objects
        .obj(id)
        .is_some_and(|object| kind.matches(object))
    {
        return c.fail(ERROR_INVALID_HANDLE, 0);
    }
    let access = match desired_access(kind, access) {
        Ok(access) => access,
        Err(error) => return failure(c, error, 0),
    };
    match c.p.objects.open_access(id, inherit, access) {
        Some(handle) => Flow::ret(u64::from(handle)),
        None => c.fail(ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}
pub(super) fn open_event_w(c: &mut Ctx) -> ApiResult {
    open(c, true, Kind::Event)
}
pub(super) fn open_event_a(c: &mut Ctx) -> ApiResult {
    open(c, false, Kind::Event)
}
pub(super) fn open_mutex_w(c: &mut Ctx) -> ApiResult {
    open(c, true, Kind::Mutex)
}
pub(super) fn open_mutex_a(c: &mut Ctx) -> ApiResult {
    open(c, false, Kind::Mutex)
}
pub(super) fn open_semaphore_w(c: &mut Ctx) -> ApiResult {
    open(c, true, Kind::Semaphore)
}
pub(super) fn open_semaphore_a(c: &mut Ctx) -> ApiResult {
    open(c, false, Kind::Semaphore)
}

fn event_state(c: &mut Ctx, state: bool) -> ApiResult {
    let handle = c.ptr(0)?;
    let id = match object(c, handle, Kind::Event, MODIFY_STATE) {
        Ok(id) => id,
        Err(error) => return failure(c, error, 0),
    };
    if let Some(Object::Event { signaled, .. }) = c.p.objects.obj_mut(id) {
        *signaled = i32::from(state);
    }
    Flow::bool(true)
}
pub(super) fn set_event(c: &mut Ctx) -> ApiResult {
    event_state(c, true)
}
pub(super) fn reset_event(c: &mut Ctx) -> ApiResult {
    event_state(c, false)
}

pub(super) fn release_mutex(c: &mut Ctx) -> ApiResult {
    let handle = c.ptr(0)?;
    // MUTEX_MODIFY_STATE is reserved, not a ReleaseMutex prerequisite. Any
    // valid mutex handle is sufficient; ownership remains mandatory.
    let id = match object(c, handle, Kind::Mutex, 0) {
        Ok(id) => id,
        Err(error) => return failure(c, error, 0),
    };
    let Some(Object::Mutex { owner, count, .. }) = c.p.objects.obj_mut(id) else {
        unreachable!()
    };
    if *owner != Some(c.t.tid) || *count == 0 {
        return c.fail(ERROR_NOT_OWNER, 0);
    }
    *count -= 1;
    if *count == 0 {
        *owner = None;
    }
    Flow::bool(true)
}

pub(super) fn release_semaphore(c: &mut Ctx) -> ApiResult {
    let (handle, release, out) = (c.ptr(0)?, c.i32(1)?, c.ptr(2)?);
    let id = match object(c, handle, Kind::Semaphore, MODIFY_STATE) {
        Ok(id) => id,
        Err(error) => return failure(c, error, 0),
    };
    if release <= 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let Some(Object::Semaphore { count, max }) = c.p.objects.obj(id) else {
        unreachable!()
    };
    let previous = *count;
    let Some(next) = count.checked_add(release).filter(|&next| next <= *max) else {
        return c.fail(ERROR_TOO_MANY_POSTS, 0);
    };
    if out != 0 {
        writable(c, out, 4)?;
        c.mem().w32(out, previous as u32)?;
    }
    if let Some(Object::Semaphore { count, .. }) = c.p.objects.obj_mut(id) {
        *count = next;
    }
    Flow::bool(true)
}
