//! Bounded, checked object waits and scheduling delays.

use super::super::super::hle::Value;
use super::super::super::sync::{self, Wait};
use super::*;
use std::collections::HashSet;
use std::time::{Duration, Instant};

const INFINITE: u32 = u32::MAX;
const WAIT_FAILED: u64 = u32::MAX as u64;
const MAXIMUM_WAIT_OBJECTS: u32 = 64;

fn deadline(milliseconds: u32) -> Checked<Option<Instant>> {
    if milliseconds == INFINITE {
        return Ok(None);
    }
    Instant::now()
        .checked_add(Duration::from_millis(u64::from(milliseconds)))
        .map(Some)
        .ok_or(ServiceError::Win32(ERROR_NOT_SUPPORTED))
}

pub(super) fn switch_thread(c: &mut Ctx) -> ApiResult {
    // One guest processor, equal priorities, no thread pool/concurrency cap.
    // Match loader-serialization eligibility, including the current thread,
    // which is temporarily absent from Proc::threads during HLE.
    let initializing = |thread: &Thread| {
        !thread.attached
            && thread
                .frames
                .iter()
                .any(|frame| frame.api.name == "RtlUserThreadStart")
    };
    let other_ready = if initializing(c.t) {
        false
    } else if let Some(owner) = c.p.threads.values().find(|thread| initializing(thread)) {
        owner.runnable() && owner.terminate.is_none()
    } else if c.t.main && !c.t.attached {
        false
    } else if let Some(main) =
        c.p.threads
            .values()
            .find(|thread| thread.main && !thread.attached)
    {
        main.runnable() && main.terminate.is_none()
    } else {
        c.p.threads
            .values()
            .any(|thread| thread.runnable() && thread.terminate.is_none())
    };
    Ok(Flow::Yield(Value::Int(u64::from(other_ready))))
}

fn delay(c: &mut Ctx, alertable: bool, returns_status: bool) -> ApiResult {
    let milliseconds = c.u32(0)?;
    if milliseconds == 0 && (!alertable || c.t.apcs.is_empty()) {
        return Ok(Flow::Yield(if returns_status {
            Value::Int(0)
        } else {
            Value::None
        }));
    }
    let deadline = match deadline(milliseconds) {
        Ok(deadline) => deadline,
        Err(error) => return failure(c, error, 0),
    };
    Flow::block(
        Wait::Sleep {
            deadline,
            alertable,
        },
        move |_, status| {
            if returns_status {
                Flow::ret(status)
            } else {
                Flow::void()
            }
        },
    )
}
pub(super) fn sleep(c: &mut Ctx) -> ApiResult {
    delay(c, false, false)
}
pub(super) fn sleep_ex(c: &mut Ctx) -> ApiResult {
    let alertable = c.bool(1)?;
    delay(c, alertable, true)
}

fn wait_object(c: &Ctx, handle: u64) -> Checked<ObjId> {
    let id = if handle == c.arch().ptr(u64::MAX - 1) {
        c.t.obj
    } else if handle == c.arch().ptr(u64::MAX) {
        c.p.objects
            .iter()
            .find_map(|(id, object)| match object {
                Object::Process { pid, .. } if *pid == c.p.pid => Some(id),
                _ => None,
            })
            .ok_or(ServiceError::Win32(ERROR_INVALID_HANDLE))?
    } else {
        let id =
            c.p.objects
                .id(handle)
                .ok_or(ServiceError::Win32(ERROR_INVALID_HANDLE))?;
        let access =
            c.p.objects
                .access(handle)
                .ok_or(ServiceError::Win32(ERROR_INVALID_HANDLE))?;
        if access & objects::SYNCHRONIZE == 0 {
            return Err(ServiceError::Win32(ERROR_ACCESS_DENIED));
        }
        id
    };
    match c.p.objects.obj(id) {
        Some(
            Object::Event { .. }
            | Object::Mutex { .. }
            | Object::Semaphore { .. }
            | Object::Thread { .. }
            | Object::Process { .. },
        ) => Ok(id),
        Some(_) => Err(ServiceError::Win32(ERROR_NOT_SUPPORTED)),
        None => Err(ServiceError::Win32(ERROR_INVALID_HANDLE)),
    }
}

fn wait(c: &mut Ctx, objs: Vec<ObjId>, all: bool, milliseconds: u32, alertable: bool) -> ApiResult {
    // No state is consumed until every handle, access grant, duplicate and
    // timeout has been checked. Immediate waits do not yield to another thread.
    let deadline = match deadline(milliseconds) {
        Ok(deadline) => deadline,
        Err(error) => return failure(c, error, WAIT_FAILED),
    };
    if let Some(status) = sync::try_objects(c.p, c.t.tid, &objs, all)? {
        return Flow::ret(status);
    }
    if milliseconds == 0 && (!alertable || c.t.apcs.is_empty()) {
        return Flow::ret(sync::WAIT_TIMEOUT);
    }
    // Shared dispatch/scheduler pin every ObjId while parked and release on
    // completion, APC interruption, cancellation, or thread destruction.
    Flow::block(
        Wait::Objects {
            objs,
            all,
            deadline,
            alertable,
        },
        |_, status| Flow::ret(status),
    )
}

fn wait_single(c: &mut Ctx, alertable: bool) -> ApiResult {
    let (handle, milliseconds) = (c.ptr(0)?, c.u32(1)?);
    let id = match wait_object(c, handle) {
        Ok(id) => id,
        Err(error) => return failure(c, error, WAIT_FAILED),
    };
    wait(c, vec![id], false, milliseconds, alertable)
}
pub(super) fn single(c: &mut Ctx) -> ApiResult {
    wait_single(c, false)
}
pub(super) fn single_ex(c: &mut Ctx) -> ApiResult {
    let alertable = c.bool(2)?;
    wait_single(c, alertable)
}

fn wait_multiple(c: &mut Ctx, alertable: bool) -> ApiResult {
    let (count, array, all, milliseconds) = (c.u32(0)?, c.ptr(1)?, c.bool(2)?, c.u32(3)?);
    if count == 0 || count > MAXIMUM_WAIT_OBJECTS {
        return c.fail(ERROR_INVALID_PARAMETER, WAIT_FAILED);
    }
    // <=64 * 8 = 512 bytes, so host allocations and loops are input-bounded.
    checked_add(c, array, 0, u64::from(count) * c.psize())?;
    let bytes = c.mem().bytes(array, count as usize * c.psize() as usize)?;
    let mut ids = Vec::with_capacity(count as usize);
    let mut unique = HashSet::with_capacity(count as usize);
    for word in bytes.chunks_exact(c.psize() as usize) {
        let handle = if c.psize() == 4 {
            u64::from(u32::from_le_bytes(word.try_into().unwrap()))
        } else {
            u64::from_le_bytes(word.try_into().unwrap())
        };
        let id = match wait_object(c, handle) {
            Ok(id) => id,
            Err(error) => return failure(c, error, WAIT_FAILED),
        };
        // Native duplicate aliases are not covered by the public duplicate
        // handle prohibition. Reject them in this profile to avoid consuming
        // a single semaphore/event twice in an atomic wait-all.
        if !unique.insert(id) {
            return c.fail(ERROR_INVALID_PARAMETER, WAIT_FAILED);
        }
        ids.push(id);
    }
    wait(c, ids, all, milliseconds, alertable)
}
pub(super) fn multiple(c: &mut Ctx) -> ApiResult {
    wait_multiple(c, false)
}
pub(super) fn multiple_ex(c: &mut Ctx) -> ApiResult {
    let alertable = c.bool(4)?;
    wait_multiple(c, alertable)
}
