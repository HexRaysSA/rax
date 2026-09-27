//! Win32 threads, named synchronization objects, and alertable waits.
//!
//! This is the single-process, single-guest-processor profile described in
//! `docs/architecture/user-mode/windows-threading.md`. Custom security
//! descriptors and private namespaces are rejected, not silently ignored.

mod objects;
#[cfg(test)]
mod tests;
mod waits;

use super::super::arch::WinArch;
use super::super::hle::{ApiResult, Arg::*, Conv::Stdcall, Ctx, Export, Flow};
use super::super::layout::offsets;
use super::super::memory::{Mem, MemFault};
use super::super::nt::error::*;
use super::super::objects::{ObjId, Object};
use super::super::process::{Thread, ThreadState, thread};
use crate::error::MemoryAccessKind;

pub(super) static EXPORTS: &[Export] = &[
    Export::func(
        "CreateThread",
        Stdcall,
        &[Ptr, Ptr, Ptr, Ptr, I32, Ptr],
        create_thread,
    ),
    Export::func("GetExitCodeThread", Stdcall, &[Ptr, Ptr], exit_code),
    Export::func("SuspendThread", Stdcall, &[Ptr], suspend_thread),
    Export::func("ResumeThread", Stdcall, &[Ptr], resume_thread),
    Export::func("TerminateThread", Stdcall, &[Ptr, I32], terminate_thread),
    Export::func("SwitchToThread", Stdcall, &[], waits::switch_thread),
    Export::func("Sleep", Stdcall, &[I32], waits::sleep),
    Export::func("SleepEx", Stdcall, &[I32, I32], waits::sleep_ex),
    Export::func("QueueUserAPC", Stdcall, &[Ptr, Ptr, Ptr], queue_apc),
    Export::func(
        "CreateEventW",
        Stdcall,
        &[Ptr, I32, I32, Ptr],
        objects::create_event_w,
    ),
    Export::func(
        "CreateEventA",
        Stdcall,
        &[Ptr, I32, I32, Ptr],
        objects::create_event_a,
    ),
    Export::func(
        "OpenEventW",
        Stdcall,
        &[I32, I32, Ptr],
        objects::open_event_w,
    ),
    Export::func(
        "OpenEventA",
        Stdcall,
        &[I32, I32, Ptr],
        objects::open_event_a,
    ),
    Export::func("SetEvent", Stdcall, &[Ptr], objects::set_event),
    Export::func("ResetEvent", Stdcall, &[Ptr], objects::reset_event),
    Export::func(
        "CreateMutexW",
        Stdcall,
        &[Ptr, I32, Ptr],
        objects::create_mutex_w,
    ),
    Export::func(
        "CreateMutexA",
        Stdcall,
        &[Ptr, I32, Ptr],
        objects::create_mutex_a,
    ),
    Export::func(
        "OpenMutexW",
        Stdcall,
        &[I32, I32, Ptr],
        objects::open_mutex_w,
    ),
    Export::func(
        "OpenMutexA",
        Stdcall,
        &[I32, I32, Ptr],
        objects::open_mutex_a,
    ),
    Export::func("ReleaseMutex", Stdcall, &[Ptr], objects::release_mutex),
    Export::func(
        "CreateSemaphoreW",
        Stdcall,
        &[Ptr, I32, I32, Ptr],
        objects::create_semaphore_w,
    ),
    Export::func(
        "CreateSemaphoreA",
        Stdcall,
        &[Ptr, I32, I32, Ptr],
        objects::create_semaphore_a,
    ),
    Export::func(
        "OpenSemaphoreW",
        Stdcall,
        &[I32, I32, Ptr],
        objects::open_semaphore_w,
    ),
    Export::func(
        "OpenSemaphoreA",
        Stdcall,
        &[I32, I32, Ptr],
        objects::open_semaphore_a,
    ),
    Export::func(
        "ReleaseSemaphore",
        Stdcall,
        &[Ptr, I32, Ptr],
        objects::release_semaphore,
    ),
    Export::func("WaitForSingleObject", Stdcall, &[Ptr, I32], waits::single),
    Export::func(
        "WaitForSingleObjectEx",
        Stdcall,
        &[Ptr, I32, I32],
        waits::single_ex,
    ),
    Export::func(
        "WaitForMultipleObjects",
        Stdcall,
        &[I32, Ptr, I32, I32],
        waits::multiple,
    ),
    Export::func(
        "WaitForMultipleObjectsEx",
        Stdcall,
        &[I32, Ptr, I32, I32, I32],
        waits::multiple_ex,
    ),
];

const THREAD_TERMINATE: u32 = 0x0001;
const THREAD_SUSPEND_RESUME: u32 = 0x0002;
const THREAD_SET_CONTEXT: u32 = 0x0010;
const THREAD_QUERY_INFORMATION: u32 = 0x0040;
const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
const CREATE_SUSPENDED: u32 = 4;
const STACK_SIZE_PARAM_IS_A_RESERVATION: u32 = 0x10000;
const MAXIMUM_SUSPEND_COUNT: u32 = 127;
const STILL_ACTIVE: u32 = 259;
// Profile error for the documented maximum-count failure. Its exact native
// error mapping is not established by the consulted SuspendThread contract.
const ERROR_SIGNAL_REFUSED: u32 = 156;

#[derive(Debug)]
enum ServiceError {
    Win32(u32),
    Fault(MemFault),
}
impl From<MemFault> for ServiceError {
    fn from(fault: MemFault) -> Self {
        Self::Fault(fault)
    }
}
type Checked<T> = Result<T, ServiceError>;

fn failure(c: &mut Ctx, error: ServiceError, value: u64) -> ApiResult {
    match error {
        ServiceError::Win32(error) => c.fail(error, value),
        ServiceError::Fault(fault) => Err(fault.into()),
    }
}

/// Probe without changing guest data. The flat x86 operand cannot cross 2^32.
fn writable(c: &Ctx, addr: u64, len: usize) -> Result<(), MemFault> {
    if c.arch() == WinArch::X86 && addr + len as u64 > 0x1_0000_0000 {
        return Err(MemFault {
            addr: 0x1_0000_0000,
            write: true,
        });
    }
    c.mem()
        .probe(addr, len, MemoryAccessKind::Write)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: true,
        })
}

fn checked_add(c: &Ctx, addr: u64, offset: u64, len: u64) -> Result<u64, MemFault> {
    let at = if c.arch() == WinArch::X86 {
        u64::from((addr as u32).wrapping_add(offset as u32))
    } else {
        addr.checked_add(offset).ok_or(MemFault {
            addr: u64::MAX,
            write: false,
        })?
    };
    let end = at.checked_add(len).ok_or(MemFault {
        addr: u64::MAX,
        write: false,
    })?;
    if c.arch() == WinArch::X86 && end > 0x1_0000_0000 {
        return Err(MemFault {
            addr: 0x1_0000_0000,
            write: false,
        });
    }
    Ok(at)
}

/// NULL descriptor only; existing named objects ignore this member per Win32.
fn security(c: &Ctx, addr: u64, ignore_descriptor: bool) -> Checked<bool> {
    if addr == 0 {
        return Ok(false);
    }
    let (size, descriptor, inherit) = if c.arch().is64() {
        (24, 8, 16)
    } else {
        (12, 4, 8)
    };
    checked_add(c, addr, 0, size as u64)?;
    let bytes = c.mem().bytes(addr, size)?;
    let length = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if length != size as u32 {
        return Err(ServiceError::Win32(ERROR_INVALID_PARAMETER));
    }
    let descriptor = &bytes[descriptor..descriptor + c.psize() as usize];
    if !ignore_descriptor && descriptor.iter().any(|&byte| byte != 0) {
        return Err(ServiceError::Win32(ERROR_NOT_SUPPORTED));
    }
    Ok(u32::from_le_bytes(bytes[inherit..inherit + 4].try_into().unwrap()) != 0)
}

fn thread_object(c: &Ctx, handle: u64, access: u32, any_access: bool) -> Checked<ObjId> {
    if handle == c.arch().ptr(u64::MAX - 1) {
        return Ok(c.t.obj);
    }
    let id =
        c.p.objects
            .id(handle)
            .ok_or(ServiceError::Win32(ERROR_INVALID_HANDLE))?;
    if !matches!(c.p.objects.obj(id), Some(Object::Thread { .. })) {
        return Err(ServiceError::Win32(ERROR_INVALID_HANDLE));
    }
    let grant =
        c.p.objects
            .access(handle)
            .ok_or(ServiceError::Win32(ERROR_INVALID_HANDLE))?;
    if if any_access {
        grant & access == 0
    } else {
        grant & access != access
    } {
        return Err(ServiceError::Win32(ERROR_ACCESS_DENIED));
    }
    Ok(id)
}

fn live_thread<'a>(c: &'a mut Ctx<'_>, id: ObjId) -> Checked<&'a mut Thread> {
    let Some(Object::Thread { tid, exit_code }) = c.p.objects.obj(id) else {
        return Err(ServiceError::Win32(ERROR_INVALID_HANDLE));
    };
    if exit_code.is_some() {
        return Err(ServiceError::Win32(ERROR_ACCESS_DENIED));
    }
    let tid = *tid;
    let target = if tid == c.t.tid {
        &mut *c.t
    } else {
        c.p.threads
            .get_mut(&tid)
            .ok_or(ServiceError::Win32(ERROR_ACCESS_DENIED))?
    };
    if target.terminate.is_some() || matches!(target.state, ThreadState::Exited(_)) {
        return Err(ServiceError::Win32(ERROR_ACCESS_DENIED));
    }
    Ok(target)
}

/// Reserve rounding follows Thread Stack Size; commitment remains the explicit
/// fixed-stack profile, not a claim of Windows demand growth.
fn stack_reserve(default: u64, size: u64, flags: u32) -> Option<u64> {
    let default = if default == 0 { 0x10_0000 } else { default };
    if size == 0 {
        return Some(default);
    }
    if flags & STACK_SIZE_PARAM_IS_A_RESERVATION != 0 {
        return Some(size);
    }
    let commit = size.checked_add(0xFFF)? & !0xFFF;
    let usable = default.max(0x10000).checked_add(0xFFFF)? & !0xFFFF;
    if commit < default && commit.checked_add(0x2000)? <= usable {
        Some(default)
    } else {
        // Add two low pages for the existing terminal guard/reserved layout:
        // committed usable bytes must never be smaller than the request.
        commit
            .checked_add(0x2000)?
            .checked_add(0xF_FFFF)
            .map(|n| n & !0xF_FFFF)
    }
}

fn create_thread(c: &mut Ctx) -> ApiResult {
    let (attrs, size, start, parameter, flags, out) = (
        c.ptr(0)?,
        c.ptr(1)?,
        c.ptr(2)?,
        c.ptr(3)?,
        c.u32(4)?,
        c.ptr(5)?,
    );
    if flags & !(CREATE_SUSPENDED | STACK_SIZE_PARAM_IS_A_RESERVATION) != 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let inherit = match security(c, attrs, false) {
        Ok(value) => value,
        Err(error) => return failure(c, error, 0),
    };
    if out != 0 {
        writable(c, out, 4)?;
    }
    let Some(reserve) = stack_reserve(c.p.exe_stack_reserve, size, flags) else {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    };
    let tid = match thread::create(c.p, start, parameter, reserve, false) {
        Ok(tid) => tid,
        Err(status) => return c.fail(super::super::nt::status_to_error(status), 0),
    };
    let id = c.p.threads[&tid].obj;
    let Some(handle) = c.p.objects.open_access(id, inherit, THREAD_ALL_ACCESS) else {
        if let Some(target) = c.p.threads.remove(&tid) {
            thread::destroy(c.p, target, 0);
        }
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    };
    c.p.threads.get_mut(&tid).unwrap().suspend = u32::from(flags & CREATE_SUSPENDED != 0);
    if out != 0
        && let Err(fault) = c.mem().w32(out, tid)
    {
        let _ = c.p.objects.close(u64::from(handle));
        if let Some(target) = c.p.threads.remove(&tid) {
            thread::destroy(c.p, target, 0);
        }
        return Err(fault.into());
    }
    Flow::ret(u64::from(handle))
}

fn exit_code(c: &mut Ctx) -> ApiResult {
    let (handle, out) = (c.ptr(0)?, c.ptr(1)?);
    let id = match thread_object(
        c,
        handle,
        THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
        true,
    ) {
        Ok(id) => id,
        Err(error) => return failure(c, error, 0),
    };
    let Some(Object::Thread { exit_code, .. }) = c.p.objects.obj(id) else {
        unreachable!()
    };
    c.mem().w32(out, exit_code.unwrap_or(STILL_ACTIVE))?;
    Flow::bool(true)
}

fn suspend_thread(c: &mut Ctx) -> ApiResult {
    change_suspend(c, true)
}
fn resume_thread(c: &mut Ctx) -> ApiResult {
    change_suspend(c, false)
}
fn change_suspend(c: &mut Ctx, suspend: bool) -> ApiResult {
    let handle = c.ptr(0)?;
    let result = (|| {
        let id = thread_object(c, handle, THREAD_SUSPEND_RESUME, false)?;
        let target = live_thread(c, id)?;
        let previous = target.suspend;
        if suspend {
            if previous >= MAXIMUM_SUSPEND_COUNT {
                return Err(ServiceError::Win32(ERROR_SIGNAL_REFUSED));
            }
            target.suspend += 1;
        } else {
            target.suspend = previous.saturating_sub(1);
        }
        Ok(previous)
    })();
    match result {
        Ok(previous) => Flow::ret(u64::from(previous)),
        Err(error) => failure(c, error, u64::from(u32::MAX)),
    }
}

fn terminate_thread(c: &mut Ctx) -> ApiResult {
    let (handle, code) = (c.ptr(0)?, c.u32(1)?);
    let id = match thread_object(c, handle, THREAD_TERMINATE, false) {
        Ok(id) => id,
        Err(error) => return failure(c, error, 0),
    };
    if id == c.t.obj {
        return Ok(Flow::ExitThread(code));
    }
    match live_thread(c, id) {
        Ok(target) => {
            target.terminate = Some(code);
            Flow::bool(true)
        }
        Err(error) => failure(c, error, 0),
    }
}

fn queue_apc(c: &mut Ctx) -> ApiResult {
    let (routine, handle, data) = (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?);
    let id = match thread_object(c, handle, THREAD_SET_CONTEXT, false) {
        Ok(id) => id,
        Err(error) => return failure(c, error, 0),
    };
    let Some(Object::Thread { tid, exit_code }) = c.p.objects.obj(id) else {
        unreachable!()
    };
    let tid = *tid;
    if exit_code.is_some() {
        return c.fail(ERROR_GEN_FAILURE, 0);
    }
    let target = if tid == c.t.tid {
        &mut *c.t
    } else {
        let Some(target) = c.p.threads.get_mut(&tid) else {
            return c.fail(ERROR_GEN_FAILURE, 0);
        };
        target
    };
    if target.terminate.is_some() || matches!(target.state, ThreadState::Exited(_)) {
        return c.fail(ERROR_GEN_FAILURE, 0);
    }
    if target.apcs.try_reserve(1).is_err() {
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    }
    target.apcs.push_back((routine, data));
    Flow::ret(1)
}
