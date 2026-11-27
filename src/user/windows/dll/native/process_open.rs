//! Open a query or synchronization handle to an existing guest process.
use super::client_open::{self, ClientOpen};
use super::query::{guard_result, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{ObjId, Object};

const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const SUPPORTED_ACCESS: u32 =
    PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;

pub(super) fn open(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    if c.arch() == WinArch::X86 {
        write_guard_result(c, result)
    } else {
        guard_result(c, result)
    }
}

fn checked(c: &mut Ctx) -> ApiResult {
    let request = match client_open::capture(c)? {
        Ok(request) => request,
        Err(status) => return Flow::ret(status.into()),
    };
    let id = match resolve(c, &request) {
        Ok(id) => id,
        Err(status) => {
            // The WoW64 wrapper copies its initialized native handle back
            // even when the kernel rejects a captured request.
            if c.arch() == WinArch::X86 {
                c.write_ptr(request.output, 0)?;
            }
            return Flow::ret(status.into());
        }
    };
    if request.desired & !SUPPORTED_ACCESS != 0 {
        return Err(c.unsupported(format!("NtOpenProcess access {:#x}", request.desired)));
    }
    let mut grant = request.desired;
    if grant & PROCESS_QUERY_INFORMATION != 0 {
        grant |= PROCESS_QUERY_LIMITED_INFORMATION;
    }
    client_open::publish(c, request.output, id, request.flags, grant)
}

fn resolve(c: &Ctx, request: &ClientOpen) -> Result<ObjId, u32> {
    if !request.attributes_present {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let Some((pid, tid)) = request.client.filter(|_| request.name == 0) else {
        return Err(STATUS_INVALID_PARAMETER_MIX);
    };
    let Ok(pid) = u32::try_from(if tid == 0 { pid & !3 } else { pid }) else {
        return Err(STATUS_INVALID_CID);
    };
    // This namespace contains guest identities only. An unknown ID must never
    // be passed to an operating system process API.
    let Some(id) = c.p.objects.iter().find_map(|(id, object)| {
        matches!(object, Object::Process { pid: target, .. } if *target == pid).then_some(id)
    }) else {
        return Err(STATUS_INVALID_CID);
    };
    if tid != 0 {
        let Ok(tid) = u32::try_from(tid & !3) else {
            return Err(STATUS_INVALID_CID);
        };
        let known_thread = if pid == c.p.pid {
            tid == c.t.tid
                || c.p.objects.iter().any(|(id, object)| {
                    matches!(object, Object::Thread { tid: target, .. } if *target == tid)
                        && c.p.objects.thread_creation_flags(id).is_some()
                })
        } else {
            c.p.children
                .basic(pid)
                .is_some_and(|(info, _)| info.primary_tid == tid)
                || c.p
                    .children
                    .with_process(pid, |child| child.threads.contains_key(&tid))
                    .unwrap_or(false)
        };
        if !known_thread {
            return Err(STATUS_INVALID_CID);
        }
    }
    if request.flags & 0xb0 != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if request.desired == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(id)
}
