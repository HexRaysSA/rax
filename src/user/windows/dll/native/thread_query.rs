//! Guest thread basic information, retained Win32 start, and caller thread count.
//! PHNT layouts and independent native captures are retained under
//! `docs/specifications/windows/native-thread-query/`. No guest query reaches
//! host thread handles. Priority and affinity describe the existing one-CPU
//! virtual scheduler, not the host's transient priority boosts or CPU mask.

use super::query::{guard_result, probe_write, return_length, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, ObjId, Object};
use crate::user::windows::process::thread::ThreadState;

const BASIC: u32 = 0;
const WIN32_START: u32 = 9;
const AM_I_LAST: u32 = 12;
// The selected native kernel recognizes class60, newer than retained PHNT;
// native boundary observations reject classes61,64 and65535.
const MAX_THREAD_INFO_CLASS: u32 = 61;
const MAX_WOW64_THREAD_INFO_CLASS: u32 = 60;

pub(super) fn information(c: &mut Ctx) -> ApiResult {
    let result = query(c);
    if c.arch() == WinArch::X86 {
        // The WoW wrapper visits read-only output guards for all three classes,
        // including the otherwise forwarded last-thread query.
        guard_result(c, result)
    } else {
        write_guard_result(c, result)
    }
}

/// Class17 forwards the one-byte destination even under WoW64. Its direct
/// store rejects read-only guards before visiting them; ReturnLength is probed
/// separately first. Independent all-ABI observations cover the copy frontier.
fn hidden(c: &mut Ctx, handle: u64, output: u64, length: u32, returned: u64) -> ApiResult {
    if length >= 4 && output % 4 != 0 {
        return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
    }
    if length != 0
        && output
            .checked_add(u64::from(length))
            .is_none_or(|end| end > c.p.vm.high())
    {
        return Flow::ret(STATUS_ACCESS_VIOLATION.into());
    }
    if returned != 0
        && let Err(fault) = probe_write(c, returned, 4)
    {
        return guard_result(c, Err(fault.into()));
    }
    if length != 1 {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    let id = match target(c, handle, 17) {
        Ok(id) => id,
        Err(status) => return Flow::ret(status.into()),
    };
    let flags =
        c.p.objects
            .thread_creation_flags(id)
            .ok_or_else(|| c.unsupported("thread hidden state belongs to an external process"))?;
    c.mem().w8(output, u8::from(flags & 4 != 0))?;
    return_length(c, returned, 1)?;
    Flow::ret(0)
}

fn query(c: &mut Ctx) -> ApiResult {
    let (handle, class, output, length, returned) =
        (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.u32(3)?, c.ptr(4)?);
    if class == 17 {
        let result = hidden(c, handle, output, length, returned);
        return write_guard_result(c, result);
    }
    if c.arch() == WinArch::X86 && matches!(class, BASIC | WIN32_START) {
        return converted(c, handle, class, output, length, returned);
    }
    if c.arch() == WinArch::X86 && class >= MAX_WOW64_THREAD_INFO_CLASS {
        return Flow::ret(STATUS_INVALID_INFO_CLASS.into());
    }
    // Forwarded/native entries check ULONG alignment and the user span before
    // probing ReturnLength, then dispatch the class and exact record length.
    if length != 0 {
        if output % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        if output
            .checked_add(u64::from(length))
            .is_none_or(|end| end > c.p.vm.high())
        {
            return Flow::ret(STATUS_ACCESS_VIOLATION.into());
        }
    }
    if returned != 0
        && let Err(fault) = probe_write(c, returned, 4)
    {
        // The native ReturnLength probe visits even a read-only guard. Direct
        // class9/12 output stores instead reject write protection first.
        return guard_result(c, Err(fault.into()));
    }
    let required = match class {
        BASIC => 48,
        WIN32_START => 8,
        AM_I_LAST => 4,
        _ if class >= MAX_THREAD_INFO_CLASS => {
            return Flow::ret(STATUS_INVALID_INFO_CLASS.into());
        }
        _ => return Err(c.unsupported(format!("NtQueryInformationThread class {class}"))),
    };
    if length != required {
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    match class {
        AM_I_LAST => c.mem().w32(output, u32::from(last_thread(c)))?,
        WIN32_START => {
            let id = match target(c, handle, class) {
                Ok(id) => id,
                Err(status) => return Flow::ret(status.into()),
            };
            let start = start(c, id)?;
            c.mem().w64(output, start)?;
        }
        BASIC => {
            let id = match target(c, handle, class) {
                Ok(id) => id,
                Err(status) => return Flow::ret(status.into()),
            };
            let values = basic(c, id)?;
            for (index, value) in values.into_iter().enumerate() {
                if let Err(fault) = c.mem().w64(output + index as u64 * 8, value) {
                    // Native basic-info copies visit a read-only output guard;
                    // each reached eight-byte store is otherwise atomic.
                    return guard_result(c, Err(fault.into()));
                }
            }
        }
        _ => unreachable!(),
    }
    return_length(c, returned, required)?;
    Flow::ret(0)
}

fn target(c: &Ctx, handle: u64, class: u32) -> Result<ObjId, u32> {
    if handle == c.arch().ptr(CURRENT_THREAD) {
        return Ok(c.t.obj);
    }
    if handle == c.arch().ptr(CURRENT_PROCESS) {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    let id = c.p.objects.id(handle).ok_or(STATUS_INVALID_HANDLE)?;
    if !matches!(c.p.objects.obj(id), Some(Object::Thread { .. })) {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    let allowed = if class == BASIC { 0x840 } else { 0x40 };
    if c.p.objects.access(handle).unwrap_or(0) & allowed == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(id)
}

fn start(c: &Ctx, id: ObjId) -> Result<u64, ApiErr> {
    c.p.objects
        .thread_start(id)
        .ok_or_else(|| c.unsupported("thread start belongs to an external process"))
}

fn basic(c: &Ctx, id: ObjId) -> Result<[u64; 6], ApiErr> {
    let Some(Object::Thread { tid, exit_code }) = c.p.objects.obj(id) else {
        unreachable!("validated thread object")
    };
    let teb = if exit_code.is_some() {
        // A retained object outlives its TEB; reject unowned external objects.
        start(c, id)?;
        0
    } else if id == c.t.obj {
        c.t.teb
    } else {
        c.p.threads
            .get(tid)
            .filter(|thread| thread.obj == id)
            .ok_or_else(|| c.unsupported("thread basic information outside the guest scheduler"))?
            .teb
    };
    Ok([
        u64::from(exit_code.unwrap_or(STATUS_PENDING)),
        teb,
        u64::from(c.p.pid),
        u64::from(*tid),
        1, // Existing single-processor virtual affinity.
        8, // Scheduler priority 8; relative base priority occupies the high zero DWORD.
    ])
}

fn last_thread(c: &Ctx) -> bool {
    // Class12 ignores ThreadHandle: the count belongs to the caller's process.
    !c.p.threads
        .values()
        .any(|thread| !matches!(thread.state, ThreadState::Exited(_)))
}

fn converted(
    c: &mut Ctx,
    handle: u64,
    class: u32,
    output: u64,
    length: u32,
    returned: u64,
) -> ApiResult {
    let required = if class == BASIC { 28 } else { 4 };
    let status = if class == BASIC && output == 0 {
        STATUS_INVALID_PARAMETER
    } else if length != required {
        STATUS_INFO_LENGTH_MISMATCH
    } else if class == WIN32_START && output == 0 {
        STATUS_ACCESS_VIOLATION
    } else {
        target(c, handle, class).err().unwrap_or(STATUS_SUCCESS)
    };
    if length == required && output != 0 {
        if (class == BASIC || status == STATUS_SUCCESS)
            && let Err(fault) = probe_write(c, output, required as usize)
        {
            // Converted basic information probes all28 bytes before its first
            // store. Both converted classes visit read-only output guards.
            return guard_result(c, Err(fault.into()));
        }
        if class == WIN32_START {
            if status == STATUS_SUCCESS {
                let id = target(c, handle, class).expect("validated thread");
                let address = start(c, id)?;
                c.mem().w32(output, address as u32)?;
            }
        } else {
            let values = if status == STATUS_SUCCESS {
                let id = target(c, handle, class).expect("validated thread");
                basic(c, id)?
            } else {
                // Native WoW64 converts uninitialized private scratch fields
                // on kernel failure. Their values are undefined, not host
                // state to import. Use deterministic guest-private zeroes;
                // the separately queried TEB destination remains untouched.
                [0; 6]
            };
            for (index, value) in [values[0], values[2], values[3], values[4], values[5], 0]
                .into_iter()
                .enumerate()
            {
                let offset = [0, 8, 12, 16, 20, 24][index];
                c.mem().w32(output + offset, value as u32)?;
            }
            if status == STATUS_SUCCESS {
                let teb = if values[1] == 0 { 0x2000 } else { values[1] };
                c.mem().w32(output + 4, teb as u32)?;
            }
        }
    }
    let result_length = if class == BASIC {
        28
    } else if status == STATUS_SUCCESS {
        4
    } else {
        0xffff_fffc
    };
    // The measured WoW wrapper catches ReturnLength store faults and retains
    // the kernel status. Output conversion faults instead escape before this.
    if returned != 0
        && let Err(fault) = c.mem().w32(returned, result_length)
    {
        // Its protected store swallows the exception, including guard status,
        // but the reached native guard is still consumed.
        c.p.vm.take_guard(fault.addr);
    }
    Flow::ret(status.into())
}
