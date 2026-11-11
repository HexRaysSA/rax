//! NT creation of guest-owned threads; no guest request creates a host thread.
use super::query::{guard_result, probe_write};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use crate::user::windows::process::thread;

struct Output {
    kind: u64,
    pointer: u64,
    returned: u64,
    bytes: u64,
}

enum Rejection {
    Capture(u32),
    Kernel(u32),
}

fn reject(c: &mut Ctx, output: u64, rejection: Rejection) -> ApiResult {
    let status = match rejection {
        Rejection::Capture(status) => status,
        Rejection::Kernel(status) => {
            if c.arch() == WinArch::X86 {
                c.write_ptr(output, 0)?;
            }
            status
        }
    };
    Flow::ret(status.into())
}

pub(super) fn create(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    guard_result(c, result)
}

fn inherit(c: &Ctx, pointer: u64) -> Result<Result<bool, Rejection>, ApiErr> {
    if pointer == 0 {
        return Ok(Ok(false));
    }
    let width = c.psize();
    if c.arch() != WinArch::X86 && pointer % width != 0 {
        return Ok(Err(Rejection::Capture(STATUS_DATATYPE_MISALIGNMENT)));
    }
    if c.mem().u32(pointer)? != 6 * width as u32 {
        return Ok(Err(Rejection::Capture(STATUS_INVALID_PARAMETER)));
    }
    let root = c.mem().ptr(pointer + width, width)?;
    let name = c.mem().ptr(pointer + 2 * width, width)?;
    let flags = c.mem().u32(pointer + 3 * width)?;
    let security = c.mem().ptr(pointer + 4 * width, width)?;
    let qos = c.mem().ptr(pointer + 5 * width, width)?;
    if root != 0 {
        return Ok(Err(Rejection::Kernel(STATUS_OBJECT_NAME_INVALID)));
    }
    if flags & 0x20 != 0 {
        return Ok(Err(Rejection::Kernel(STATUS_INVALID_PARAMETER)));
    }
    if name != 0 {
        let length = c.mem().u16(name)?;
        c.mem().bytes(name, (2 * width) as usize)?;
        if length != 0 {
            return Err(c.unsupported("named thread creation is not yet captured"));
        }
    }
    // Native user-mode creation accepts these unnamed-object hints without
    // creating a kernel-only handle. Only OBJ_INHERIT changes handle flags.
    if flags & !0x0001_1f42 != 0 {
        return Ok(Err(Rejection::Kernel(STATUS_INVALID_PARAMETER)));
    }
    if security != 0 || qos != 0 {
        return Err(c.unsupported("thread creation security attributes are not yet captured"));
    }
    Ok(Ok(flags & 2 != 0))
}

fn outputs(c: &Ctx, list: u64) -> Result<Result<Vec<Output>, Rejection>, ApiErr> {
    if list == 0 {
        return Ok(Ok(Vec::new()));
    }
    let width = c.psize();
    let wow = c.arch() == WinArch::X86;
    if !wow && list % 4 != 0 {
        return Ok(Err(Rejection::Capture(STATUS_DATATYPE_MISALIGNMENT)));
    }
    let length = c.mem().ptr(list, width)?;
    if length <= width || (length - width) % (4 * width) != 0 {
        return Ok(Err(Rejection::Capture(STATUS_INVALID_PARAMETER)));
    }
    if length > 65 * width {
        return Err(c.unsupported("thread creation attribute list exceeds bounded capture"));
    }
    let mut outputs = Vec::new();
    for index in 0..(length - width) / (4 * width) {
        let entry = list
            .checked_add(width + index * 4 * width)
            .ok_or_else(|| c.unsupported("thread creation attribute address overflow"))?;
        let kind = c.mem().ptr(entry, width)?;
        let bytes = c.mem().ptr(entry + width, width)?;
        let pointer = c.mem().ptr(entry + 2 * width, width)?;
        let returned = c.mem().ptr(entry + 3 * width, width)?;
        let expected = match kind {
            0x10003 => 2 * width,
            0x10004 => width,
            0x100ff => return Ok(Err(Rejection::Kernel(STATUS_INVALID_PARAMETER))),
            _ => return Err(c.unsupported("thread creation attribute is not yet captured")),
        };
        if (!wow && bytes != expected) || outputs.iter().any(|output: &Output| output.kind == kind)
        {
            return Ok(Err(Rejection::Kernel(STATUS_INVALID_PARAMETER)));
        }
        if !wow {
            if pointer % 4 != 0 || returned % 4 != 0 {
                return Ok(Err(Rejection::Kernel(STATUS_DATATYPE_MISALIGNMENT)));
            }
            probe_write(c, pointer, expected as usize)?;
            if returned != 0 {
                probe_write(c, returned, width as usize)?;
                c.mem().wptr(returned, width, expected)?;
            }
        }
        outputs.push(Output {
            kind,
            pointer,
            returned,
            bytes: expected,
        });
    }
    Ok(Ok(outputs))
}

fn process_status(c: &Ctx, handle: u64) -> Result<u32, ApiErr> {
    if handle == c.arch().ptr(u64::MAX) {
        return Ok(STATUS_SUCCESS);
    }
    if handle == c.arch().ptr(u64::MAX - 1) {
        return Ok(STATUS_OBJECT_TYPE_MISMATCH);
    }
    match c.p.objects.get(handle) {
        None => Ok(STATUS_INVALID_HANDLE),
        Some(Object::Process { pid, .. }) => {
            if c.p.objects.access(handle).unwrap_or(0) & 2 == 0 {
                Ok(STATUS_ACCESS_DENIED)
            } else if *pid != c.p.pid {
                Err(c.unsupported("thread creation in another guest process is not implemented"))
            } else {
                Ok(STATUS_SUCCESS)
            }
        }
        Some(_) => Ok(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

fn publish(c: &Ctx, tid: u32, outputs: &[Output]) -> Result<(), ApiErr> {
    let created = &c.p.threads[&tid];
    for output in outputs {
        if output.kind == 0x10003 {
            c.mem()
                .wptr(output.pointer, c.psize(), u64::from(c.p.pid))?;
            c.mem()
                .wptr(output.pointer + c.psize(), c.psize(), u64::from(tid))?;
        } else {
            c.mem().wptr(output.pointer, c.psize(), created.teb)?;
        }
        if c.arch() == WinArch::X86 && output.returned != 0 {
            c.mem().wptr(output.returned, c.psize(), output.bytes)?;
        }
    }
    Ok(())
}

fn discard(c: &mut Ctx, tid: u32) {
    if let Some(created) = c.p.threads.remove(&tid) {
        thread::destroy(c.p, created, 0);
    }
}

fn checked(c: &mut Ctx) -> ApiResult {
    let output = c.ptr(0)?;
    let desired = c.u32(1)?;
    let attributes = c.ptr(2)?;
    let process = c.ptr(3)?;
    let start = c.ptr(4)?;
    let argument = c.ptr(5)?;
    let flags = c.u32(6)?;
    let zero_bits = c.ptr(7)?;
    let commit = c.ptr(8)?;
    let reserve = c.ptr(9)?;
    let list = c.ptr(10)?;
    probe_write(c, output, c.psize() as usize)?;
    let inherit = match inherit(c, attributes)? {
        Ok(inherit) => inherit,
        Err(rejection) => return reject(c, output, rejection),
    };
    let outputs = match outputs(c, list)? {
        Ok(outputs) => outputs,
        Err(rejection) => return reject(c, output, rejection),
    };
    let wow_copy = c.arch() == WinArch::X86;
    if wow_copy {
        // The thunk publishes its initially null local handle on a kernel
        // failure after successful attribute conversion, including a null list.
        c.write_ptr(output, 0)?;
    }
    if flags & !0x7f != 0 {
        return Flow::ret(0xc000_00f5u64); // STATUS_INVALID_PARAMETER_7.
    }
    if flags & !9 != 0 {
        return Err(c.unsupported("thread creation flags require additional native qualification"));
    }
    let status = process_status(c, process)?;
    if status != STATUS_SUCCESS {
        return Flow::ret(status.into());
    }
    let access =
        c.p.thread_access
            .as_ref()
            .map_err(|error| c.unsupported(format!("thread creation rights: {error}")))?;
    let grant = access.grant(desired);
    if c.arch() == WinArch::X86
        && let Err(status) = grant
    {
        return Flow::ret(status.into());
    }
    let tid = match thread::create_sized(c.p, start, argument, commit, reserve, zero_bits) {
        Ok(tid) => tid,
        Err(status) => return Flow::ret(status.into()),
    };
    if c.arch() != WinArch::X86
        && let Err(error) = publish(c, tid, &outputs)
    {
        discard(c, tid);
        return Err(error);
    }
    let granted = match grant {
        Ok(granted) => granted,
        Err(status) => {
            discard(c, tid);
            return Flow::ret(status.into());
        }
    };
    let created =
        c.p.threads
            .get_mut(&tid)
            .expect("new guest thread is retained");
    created.suspend = flags & 1;
    let object = created.obj;
    let Some(handle) = c.p.objects.open_access(object, inherit, granted) else {
        discard(c, tid);
        return Flow::ret(STATUS_INSUFFICIENT_RESOURCES.into());
    };
    let result = (|| {
        c.write_ptr(output, u64::from(handle))?;
        if c.arch() == WinArch::X86 {
            publish(c, tid, &outputs)?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        // WoW64 can leave a stale caller handle word after kernel birth.
        // Native observation confirms that the handle has already been closed.
        // Keep the caller bytes while completing deterministic guest rollback.
        let _ = c.p.objects.close(u64::from(handle));
        discard(c, tid);
        return Err(error);
    }
    Flow::ret(STATUS_SUCCESS.into())
}
