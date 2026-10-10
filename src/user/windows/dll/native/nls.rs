//! Snapshot-backed NLS views, with build29683 native/WoW64 probe priority.
use super::query::{guard_result, probe_write};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{AllocKind, Mem, prot};
use crate::user::windows::nt::status::*;
use std::sync::Arc;

pub(super) fn get(c: &mut Ctx) -> ApiResult {
    let result = get_checked(c);
    match guard_result(c, result) {
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        result => result,
    }
}
fn get_checked(c: &mut Ctx) -> ApiResult {
    let (kind, data, context, out, size) = (c.u32(0)?, c.u32(1)?, c.ptr(2)?, c.ptr(3)?, c.ptr(4)?);
    let wow = c.arch() == WinArch::X86;
    if wow && context != 0 {
        c.read_ptr(context)?;
    }
    if out != 0 {
        probe_write(c, out, c.psize() as usize)?;
    }
    if !wow && size != 0 {
        probe_write(c, size, 4)?;
    }
    if !wow && context != 0 {
        c.read_ptr(context)?;
    }
    let early = if context != 0 {
        Some(STATUS_INVALID_PARAMETER_3)
    } else if out == 0 {
        Some(STATUS_INVALID_PARAMETER)
    } else if !matches!(kind, 11 | 12 | 14) {
        Some(STATUS_INVALID_PARAMETER_1)
    } else {
        None
    };
    if let Some(status) = early {
        // WoW64 attempts its size destination even on a kernel error. Faults
        // from that optional copy are consumed and do not replace the status;
        // no size bytes are defined by a failing query in this profile.
        if wow {
            compatibility_size(c, size, None);
        }
        return Flow::ret(status.into());
    }
    let nls =
        c.p.nls
            .as_ref()
            .ok_or_else(|| c.unsupported("NLS sections were not selected"))?;
    let Some(bytes) = nls.section(kind, data) else {
        if wow {
            compatibility_size(c, size, None);
        }
        return Flow::ret(STATUS_OBJECT_NAME_NOT_FOUND.into());
    };
    let length = bytes.len() as u64;
    let name: Arc<str> = format!("installed NLS type {kind} data {data}").into();
    let base = match c.p.vm.reserve(
        None,
        length,
        prot::READONLY,
        AllocKind::Mapped,
        false,
        Some(name),
    ) {
        Ok(base) => base,
        Err(error) => {
            if wow {
                compatibility_size(c, size, None);
            }
            return Flow::ret(error.status().into());
        }
    };
    // Fill under exclusive scheduler ownership before publishing the view.
    if let Err(error) = c.p.vm.commit(base, length, prot::READWRITE) {
        let _ = c.p.vm.release(base);
        return Flow::ret(error.status().into());
    }
    if let Err(fault) = c.mem().wr(base, &bytes) {
        let _ = c.p.vm.release(base);
        return Err(fault.into());
    }
    if let Err(error) =
        c.p.vm
            .protect(base, length, prot::READONLY)
            .and_then(|_| c.p.vm.seal_nls_view(base))
    {
        let _ = c.p.vm.release(base);
        return Flow::ret(error.status().into());
    }
    if let Err(fault) = c.write_ptr(out, base) {
        let _ = c.p.vm.release(base);
        return Err(fault.into());
    }
    if wow {
        compatibility_size(c, size, Some(length as u32));
    } else if size != 0 {
        c.mem().w32(size, length as u32)?;
    }
    Flow::ret(STATUS_SUCCESS.into())
}
fn compatibility_size(c: &mut Ctx, size: u64, value: Option<u32>) {
    if size == 0 {
        return;
    }
    let result = probe_write(c, size, 4).and_then(|_| {
        if let Some(value) = value {
            c.mem().w32(size, value)
        } else {
            Ok(())
        }
    });
    if let Err(fault) = result {
        c.p.vm.take_guard(fault.addr);
    }
}

pub(super) fn unmap(c: &mut Ctx) -> ApiResult {
    let (process, address) = (c.ptr(0)?, c.ptr(1)?);
    if process == c.arch().ptr(u64::MAX - 1) {
        return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
    }
    if process != c.arch().ptr(u64::MAX) {
        use crate::user::windows::objects::Object;
        match c.p.objects.get(process) {
            None => return Flow::ret(STATUS_INVALID_HANDLE.into()),
            Some(Object::Process { pid, .. }) => {
                if c.p.objects.access(process).unwrap_or(0) & 8 == 0 {
                    return Flow::ret(STATUS_ACCESS_DENIED.into());
                }
                if *pid != c.p.pid {
                    return Err(c.unsupported("NLS unmap for another process"));
                }
            }
            Some(_) => return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into()),
        }
    }
    let Some(allocation) = c.p.vm.allocation(address) else {
        return Flow::ret(STATUS_NOT_MAPPED_VIEW.into());
    };
    let base = allocation.base;
    if allocation.kind == AllocKind::Private {
        return Flow::ret(STATUS_NOT_MAPPED_VIEW.into());
    }
    if !c.p.vm.is_nls_view(base) {
        return Err(c.unsupported("unmap outside selected NLS views"));
    }
    match c.p.vm.release(base) {
        Ok(_) => Flow::ret(STATUS_SUCCESS.into()),
        Err(error) => Flow::ret(error.status().into()),
    }
}
