//! NtCreateFile has an allocation/EA capture phase distinct from NtOpenFile.
//! Native and WoW64 stores are modeled before transferring any host resource.

mod capture;

use super::file_attributes::attributes;
use super::file_open::{self, Request, host::Creation};
use super::named_object::{Checked, Failure, finish_with, status};
use super::query::probe_write;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;

pub(super) fn create(c: &mut Ctx) -> ApiResult {
    let mut caller_store = false;
    let result = checked(c, &mut caller_store);
    finish_with(c, result, caller_store)
}

fn parameters(r: Request, disposition: u32, attributes: u32) -> Checked<()> {
    if disposition > 5
        || r.share & !7 != 0
        || r.options & !0x20ff_ffff != 0
        || r.options & 0x30 == 0x30
        || r.options & 0x30 != 0 && r.access & 0x100000 == 0
        || r.options & 0x1000 != 0 && r.access & 0x10000 == 0
        || r.access & !0xf31f_01ff != 0
        || attributes & !0x00da_ffb7 != 0
    {
        return status(STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

fn checked(c: &mut Ctx, caller_store: &mut bool) -> Checked<u32> {
    let r = Request {
        output: c.ptr(0)?,
        access: c.u32(1)?,
        attributes: c.ptr(2)?,
        io: c.ptr(3)?,
        share: c.u32(6)?,
        options: c.u32(8)?,
    };
    let allocation = c.ptr(4)?;
    let attributes = c.u32(5)?;
    let disposition = c.u32(7)?;
    let ea = c.ptr(9)?;
    let ea_bytes = c.u32(10)?;
    let wow = c.arch() == WinArch::X86;
    // Failed conversion never reaches the WoW64 handle store.
    let converted = if wow {
        Some(attributes::capture_create(c, r.attributes, true)?)
    } else {
        None
    };
    let mut ea_failure = false;
    let core = (|| {
        parameters(r, disposition, attributes)?;
        if !wow {
            probe_write(c, r.output, c.psize() as usize)?;
            probe_write(c, r.io, 4)?;
        } else if r.output == 0 || r.io == 0 {
            return status(STATUS_ACCESS_VIOLATION);
        }
        let allocation = capture::allocation(c, allocation)?;
        let ea = capture::ea(c, ea, ea_bytes)?;
        if !ea.is_empty() {
            if !wow {
                // The native EA validator initializes Information, including
                // when a later object capture or filesystem lookup fails.
                c.mem().w64(
                    r.io.checked_add(8)
                        .ok_or(Failure::Status(STATUS_ACCESS_VIOLATION))?,
                    0,
                )?;
            }
            if !capture::valid_ea(&ea) {
                ea_failure = true;
                if !wow {
                    c.mem().w32(r.io, 0x8000_0014)?;
                }
                return status(0x8000_0014);
            }
        }
        if r.access == 0 {
            return status(STATUS_ACCESS_DENIED);
        }
        file_open::kernel(
            c,
            r,
            converted,
            Some(Creation {
                disposition,
                attributes,
                allocation,
                ea,
            }),
        )
    })();
    let (code, handle, information) = match core {
        Ok((handle, information)) => (STATUS_SUCCESS, handle, information),
        Err(Failure::Status(code)) => (code, 0, 0),
        Err(Failure::Api(ApiErr::Fault(fault))) if wow => {
            let code = if c.p.vm.take_guard(fault.addr) {
                STATUS_GUARD_PAGE_VIOLATION
            } else {
                STATUS_ACCESS_VIOLATION
            };
            (code, 0, 0)
        }
        Err(error) => return Err(error),
    };
    if !wow && code != STATUS_SUCCESS {
        return Ok(code);
    }
    *caller_store = true;
    let result = (|| {
        c.mem().wptr(r.output, c.psize(), handle)?;
        if code == STATUS_SUCCESS || ea_failure {
            if wow {
                c.mem().w32(r.io, code)?;
            } else {
                c.mem().w64(r.io, 0)?;
            }
            c.mem().wptr(
                r.io.checked_add(c.psize())
                    .ok_or(Failure::Status(STATUS_ACCESS_VIOLATION))?,
                c.psize(),
                information,
            )?;
        }
        Ok(code)
    })();
    if wow && result.is_err() && handle != 0 {
        let _ = c.p.objects.close(handle);
    }
    result
}
