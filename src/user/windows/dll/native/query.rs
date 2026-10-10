//! Checked system queries made by installed NTDLL initialization.
//!
//! The four-argument API is documented at
//! <https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation>.
//! Class 50's private layout, exact lengths, alignment and WoW64 write ordering
//! are native observations on Windows 10.0.29683.1000, recorded in
//! `src/user/windows/native-runtime.md`. No guest request calls the host kernel.

use crate::error::MemoryAccessKind;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::{
    STATUS_DATATYPE_MISALIGNMENT, STATUS_GUARD_PAGE_VIOLATION, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_PARAMETER,
};

const SYSTEM_RANGE_START_INFORMATION: u32 = 50;
const WOW64_LENGTH_FAILURE: u32 = 0xFFFF_FFFC;

fn probe_write(c: &Ctx, address: u64, bytes: usize) -> Result<(), MemFault> {
    c.mem()
        .probe(address, bytes, MemoryAccessKind::Write)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: true,
        })
}

fn return_length(c: &Ctx, address: u64, bytes: u32) -> Result<(), MemFault> {
    if address != 0 {
        c.mem().w32(address, bytes)?;
    }
    Ok(())
}

pub(super) fn system_information(c: &mut Ctx) -> ApiResult {
    let result = query(c);
    if let Err(ApiErr::Fault(fault)) = &result
        && c.p.vm.take_guard(fault.addr)
    {
        return Flow::ret(STATUS_GUARD_PAGE_VIOLATION.into());
    }
    result
}

fn query(c: &mut Ctx) -> ApiResult {
    let (class, output, length, returned) = (c.u32(0)?, c.ptr(1)?, c.u32(2)?, c.ptr(3)?);
    // Native 64-bit entry probes both destinations before class/length dispatch.
    // Its output alignment is ULONG alignment (4), not pointer alignment (8).
    // The installed WoW64 wrapper instead copies its converted output first.
    if c.arch() != WinArch::X86 {
        if returned != 0 {
            probe_write(c, returned, 4)?;
        }
        if length != 0 {
            if output % 4 != 0 {
                return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
            }
            probe_write(c, output, length as usize)?;
        }
    }
    if class != SYSTEM_RANGE_START_INFORMATION {
        return Err(c.unsupported(format!("NtQuerySystemInformation class {class}")));
    }
    if length != c.psize() as u32 {
        let required = if c.arch() == WinArch::X86 {
            WOW64_LENGTH_FAILURE
        } else {
            c.psize() as u32
        };
        return_length(c, returned, required)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    if c.arch() == WinArch::X86 && output == 0 {
        return_length(c, returned, WOW64_LENGTH_FAILURE)?;
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let range = match c.arch() {
        WinArch::X86 => c.p.vm.high(),
        _ => 0xFFFF_8000_0000_0000,
    };
    c.write_ptr(output, range)?;
    return_length(c, returned, c.psize() as u32)?;
    Flow::ret(0)
}
