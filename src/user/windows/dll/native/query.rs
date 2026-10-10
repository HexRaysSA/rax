//! Checked system queries made by installed NTDLL initialization.
//!
//! The four-argument API is documented at
//! <https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation>.
//! Classes 0 and 50's private layouts, exact lengths, alignment and WoW64 ordering
//! are native observations on Windows 10.0.29683.1000, recorded in
//! `src/user/windows/native-runtime.md`. No guest request calls the host kernel.

use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{ALLOCATION_GRANULARITY, Mem, MemFault};
use crate::user::windows::nt::status::{
    STATUS_DATATYPE_MISALIGNMENT, STATUS_GUARD_PAGE_VIOLATION, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_PARAMETER,
};
use vm_memory::{Address, GuestMemory};

const SYSTEM_BASIC_INFORMATION: u32 = 0;
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
    match class {
        SYSTEM_BASIC_INFORMATION => basic_information(c, output, length, returned),
        SYSTEM_RANGE_START_INFORMATION => range_start(c, output, length, returned),
        _ => Err(c.unsupported(format!("NtQuerySystemInformation class {class}"))),
    }
}

fn range_start(c: &mut Ctx, output: u64, length: u32, returned: u64) -> ApiResult {
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

fn basic_information(c: &mut Ctx, output: u64, length: u32, returned: u64) -> ApiResult {
    let required = if c.arch() == WinArch::X86 { 44 } else { 64 };
    if length != required {
        return_length(c, returned, required)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    if c.arch() == WinArch::X86 && output == 0 {
        // Observed WoW64 conversion of the null-output error's native length.
        return_length(c, returned, 0xFFFF_FFEC)?;
        return Err(MemFault {
            addr: 0,
            write: true,
        }
        .into());
    }
    // WoW64 probes just the converted fields; its last three padding bytes
    // may be inaccessible and are never written. 64-bit entry probed all 64.
    let written = if c.arch() == WinArch::X86 { 41 } else { 64 };
    probe_write(c, output, written)?;
    let pages = u32::try_from(c.p.vm.commit_limit() / PAGE_SIZE)
        .map_err(|_| c.unsupported("SystemBasicInformation physical page count exceeds ULONG"))?;
    let highest = u32::try_from(c.p.space.physical_memory().last_addr().raw_value() / PAGE_SIZE)
        .map_err(|_| c.unsupported("SystemBasicInformation physical frame extent exceeds ULONG"))?;
    let mut data = [0u8; 64];
    // The reserved span is the recorded private profile, not public SDK fields.
    // Guest timer granularity: 1 ms = 10,000 units of 100 ns. One virtual CPU,
    // no paging file, and usable backing pages (excluding reserved frames).
    for (index, value) in [
        0,
        10_000,
        PAGE_SIZE as u32,
        pages,
        0,
        highest,
        ALLOCATION_GRANULARITY as u32,
    ]
    .into_iter()
    .enumerate()
    {
        data[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    let first = if c.arch() == WinArch::X86 { 28 } else { 32 };
    let width = c.psize() as usize;
    for (index, value) in [c.p.vm.low(), c.p.vm.high() - 1, 1].into_iter().enumerate() {
        let at = first + index * width;
        data[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }
    data[first + 3 * width] = 1;
    c.mem().wr(output, &data[..written])?;
    return_length(c, returned, required)?;
    Flow::ret(0)
}
