//! Checked system queries made by installed NTDLL initialization.
//!
//! The four-argument API is documented at
//! <https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation>.
//! Classes 0, 50, 62, 197 and 250's private layouts, lengths, alignment and WoW64 ordering
//! are native observations on Windows 10.0.29683.1000, recorded in
//! `src/user/windows/native-runtime.md`. No guest request calls the host kernel.

use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::{ALLOCATION_GRANULARITY, Mem, MemFault};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT, STATUS_GUARD_PAGE_VIOLATION,
    STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER,
    STATUS_NO_MEMORY,
};
use vm_memory::{Address, GuestMemory};

const SYSTEM_BASIC_INFORMATION: u32 = 0;
const SYSTEM_EMULATION_BASIC_INFORMATION: u32 = 62;
const SYSTEM_RANGE_START_INFORMATION: u32 = 50;
const SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION: u32 = 197;
const SYSTEM_PROCESSOR_FEATURES_BITMAP_INFORMATION: u32 = 250;
const WOW64_LENGTH_FAILURE: u32 = 0xFFFF_FFFC;

pub(super) fn probe_write(c: &Ctx, address: u64, bytes: usize) -> Result<(), MemFault> {
    c.mem()
        .probe(address, bytes, MemoryAccessKind::Write)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: true,
        })
}

pub(super) fn return_length(c: &Ctx, address: u64, bytes: u32) -> Result<(), MemFault> {
    if address != 0 {
        c.mem().w32(address, bytes)?;
    }
    Ok(())
}

pub(super) fn system_information(c: &mut Ctx) -> ApiResult {
    let result = query(c);
    guard_result(c, result)
}

pub(super) fn guard_result(c: &mut Ctx, result: ApiResult) -> ApiResult {
    if let Err(ApiErr::Fault(fault)) = &result
        && c.p.vm.take_guard(fault.addr)
    {
        return Flow::ret(STATUS_GUARD_PAGE_VIOLATION.into());
    }
    result
}

fn query(c: &mut Ctx) -> ApiResult {
    let (class, output, length, returned) = (c.u32(0)?, c.ptr(1)?, c.u32(2)?, c.ptr(3)?);
    if class == SYSTEM_PROCESSOR_FEATURES_BITMAP_INFORMATION && c.arch() == WinArch::X86 {
        // The recorded WoW64 wrapper rejects this class before either probe;
        // it has no native bitmap conversion, and leaves ReturnLength intact.
        return Flow::ret(STATUS_INVALID_INFO_CLASS.into());
    }
    // Native 64-bit entry probes both destinations before class/length dispatch.
    // Its output alignment is ULONG alignment (4), not pointer alignment (8).
    // The installed WoW64 wrapper instead copies its converted output first.
    if c.arch() != WinArch::X86 {
        if length != 0 {
            if output % 4 != 0 {
                return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
            }
            if class == SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION
                && output
                    .checked_add(u64::from(length))
                    .is_none_or(|end| end > c.p.vm.high())
            {
                // The measured class197 native entry rejects an upper user
                // span without touching its guard. ReturnLength is instead
                // touched directly below, including a crossing four-byte store.
                return Flow::ret(STATUS_ACCESS_VIOLATION.into());
            }
            probe_write(c, output, length as usize)?;
        }
        if returned != 0 {
            probe_write(c, returned, 4)?;
        }
    }
    match class {
        SYSTEM_BASIC_INFORMATION | SYSTEM_EMULATION_BASIC_INFORMATION => {
            basic_information(c, output, length, returned)
        }
        SYSTEM_RANGE_START_INFORMATION => range_start(c, output, length, returned),
        SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION => {
            hypervisor_shared_page(c, output, length, returned)
        }
        SYSTEM_PROCESSOR_FEATURES_BITMAP_INFORMATION => {
            processor_features(c, output, length, returned)
        }
        _ => Err(c.unsupported(format!("NtQuerySystemInformation class {class}"))),
    }
}

fn hypervisor_shared_page(c: &mut Ctx, output: u64, length: u32, returned: u64) -> ApiResult {
    if c.arch() == WinArch::X86 && output == 0 && length != 0 {
        // WoW64's null-output conversion precedes the short-length check and
        // publishes its observed translated error length before the fault.
        return_length(c, returned, WOW64_LENGTH_FAILURE)?;
        return Err(MemFault {
            addr: 0,
            write: true,
        }
        .into());
    }
    if c.arch() == WinArch::X86 && length != 0 {
        // Selected WoW64 reserves align_up(length + 4, 16) bytes before
        // either destination is touched; its heap fallback adds a 16-byte
        // list node and raises STATUS_NO_MEMORY on allocation failure. Model
        // temporary backing within the guest's no-paging-file budget, without
        // allocating host storage or exposing a native scratch address.
        let capture = ((u64::from(length) + 19) & !15) + 16;
        let charge = (capture + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if charge > c.p.vm.commit_limit() - c.p.vm.committed_bytes()
            || charge > c.p.vm.high() - c.p.vm.low()
        {
            return Flow::ret(STATUS_NO_MEMORY.into());
        }
    }
    let required = c.psize() as u32;
    if length < required {
        return_length(c, returned, required)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    // The guest has no hypervisor timing-page mapping. PHNT specifies NULL
    // for that profile. Never publish or dereference a host virtual address.
    // WoW64 writes only its converted pointer, then ReturnLength; native64
    // already probed both destinations and the entire supplied output span.
    c.write_ptr(output, 0)?;
    return_length(c, returned, required)?;
    Flow::ret(0)
}

fn processor_features(c: &mut Ctx, output: u64, length: u32, returned: u64) -> ApiResult {
    const BYTES: usize = 16;
    // Native entry already probed the entire supplied extent and ReturnLength.
    // This profile accepts >=16 bytes in ULONG64 multiples but writes only 16.
    if length < BYTES as u32 || length % 8 != 0 {
        return_length(c, returned, BYTES as u32)?;
        return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
    }
    let mut bitmap = [0u8; BYTES];
    for bit in 0..BYTES * 8 {
        // The baseline 64 PF entries reside in KUSER_SHARED_DATA. Bitmap bit
        // zero describes PF 64; shifting baseline flags here would be wrong.
        if crate::user::windows::dll::processor_feature_present(&c.t.cpu, 64 + bit as u32) {
            bitmap[bit / 8] |= 1 << (bit % 8);
        }
    }
    c.mem().wr(output, &bitmap)?;
    return_length(c, returned, BYTES as u32)?;
    Flow::ret(0)
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
