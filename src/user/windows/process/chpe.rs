//! Initial CHPE V2 process data, before installed RTL executes.
//! The completed normal-creation control supplies the finite identity and bytes;
//! later RTL owns its flags, Section and work-list initialization.
use super::Proc;
use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::{WOW64_FS_GDT_INDEX, WinArch, WinCpu};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;

const FIELD: u64 = 0x338;
const RECORD: u64 = 0x7d8;
const BYTES: usize = 32;
const _: () = assert!(RECORD + BYTES as u64 <= PAGE_SIZE);

fn access_error<T>(_: T) -> u32 {
    STATUS_ACCESS_VIOLATION
}

pub(super) fn selected(p: &Proc) -> Result<bool, u32> {
    if p.arch != WinArch::X64 {
        return Ok(false);
    }
    let Some(native) = p.native.as_ref() else {
        return Ok(false);
    };
    match native.object_namespace.native_machine {
        Some(0x8664) => Ok(false),
        Some(0xaa64)
            if (
                native.version.major,
                native.version.minor,
                native.version.build,
            ) == (10, 0, 29704) =>
        {
            Ok(true)
        }
        _ => Err(STATUS_NOT_SUPPORTED),
    }
}

/// Called once during construction, before any guest instruction or thread.
/// Both stores stay in the existing process-owned PEB page. No allocation,
/// host pointer, native handle or post-initialization callback is published.
pub(super) fn initialize(p: &mut Proc) -> Result<(), u32> {
    if !selected(p)? {
        return Ok(());
    }
    if p.peb % PAGE_SIZE != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let field = p.peb.checked_add(FIELD).ok_or(STATUS_ACCESS_VIOLATION)?;
    let record = p.peb.checked_add(RECORD).ok_or(STATUS_ACCESS_VIOLATION)?;
    p.space
        .probe(field, 8, MemoryAccessKind::Write)
        .map_err(access_error)?;
    p.space
        .probe(record, BYTES, MemoryAccessKind::Write)
        .map_err(access_error)?;
    if p.space.u64(field).map_err(access_error)? != 0
        || p.space
            .bytes(record, BYTES)
            .map_err(access_error)?
            .iter()
            .any(|&b| b != 0)
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // Measured kernel 29704 compatibility XSTATE configuration. This kernel
    // exposes x87/SSE/AVX to its x64 translator, independently of host CPU
    // capabilities. Installed RTL owns the extended-context allocations.
    let mut xstate = [0u8; 840];
    xstate[..8].copy_from_slice(&7u64.to_le_bytes());
    xstate[8..16].copy_from_slice(&7u64.to_le_bytes());
    for at in [16, 552, 832] {
        xstate[at..at + 4].copy_from_slice(&832u32.to_le_bytes());
    }
    for (n, (offset, size)) in [(0u32, 160u32), (160, 256), (576, 256)]
        .into_iter()
        .enumerate()
    {
        let at = 24 + n * 8;
        xstate[at..at + 4].copy_from_slice(&offset.to_le_bytes());
        xstate[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
    }
    p.vm.poke(
        crate::user::windows::layout::KUSER_SHARED_DATA + 0x3d8,
        &xstate,
    )
    .map_err(access_error)?;
    let mut bytes = [0; BYTES];
    bytes[4..6].copy_from_slice(&0xaa64u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&0x8664u16.to_le_bytes());
    // Construction excludes guest execution and concurrent address-space edits;
    // the complete preflight makes both writes infallible in this ownership phase.
    p.space.wr(record, &bytes).map_err(access_error)?;
    p.space.w64(field, record).map_err(access_error)?;
    Ok(())
}

/// Initialize the measured selectors before saving a loader/CHPE context.
/// Process construction already enforces `selected(p)?`; other constructed
/// profiles retain their existing CPU state. GS is loaded before `set_teb`
/// supplies the guest-owned base, never a captured native address.
pub(super) fn initialize_thread(p: &Proc, cpu: &mut WinCpu) -> Result<(), u32> {
    if selected(p) != Ok(true) {
        return Ok(());
    }
    if cpu.arch() != WinArch::X64 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    use crate::isa::x86_64::{X86UserSegment, gdt_entry};

    let v = cpu.x86_mut().ok_or(STATUS_INVALID_PARAMETER)?.vcpu_mut();
    // Native LAR/LSL/RDFSBASE: access 0x0040F300, limit 0xFFF, base 0.
    if !v.set_user_gdt_entry(WOW64_FS_GDT_INDEX, gdt_entry(0x40f3, 0, 0xfff)) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    for (segment, selector) in [(X86UserSegment::Fs, 0x53), (X86UserSegment::Gs, 0x2b)] {
        v.load_user_segment(segment, selector)
            .map_err(|_| STATUS_INVALID_PARAMETER)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
