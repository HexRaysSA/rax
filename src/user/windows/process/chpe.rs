//! Initial CHPE V2 process data, before installed RTL executes.
//! The completed normal-creation control supplies the finite identity and bytes;
//! later RTL owns its flags, Section and work-list initialization.
use super::Proc;
use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;

const FIELD: u64 = 0x338;
const RECORD: u64 = 0x7d8;
const BYTES: usize = 32;
const _: () = assert!(RECORD + BYTES as u64 <= PAGE_SIZE);

fn access_error<T>(_: T) -> u32 {
    STATUS_ACCESS_VIOLATION
}

fn selected(p: &Proc) -> Result<bool, u32> {
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
    let mut bytes = [0; BYTES];
    bytes[4..6].copy_from_slice(&0xaa64u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&0x8664u16.to_le_bytes());
    // Construction excludes guest execution and concurrent address-space edits;
    // the complete preflight makes both writes infallible in this ownership phase.
    p.space.wr(record, &bytes).map_err(access_error)?;
    p.space.w64(field, record).map_err(access_error)?;
    Ok(())
}

#[cfg(test)]
mod tests;
