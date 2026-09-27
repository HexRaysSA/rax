//! The loader's data in guest memory: `PEB_LDR_DATA` and one
//! `LDR_DATA_TABLE_ENTRY` per module, linked into the load-order,
//! memory-order, and initialization-order lists that
//! `EnumProcessModules`, `GetModuleHandle`, and debuggers read.
//!
//! Entries and their name strings are allocated from the process heap, as
//! the Windows loader allocates them.

use super::LoadError;
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{STATUS_INVALID_IMAGE_FORMAT, STATUS_NO_MEMORY};
use crate::user::windows::process::Proc;

/// Allocates zeroed `size` bytes from the process heap for loader data.
fn alloc(p: &mut Proc, size: u64) -> Result<u64, LoadError> {
    let heap = p.process_heap;
    p.heaps
        .alloc(&mut p.vm, heap, size, true)
        .ok_or_else(|| LoadError::new(STATUS_NO_MEMORY, "process heap exhausted for loader data"))
}

fn write_error() -> LoadError {
    LoadError::new(STATUS_NO_MEMORY, "cannot write loader data")
}

fn offset(at: u64, size: u64) -> Result<u64, LoadError> {
    at.checked_add(size)
        .ok_or_else(|| LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "loader data address overflow"))
}

/// Writes a `UNICODE_STRING` for `s` (with a terminating NUL after the
/// counted characters) at `at`.
fn put_unicode_string(p: &mut Proc, at: u64, s: &str) -> Result<(), LoadError> {
    let units: Vec<u16> = s.encode_utf16().collect();
    let bytes = units
        .len()
        .checked_mul(2)
        .filter(|&n| n <= 0xFFFC)
        .ok_or_else(|| {
            LoadError::new(
                STATUS_INVALID_IMAGE_FORMAT,
                "loader name exceeds UNICODE_STRING length",
            )
        })?;
    let buf = alloc(p, bytes as u64 + 2)?;
    p.space.put_wstr(buf, &units).map_err(|_| write_error())?;
    let o = offsets(p.arch);
    p.space.w16(at, bytes as u16).map_err(|_| write_error())?;
    p.space
        .w16(offset(at, 2)?, (bytes + 2) as u16)
        .map_err(|_| write_error())?;
    p.space
        .wptr(offset(at, o.ptr)?, o.ptr, buf)
        .map_err(|_| write_error())
}

/// Initializes an empty list head at `head`.
fn init_list(p: &Proc, head: u64) -> Result<(), LoadError> {
    let ptr = offsets(p.arch).ptr;
    p.space.wptr(head, ptr, head).map_err(|_| write_error())?;
    p.space
        .wptr(offset(head, ptr)?, ptr, head)
        .map_err(|_| write_error())
}

/// Appends `link` to the list at `head` (`InsertTailList`).
fn insert_tail(p: &Proc, head: u64, link: u64) -> Result<(), LoadError> {
    let ptr = offsets(p.arch).ptr;
    let tail = offset(head, ptr)?;
    let blink = p
        .space
        .ptr(tail, ptr)
        .map_err(|_| LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "unreadable loader list tail"))?;
    p.space.wptr(link, ptr, head).map_err(|_| write_error())?;
    p.space
        .wptr(offset(link, ptr)?, ptr, blink)
        .map_err(|_| write_error())?;
    p.space.wptr(blink, ptr, link).map_err(|_| write_error())?;
    p.space.wptr(tail, ptr, link).map_err(|_| write_error())
}

/// Removes `link` from its list (`RemoveEntryList`).
fn remove(p: &Proc, link: u64) -> Result<(), LoadError> {
    let ptr = offsets(p.arch).ptr;
    let flink = p
        .space
        .ptr(link, ptr)
        .map_err(|_| LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "unreadable loader list link"))?;
    let blink = p
        .space
        .ptr(offset(link, ptr)?, ptr)
        .map_err(|_| LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "unreadable loader list link"))?;
    p.space.wptr(blink, ptr, flink).map_err(|_| write_error())?;
    p.space
        .wptr(offset(flink, ptr)?, ptr, blink)
        .map_err(|_| write_error())
}

/// Creates `PEB_LDR_DATA` and stores it in the PEB.
pub fn init(p: &mut Proc) -> Result<(), LoadError> {
    let o = *offsets(p.arch);
    let ldr = alloc(p, o.ldr_size)?;
    p.space
        .w32(ldr + o.ldr_length, o.ldr_size as u32)
        .map_err(|_| write_error())?;
    p.space
        .w8(ldr + o.ldr_initialized, 1)
        .map_err(|_| write_error())?;
    init_list(p, ldr + o.ldr_in_load_order)?;
    init_list(p, ldr + o.ldr_in_memory_order)?;
    init_list(p, ldr + o.ldr_in_init_order)?;
    p.space
        .wptr(p.peb + o.peb_ldr, o.ptr, ldr)
        .map_err(|_| write_error())?;
    p.modules.ldr_data = ldr;
    Ok(())
}

/// `LDR_DATA_TABLE_ENTRY.Flags`: `LDRP_IMAGE_DLL`.
const LDRP_IMAGE_DLL: u32 = 0x0000_0004;
/// `LDRP_ENTRY_PROCESSED`.
const LDRP_ENTRY_PROCESSED: u32 = 0x0000_4000;

/// Creates module `idx`'s entry and links it into the load-order and
/// memory-order lists.
pub fn add_entry(p: &mut Proc, idx: usize) -> Result<(), LoadError> {
    let o = *offsets(p.arch);
    let e = alloc(p, o.entry_size)?;
    let (base, entry, size, path, name, timestamp, is_exe) = {
        let m = &p.modules.list[idx];
        (
            m.base,
            m.entry,
            m.size,
            m.path.clone(),
            m.name.clone(),
            m.timestamp,
            matches!(m.kind, super::ModuleKind::Exe),
        )
    };
    p.space
        .wptr(e + o.entry_dll_base, o.ptr, base)
        .map_err(|_| write_error())?;
    p.space
        .wptr(e + o.entry_entry_point, o.ptr, entry)
        .map_err(|_| write_error())?;
    p.space
        .w32(e + o.entry_size_of_image, size as u32)
        .map_err(|_| write_error())?;
    put_unicode_string(p, e + o.entry_full_name, &path)?;
    put_unicode_string(p, e + o.entry_base_name, &name)?;
    let flags = if is_exe { 0 } else { LDRP_IMAGE_DLL };
    p.space
        .w32(e + o.entry_flags, flags)
        .map_err(|_| write_error())?;
    p.space
        .w16(e + o.entry_load_count, 0xFFFF)
        .map_err(|_| write_error())?;
    init_list(p, e + o.entry_hash_links)?;
    p.space
        .w32(e + o.entry_time_date_stamp, timestamp)
        .map_err(|_| write_error())?;
    p.space
        .wptr(e + o.entry_original_base, o.ptr, base)
        .map_err(|_| write_error())?;
    p.space
        .w32(e + o.entry_reference_count, 1)
        .map_err(|_| write_error())?;
    let ldr = p.modules.ldr_data;
    insert_tail(p, ldr + o.ldr_in_load_order, e + o.entry_in_load_order)?;
    insert_tail(p, ldr + o.ldr_in_memory_order, e + o.entry_in_memory_order)?;
    p.modules.list[idx].ldr_entry = e;
    Ok(())
}

/// Links module `idx` into the initialization-order list and marks it
/// processed (done when its initialization starts).
pub fn link_init_order(p: &mut Proc, idx: usize) -> Result<(), LoadError> {
    let o = *offsets(p.arch);
    let e = p.modules.list[idx].ldr_entry;
    if e == 0 {
        return Ok(());
    }
    let flags = p.space.u32(e + o.entry_flags).map_err(|_| {
        LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "unreadable loader entry flags")
    })?;
    p.space
        .w32(e + o.entry_flags, flags | LDRP_ENTRY_PROCESSED)
        .map_err(|_| write_error())?;
    let ldr = p.modules.ldr_data;
    insert_tail(p, ldr + o.ldr_in_init_order, e + o.entry_in_init_order)
}

/// Unlinks module `idx`'s entry from every list (`FreeLibrary` of the
/// last reference).
pub fn remove_entry(p: &mut Proc, idx: usize) -> Result<(), LoadError> {
    let o = *offsets(p.arch);
    let e = p.modules.list[idx].ldr_entry;
    if e == 0 {
        return Ok(());
    }
    remove(p, e + o.entry_in_load_order)?;
    remove(p, e + o.entry_in_memory_order)?;
    let flags = p.space.u32(e + o.entry_flags).map_err(|_| {
        LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "unreadable loader entry flags")
    })?;
    if flags & LDRP_ENTRY_PROCESSED != 0 {
        remove(p, e + o.entry_in_init_order)?;
    }
    Ok(())
}
