//! The loader's data in guest memory: `PEB_LDR_DATA` and one
//! `LDR_DATA_TABLE_ENTRY` per module, linked into the load-order,
//! memory-order, and initialization-order lists that
//! `EnumProcessModules`, `GetModuleHandle`, and debuggers read.
//!
//! Entries and their name strings are allocated from the process heap, as
//! the Windows loader allocates them.

use super::LoadError;
use crate::error::MemoryAccessKind;
use crate::user::windows::heap::HeapError;
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_INVALID_IMAGE_FORMAT, STATUS_NO_MEMORY,
};
use crate::user::windows::process::Proc;

/// Allocates zeroed `size` bytes from the process heap for loader data.
fn alloc(p: &mut Proc, size: u64) -> Result<u64, LoadError> {
    let heap = p.process_heap;
    p.heaps
        .alloc_checked(&mut p.vm, heap, size, true)
        .map_err(|error| {
            let status = match error {
                HeapError::NoMemory => STATUS_NO_MEMORY,
                HeapError::MemoryFault(_) => STATUS_ACCESS_VIOLATION,
                HeapError::BadHeap | HeapError::BadBlock => STATUS_INVALID_IMAGE_FORMAT,
            };
            LoadError::new(status, format!("cannot allocate loader data: {error:?}"))
        })
}

fn write_error() -> LoadError {
    LoadError::new(STATUS_ACCESS_VIOLATION, "cannot write loader data")
}

fn alloc_owned(p: &mut Proc, idx: usize, size: u64) -> Result<u64, LoadError> {
    let block = alloc(p, size)?;
    p.modules
        .dynamic
        .ldr_allocations
        .entry(idx)
        .or_default()
        .push(block);
    Ok(block)
}

fn writable(p: &Proc, at: u64, len: u64) -> Result<(), LoadError> {
    let len = usize::try_from(len).map_err(|_| write_error())?;
    p.space
        .probe(at, len, MemoryAccessKind::Write)
        .map_err(|_| write_error())
}

fn offset(at: u64, size: u64) -> Result<u64, LoadError> {
    at.checked_add(size)
        .ok_or_else(|| LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "loader data address overflow"))
}

/// Writes a `UNICODE_STRING` for `s` (with a terminating NUL after the
/// counted characters) at `at`.
fn put_unicode_string(p: &mut Proc, idx: usize, at: u64, s: &str) -> Result<(), LoadError> {
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
    let buf = alloc_owned(p, idx, bytes as u64 + 2)?;
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
    // Check every destination before changing the linked list. Guest list
    // corruption must not publish a partially inserted entry.
    for at in [link, offset(link, ptr)?, blink, tail] {
        writable(p, at, ptr)?;
    }
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
    writable(p, blink, ptr)?;
    writable(p, offset(flink, ptr)?, ptr)?;
    p.space.wptr(blink, ptr, flink).map_err(|_| write_error())?;
    p.space
        .wptr(offset(flink, ptr)?, ptr, blink)
        .map_err(|_| write_error())
}

/// Creates `PEB_LDR_DATA` and stores it in the PEB.
///
/// Startup compatibility reports allocation/publication failure as
/// `STATUS_NO_MEMORY`. This is the existing RAX contract, not a specified
/// native status for corrupt private startup storage. Dynamic loader writes
/// retain their separate access-fault classification.
pub fn init(p: &mut Proc) -> Result<(), LoadError> {
    let o = *offsets(p.arch);
    let startup_error = |mut error: LoadError| {
        error.status = STATUS_NO_MEMORY;
        error
    };
    let destination = p
        .peb
        .checked_add(o.peb_ldr)
        .ok_or_else(|| LoadError::new(STATUS_NO_MEMORY, "PEB loader pointer address overflow"))?;
    // Do not allocate or zero an unpublishable block. The host dispatcher is
    // serial, so the destination cannot change between probe and publication.
    writable(p, destination, o.ptr).map_err(startup_error)?;
    let ldr = alloc(p, o.ldr_size).map_err(startup_error)?;
    let result = (|| {
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
            .wptr(destination, o.ptr, ldr)
            .map_err(|_| write_error())
    })();
    if let Err(error) = result {
        if let Err(cleanup) = p.heaps.free(p.process_heap, ldr) {
            p.fail(format!(
                "startup loader allocation cleanup failed: {cleanup:?}; original: {error}"
            ));
        }
        return Err(startup_error(error));
    }
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
    let e = alloc_owned(p, idx, o.entry_size)?;
    p.modules.list[idx].ldr_entry = e;
    p.modules.dynamic.ldr_links.insert(idx, [false; 3]);
    let (base, entry, size, path, name, timestamp, is_dll, count) = {
        let m = &p.modules.list[idx];
        (
            m.base,
            m.entry,
            m.size,
            m.path.clone(),
            m.name.clone(),
            m.timestamp,
            matches!(
                m.kind,
                super::ModuleKind::Native | super::ModuleKind::Builtin(_)
            ),
            m.load_count,
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
    put_unicode_string(p, idx, e + o.entry_full_name, &path)?;
    put_unicode_string(p, idx, e + o.entry_base_name, &name)?;
    let flags = if is_dll { LDRP_IMAGE_DLL } else { 0 };
    p.space
        .w32(e + o.entry_flags, flags)
        .map_err(|_| write_error())?;
    set_count(p, idx, count)?;
    init_list(p, e + o.entry_hash_links)?;
    p.space
        .w32(e + o.entry_time_date_stamp, timestamp)
        .map_err(|_| write_error())?;
    p.space
        .wptr(e + o.entry_original_base, o.ptr, base)
        .map_err(|_| write_error())?;
    let ldr = p.modules.ldr_data;
    insert_tail(p, ldr + o.ldr_in_load_order, e + o.entry_in_load_order)?;
    p.modules.dynamic.ldr_links.get_mut(&idx).unwrap()[0] = true;
    insert_tail(p, ldr + o.ldr_in_memory_order, e + o.entry_in_memory_order)?;
    p.modules.dynamic.ldr_links.get_mut(&idx).unwrap()[1] = true;
    Ok(())
}

/// The host's explicit reference counter is authoritative. The legacy 16-bit
/// field saturates below its pinned sentinel; the 32-bit field remains exact.
pub(crate) fn set_count(p: &Proc, idx: usize, count: u32) -> Result<(), LoadError> {
    let o = *offsets(p.arch);
    let e = p.modules.list[idx].ldr_entry;
    if e == 0 {
        return Ok(());
    }
    writable(p, e + o.entry_load_count, 2)?;
    writable(p, e + o.entry_reference_count, 4)?;
    let legacy = if count == u32::MAX {
        0xFFFF
    } else {
        count.min(0xFFFE) as u16
    };
    p.space
        .w16(e + o.entry_load_count, legacy)
        .map_err(|_| write_error())?;
    p.space
        .w32(e + o.entry_reference_count, count)
        .map_err(|_| write_error())
}

/// Links module `idx` into the initialization-order list and marks it
/// processed (done when its initialization starts).
pub fn link_init_order(p: &mut Proc, idx: usize) -> Result<(), LoadError> {
    let o = *offsets(p.arch);
    let e = p.modules.list[idx].ldr_entry;
    if e == 0 {
        return Ok(());
    }
    if p.modules
        .dynamic
        .ldr_links
        .get(&idx)
        .is_some_and(|links| links[2])
    {
        return Ok(());
    }
    let flags = p.space.u32(e + o.entry_flags).map_err(|_| {
        LoadError::new(STATUS_INVALID_IMAGE_FORMAT, "unreadable loader entry flags")
    })?;
    writable(p, e + o.entry_flags, 4)?;
    let ldr = p.modules.ldr_data;
    insert_tail(p, ldr + o.ldr_in_init_order, e + o.entry_in_init_order)?;
    p.modules.dynamic.ldr_links.entry(idx).or_insert([false; 3])[2] = true;
    p.space
        .w32(e + o.entry_flags, flags | LDRP_ENTRY_PROCESSED)
        .map_err(|_| write_error())
}

/// Unlinks module `idx`'s entry from every list (`FreeLibrary` of the
/// last reference).
pub fn remove_entry(p: &mut Proc, idx: usize) -> Result<(), LoadError> {
    let o = *offsets(p.arch);
    let e = p.modules.list[idx].ldr_entry;
    let links = p
        .modules
        .dynamic
        .ldr_links
        .get(&idx)
        .copied()
        .unwrap_or([false; 3]);
    for (which, off) in [
        o.entry_in_load_order,
        o.entry_in_memory_order,
        o.entry_in_init_order,
    ]
    .into_iter()
    .enumerate()
    {
        if links[which] {
            remove(p, e + off)?;
            p.modules.dynamic.ldr_links.get_mut(&idx).unwrap()[which] = false;
        }
    }
    // Retain the ledger until each free succeeds; an interrupted cleanup is
    // resumable without trusting the guest's UNICODE_STRING pointers.
    while let Some(block) = p
        .modules
        .dynamic
        .ldr_allocations
        .get(&idx)
        .and_then(|v| v.last())
        .copied()
    {
        p.heaps.free(p.process_heap, block).map_err(|_| {
            LoadError::new(
                STATUS_INVALID_IMAGE_FORMAT,
                "invalid owned loader allocation",
            )
        })?;
        p.modules
            .dynamic
            .ldr_allocations
            .get_mut(&idx)
            .unwrap()
            .pop();
    }
    p.modules.dynamic.ldr_allocations.remove(&idx);
    p.modules.dynamic.ldr_links.remove(&idx);
    p.modules.list[idx].ldr_entry = 0;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::memory::prot;
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};

    fn images() -> [&'static [u8]; 3] {
        [
            include_bytes!("../../../../tests/fixtures/user/windows/bin/x86/smoke.exe"),
            include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe"),
            include_bytes!("../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe"),
        ]
    }

    fn process(bytes: &[u8]) -> WindowsProcess {
        let mut config = WindowsConfig::new("ldr-startup-test.exe", Vec::new());
        config.seed = Some(1);
        config.arena_bytes = 64 << 20;
        WindowsProcess::spawn_image(config, bytes.to_vec()).unwrap()
    }

    #[test]
    fn startup_unwritable_peb_keeps_compatibility_status_without_allocating() {
        for image in images() {
            let mut process = process(image);
            let p = process.state_mut();
            let old_heap = p.process_heap;
            let old_ldr = p.modules.ldr_data;
            let o = *offsets(p.arch);
            let heap = p.heaps.create(&mut p.vm, 0, 0x1000, 0x2000).unwrap();
            p.process_heap = heap;
            let available = p.heaps.alloc(&mut p.vm, heap, o.ldr_size, false).unwrap();
            let poison = vec![0xA5; o.ldr_size as usize];
            p.space.wr(available, &poison).unwrap();
            p.heaps.free(heap, available).unwrap();
            p.vm.protect(p.peb, 0x1000, prot::NOACCESS).unwrap();
            let committed = p.vm.committed_bytes();
            assert_eq!(init(p).unwrap_err().status, STATUS_NO_MEMORY);
            assert_eq!(p.vm.committed_bytes(), committed);
            assert_eq!(p.modules.ldr_data, old_ldr);
            let mut actual = vec![0; poison.len()];
            p.space.rd(available, &mut actual).unwrap();
            assert_eq!(actual, poison, "preflight must precede heap zeroing");
            let next = p.heaps.alloc(&mut p.vm, heap, o.ldr_size, false).unwrap();
            assert_eq!(
                next, available,
                "failed startup must not consume a heap block"
            );
            p.heaps.free(heap, next).unwrap();
            p.vm.protect(p.peb, 0x1000, prot::READWRITE).unwrap();
            p.process_heap = old_heap;
        }
    }

    #[test]
    fn startup_heap_access_failure_retains_no_memory_compatibility() {
        for image in images() {
            let mut process = process(image);
            let p = process.state_mut();
            let old_heap = p.process_heap;
            let old_ldr = p.modules.ldr_data;
            let heap = p.heaps.create(&mut p.vm, 0, 0x1000, 0x2000).unwrap();
            p.process_heap = heap;
            p.vm.protect(heap, 0x1000, prot::READONLY).unwrap();
            assert_eq!(init(p).unwrap_err().status, STATUS_NO_MEMORY);
            assert_eq!(p.modules.ldr_data, old_ldr);
            assert!(p.failure.is_none());
            p.vm.protect(heap, 0x1000, prot::READWRITE).unwrap();
            p.process_heap = old_heap;
        }
    }
}
