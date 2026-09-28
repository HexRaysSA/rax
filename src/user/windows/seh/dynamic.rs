//! Guest-owned, fixed dynamic function tables registered through Kernel32.
//!
//! Unlike PE `.pdata`, `RtlAddFunctionTable` supplies no image extent. The
//! array, code, and unwind data can occupy separate guest mappings. Every
//! lookup therefore reads the live guest array and uses checked guest memory
//! for metadata; no host pointer or invented image bound is involved.

use super::unwind::FunctionEntry;
use crate::user::windows::arch::WinArch;
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::process::Proc;

/// Admission bound across all registered tables: no guest call may force an
/// unbounded host-side scan. This is a RAX policy, not a native Windows limit.
pub(crate) const MAX_ENTRIES: u32 = 65_536;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Table {
    /// Original guest array pointer: also the deletion identity.
    pub pointer: u64,
    pub count: u32,
    /// Base added to entry RVAs, not necessarily an image/allocation base.
    pub base: u64,
}

fn bad(address: u64) -> MemFault {
    MemFault {
        addr: address,
        write: false,
    }
}

fn width(arch: WinArch) -> u64 {
    match arch {
        WinArch::X64 => 12,
        WinArch::Arm64 => 8,
        WinArch::X86 => 0,
    }
}

fn entry_address(table: Table, arch: WinArch, index: u32) -> Result<u64, MemFault> {
    table
        .pointer
        .checked_add(u64::from(index) * width(arch))
        .ok_or_else(|| bad(u64::MAX))
}

/// Reads one live entry. `None` is malformed metadata, not a leaf.
fn read_entry(
    p: &Proc,
    table: Table,
    index: u32,
) -> Result<Option<(FunctionEntry, u64)>, MemFault> {
    let at = entry_address(table, p.arch, index)?;
    let begin = p.space.u32(at)?;
    let second = p.space.u32(at + 4)?;
    let (end, unwind) = match p.arch {
        WinArch::X64 => {
            let unwind = p.space.u32(at + 8)?;
            if begin >= second {
                return Ok(None);
            }
            (u64::from(second), unwind)
        }
        WinArch::Arm64 => {
            if begin & 3 != 0 {
                return Ok(None);
            }
            let length = match second & 3 {
                1 | 2 => ((second >> 2) & 0x7ff) * 4,
                0 => {
                    let Some(xdata) = table.base.checked_add(u64::from(second)) else {
                        return Ok(None);
                    };
                    (p.space.u32(xdata)? & 0x3ffff) * 4
                }
                _ => return Ok(None),
            };
            if length == 0 {
                return Ok(None);
            }
            (u64::from(begin) + u64::from(length), second)
        }
        WinArch::X86 => return Ok(None),
    };
    let Some(start) = table.base.checked_add(u64::from(begin)) else {
        return Ok(None);
    };
    let Some(limit) = table.base.checked_add(end) else {
        return Ok(None);
    };
    if start >= limit || table.base.checked_add(u64::from(unwind)).is_none() {
        return Ok(None);
    }
    Ok(Some((
        FunctionEntry {
            image_base: table.base,
            entry: at,
            begin,
            end: if p.arch == WinArch::X64 { second } else { 0 },
            unwind,
        },
        limit,
    )))
}

/// Registers a fixed array. Structural rejection returns `false`; a genuine
/// inaccessible guest read returns the existing checked-memory fault.
pub(crate) fn register(
    p: &mut Proc,
    pointer: u64,
    count: u32,
    base: u64,
) -> Result<bool, MemFault> {
    let stride = width(p.arch);
    if stride == 0
        || pointer == 0
        || pointer & 3 != 0
        || count == 0
        || count > MAX_ENTRIES
        || p.seh
            .dynamic_tables
            .iter()
            .map(|table| u64::from(table.count))
            .sum::<u64>()
            + u64::from(count)
            > u64::from(MAX_ENTRIES)
        || p.seh
            .dynamic_tables
            .iter()
            .any(|table| table.pointer == pointer)
        || pointer.checked_add(u64::from(count) * stride).is_none()
    {
        return Ok(false);
    }
    let table = Table {
        pointer,
        count,
        base,
    };
    for index in 0..count {
        if read_entry(p, table, index)?.is_none() {
            return Ok(false);
        }
    }
    p.seh.dynamic_tables.push(table);
    Ok(true)
}

/// Removes exactly one registration by its original guest array pointer.
pub(crate) fn delete(p: &mut Proc, pointer: u64) -> bool {
    let Some(index) = p
        .seh
        .dynamic_tables
        .iter()
        .position(|table| table.pointer == pointer)
    else {
        return false;
    };
    p.seh.dynamic_tables.remove(index);
    true
}

/// Finds a live dynamic entry for `pc`. Tables and entries may be unsorted.
/// More than one match has undocumented precedence and fails closed.
pub(crate) fn lookup(p: &Proc, pc: u64) -> Result<Option<FunctionEntry>, MemFault> {
    let mut found = None;
    for &table in &p.seh.dynamic_tables {
        for index in 0..table.count {
            let Some((entry, end)) = read_entry(p, table, index)? else {
                return Err(bad(entry_address(table, p.arch, index)?));
            };
            let start = table.base + u64::from(entry.begin);
            if pc >= start && pc < end {
                if found.is_some() {
                    return Err(bad(pc));
                }
                found = Some(entry);
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::mm::PAGE_SIZE;
    use crate::user::windows::context::RegContext;
    use crate::user::windows::memory::{mem, prot};
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};
    use crate::user::windows::seh::unwind::{self, UNW_FLAG_EHANDLER};

    fn with_process(arch: WinArch, test: impl FnOnce(&mut Proc)) {
        let image: &[u8] = match arch {
            WinArch::X86 => {
                include_bytes!("../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
            WinArch::X64 => {
                include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::Arm64 => {
                include_bytes!("../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
            }
        };
        let mut config = WindowsConfig::new("dynamic-unwind.exe", Vec::new());
        config.seed = Some(1);
        config.arena_bytes = 64 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        test(process.state_mut());
    }

    fn page(p: &mut Proc) -> u64 {
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0
    }

    fn write_x64(p: &Proc, table: u64, index: u64, begin: u32, end: u32, unwind: u32) {
        let at = table + 12 * index;
        p.space.w32(at, begin).unwrap();
        p.space.w32(at + 4, end).unwrap();
        p.space.w32(at + 8, unwind).unwrap();
    }

    #[test]
    fn x64_dynamic_nonleaf_unwind_registration_and_exact_pointer_delete() {
        with_process(WinArch::X64, |p| {
            let code = page(p);
            let table = page(p);
            assert!(p.modules.by_address(code).is_none());
            write_x64(p, table, 0, 0, 0x20, 0x100);
            // Version 1; 4-byte prolog; UWOP_ALLOC_SMALL, OpInfo=4 =>
            // (4 * 8 + 8) bytes = 40 bytes of fixed stack allocation.
            p.space
                .wr(code + 0x100, &[1, 4, 1, 0, 4, 0x42, 0, 0])
                .unwrap();
            let thread = p.threads.values().next().unwrap();
            let mut context = RegContext::capture(&thread.cpu);
            let sp = context.sp() - 0x100;
            let caller = 0x1234_5678u64;
            p.space.w64(sp, 0xDEAD_BEEF).unwrap();
            p.space.w64(sp + 40, caller).unwrap();
            context.set_pc(code + 8);
            context.set_sp(sp);

            assert_eq!(unwind::lookup(p, code + 8).unwrap(), None);
            let mut before = context.clone();
            assert_eq!(unwind::step(p, 0, &mut before).unwrap().0, None);
            assert_eq!((before.pc(), before.sp()), (0xDEAD_BEEF, sp + 8));

            assert!(register(p, table, 1, code).unwrap());
            assert!(!register(p, table, 1, code).unwrap());
            let found = unwind::lookup(p, code + 8).unwrap().unwrap();
            assert_eq!((found.entry, found.image_base), (table, code));
            let mut through_table = context.clone();
            assert_eq!(
                unwind::step(p, 0, &mut through_table).unwrap().0,
                Some(found)
            );
            assert_eq!((through_table.pc(), through_table.sp()), (caller, sp + 48));

            assert!(!delete(p, table + 12));
            assert!(delete(p, table));
            assert!(!delete(p, table));
            assert_eq!(unwind::lookup(p, code + 8).unwrap(), None);
        });
    }

    #[test]
    fn x64_unsorted_and_mutated_tables_are_read_live() {
        with_process(WinArch::X64, |p| {
            let code = page(p);
            let table = page(p);
            write_x64(p, table, 0, 0x40, 0x60, 0x100);
            write_x64(p, table, 1, 0, 0x20, 0x100);
            assert!(register(p, table, 2, code).unwrap());
            assert_eq!(
                unwind::lookup(p, code + 0x10).unwrap().unwrap().entry,
                table + 12
            );
            assert_eq!(
                unwind::lookup(p, code + 0x50).unwrap().unwrap().entry,
                table
            );

            // Reorder live guest bytes after registration. A cached sorted
            // flag or snapshotted entry list would miss this new location.
            write_x64(p, table, 1, 0x80, 0xA0, 0x100);
            assert_eq!(unwind::lookup(p, code + 0x10).unwrap(), None);
            assert_eq!(
                unwind::lookup(p, code + 0x90).unwrap().unwrap().entry,
                table + 12
            );

            p.vm.protect(table, PAGE_SIZE, prot::NOACCESS).unwrap();
            assert_eq!(unwind::lookup(p, code + 0x50), Err(bad(table)));
            // Deletion uses only pointer identity, not a read from retired
            // guest storage.
            assert!(delete(p, table));
            assert_eq!(unwind::lookup(p, code + 0x50).unwrap(), None);
        });
    }

    #[test]
    fn image_lookup_miss_falls_through_and_overlaps_fail_closed() {
        with_process(WinArch::X64, |p| {
            let code = page(p);
            let table = page(p);
            let other = page(p);
            write_x64(p, table, 0, 0, 0x20, 0x100);
            write_x64(p, other, 0, 0, 0x20, 0x100);
            assert!(register(p, table, 1, code).unwrap());
            assert!(register(p, other, 1, code).unwrap());
            assert_eq!(unwind::lookup(p, code + 8), Err(bad(code + 8)));
            assert!(delete(p, other));
            assert_eq!(unwind::lookup(p, code + 8).unwrap().unwrap().entry, table);
            assert!(delete(p, table));

            let module_base = p.modules.exe().base;
            p.modules.list[0].pdata = crate::user::image::pe::DataDirectory { rva: 0, size: 0 };
            write_x64(p, table, 0, 0, 0x80, 0x100);
            assert!(register(p, table, 1, module_base).unwrap());
            assert_eq!(
                unwind::lookup(p, module_base + 0x40)
                    .unwrap()
                    .unwrap()
                    .entry,
                table
            );
            let module_size = p.modules.exe().size;
            p.vm.protect(module_base, module_size, prot::READWRITE)
                .unwrap();
            p.space.w32(module_base + 0x1000, 0x10).unwrap();
            p.space.w32(module_base + 0x1004, 0x80).unwrap();
            p.space.w32(module_base + 0x1008, 0x1800).unwrap();
            p.modules.list[0].pdata = crate::user::image::pe::DataDirectory {
                rva: 0x1000,
                size: 12,
            };
            assert_eq!(
                unwind::lookup(p, module_base + 0x40),
                Err(bad(module_base + 0x40))
            );
        });
    }

    #[test]
    fn x64_metadata_fault_keeps_context_and_malformed_mutation_is_not_leaf() {
        with_process(WinArch::X64, |p| {
            let code = page(p);
            let table = page(p);
            write_x64(p, table, 0, 0, 0x20, 0x100);
            assert!(register(p, table, 1, code).unwrap());
            let thread = p.threads.values().next().unwrap();
            let mut context = RegContext::capture(&thread.cpu);
            context.set_pc(code + 8);
            let before = context.clone();
            assert!(unwind::step(p, UNW_FLAG_EHANDLER, &mut context).is_err());
            assert_eq!(context, before);

            write_x64(p, table, 0, 0x20, 0x20, 0x100);
            assert_eq!(unwind::lookup(p, code + 8), Err(bad(table)));
        });
    }

    #[test]
    fn arm64_packed_and_full_xdata_use_registered_base() {
        with_process(WinArch::Arm64, |p| {
            let code = page(p);
            let table = page(p);
            let thread = p.threads.values().next().unwrap();
            let mut context = RegContext::capture(&thread.cpu);
            let sp = context.sp() - 0x100;
            p.space.w64(sp, 0x9876).unwrap();
            p.space.w64(sp + 8, 0x5678).unwrap();
            context.set_pc(code + 0x20);
            context.set_sp(sp);
            context.set_gpr(30, 0x1234);

            let packed = 1 | (64 << 2) | (3 << 21) | (4 << 23);
            p.space.w32(table, 0).unwrap();
            p.space.w32(table + 4, packed).unwrap();
            assert!(register(p, table, 1, code).unwrap());
            let mut next = context.clone();
            assert_eq!(
                unwind::step(p, 0, &mut next).unwrap().0.unwrap().entry,
                table
            );
            assert_eq!(
                (next.gpr(29), next.pc(), next.sp()),
                (0x9876, 0x5678, sp + 64)
            );
            assert!(delete(p, table));

            p.space.w32(table + 4, 0x100).unwrap();
            p.space
                .w32(code + 0x100, 64 | (1 << 20) | (1 << 27))
                .unwrap();
            p.space.wr(code + 0x104, &[0xE1, 0x87, 0xE4, 0]).unwrap();
            assert!(register(p, table, 1, code).unwrap());
            context.set_gpr(29, sp);
            let mut next = context.clone();
            assert_eq!(
                unwind::step(p, 0, &mut next).unwrap().0.unwrap().entry,
                table
            );
            assert_eq!(
                (next.gpr(29), next.pc(), next.sp()),
                (0x9876, 0x5678, sp + 64)
            );
        });
    }

    #[test]
    fn admission_cap_empty_pointer_and_reserved_arm64_flags_are_bounded() {
        for arch in [WinArch::X64, WinArch::Arm64] {
            with_process(arch, |p| {
                let table = page(p);
                let code = page(p);
                assert!(!register(p, table, 0, code).unwrap());
                assert!(!register(p, table, MAX_ENTRIES + 1, code).unwrap());
                assert!(!register(p, 0, 1, code).unwrap());
                assert!(!register(p, u64::MAX - 3, 1, code).unwrap());
                assert!(p.seh.dynamic_tables.is_empty());
                if arch == WinArch::Arm64 {
                    p.space.w32(table, 0).unwrap();
                    p.space.w32(table + 4, 3).unwrap();
                    assert!(!register(p, table, 1, code).unwrap());
                }
            });
        }
    }

    #[test]
    fn aggregate_entry_cap_rejects_a_second_table_without_reading_it() {
        with_process(WinArch::X64, |p| {
            let code = page(p);
            let first = page(p);
            let second = page(p);
            write_x64(p, first, 0, 0, 0x20, 0x100);
            assert!(register(p, first, 1, code).unwrap());
            p.vm.protect(second, PAGE_SIZE, prot::NOACCESS).unwrap();
            assert!(!register(p, second, MAX_ENTRIES, code).unwrap());
            assert_eq!(p.seh.dynamic_tables.len(), 1);
            assert_eq!(lookup(p, code + 8).unwrap().unwrap().entry, first);
        });
    }
}
