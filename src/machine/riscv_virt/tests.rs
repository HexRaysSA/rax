//! ELF boot contracts, independently specified by the retained gABI chapters.
use super::*;
use vm_memory::{Bytes, GuestAddress};
#[path = "../../../tests/support/riscv_startup.rs"]
mod program;
fn memory() -> GuestMemoryMmap {
    GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 65536)]).unwrap()
}

#[test]
fn elf_entry_is_not_inferred_from_mret_bytes() {
    let mem = memory();
    let words = [0x00000013u32, 0x30200073, 0x00000013];
    let code = words
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    let image = program::elf(&code, 0x1000, 0x1000);
    let info = RiscvVirtMachine::load_elf(&mem, &image).unwrap();
    assert_eq!(
        info.entry_point, 0x1000,
        "e_entry must remain the execution entry"
    );
}

#[test]
fn elf_zero_fills_the_memory_tail() {
    let mem = memory();
    mem.write_slice(&[0xa5; 64], GuestAddress(0x1000)).unwrap();
    let mut image = program::elf(&0x00000013u32.to_le_bytes(), 0x1000, 0x1000);
    program::put64(&mut image, 104, 64);
    RiscvVirtMachine::load_elf(&mem, &image).unwrap();
    let mut actual = [0; 64];
    mem.read_slice(&mut actual, GuestAddress(0x1000)).unwrap();
    assert_eq!(&actual[..4], &0x00000013u32.to_le_bytes());
    assert_eq!(
        &actual[4..],
        &[0; 60],
        "PT_LOAD p_memsz-p_filesz must be zero"
    );
}

#[test]
fn invalid_later_segment_rejects_before_publishing_the_first_segment() {
    let mem = memory();
    mem.write_slice(&[0xa5; 64], GuestAddress(0x1000)).unwrap();
    let mut image = program::elf(&0x00000013u32.to_le_bytes(), 0x1000, 0x1000);
    program::put16(&mut image, 56, 2);
    program::put32(&mut image, 120, 1);
    program::put64(&mut image, 128, u64::MAX);
    program::put64(&mut image, 136, 0x2000);
    program::put64(&mut image, 144, 0x2000);
    program::put64(&mut image, 152, 1);
    program::put64(&mut image, 160, 1);
    assert!(RiscvVirtMachine::load_elf(&mem, &image).is_err());
    let mut actual = [0; 64];
    mem.read_slice(&mut actual, GuestAddress(0x1000)).unwrap();
    assert_eq!(
        actual, [0xa5; 64],
        "admission must precede all image stores"
    );
}

#[test]
fn malformed_elf_memory_size_entry_and_alignment_do_not_mutate_ram() {
    for mutation in 0..6 {
        let mem = memory();
        mem.write_slice(&[0xa5; 64], GuestAddress(0x1000)).unwrap();
        let mut image = program::elf(&0x0000_0013u32.to_le_bytes(), 0x1000, 0x1000);
        match mutation {
            0 => program::put64(&mut image, 104, 3),
            1 => program::put64(&mut image, 104, u64::MAX),
            2 => program::put64(&mut image, 24, 0x2000),
            3 => program::put64(&mut image, 24, 0x1001),
            4 => program::put64(&mut image, 112, 3),
            5 => program::put32(&mut image, 68, 6),
            _ => unreachable!(),
        }
        assert!(
            RiscvVirtMachine::load_elf(&mem, &image).is_err(),
            "mutation {mutation}"
        );
        let mut actual = [0; 64];
        mem.read_slice(&mut actual, GuestAddress(0x1000)).unwrap();
        assert_eq!(actual, [0xa5; 64]);
    }
}

#[test]
fn raw_image_bounds_are_admitted_before_any_write() {
    let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
    mem.write_slice(&[0xa5; 64], GuestAddress(0)).unwrap();
    assert!(RiscvVirtMachine::load_raw(&mem, &[0x13; 4097]).is_err());
    let mut actual = [0; 64];
    mem.read_slice(&mut actual, GuestAddress(0)).unwrap();
    assert_eq!(actual, [0xa5; 64]);
}

#[test]
fn boot_stack_geometry_rejects_invalid_topology_image_overlap_and_holes() {
    use crate::machine::BootInfo;
    let boot = BootInfo::RiscV(RiscVBootInfo {
        entry_point: 0x1000,
        load_addr: 0x1000,
        image_size: 4,
        tohost_addr: None,
    });
    let mem = memory();
    for (id, count) in [(0, 0), (2, 2), (u32::MAX, 255)] {
        assert!(super::startup::hart_state(&mem, &boot, id, count).is_err());
    }
    let mut stacks = Vec::new();
    for id in 0..4 {
        let CpuState::RiscV(state) = super::startup::hart_state(&mem, &boot, id, 4).unwrap() else {
            panic!()
        };
        assert_eq!(state.regs.x[10], u64::from(id));
        assert_eq!(state.regs.pc, 0x1000);
        assert_eq!(state.regs.x[2] & 15, 0);
        stacks.push(state.regs.x[2]);
    }
    assert_eq!(stacks, [65520, 61424, 57328, 53232]);
    let tiny = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
    assert!(super::startup::hart_state(&tiny, &boot, 0, 1).is_err());
    let holes =
        GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 8192), (GuestAddress(16384), 4096)])
            .unwrap();
    assert!(super::startup::hart_state(&holes, &boot, 0, 2).is_err());
}

fn with_symbols(symbols: &[(&str, u64, u16)]) -> Vec<u8> {
    let mut image = program::elf(&[0x13, 0, 0, 0], 0x1000, 0x1000);
    let mut names = vec![0];
    let mut entries = vec![0; 24];
    for (name, value, section) in symbols {
        let name_offset = names.len() as u32;
        names.extend_from_slice(name.as_bytes());
        names.push(0);
        let at = entries.len();
        entries.resize(at + 24, 0);
        program::put32(&mut entries, at, name_offset);
        entries[at + 4] = 0x10;
        program::put16(&mut entries, at + 6, *section);
        program::put64(&mut entries, at + 8, *value);
    }
    let names_at = image.len();
    image.extend_from_slice(&names);
    let symbols_at = image.len();
    image.extend_from_slice(&entries);
    let sections_at = image.len();
    image.resize(sections_at + 4 * 64, 0);
    program::put64(&mut image, 40, sections_at as u64);
    program::put16(&mut image, 60, 4);
    for (index, kind, address, offset, size, link, align, entry_size) in [
        (1, 1, 0x1000, 4096, 4, 0, 4, 0),
        (2, 3, 0, names_at, names.len(), 0, 1, 0),
        (3, 2, 0, symbols_at, entries.len(), 2, 8, 24),
    ] {
        let at = sections_at + index * 64;
        program::put32(&mut image, at + 4, kind);
        program::put64(&mut image, at + 16, address);
        program::put64(&mut image, at + 24, offset as u64);
        program::put64(&mut image, at + 32, size as u64);
        program::put32(&mut image, at + 40, link);
        program::put64(&mut image, at + 48, align);
        program::put64(&mut image, at + 56, entry_size);
    }
    image
}

#[test]
fn elf_symbols_do_not_replace_entry_and_defined_zero_tohost_is_retained() {
    let image = with_symbols(&[
        ("test_entry", 0x1008, 1),
        ("test_1", 0x100c, 1),
        ("tohost", 0, 1),
    ]);
    let info = RiscvVirtMachine::load_elf(&memory(), &image).unwrap();
    assert_eq!(info.entry_point, 0x1000);
    assert_eq!(info.tohost_addr, Some(0));
    let image = with_symbols(&[("tohost", 0x2000, 0)]);
    assert_eq!(
        RiscvVirtMachine::load_elf(&memory(), &image)
            .unwrap()
            .tohost_addr,
        None
    );
}

#[test]
fn conflicting_tohost_symbols_reject_before_image_publication() {
    let mem = memory();
    mem.write_slice(&[0xa5; 4], GuestAddress(0x1000)).unwrap();
    let image = with_symbols(&[("tohost", 0x2000, 1), ("tohost", 0x2008, 1)]);
    assert!(RiscvVirtMachine::load_elf(&mem, &image).is_err());
    assert_eq!(
        mem.read_obj::<u32>(GuestAddress(0x1000)).unwrap(),
        0xa5a5a5a5
    );
}

#[test]
fn unsupported_elf_profiles_and_segment_holes_reject_without_publication() {
    for mutation in 0..7 {
        let mem = memory();
        mem.write_slice(&[0xa5; 4], GuestAddress(0x1000)).unwrap();
        let mut image = program::elf(&[0x13, 0, 0, 0], 0x1000, 0x1000);
        match mutation {
            0 => image[4] = 1,                       // ELFCLASS32
            1 => image[5] = 2,                       // ELFDATA2MSB
            2 => program::put16(&mut image, 18, 62), // EM_X86_64
            3 => program::put16(&mut image, 16, 1),  // ET_REL
            4 => program::put32(&mut image, 20, 0),  // EV_NONE
            5 | 6 => {
                program::put16(&mut image, 56, 2);
                program::put32(&mut image, 120, if mutation == 5 { 2 } else { 3 });
            }
            _ => unreachable!(),
        }
        assert!(
            RiscvVirtMachine::load_elf(&mem, &image).is_err(),
            "profile {mutation}"
        );
        assert_eq!(
            mem.read_obj::<u32>(GuestAddress(0x1000)).unwrap(),
            0xa5a5a5a5
        );
    }
    let holes =
        GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 8192), (GuestAddress(16384), 4096)])
            .unwrap();
    holes.write_slice(&[0xa5; 4], GuestAddress(0x1000)).unwrap();
    let mut image = program::elf(&[0x13, 0, 0, 0], 0x1000, 0x1000);
    program::put64(&mut image, 104, 16384);
    assert!(RiscvVirtMachine::load_elf(&holes, &image).is_err());
    assert_eq!(
        holes.read_obj::<u32>(GuestAddress(0x1000)).unwrap(),
        0xa5a5a5a5
    );
}

#[test]
fn malformed_elf_header_fields_reject_without_publication() {
    for mutation in 0..3 {
        let mem = memory();
        mem.write_slice(&[0xa5; 4], GuestAddress(0x1000)).unwrap();
        let mut image = program::elf(&[0x13, 0, 0, 0], 0x1000, 0x1000);
        match mutation {
            0 => image[6] = 0,                      // EI_VERSION must be EV_CURRENT.
            1 => program::put16(&mut image, 52, 0), // ELF64_Ehdr is 64 bytes.
            2 => program::put16(&mut image, 54, 0), // ELF64_Phdr is 56 bytes.
            _ => unreachable!(),
        }
        assert!(
            RiscvVirtMachine::load_elf(&mem, &image).is_err(),
            "field {mutation}"
        );
        assert_eq!(
            mem.read_obj::<u32>(GuestAddress(0x1000)).unwrap(),
            0xa5a5a5a5
        );
    }
}

#[test]
fn elf_bss_zero_fill_covers_a_full_chunk_and_a_partial_tail() {
    let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 256 * 1024)]).unwrap();
    let mut image = program::elf(&[0x13, 0, 0, 0], 0x1000, 0x1000);
    let memory_size = 4 + 65536 + 17;
    mem.write_slice(&vec![0xa5; memory_size], GuestAddress(0x1000))
        .unwrap();
    program::put64(&mut image, 104, memory_size as u64);
    let info = RiscvVirtMachine::load_elf(&mem, &image).unwrap();
    assert_eq!(info.image_size, memory_size as u64);
    let mut tail = vec![0xa5; memory_size - 4];
    mem.read_slice(&mut tail, GuestAddress(0x1004)).unwrap();
    assert!(tail.iter().all(|byte| *byte == 0));
}

#[cfg(unix)]
#[test]
fn readonly_late_segment_and_bootstrap_stacks_reject_without_writes() {
    use crate::vm::memory::vm::{GuestRegionMmap, MmapRegion};

    let mem = GuestMemoryMmap::from_regions(
        [
            (0, 8192, libc::PROT_READ | libc::PROT_WRITE),
            (8192, 57344, libc::PROT_READ),
        ]
        .into_iter()
        .map(|(address, size, protection)| {
            GuestRegionMmap::new(
                MmapRegion::build(None, size, protection, libc::MAP_PRIVATE | libc::MAP_ANON)
                    .unwrap(),
                GuestAddress(address),
            )
            .unwrap()
        })
        .collect(),
    )
    .unwrap();
    mem.write_slice(&[0xa5; 4], GuestAddress(0x1000)).unwrap();
    let mut image = program::elf(&[0x13, 0, 0, 0], 0x1000, 0x1000);
    program::put16(&mut image, 56, 2);
    program::put32(&mut image, 120, 1);
    program::put32(&mut image, 124, 6);
    for (at, value) in [
        (128, 4096),
        (136, 0x2000),
        (144, 0x2000),
        (152, 4),
        (160, 4),
        (168, 4096),
    ] {
        program::put64(&mut image, at, value);
    }
    assert!(RiscvVirtMachine::load_elf(&mem, &image).is_err());
    assert_eq!(
        mem.read_obj::<u32>(GuestAddress(0x1000)).unwrap(),
        0xa5a5a5a5
    );
    let boot = BootInfo::RiscV(RiscVBootInfo {
        entry_point: 0x1000,
        load_addr: 0x1000,
        image_size: 4,
        tohost_addr: None,
    });
    assert!(super::startup::hart_state(&mem, &boot, 0, 1).is_err());
}
