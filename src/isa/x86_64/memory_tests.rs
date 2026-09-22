//! x86-64 MMU fault-boundary tests.

use super::memory::Mmu;
use crate::vm::vcpu::SystemRegisters;
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

#[test]
fn physical_access_fault_names_the_unmapped_address_once() {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap());
    let mmu = Mmu::new(memory);
    let mut byte = [0u8; 1];
    for (operation, result) in [
        ("read", mmu.read_phys(0x2000, &mut byte)),
        ("write", mmu.write_phys(0x2000, &byte)),
    ] {
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains(&format!(
                "failed to {operation} at 0x2000: physical range is unmapped"
            )),
            "{error}"
        );
        assert_eq!(error.matches("0x2000").count(), 1, "{error}");
        assert!(!error.contains("8192"), "{error}");
    }
}

#[test]
fn crossing_write_preflights_all_pages_before_committing_ram() {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap());
    let mut mmu = Mmu::new(memory.clone());
    let sregs = SystemRegisters::default();
    memory
        .write_slice(&[0xA5, 0xA5], GuestAddress(0x0FFE))
        .unwrap();

    assert!(
        mmu.write_u32(0x0FFE, 0x1122_3344, &sregs).is_err(),
        "second page is unmapped"
    );

    let mut tail = [0u8; 2];
    memory.read_slice(&mut tail, GuestAddress(0x0FFE)).unwrap();
    assert_eq!(tail, [0xA5, 0xA5]);
}

#[test]
fn crossing_write_preflights_later_virtual_page_before_committing_ram() {
    const PML4: u64 = 0x1000;
    const PDPT: u64 = 0x2000;
    const PD: u64 = 0x3000;
    const PT: u64 = 0x4000;
    const DATA: u64 = 0x6000;
    const PRESENT_WRITABLE: u64 = 0x3;

    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x8000)]).unwrap());
    for (entry_address, entry_value) in [
        (PML4, PDPT | PRESENT_WRITABLE),
        (PDPT, PD | PRESENT_WRITABLE),
        (PD, PT | PRESENT_WRITABLE),
        (PT, DATA | PRESENT_WRITABLE),
    ] {
        memory
            .write_slice(&entry_value.to_le_bytes(), GuestAddress(entry_address))
            .unwrap();
    }
    memory
        .write_slice(&[0xA5, 0xA5], GuestAddress(DATA + 0x0FFE))
        .unwrap();
    let mut mmu = Mmu::new(memory.clone());
    let mut sregs = SystemRegisters {
        cr0: 0x8000_0001,
        cr3: PML4,
        efer: 0x500,
        ..SystemRegisters::default()
    };
    sregs.cs.l = true;

    let error = mmu.write_u32(0x0FFE, 0x1122_3344, &sregs).unwrap_err();
    assert!(
        matches!(
            error,
            crate::error::Error::PageFault {
                vaddr: 0x1000,
                error_code: 0x2,
            }
        ),
        "later non-present page must fault as a write: {error:?}"
    );

    let mut tail = [0u8; 2];
    memory
        .read_slice(&mut tail, GuestAddress(DATA + 0x0FFE))
        .unwrap();
    assert_eq!(tail, [0xA5, 0xA5]);
}

#[test]
fn crossing_write_commits_every_chunk_after_successful_preflight() {
    let memory =
        Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x2000)]).unwrap());
    let mut mmu = Mmu::new(memory.clone());
    let sregs = SystemRegisters::default();
    let value = 0x0123_4567_89AB_CDEFu64;

    mmu.write_u64(0x0FFC, value, &sregs).unwrap();

    let mut bytes = [0u8; 8];
    memory.read_slice(&mut bytes, GuestAddress(0x0FFC)).unwrap();
    assert_eq!(bytes, value.to_le_bytes());
}
