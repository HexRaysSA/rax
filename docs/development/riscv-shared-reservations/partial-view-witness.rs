//! Supplemental Unix witness for differently based, overlapping RAM views.
use rax::backend::emulator::riscv::RiscVVcpu;
use rax::isa::riscv::RiscVConfig;
use rax::vm::vcpu::{CpuState, VCpu};
use std::sync::Arc;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegion};

#[test]
fn a_larger_view_invalidates_the_same_physical_word_in_a_subview() {
    // The runner obtains this value with sysconf(_SC_PAGESIZE).
    let page: usize = std::env::var("RAX_WITNESS_HOST_PAGE")
        .unwrap()
        .parse()
        .unwrap();
    assert!(page.is_power_of_two() && page >= 4096);
    let parent: Arc<GuestRegionMmap> = Arc::new(
        GuestRegionMmap::from_range(GuestAddress(0), page.checked_mul(4).unwrap(), None).unwrap(),
    );
    // SAFETY: the parent owns four readable/writable host pages and remains
    // alive until both CPUs and views are dropped. One actual host-page offset
    // preserves mmap alignment; the subview spans exactly the second page.
    // No Rust references alias the bytes, and all subsequent guest accesses use
    // vm-memory and the emulator's tracked writer locks. build_raw owns no mmap.
    let raw = unsafe {
        MmapRegion::build_raw(
            parent.as_ptr().add(page),
            page,
            parent.prot(),
            parent.flags(),
        )
        .unwrap()
    };
    let sub = Arc::new(GuestRegionMmap::new(raw, GuestAddress(0)).unwrap());
    let first = Arc::new(GuestMemoryMmap::from_arc_regions(vec![sub]).unwrap());
    let second = Arc::new(GuestMemoryMmap::from_arc_regions(vec![parent.clone()]).unwrap());
    first
        .write_slice(
            &[0x1005_22afu32, 0x1855_25af]
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<_>>(),
            GuestAddress(0),
        )
        .unwrap();
    second
        .write_slice(&0x00c5_2023u32.to_le_bytes(), GuestAddress(0x100))
        .unwrap();
    first
        .write_obj(0x1111_1111u32, GuestAddress(0x800))
        .unwrap();
    let mut reader = RiscVVcpu::new_embedded(0, first.clone(), RiscVConfig::rv64gc());
    let mut writer = RiscVVcpu::new_embedded(1, second, RiscVConfig::rv64gc());
    for (hart, pc, address) in [
        (&mut reader, 0, 0x800),
        (&mut writer, 0x100, page as u64 + 0x800),
    ] {
        let CpuState::RiscV(mut state) = hart.get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = pc;
        state.regs.x[10] = address;
        state.regs.x[12] = 0x1111_1111;
        hart.set_state(&CpuState::RiscV(state)).unwrap();
    }
    assert!(reader.step_insn().unwrap().is_none());
    assert!(writer.step_insn().unwrap().is_none());
    assert!(reader.step_insn().unwrap().is_none());
    let CpuState::RiscV(state) = reader.get_state().unwrap() else {
        panic!()
    };
    assert_ne!(state.regs.x[11], 0);
    assert_eq!(
        first.read_obj::<u32>(GuestAddress(0x800)).unwrap(),
        0x1111_1111
    );
}
