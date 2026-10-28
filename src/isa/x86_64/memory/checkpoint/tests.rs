use super::*;
use crate::vm::timing::{ClockMode, TimingContext};
use crate::vm::vcpu::SystemRegisters;
use std::sync::Arc;
use vm_memory::{GuestAddress, GuestMemoryMmap};

fn mmu() -> Mmu {
    Mmu::new(Arc::new(
        GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap(),
    ))
}
fn read_register(mmu: &Mmu, offset: u64) -> u32 {
    let mut bytes = [0; 4];
    mmu.read_phys(0xfee0_0000 + offset, &mut bytes).unwrap();
    u32::from_le_bytes(bytes)
}
fn write_register(mmu: &Mmu, offset: u64, value: u32) {
    mmu.write_phys(0xfee0_0000 + offset, &value.to_le_bytes())
        .unwrap();
}
fn encoded(mmu: &Mmu) -> Vec<u8> {
    crate::codec::serialize(&mmu.checkpoint_state().unwrap()).unwrap()
}
fn decode(raw: &[u8]) -> MmuContext {
    crate::codec::deserialize(raw).unwrap()
}

#[test]
fn inline_lapic_restores_over_cold_target_ram_bindings() {
    let source = mmu();
    write_register(&source, 0x80, 0x70);
    let target = mmu();
    write_register(&target, 0x80, 0x11);
    let restored = decode(&encoded(&source)).prepare(&target).unwrap();
    assert_eq!(read_register(&restored, 0x80), 0x70);
    assert_eq!(read_register(&target, 0x80), 0x11);
    assert!(Arc::ptr_eq(&restored.memory, &target.memory));
    assert!(!Arc::ptr_eq(&restored.memory, &source.memory));
}

#[test]
fn buffered_guest_accesses_keep_order_and_are_drained_once() {
    let mut source = mmu();
    source.set_mem_recording(true);
    let mut sregs = SystemRegisters::default();
    sregs.cr0 = 0;
    sregs.efer = 0;
    source.write_u8(0x100, 0x5a, &sregs).unwrap();
    assert_eq!(source.read_u8(0x100, &sregs).unwrap(), 0x5a);
    source.record_fetch(0x200, 3);
    let mut restored = decode(&encoded(&source)).prepare(&mmu()).unwrap();
    let mut want = Vec::new();
    let mut got = Vec::new();
    source.drain_mem_records(&mut want);
    restored.drain_mem_records(&mut got);
    let projection = |records: Vec<MemRecord>| {
        records
            .into_iter()
            .map(|r| (r.access, r.addr, r.size, r.value, r.rip))
            .collect::<Vec<_>>()
    };
    assert_eq!(got.len(), 3);
    assert_eq!(projection(got), projection(want));
    let mut second = Vec::new();
    restored.drain_mem_records(&mut second);
    assert!(second.is_empty());
}

#[test]
fn complete_private_descriptor_bytes_survive_without_guest_ram_copies() {
    let mut source = mmu();
    let bytes: Vec<u8> = (0..128).map(|x| x as u8 ^ 0xa5).collect();
    source.user_tables = Some(Box::new(UserTables::from_checkpoint(&bytes).unwrap()));
    let mut restored = decode(&encoded(&source)).prepare(&mmu()).unwrap();
    let mut actual = [0; 128];
    restored
        .read_supervisor(
            crate::isa::x86_64::USER_GDT_BASE,
            &mut actual,
            &SystemRegisters::default(),
        )
        .unwrap();
    assert_eq!(actual.as_slice(), bytes);
}

#[test]
fn local_timer_phase_rebases_across_both_earlier_and_later_clock_origins() {
    for periodic in [false, true] {
        let source_clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
        let _source = source_clock.enter();
        source_clock.advance_retired(3000).unwrap(); // 1000 ns.
        let source = mmu();
        write_register(&source, 0x3e0, 0xb); // Divisor1: one tick per ns.
        write_register(&source, 0x320, 0x40 | (u32::from(periodic) << 17));
        write_register(&source, 0x380, 1000);
        source_clock.advance_retired(750).unwrap(); // 250 ns elapsed.
        assert_eq!(read_register(&source, 0x390), 750);
        let raw = encoded(&source);
        for target_units in [0, 30_000] {
            let target_clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
            let _target = target_clock.enter();
            target_clock.advance_retired(target_units).unwrap();
            let restored = decode(&raw).prepare(&mmu()).unwrap();
            assert_eq!(read_register(&restored, 0x390), 750);
            assert_eq!(restored.tick_lapic_timer(), None);
            target_clock.advance_retired(2250).unwrap();
            assert_eq!(restored.tick_lapic_timer(), Some(0x40));
            restored.clear_lapic_pending();
            assert_eq!(restored.tick_lapic_timer(), None);
            if periodic {
                assert_eq!(read_register(&restored, 0x390), 1000);
                target_clock.advance_retired(2997).unwrap();
                assert_eq!(restored.tick_lapic_timer(), None);
                target_clock.advance_retired(3).unwrap();
                assert_eq!(restored.tick_lapic_timer(), Some(0x40));
            } else {
                assert_eq!(read_register(&restored, 0x390), 0);
            }
        }
    }
}

#[test]
fn incompatible_binding_and_invalid_record_fail_before_target_changes() {
    let source = mmu();
    let target = mmu();
    write_register(&target, 0x80, 0x33);
    let mut context = decode(&encoded(&source));
    context.shared_lapic = true;
    assert!(context.prepare(&target).is_err());
    assert_eq!(read_register(&target, 0x80), 0x33);
    let mut context = decode(&encoded(&source));
    context.mem_rec.push(AccessRecord {
        access: 255,
        addr: 0,
        size: 1,
        value: 0,
        rip: 0,
    });
    assert!(context.prepare(&target).is_err());
    assert_eq!(read_register(&target, 0x80), 0x33);
    let held = source.lapic.borrow_mut();
    assert!(source.checkpoint_state().is_err());
    drop(held);
}
