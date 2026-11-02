use super::{Gic, GicConfig, INTID_SPURIOUS, RoutingMode, checkpoint::GicCheckpoint};
use std::sync::{Arc, atomic::Ordering};

fn controller(count: u8) -> Gic {
    let mut gic = Gic::new(GicConfig {
        num_cpus: count,
        ..Default::default()
    });
    gic.write_dist(0, 3);
    for id in 0..usize::from(count) {
        gic.write_redist(id, 0x14, 0);
        gic.set_group_enable(id, false, true);
        gic.set_group_enable(id, true, true);
    }
    gic
}

fn request(gic: &mut Gic, id: usize, intid: u32, group: u8) {
    if intid < 32 {
        gic.cpu_mut(id).unwrap().private_interrupts[intid as usize].group = group;
        gic.write_redist(id, 0x10100, 1 << intid);
        gic.write_redist(id, 0x10200, 1 << intid);
    } else {
        gic.write_dist(0x84, u32::from(group) << (intid - 32));
        gic.set_enabled(intid, true);
        gic.set_routing(intid, RoutingMode::Affinity(id as u64));
        gic.set_pending(intid);
    }
}

#[test]
fn wrong_bank_reads_do_not_acknowledge_sgi_ppi_or_spi_on_any_pe() {
    for count in [1, 2, 4] {
        for group in [0, 1] {
            for intid in [7, 30, 40] {
                let mut gic = controller(count);
                let id = usize::from(count - 1);
                request(&mut gic, id, intid, group);
                let before = crate::codec::serialize(&gic.checkpoint()).unwrap();
                assert_eq!(gic.highest_pending_in_group(id, 1 - group), INTID_SPURIOUS);
                assert_eq!(gic.acknowledge_group(id, 1 - group), INTID_SPURIOUS);
                assert_eq!(before, crate::codec::serialize(&gic.checkpoint()).unwrap());
                assert_eq!(gic.highest_pending_in_group(id, group), intid);
                assert_eq!(gic.acknowledge_group(id, group), intid);
            }
        }
    }
}

#[test]
fn wrong_eoir_bank_preserves_active_priority_and_source_in_both_modes() {
    for mode in [false, true] {
        for group in [0, 1] {
            for intid in [7, 30, 40] {
                let mut gic = controller(1);
                request(&mut gic, 0, intid, group);
                gic.cpu_mut(0).unwrap().eoi_mode = mode;
                assert_eq!(gic.acknowledge_group(0, group), intid);
                let before = crate::codec::serialize(&gic.checkpoint()).unwrap();
                gic.end_of_interrupt_group(0, intid, 1 - group);
                assert_eq!(before, crate::codec::serialize(&gic.checkpoint()).unwrap());
                gic.end_of_interrupt_group(0, intid, group);
                let cpu = gic.cpu(0).unwrap();
                assert_eq!(cpu.running_priority, 0xff);
                assert!(cpu.active_priorities.is_empty());
                let active = if intid < 32 {
                    cpu.private_interrupts[intid as usize].state.is_active()
                } else {
                    gic.read_dist(0x304) & (1 << (intid - 32)) != 0
                };
                assert_eq!(active, mode);
                if mode {
                    gic.deactivate(0, intid);
                }
            }
        }
    }
}

#[test]
fn other_bank_cannot_select_a_lower_priority_candidate() {
    for first in [0, 1] {
        let mut gic = controller(1);
        request(&mut gic, 0, 7, first);
        request(&mut gic, 0, 8, 1 - first);
        gic.cpu_mut(0).unwrap().private_interrupts[7].priority = 0x10;
        gic.cpu_mut(0).unwrap().private_interrupts[8].priority = 0x80;
        assert_eq!(gic.highest_pending_in_group(0, 1 - first), INTID_SPURIOUS);
        assert_eq!(gic.acknowledge_group(0, 1 - first), INTID_SPURIOUS);
        assert_eq!(gic.acknowledge_group(0, first), 7);
        assert_eq!(gic.acknowledge_group(0, 1 - first), INTID_SPURIOUS);
        // HPPIR observes the pending candidate even when RPR prevents activation.
        assert_eq!(gic.highest_pending_in_group(0, 1 - first), 8);
        gic.end_of_interrupt_group(0, 7, first);
        assert_eq!(gic.acknowledge_group(0, 1 - first), 8);
    }
}

#[test]
fn any_spi_selects_exactly_one_awake_participating_pe_and_retargets() {
    for count in [1, 2, 4] {
        for group in [0, 1] {
            let mut gic = controller(count);
            for id in 0..usize::from(count) {
                gic.write_redist(id, 0x14, 2);
            }
            request(&mut gic, 0, 40, group);
            gic.set_routing(40, RoutingMode::Any);
            let signals = |gic: &Gic| {
                (0..usize::from(count))
                    .filter(|id| gic.pending_interrupt(*id))
                    .collect::<Vec<_>>()
            };
            assert!(signals(&gic).is_empty());
            let last = usize::from(count - 1);
            gic.write_redist(last, 0x14, 0);
            assert_eq!(signals(&gic), [last]);
            gic.write_redist(0, 0x14, 0);
            assert_eq!(signals(&gic), [0]);
            gic.set_group_enable(0, group == 1, false);
            assert_eq!(signals(&gic), if count == 1 { vec![] } else { vec![last] });
            assert_eq!(gic.read_dist(0) & (1 << 7), 0); // E1NWF=0.
            assert_eq!(gic.read_redist(0, 8) & (1 << 5), 0); // DPGS=0.
        }
    }
}

#[test]
fn serialized_restore_recomputes_group_and_any_target_in_existing_arcs() {
    for count in [1, 2, 4] {
        for group in [0, 1] {
            let mut source = controller(count);
            request(&mut source, 0, 40, group);
            source.set_routing(40, RoutingMode::Any);
            for id in 0..usize::from(count - 1) {
                source.write_redist(id, 0x14, 2);
            }
            let encoded = crate::codec::serialize(&source.checkpoint()).unwrap();
            let state: GicCheckpoint = crate::codec::deserialize(&encoded).unwrap();
            let mut target = controller(count);
            let handles = (0..usize::from(count))
                .map(|id| target.irq_line(id).unwrap())
                .collect::<Vec<_>>();
            target.validate_checkpoint(&state).unwrap();
            target.restore_checkpoint(state);
            for (id, line) in handles.iter().enumerate() {
                assert!(Arc::ptr_eq(line, &target.irq_line(id).unwrap()));
                assert_eq!(line.load(Ordering::Acquire), id == usize::from(count - 1));
                assert_eq!(
                    target.pending_group(id),
                    (id == usize::from(count - 1)).then_some(group)
                );
            }
        }
    }
}

#[test]
fn distributor_state_aliases_read_enabled_pending_and_active_at_spi_boundaries() {
    let mut gic = Gic::new(GicConfig {
        num_spis: 988,
        ..Default::default()
    });
    for intid in [32u32, 63, 64, 287, 1019] {
        let word = u64::from(intid / 32) * 4;
        let bit = 1 << (intid % 32);
        gic.write_dist(0x100 + word, bit);
        gic.write_dist(0x200 + word, bit);
        gic.write_dist(0x300 + word, bit);
        for (set, clear) in [(0x100, 0x180), (0x200, 0x280), (0x300, 0x380)] {
            assert_ne!(
                gic.read_dist(set + word) & bit,
                0,
                "set bank {set:#x} INTID {intid}"
            );
            assert_ne!(
                gic.read_dist(clear + word) & bit,
                0,
                "clear bank {clear:#x} INTID {intid}"
            );
            gic.write_dist(clear + word, 0);
            assert_ne!(gic.read_dist(set + word) & bit, 0);
            gic.write_dist(clear + word, bit);
            assert_eq!(gic.read_dist(set + word) & bit, 0);
        }
    }
    for offset in [0x100, 0x180, 0x200, 0x280, 0x300, 0x380] {
        gic.write_dist(offset, u32::MAX); // SGI/PPI bank is RAZ/WI under ARE=1.
        assert_eq!(gic.read_dist(offset), 0);
    }
    gic.write_dist(0x37c, u32::MAX);
    assert_eq!(gic.read_dist(0x37c) & 0xf000_0000, 0); // Special INTIDs1020-1023.
}

#[test]
fn active_register_writes_retain_pending_sources_and_do_not_drop_cpu_priority() {
    let mut gic = controller(1);
    request(&mut gic, 0, 40, 1);
    gic.set_spi_level(40, true);
    gic.write_dist(0x304, 1 << 8);
    assert!(!gic.pending_interrupt(0));
    assert_eq!(gic.cpu(0).unwrap().running_priority, 0xff);
    assert_ne!(gic.read_dist(0x284) & (1 << 8), 0);
    gic.write_dist(0x384, 1 << 8);
    assert!(gic.pending_interrupt(0));
    assert_eq!(gic.acknowledge_group(0, 1), 40);
    let priorities = gic.cpu(0).unwrap().active_priorities.clone();
    gic.write_dist(0x384, 1 << 8);
    assert_eq!(gic.cpu(0).unwrap().active_priorities, priorities);
    assert_eq!(gic.cpu(0).unwrap().running_priority, 0xa0);
    assert_ne!(gic.read_dist(0x204) & (1 << 8), 0);
    gic.end_of_interrupt_group(0, 40, 1);
    assert!(gic.pending_interrupt(0));
}

#[test]
fn redistributor_set_active_preserves_private_pending_without_priority_drop() {
    for count in [1, 2, 4] {
        for group in [0, 1] {
            for intid in [7, 30] {
                let mut gic = controller(count);
                let id = usize::from(count - 1);
                request(&mut gic, id, intid, group);
                let bit = 1 << intid;
                gic.write_redist(id, 0x10300, bit);
                assert_ne!(gic.read_redist(id, 0x10300) & bit, 0);
                assert_ne!(gic.read_redist(id, 0x10380) & bit, 0);
                assert_ne!(gic.read_redist(id, 0x10200) & bit, 0);
                assert_eq!(gic.cpu(id).unwrap().running_priority, 0xff);
                assert!(!gic.pending_interrupt(id));
                gic.write_redist(id, 0x10380, 0);
                assert_ne!(gic.read_redist(id, 0x10300) & bit, 0);
                gic.write_redist(id, 0x10380, bit);
                assert_eq!(gic.read_redist(id, 0x10300) & bit, 0);
                assert_ne!(gic.read_redist(id, 0x10200) & bit, 0);
                assert_eq!(gic.acknowledge_group(id, group), intid);
            }
        }
    }
}
