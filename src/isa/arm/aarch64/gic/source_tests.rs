//! Independent physical and software pending sources at the GIC boundary.
use super::*;

fn configured(count: u8) -> Gic {
    let mut gic = Gic::new(GicConfig {
        num_cpus: count,
        ..Default::default()
    });
    gic.write_dist(0, 3);
    for id in 0..usize::from(count) {
        gic.set_group_enable(id, false, true);
        gic.set_group_enable(id, true, true);
        gic.set_priority_mask(id, 0xff);
        gic.write_redist(id, 0x10080, u32::MAX);
        gic.write_redist(id, 0x10100, u32::MAX);
    }
    gic
}

#[test]
fn software_pending_ppi_survives_physical_deassertion_on_every_pe() {
    for count in [1, 2, 4] {
        for id in 0..usize::from(count) {
            for intid in 16..32 {
                let mut gic = configured(count);
                let bit = 1u32 << intid;
                gic.set_ppi_level(id, intid, true);
                gic.write_redist(id, 0x10200, bit);
                gic.set_ppi_level(id, intid, false);
                assert_ne!(gic.read_redist(id, 0x10200) & bit, 0, "PE{id} PPI{intid}");
                assert!(
                    gic.irq_line(id)
                        .unwrap()
                        .load(std::sync::atomic::Ordering::Acquire)
                );
                gic.write_redist(id, 0x10280, bit);
                assert_eq!(gic.read_redist(id, 0x10200) & bit, 0);
            }
        }
    }
}

#[test]
fn guest_clear_pending_cannot_withdraw_an_asserted_level_ppi() {
    for count in [1, 2, 4] {
        for id in 0..usize::from(count) {
            for intid in 16..32 {
                let mut gic = configured(count);
                let bit = 1u32 << intid;
                gic.set_ppi_level(id, intid, true);
                gic.write_redist(id, 0x10280, bit);
                assert_ne!(gic.read_redist(id, 0x10200) & bit, 0, "PE{id} PPI{intid}");
                assert_eq!(gic.acknowledge(id), intid);
                gic.write_redist(id, 0x10280, bit);
                assert_eq!(
                    gic.cpu(id).unwrap().private_interrupts[intid as usize].state,
                    InterruptState::ActivePending
                );
                gic.end_of_interrupt(id, intid);
                assert!(gic.pending_interrupt(id));
                gic.set_ppi_level(id, intid, false);
                assert!(!gic.pending_interrupt(id));
            }
        }
    }
}

#[test]
fn consumed_edges_do_not_reappear_until_a_new_physical_rising_edge() {
    for count in [1, 2, 4] {
        for id in 0..usize::from(count) {
            let mut gic = configured(count);
            gic.cpu_mut(id).unwrap().private_interrupts[27].trigger = TriggerType::Edge;
            gic.set_ppi_level(id, 27, true);
            assert_eq!(gic.acknowledge(id), 27);
            gic.end_of_interrupt(id, 27);
            let saved = gic.checkpoint();
            gic.validate_checkpoint(&saved).unwrap();
            gic.set_ppi_level(id, 27, false);
            gic.restore_checkpoint(saved);
            gic.set_ppi_level(id, 27, true); // Already high at capture.
            assert!(!gic.pending_interrupt(id));
            gic.set_ppi_level(id, 27, false);
            gic.set_ppi_level(id, 27, true);
            assert_eq!(gic.acknowledge(id), 27);
            gic.end_of_interrupt(id, 27);
            assert!(!gic.pending_interrupt(id));
        }
    }
}

#[test]
fn active_level_software_pending_is_independent_through_clear_and_eoi() {
    let mut gic = configured(2);
    gic.set_ppi_level(1, 30, true);
    assert_eq!(gic.acknowledge(1), 30);
    gic.write_redist(1, 0x10200, 1 << 30);
    gic.set_ppi_level(1, 30, false);
    assert_eq!(
        gic.cpu(1).unwrap().private_interrupts[30].state,
        InterruptState::ActivePending
    );
    let raw = crate::codec::serialize(&gic.checkpoint()).unwrap();
    let saved = crate::codec::deserialize_strict(&raw).unwrap();
    gic.reset();
    gic.validate_checkpoint(&saved).unwrap();
    gic.restore_checkpoint(saved);
    gic.write_redist(1, 0x10280, 1 << 30);
    assert_eq!(
        gic.cpu(1).unwrap().private_interrupts[30].state,
        InterruptState::Active
    );
    gic.end_of_interrupt(1, 30);
    assert_eq!(
        gic.cpu(1).unwrap().private_interrupts[30].state,
        InterruptState::Inactive
    );
}

#[test]
fn spi_software_latch_and_physical_input_survive_independent_clear_and_restore() {
    for count in [1, 2, 4] {
        let mut gic = configured(count);
        gic.set_enabled(40, true);
        gic.set_spi_level(40, true);
        gic.write_dist(0x0204, 1 << 8);
        let raw = crate::codec::serialize(&gic.checkpoint()).unwrap();
        let saved = crate::codec::deserialize_strict(&raw).unwrap();
        gic.reset();
        gic.restore_checkpoint(saved);
        gic.set_spi_level(40, false);
        assert_ne!(gic.read_dist(0x0204) & (1 << 8), 0);
        gic.write_dist(0x0284, 1 << 8);
        assert_eq!(gic.read_dist(0x0204) & (1 << 8), 0);
        gic.set_spi_level(40, true);
        gic.write_dist(0x0284, 1 << 8);
        assert_ne!(gic.read_dist(0x0204) & (1 << 8), 0);
        gic.set_spi_level(40, false);
        assert_eq!(gic.read_dist(0x0204) & (1 << 8), 0);
    }
}

fn legacy(gic: &Gic) -> checkpoint::LegacyGicCheckpoint {
    serde_json::from_value(serde_json::to_value(gic.checkpoint()).unwrap()).unwrap()
}

#[test]
fn legacy_aggregate_bytes_cannot_disambiguate_pending_sources_or_consumed_edges() {
    let mut physical = configured(1);
    physical.set_ppi_level(0, 30, true);
    let before = crate::codec::serialize(&legacy(&physical)).unwrap();
    let mut overlapping = configured(1);
    overlapping.set_ppi_level(0, 30, true);
    overlapping.write_redist(0, 0x10200, 1 << 30);
    assert_eq!(
        before,
        crate::codec::serialize(&legacy(&overlapping)).unwrap()
    );
    assert!(
        legacy(&physical)
            .upgrade()
            .unwrap_err()
            .to_string()
            .contains("ambiguous")
    );
    physical.set_ppi_level(0, 30, false);
    overlapping.set_ppi_level(0, 30, false);
    assert!(!physical.pending_interrupt(0));
    assert!(overlapping.pending_interrupt(0));

    let mut low = configured(1);
    let mut high = configured(1);
    for gic in [&mut low, &mut high] {
        gic.cpu_mut(0).unwrap().private_interrupts[27].trigger = TriggerType::Edge;
    }
    high.set_ppi_level(0, 27, true);
    assert_eq!(high.acknowledge(0), 27);
    high.end_of_interrupt(0, 27);
    assert_eq!(
        crate::codec::serialize(&legacy(&low)).unwrap(),
        crate::codec::serialize(&legacy(&high)).unwrap()
    );
    assert!(legacy(&high).upgrade().is_err());
    low.set_ppi_level(0, 27, true);
    high.set_ppi_level(0, 27, true);
    assert!(low.pending_interrupt(0));
    assert!(!high.pending_interrupt(0));
}

#[test]
fn unambiguous_legacy_level_inputs_upgrade_without_losing_software_sgis() {
    for count in [1, 2, 4] {
        let mut gic = configured(count);
        gic.send_sgi(7, 1 << (count - 1), false);
        let old = legacy(&gic);
        let upgraded = old.upgrade().unwrap();
        let expected = crate::codec::serialize(&gic.checkpoint()).unwrap();
        assert_eq!(crate::codec::serialize(&upgraded).unwrap(), expected);
        gic.reset();
        gic.restore_checkpoint(upgraded);
        assert_eq!(gic.acknowledge(usize::from(count) - 1), 7);
    }
}

#[test]
fn physical_spi_edges_survive_consumption_and_restore_across_the_allocated_domain() {
    for intid in [32, 40, SPI_END] {
        let mut gic = Gic::new(GicConfig {
            num_spis: 992,
            ..Default::default()
        });
        gic.write_dist(0, 3);
        gic.set_group_enable(0, false, true);
        gic.set_group_enable(0, true, true);
        gic.set_enabled(intid, true);
        gic.write_dist(0xc00 + u64::from(intid / 16) * 4, 2 << ((intid % 16) * 2));
        gic.set_spi_level(intid, true);
        assert_eq!(gic.acknowledge(0), intid);
        gic.end_of_interrupt(0, intid);
        let saved = gic.checkpoint();
        gic.reset();
        gic.restore_checkpoint(saved);
        gic.set_spi_level(intid, true);
        assert_eq!(gic.acknowledge(0), INTID_SPURIOUS);
        gic.set_spi_level(intid, false);
        gic.set_spi_level(intid, true);
        assert_eq!(gic.acknowledge(0), intid);
        gic.end_of_interrupt(0, intid);
        assert!(!gic.pending_interrupt(0));
    }
}

#[test]
fn special_intids_are_not_ordinary_pending_enabled_priority_or_routing_spis() {
    let mut gic = Gic::new(GicConfig {
        num_spis: 992,
        ..Default::default()
    });
    for offset in [0xfc, 0x17c, 0x1fc, 0x27c, 0x2fc] {
        gic.write_dist(offset, 0xf000_0000);
        assert_eq!(gic.read_dist(offset) & 0xf000_0000, 0, "register{offset:x}");
    }
    gic.write_dist(0xcfc, u32::MAX);
    assert_eq!(gic.read_dist(0xcfc) & 0xff00_0000, 0);
    gic.write_dist(0x7fc, u32::MAX);
    assert_eq!(gic.read_dist(0x7fc), 0);
    for intid in 1020..=1023 {
        gic.set_spi_level(intid, true);
        gic.write_dist(0x6000 + 8 * u64::from(intid), u32::MAX);
        assert_eq!(gic.read_dist(0x6000 + 8 * u64::from(intid)), 0);
    }
    assert_eq!(gic.read_dist(0x27c) & 0xf000_0000, 0);
    gic.validate_checkpoint(&gic.checkpoint()).unwrap();
}

#[test]
fn eoi_mode_one_retains_pending_source_without_resignalling_until_deactivation() {
    let mut gic = configured(1);
    gic.cpu_mut(0).unwrap().eoi_mode = true;
    gic.set_ppi_level(0, 30, true);
    assert_eq!(gic.acknowledge(0), 30);
    gic.write_redist(0, 0x10200, 1 << 30);
    gic.set_ppi_level(0, 30, false);
    gic.end_of_interrupt(0, 30);
    assert_eq!(
        gic.cpu(0).unwrap().private_interrupts[30].state,
        InterruptState::ActivePending
    );
    assert!(!gic.pending_interrupt(0));
    let raw = crate::codec::serialize(&gic.checkpoint()).unwrap();
    let saved = crate::codec::deserialize_strict(&raw).unwrap();
    gic.reset();
    gic.restore_checkpoint(saved);
    assert!(!gic.pending_interrupt(0));
    gic.deactivate(0, 30);
    assert!(gic.pending_interrupt(0));
    gic.write_redist(0, 0x10280, 1 << 30);
    assert!(!gic.pending_interrupt(0));
}
