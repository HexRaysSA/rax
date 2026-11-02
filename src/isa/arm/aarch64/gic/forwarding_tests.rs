use super::{Gic, GicConfig, INTID_SPURIOUS, RoutingMode};
use std::sync::atomic::Ordering;

fn controller(count: u8) -> Gic {
    let mut gic = Gic::new(GicConfig {
        num_cpus: count,
        ..Default::default()
    });
    for id in 0..usize::from(count) {
        gic.write_redist(id, 0x14, 0); // Awake participating PE (IHI0069H2.3.2).
        gic.set_group_enable(id, false, true);
        gic.set_group_enable(id, true, true);
    }
    gic
}

fn pending(gic: &mut Gic, id: usize, intid: u32, group: u8) {
    if intid < 32 {
        gic.cpu_mut(id).unwrap().private_interrupts[intid as usize].group = group;
        gic.write_redist(id, 0x10100, 1 << intid);
        if intid < 16 {
            gic.send_sgi(intid, 1 << id, false)
        } else {
            gic.set_ppi_level(id, intid, true)
        }
    } else {
        gic.write_dist(0x84, if group == 1 { 1 << (intid - 32) } else { 0 });
        gic.set_enabled(intid, true);
        gic.set_routing(intid, RoutingMode::Affinity(id as u64));
        gic.set_pending(intid);
    }
}

#[test]
fn independent_distributor_enable_bits_read_back_exactly() {
    let mut gic = controller(1);
    for mask in [0, 1, 2, 3] {
        gic.write_dist(0, mask);
        assert_eq!(gic.read_dist(0) & 3, mask, "GICD_CTLR {mask}");
    }
}

#[test]
fn disabled_distributor_keeps_sgi_ppi_spi_pending_without_irq_or_ack() {
    for count in [1, 2, 4] {
        for intid in [7, 30, 40] {
            for group in [0, 1] {
                let mut gic = controller(count);
                let id = usize::from(count - 1);
                pending(&mut gic, id, intid, group);
                assert!(
                    !gic.pending_interrupt(id),
                    "disabled count={count} irq={intid} group={group}"
                );
                assert!(!gic.irq_line(id).unwrap().load(Ordering::Acquire));
                assert_eq!(gic.acknowledge(id), INTID_SPURIOUS);
                gic.write_dist(0, 1 << group);
                assert!(
                    gic.pending_interrupt(id),
                    "reenable count={count} irq={intid} group={group}"
                );
                assert_eq!(gic.acknowledge(id), intid);
            }
        }
    }
}

#[test]
fn enabling_other_cpu_group_does_not_admit_disabled_group() {
    for group in [0, 1] {
        let mut gic = controller(1);
        gic.write_dist(0, 3);
        pending(&mut gic, 0, 40, group);
        gic.set_group_enable(0, group == 1, false);
        assert!(!gic.pending_interrupt(0), "disabled cpu group {group}");
        assert_eq!(gic.acknowledge(0), INTID_SPURIOUS);
        gic.set_group_enable(0, group == 1, true);
        assert_eq!(gic.acknowledge(0), 40);
    }
}

#[test]
fn disabled_distributor_group_cannot_hide_enabled_lower_priority_group() {
    let mut gic = controller(1);
    gic.write_dist(0, 2);
    pending(&mut gic, 0, 40, 0);
    gic.set_priority(40, 0x10);
    gic.set_enabled(41, true);
    gic.set_priority(41, 0x80);
    gic.write_dist(0x84, 1 << 9);
    gic.set_pending(41);
    assert_eq!(gic.acknowledge(0), 41);
}

#[test]
fn checkpoint_restores_exact_distributor_group_mask_and_existing_irq_arc() {
    for mask in [0, 1, 2, 3] {
        let mut gic = controller(1);
        gic.write_dist(0, mask);
        pending(&mut gic, 0, 40, 0);
        let line = gic.irq_line(0).unwrap();
        let state = gic.checkpoint();
        gic.write_dist(0, 3 ^ mask);
        gic.validate_checkpoint(&state).unwrap();
        gic.restore_checkpoint(state);
        assert_eq!(gic.read_dist(0) & 3, mask);
        assert!(std::sync::Arc::ptr_eq(&line, &gic.irq_line(0).unwrap()));
        assert_eq!(line.load(Ordering::Acquire), mask & 1 != 0);
    }
}

#[test]
fn all_distributor_and_cpu_group_masks_gate_every_class_on_every_pe() {
    for count in [1, 2, 4] {
        for intid in [0, 15, 16, 31, 40] {
            for group in [0, 1] {
                for distributor in 0..4 {
                    for cpu_mask in 0..4 {
                        let mut gic = controller(count);
                        let id = usize::from(count - 1);
                        gic.write_dist(0, distributor);
                        gic.set_group_enable(id, false, cpu_mask & 1 != 0);
                        gic.set_group_enable(id, true, cpu_mask & 2 != 0);
                        pending(&mut gic, id, intid, group);
                        let expected =
                            distributor & (1 << group) != 0 && cpu_mask & (1 << group) != 0;
                        let detail = (count, intid, group, distributor, cpu_mask);
                        assert_eq!(gic.pending_interrupt(id), expected, "{detail:?}");
                        assert_eq!(
                            gic.irq_line(id).unwrap().load(Ordering::Acquire),
                            expected,
                            "{detail:?}"
                        );
                        assert_eq!(
                            gic.acknowledge(id),
                            if expected { intid } else { INTID_SPURIOUS },
                            "{detail:?}"
                        );
                        if !expected {
                            // Neither enable control consumes the pending source.
                            gic.write_dist(0, 3);
                            gic.set_group_enable(id, false, true);
                            gic.set_group_enable(id, true, true);
                            assert_eq!(gic.acknowledge(id), intid, "{detail:?}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn disabling_forwarding_withdraws_irq_without_consuming_pending_sources() {
    for intid in [7, 30, 40] {
        for group in [0, 1] {
            let mut gic = controller(1);
            gic.write_dist(0, 3);
            pending(&mut gic, 0, intid, group);
            let line = gic.irq_line(0).unwrap();
            assert!(line.load(Ordering::Acquire));
            gic.write_dist(0, 1 << (1 - group));
            assert!(!line.load(Ordering::Acquire));
            assert_eq!(gic.acknowledge(0), INTID_SPURIOUS);
            gic.write_dist(0, 3);
            assert!(line.load(Ordering::Acquire));
            gic.set_group_enable(0, group == 1, false);
            assert!(!line.load(Ordering::Acquire));
            gic.set_group_enable(0, group == 1, true);
            assert_eq!(gic.acknowledge(0), intid);
        }
    }
}

#[test]
fn any_routed_spi_excludes_pes_with_the_target_group_disabled() {
    for count in [2, 4] {
        for group in [0, 1] {
            let mut gic = controller(count);
            gic.write_dist(0, 3);
            pending(&mut gic, 0, 40, group);
            for id in 0..usize::from(count - 1) {
                gic.set_group_enable(id, group == 1, false);
            }
            gic.set_routing(40, RoutingMode::Any);
            for id in 0..usize::from(count) {
                assert_eq!(gic.pending_interrupt(id), id == usize::from(count - 1));
            }
            assert_eq!(gic.acknowledge(usize::from(count - 1)), 40);
            for id in 0..usize::from(count) {
                assert!(!gic.irq_line(id).unwrap().load(Ordering::Acquire));
            }
        }
    }
}

#[test]
fn single_security_state_control_and_reserved_bits_agree_with_typer() {
    for version in [super::GicVersion::V3, super::GicVersion::V4] {
        let mut gic = Gic::new(GicConfig {
            version,
            ..Default::default()
        });
        assert_eq!(gic.read_dist(0), 0x50);
        assert_eq!(gic.read_dist(4) & (1 << 10), 0);
        for mask in [0, 1, 2, 3] {
            gic.write_dist(0, 0xffff_fffc | mask);
            assert_eq!(gic.read_dist(0), 0x50 | mask);
        }
        gic.reset();
        assert_eq!(gic.read_dist(0), 0x50);
    }
}

#[test]
fn active_priority_prevents_acknowledging_a_nonpreempting_pending_interrupt() {
    let mut gic = controller(1);
    gic.write_dist(0, 3);
    pending(&mut gic, 0, 40, 1);
    gic.set_priority(40, 0x20);
    assert_eq!(gic.acknowledge(0), 40);
    gic.set_enabled(41, true);
    gic.set_pending(41);
    assert!(!gic.pending_interrupt(0));
    assert_eq!(gic.acknowledge(0), INTID_SPURIOUS);
    gic.end_of_interrupt(0, 40);
    gic.clear_pending(40);
    assert_eq!(gic.acknowledge(0), 41);
}

#[test]
fn invalid_checkpoint_group_mask_is_rejected_without_publishing() {
    let mut gic = controller(1);
    gic.write_dist(0, 2);
    pending(&mut gic, 0, 40, 1);
    let before = crate::codec::serialize(&gic.checkpoint()).unwrap();
    let line = gic.irq_line(0).unwrap();
    let mut value = serde_json::to_value(gic.checkpoint()).unwrap();
    value["dist_groups"] = 4.into();
    let invalid: super::checkpoint::GicCheckpoint = serde_json::from_value(value).unwrap();
    assert!(gic.validate_checkpoint(&invalid).is_err());
    assert_eq!(crate::codec::serialize(&gic.checkpoint()).unwrap(), before);
    assert!(line.load(Ordering::Acquire));
}

#[test]
fn actual_parent_source_records_preserve_sources_and_migrate_recorded_control_readback() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a64-gic-forwarding/legacy-source-fixtures.json"
    )))
    .unwrap();
    for record in fixture["records"].as_array().unwrap() {
        let hex = record["bytes_hex"].as_str().unwrap();
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let old: super::checkpoint::SourceGicCheckpoint =
            crate::codec::deserialize_strict(&bytes).unwrap();
        let saved = old.upgrade().unwrap();
        let mut gic = Gic::new(GicConfig {
            num_cpus: 2,
            num_spis: 32,
            ..Default::default()
        });
        let line = gic.irq_line(1).unwrap();
        gic.validate_checkpoint(&saved).unwrap();
        gic.restore_checkpoint(saved);
        gic.write_redist(1, 0x14, 0); // Explicit wakeup after importing the old record.
        let mask = record["represented_group_mask"].as_u64().unwrap() as u32;
        assert_eq!(gic.read_dist(0) & 3, mask);
        assert_eq!(gic.read_redist(1, 0x10200) & (1 << 27), 1 << 27);
        assert_eq!(gic.read_dist(0x204) & (1 << 8), 1 << 8);
        assert_eq!(line.load(Ordering::Acquire), mask & 1 != 0);
        // The old record held independent hardware and software requests.
        gic.set_ppi_level(1, 27, false);
        assert_ne!(gic.read_redist(1, 0x10200) & (1 << 27), 0);
        gic.set_spi_level(40, false);
        assert_ne!(gic.read_dist(0x204) & (1 << 8), 0);
        gic.write_redist(1, 0x10280, 1 << 27);
        gic.write_dist(0x284, 1 << 8);
        assert_eq!(gic.read_redist(1, 0x10200) & (1 << 27), 0);
        assert_eq!(gic.read_dist(0x204) & (1 << 8), 0);
    }
}
