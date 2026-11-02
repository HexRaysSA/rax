//! Discovery and routing expectations derived from IHI0069H12.9.22/38.
use super::{Gic, GicConfig, GicVersion, INTID_SPURIOUS, RoutingMode, SPI_END};
use std::sync::{Arc, atomic::Ordering};

fn route(intid: u32) -> u64 {
    0x6000 + 8 * u64::from(intid)
}

#[test]
fn typer_covers_every_classic_spi_allocation_including_partial_banks() {
    for count in 0..=992 {
        let gic = Gic::new(GicConfig {
            num_spis: count,
            ..Default::default()
        });
        let typer = gic.read_dist(4);
        let blocks = u32::from(count.min(988)).div_ceil(32);
        assert_eq!(typer & 31, blocks, "SPI slots={count}");
        assert_eq!((typer >> 19) & 31, 9);
        assert_eq!(typer & ((1 << 8) | (1 << 10) | (7 << 16)), 0);
    }
}

#[test]
fn fixed_affinity_routing_does_not_advertise_legacy_cpu_targets() {
    for version in [GicVersion::V3, GicVersion::V4] {
        for count in [1, 2, 4, 8, 9, 16, 255] {
            let gic = Gic::new(GicConfig {
                version,
                num_cpus: count,
                ..Default::default()
            });
            assert_ne!(gic.read_dist(0) & (1 << 4), 0);
            assert_eq!((gic.read_dist(4) >> 5) & 7, 0, "{version:?}, {count}");
        }
    }
}

#[test]
fn routing_words_preserve_other_half_and_mask_reserved_fields() {
    let mut gic = Gic::new(GicConfig {
        num_spis: 988,
        ..Default::default()
    });
    for intid in [32, 287, SPI_END] {
        let offset = route(intid);
        gic.write_dist(offset, 0x7f12_3456);
        gic.write_dist(offset + 4, 0xffff_ff78);
        assert_eq!(gic.read_dist(offset), 0x0012_3456);
        assert_eq!(gic.read_dist(offset + 4), 0x78);
        gic.write_dist(offset, 0x0009_abcd);
        assert_eq!(gic.read_dist(offset + 4), 0x78);
        gic.set_routing(intid, RoutingMode::Affinity(0x89ab_cdef));
        assert_eq!(gic.read_dist(offset), 0x00ab_cdef);
        assert_eq!(gic.read_dist(offset + 4), 0x89);
        gic.write_dist(offset, 1 << 31);
        gic.write_dist(offset + 4, 0);
        assert_eq!(gic.read_dist(offset) & (1 << 31), 1 << 31);
        assert_eq!(gic.read_dist(offset + 4), 0);
    }
}

#[test]
fn upper_route_word_can_withhold_and_retarget_a_pending_spi() {
    for count in [1, 2, 4] {
        let mut gic = Gic::new(GicConfig {
            num_cpus: count,
            ..Default::default()
        });
        for id in 0..usize::from(count) {
            gic.write_redist(id, 0x14, 0);
            gic.set_group_enable(id, true, true);
        }
        gic.write_dist(0, 2);
        gic.set_enabled(287, true);
        gic.write_dist(route(287), u32::from(count - 1));
        gic.write_dist(route(287) + 4, 1);
        gic.set_pending(287);
        for id in 0..usize::from(count) {
            assert!(
                !gic.pending_interrupt(id),
                "absent Aff3 must not route to PE{id}"
            );
        }
        gic.write_dist(route(287) + 4, 0);
        for id in 0..usize::from(count) {
            assert_eq!(gic.pending_interrupt(id), id + 1 == usize::from(count));
        }
        assert_eq!(gic.acknowledge(usize::from(count) - 1), 287);
    }
}

#[test]
fn discovered_last_spi_has_register_state_delivery_and_checkpoint_identity() {
    for slots in [1, 31, 32, 33, 255, 256, 257, 988, 992] {
        for count in [1, 2, 4] {
            let config = GicConfig {
                num_cpus: count,
                num_spis: slots,
                ..Default::default()
            };
            let mut gic = Gic::new(config.clone());
            let banks = (gic.read_dist(4) & 31) + 1;
            let mut discovered = 0;
            for bank in 1..banks {
                let offset = 0x100 + 4 * u64::from(bank);
                gic.write_dist(offset, u32::MAX);
                let enabled = gic.read_dist(offset);
                if enabled != 0 {
                    discovered = 32 * bank + 31 - enabled.leading_zeros();
                }
            }
            let top = u32::from(slots.min(988)) + 31;
            assert_eq!(discovered, top, "slots={slots}, PEs={count}");
            let target = usize::from(count - 1);
            gic.write_redist(target, 0x14, 0);
            gic.set_group_enable(target, true, true);
            gic.write_dist(0, 2);
            gic.write_dist(route(top), target as u32);
            gic.write_dist(route(top) + 4, 0);
            gic.write_dist(0xc00 + 4 * u64::from(top / 16), 2 << (2 * (top % 16)));
            let pending = 0x200 + 4 * u64::from(top / 32);
            gic.write_dist(pending, 1 << (top % 32));
            assert!(gic.pending_interrupt(target));
            let saved = gic.checkpoint();
            let mut restored = Gic::new(config);
            let line = restored.irq_line(target).unwrap();
            restored.validate_checkpoint(&saved).unwrap();
            restored.restore_checkpoint(saved);
            assert!(Arc::ptr_eq(&line, &restored.irq_line(target).unwrap()));
            assert!(line.load(Ordering::Acquire));
            assert_eq!(restored.read_dist(route(top)), target as u32);
            assert_eq!(restored.read_dist(route(top) + 4), 0);
            assert_eq!(restored.acknowledge(target), top);
            assert_ne!(restored.read_dist(0x300 + 4 * u64::from(top / 32)), 0);
            restored.end_of_interrupt(target, top);
            assert_eq!(restored.acknowledge(target), INTID_SPURIOUS);
        }
    }
}

#[test]
fn routing_registers_for_unallocated_and_special_ids_are_raz_wi() {
    for slots in [0, 1, 33, 256, 988, 992] {
        let mut gic = Gic::new(GicConfig {
            num_spis: slots,
            ..Default::default()
        });
        for intid in [31, u32::from(slots.min(988)) + 32, 1020, 1023] {
            for half in [0, 4] {
                let offset = route(intid) + half;
                gic.write_dist(offset, u32::MAX);
                assert_eq!(
                    gic.read_dist(offset),
                    0,
                    "slots={slots}, offset={offset:#x}"
                );
            }
        }
    }
}

#[test]
fn legacy_profile_keeps_cpu_target_count_and_ignores_affinity_registers() {
    for count in 1..=8 {
        let mut gic = Gic::new(GicConfig {
            version: GicVersion::V2,
            num_cpus: count,
            ..Default::default()
        });
        assert_eq!((gic.read_dist(4) >> 5) & 7, u32::from(count - 1));
        gic.write_dist(route(32), u32::MAX);
        gic.write_dist(route(32) + 4, u32::MAX);
        assert_eq!(gic.read_dist(route(32)), 0);
        assert_eq!(gic.read_dist(route(32) + 4), 0);
        assert!(matches!(gic.spis[0].routing, RoutingMode::Affinity(0)));
    }
}

#[test]
fn fixed_affinity_routing_makes_legacy_target_registers_raz_wi() {
    for version in [GicVersion::V3, GicVersion::V4] {
        let mut gic = Gic::new(GicConfig {
            version,
            num_cpus: 4,
            num_spis: 988,
            ..Default::default()
        });
        let before = crate::codec::serialize(&gic.checkpoint()).unwrap();
        for offset in (0x800..=0xbfc).step_by(4) {
            gic.write_dist(offset, u32::MAX);
            assert_eq!(gic.read_dist(offset), 0, "{version:?}, {offset:#x}");
        }
        assert_eq!(crate::codec::serialize(&gic.checkpoint()).unwrap(), before);
    }
}
