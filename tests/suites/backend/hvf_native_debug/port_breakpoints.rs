use super::data_breakpoints::{port_causes, port_relevant};

#[test]
fn all_slot_enable_condition_length_width_and_de_partitions() {
    let mut cases = 0;
    for slot in 0..4 {
        for enable in 0..4u64 {
            for condition in 0..4u64 {
                for (encoded, length) in [(0, 1u64), (1, 2), (2, 8), (3, 4)] {
                    for size in [1u8, 2, 4] {
                        for de in [false, true] {
                            for offset in 0..32u16 {
                                let port = 0x3e8 + offset;
                                let dr7 = 0x400
                                    | (enable << (slot * 2))
                                    | ((condition | (encoded << 2)) << (16 + slot * 4));
                                let mut addresses = [0; 4];
                                addresses[slot] = 0x3f8;
                                let overlaps = (u64::from(port)..u64::from(port) + u64::from(size))
                                    .any(|byte| (0x3f8..0x3f8 + length).contains(&byte));
                                let hit = de && enable != 0 && condition == 2 && overlaps;
                                assert_eq!(
                                    port_causes(
                                        dr7,
                                        if de { 8 } else { 0 },
                                        &addresses,
                                        port,
                                        size
                                    )
                                    .unwrap(),
                                    if hit { 0x1000 | (1 << slot) } else { 0 }
                                );
                                cases += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 49_152);
}

#[test]
fn matches_all_972_independent_bochs_model_records() {
    let raw =
        include_str!("../../../../docs/development/hvf-port-io-breakpoints/bochs-records.jsonl");
    let mut count = 0;
    for (index, line) in raw.lines().enumerate() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(row["case"].as_u64(), Some(index as u64));
        let addresses: [u64; 4] = std::array::from_fn(|i| row["addresses"][i].as_u64().unwrap());
        let dr7 = row["dr7"].as_u64().unwrap();
        let observed = row["bochs_pending"].as_u64().unwrap();
        // SDM permits disabled B0-B3 status either way. Compare enabled causes.
        let expected = if observed & 0x1000 == 0 {
            0
        } else {
            0x1000 | (observed & u64::from(port_relevant(dr7)))
        };
        assert_eq!(
            port_causes(
                dr7,
                row["cr4"].as_u64().unwrap(),
                &addresses,
                row["port"].as_u64().unwrap() as u16,
                row["size"].as_u64().unwrap() as u8,
            )
            .unwrap(),
            expected,
            "Bochs computational reference record{index}; no native guest claim"
        );
        count += 1;
    }
    assert_eq!(count, 972);
}

#[test]
fn port_addresses_are_extended_and_watches_retain_upper_bits() {
    let dr7 = 0x2_0401;
    for (address, expected) in [(0x3f8, 0x1001), (0x103f8, 0), (0x1_0000_03f8, 0)] {
        assert_eq!(
            port_causes(dr7, 8, &[address, 0, 0, 0], 0x3f8, 1).unwrap(),
            expected
        );
    }
    // The comparison's byte extent follows the zero-extended port. It does not
    // truncate each byte back to16 bits. These are computational range controls.
    assert_eq!(
        port_causes(dr7, 8, &[0x10000, 0, 0, 0], 0xffff, 2).unwrap(),
        0x1001
    );
    assert_eq!(port_causes(dr7, 8, &[0, 0, 0, 0], 0xffff, 2).unwrap(), 0);
    for size in [0, 3, 8, 16, 255] {
        assert!(port_causes(dr7, 8, &[0; 4], 0, size).is_err());
    }
}

#[test]
fn independent_io_slots_accumulate_and_memory_conditions_are_excluded() {
    let addresses = [0x3f8, 0x3f9, 0x3fb, 0x3fc];
    let dr7 = 0x479 | (2 << 16) | (2 << 20) | (2 << 24) | (3 << 28);
    assert_eq!(port_relevant(dr7), 7);
    for (size, expected) in [(1, 0x1001), (2, 0x1003), (4, 0x1007)] {
        assert_eq!(
            port_causes(dr7, 8, &addresses, 0x3f8, size).unwrap(),
            expected
        );
    }
    assert_eq!(port_causes(dr7, 0, &addresses, 0x3f8, 4).unwrap(), 0);
}
