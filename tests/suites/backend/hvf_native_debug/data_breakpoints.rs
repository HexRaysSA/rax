use super::data_breakpoints::{causes, relevant};

#[test]
fn intel_table_19_1_byte_range_examples() {
    let addresses = [0xa0001, 0xa0002, 0xb0002, 0xc0000];
    let dr7 = 0x400 | 0x55 | (3 << 16) | (1 << 20) | (7 << 24) | (13 << 28);
    for (linear, size, writing, expected) in [
        (0xa0001, 1, false, 1),
        (0xa0001, 2, false, 1),
        (0xa0002, 1, true, 2),
        (0xa0002, 2, true, 2),
        (0xb0001, 4, false, 4),
        (0xb0002, 1, false, 4),
        (0xb0002, 2, true, 4),
        (0xc0000, 4, true, 8),
        (0xc0001, 2, true, 8),
        (0xc0003, 1, true, 8),
        (0xa0000, 1, false, 0),
        (0xa0002, 1, false, 0),
        (0xa0003, 4, true, 0),
        (0xb0000, 2, true, 0),
        (0xc0000, 2, false, 0),
        (0xc0004, 4, true, 0),
    ] {
        assert_eq!(
            causes(dr7, &addresses, linear, size, writing).unwrap(),
            if expected == 0 { 0 } else { 0x1000 | expected }
        );
    }
}

#[test]
fn every_slot_enable_type_width_and_overlap_boundary() {
    let lengths = [(0, 1u64), (1, 2), (2, 8), (3, 4)];
    for slot in 0..4 {
        for enable in 0..4u64 {
            for condition in 0..4u64 {
                for (encoded, length) in lengths {
                    for size in [1u8, 2, 4, 8] {
                        for writing in [false, true] {
                            for offset in 0..32u64 {
                                let start = 0x1000 + offset;
                                let dr7 = 0x400
                                    | (enable << (slot * 2))
                                    | ((condition | (encoded << 2)) << (16 + slot * 4));
                                let mut addresses = [0; 4];
                                addresses[slot] = 0x1010;
                                let overlaps = (start..start + u64::from(size))
                                    .any(|b| (0x1010..0x1010 + length).contains(&b));
                                let expected = enable != 0
                                    && overlaps
                                    && (condition == 3 || (condition == 1 && writing));
                                assert_eq!(
                                    causes(dr7, &addresses, start, size, writing).unwrap(),
                                    if expected { 0x1000 | (1 << slot) } else { 0 }
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn simultaneous_local_and_global_matches_accumulate_without_unrelated_status() {
    let addresses = [0x1000, 0x1001, 0x1002, 0x1003];
    let dr7 = 0x400 | 0xe7 | (3 << 16) | (3 << 20) | (1 << 24) | (3 << 28);
    assert_eq!(relevant(dr7, false), 0xb);
    assert_eq!(causes(dr7, &addresses, 0x1000, 4, false).unwrap(), 0x100b);
    assert_eq!(causes(dr7, &addresses, 0x1000, 4, true).unwrap(), 0x100f);
}

#[test]
fn upper_linear_bits_and_wrapping_byte_extent_are_retained() {
    let addresses = [0xffff_ffff_ffff_fffc, 0, 0, 0];
    let dr7 = 0x400 | 1 | (15 << 16); // four-byte read/write watch at the high address.
    assert_eq!(
        causes(dr7, &addresses, u64::MAX - 3, 4, false).unwrap(),
        0x1001
    );
    assert_eq!(causes(dr7, &addresses, 0xffff_fffc, 4, false).unwrap(), 0);
    assert_eq!(
        causes(0x3_0401, &[0, 0, 0, 0], u64::MAX, 2, false).unwrap(),
        0x1001
    );
    for size in [0, 3, 5, 16, 255] {
        assert!(causes(dr7, &addresses, 0, size, true).is_err());
    }
}

#[test]
fn production_matching_replays_all_336_native_guest_dr6_observations() {
    let raw = include_str!(
        "../../../../docs/development/hvf-mmio-data-breakpoints/kvm-reference-v2.stdout"
    );
    let rows: Vec<serde_json::Value> = raw
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|row: &serde_json::Value| row.get("case").is_some())
        .collect();
    assert_eq!(rows.len(), 336);
    let mut zero_count_write_traps = 0;
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row["case"].as_u64(), Some(index as u64));
        assert_eq!(row["passed"].as_bool(), Some(true));
        let slot = row["slot"].as_u64().unwrap() as usize;
        let dr6 = row["dr6"].as_u64().unwrap();
        let enabled = row["enabled"].as_u64().unwrap() != 0;
        let mut addresses = [0; 4];
        addresses[slot] = 0x4008;
        let expected = if enabled && dr6 & (1 << slot) != 0 {
            0x1000 | (1 << slot)
        } else {
            0
        };
        assert_eq!(
            causes(
                row["dr7"].as_u64().unwrap(),
                &addresses,
                0x4000 + row["offset"].as_u64().unwrap(),
                row["size"].as_u64().unwrap() as u8,
                row["action"].as_u64().unwrap() != 0
            )
            .unwrap(),
            expected,
            "native record {index}"
        );
        if row["action"].as_u64() == Some(2)
            && row["rw"].as_u64() == Some(1)
            && row["tf"].as_u64() == Some(0)
            && expected != 0
        {
            zero_count_write_traps += 1;
        }
    }
    assert!(
        zero_count_write_traps > 0,
        "write-only zero-count controls must execute"
    );
}
