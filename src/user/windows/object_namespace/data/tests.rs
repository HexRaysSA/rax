use super::*;

pub(crate) fn sample() -> Arc<DataSection> {
    let mut bytes = vec![0xA5; 5 * 4096];
    // Opaque server addresses are data. A different client base does not
    // authorize scanning or rewriting address-looking words.
    bytes[40..48].copy_from_slice(&0x0000_7FF5_F57C_0000u64.to_le_bytes());
    DataSection::selected(
        0x20004,
        STATUS_PRIVILEGE_NOT_HELD,
        false,
        1 << 20,
        vec![
            DataRegion {
                offset: 0,
                size: bytes.len() as u64,
                bytes: Some(bytes.into()),
            },
            DataRegion {
                offset: 5 * 4096,
                size: (1 << 20) - 5 * 4096,
                bytes: None,
            },
        ],
    )
    .unwrap()
}

#[test]
fn selected_data_section_retains_native_grants_without_requiring_query_access() {
    let section = sample();
    for (requested, expected) in [
        (0, Err(STATUS_ACCESS_DENIED)),
        (1, Err(STATUS_ACCESS_DENIED)),
        (2, Err(STATUS_ACCESS_DENIED)),
        (4, Ok(4)),
        (5, Err(STATUS_ACCESS_DENIED)),
        (0x20000, Ok(0x20000)),
        (0x02000000, Ok(0x20004)),
        (0x01000000, Err(STATUS_PRIVILEGE_NOT_HELD)),
        (0x80000000, Err(STATUS_ACCESS_DENIED)),
        (0x40000000, Err(STATUS_ACCESS_DENIED)),
        (0x20000000, Err(STATUS_ACCESS_DENIED)),
        (0x10000000, Err(STATUS_ACCESS_DENIED)),
    ] {
        assert_eq!(section.grant(requested, false), expected, "{requested:08X}");
    }
    assert_eq!(section.grant(0, true), Ok(0));
    assert_eq!(section.grant(0x20, true), Ok(0));
    assert_eq!(
        section.regions[0].bytes.as_ref().unwrap()[40..48],
        0x0000_7FF5_F57C_0000u64.to_le_bytes()
    );
}

#[test]
fn selected_data_section_rejects_gaps_overlaps_extents_and_unbounded_storage() {
    let section = sample();
    let check = |size, regions| {
        DataSection::selected(0x20004, STATUS_PRIVILEGE_NOT_HELD, false, size, regions)
    };
    for size in [0, 1, (64 << 20) + 4096, u64::MAX] {
        assert!(check(size, section.regions.clone()).is_err());
    }
    let mut invalid = Vec::new();
    let mut runs = section.regions.clone();
    runs[1].offset += 4096;
    invalid.push(runs);
    let mut runs = section.regions.clone();
    runs[1].offset -= 4096;
    invalid.push(runs);
    let mut runs = section.regions.clone();
    runs[0].size -= 4096;
    invalid.push(runs);
    let mut runs = section.regions.clone();
    runs[0].bytes = Some(vec![0; 4096].into());
    invalid.push(runs);
    let mut runs = section.regions.clone();
    runs[1].size = u64::MAX;
    invalid.push(runs);
    invalid.push(vec![]);
    for runs in invalid {
        assert!(check(section.size, runs).is_err());
    }
    assert!(
        DataSection::selected(
            0x20005,
            STATUS_PRIVILEGE_NOT_HELD,
            false,
            section.size,
            section.regions.clone()
        )
        .is_err()
    );
    assert!(
        DataSection::selected(
            4,
            STATUS_INVALID_HANDLE,
            false,
            section.size,
            section.regions.clone()
        )
        .is_err()
    );
}

#[test]
fn theme_directory_checks_the_current_session_and_declared_section_sizes() {
    let mut header = [0u8; 4096];
    let first = "\\Windows\\Theme2323452646";
    let second = "\\Sessions\\1\\Windows\\Theme2615404641";
    let set_name = |buffer: &mut [u8], start: usize, name: &str| {
        buffer[start..start + 520].fill(0);
        for (target, unit) in buffer[start..start + 520]
            .chunks_exact_mut(2)
            .zip(name.encode_utf16())
        {
            target.copy_from_slice(&unit.to_le_bytes());
        }
    };
    for (offset, name) in [(0, first), (0x208, second), (0x428, first), (0x630, second)] {
        set_name(&mut header, offset, name);
    }
    header[0x838..0x840].copy_from_slice(&0x159000u64.to_le_bytes());
    header[0x840..0x848].copy_from_slice(&0x6000u64.to_le_bytes());
    assert_eq!(
        theme_directory(1, &header).unwrap(),
        [
            (first.encode_utf16().collect(), 0x159000),
            (second.encode_utf16().collect(), 0x6000),
        ]
    );
    assert!(theme_directory(2, &header).is_err());
    assert!(theme_directory(1, &header[..4095]).is_err());
    for wrong in [
        "\\Windows\\Theme",
        "\\Windows\\Theme4294967296",
        "\\Windows\\Theme2\\Other",
        "\\KnownDlls\\Theme1",
        "\\Windows\\Theme2123452646",
    ] {
        let mut changed = header;
        set_name(&mut changed, 0x428, wrong);
        assert!(theme_directory(1, &changed).is_err(), "{wrong}");
    }
    for wrong_size in [0, 4095, (16 << 20) + 4096, u64::MAX] {
        let mut changed = header;
        changed[0x840..0x848].copy_from_slice(&wrong_size.to_le_bytes());
        assert!(theme_directory(1, &changed).is_err(), "{wrong_size}");
    }
}
