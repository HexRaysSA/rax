use super::*;

fn entry(function: u32, index: u32, values: [u32; 4]) -> kvm_cpuid_entry2 {
    kvm_cpuid_entry2 {
        function,
        index,
        eax: values[0],
        ebx: values[1],
        ecx: values[2],
        edx: values[3],
        ..Default::default()
    }
}

fn fixture(vendor: &[u8; 12]) -> CpuId {
    let word = |offset| u32::from_le_bytes(vendor[offset..offset + 4].try_into().unwrap());
    CpuId::from_entries(&[
        entry(0, 0, [0x16, word(0), word(8), word(4)]),
        entry(1, 0, [0x50657, 0xa510_0800, 0x5a51, 0x178b_fbff]),
        entry(2, 0, [1, 2, 3, 4]),
        entry(2, 0, [5, 6, 7, 8]),
        entry(4, 0, [(31 << 26) | (1 << 14) | 0x121, 0x1c0003f, 63, 0]),
        entry(4, 1, [(31 << 26) | (63 << 14) | 0x163, 0x3c0003f, 1023, 2]),
        entry(4, 2, [0; 4]),
        entry(7, 0, [1, 0x42, 0x1000, 0x8000]),
        entry(0xd, 0, [7, 832, 832, 0]),
        entry(0x15, 0, [3, 350, 24_000_000, 0]),
        entry(0x8000_0000, 0, [0x8000_0026, 0, 0, 0]),
        entry(0x8000_0001, 0, [0, 0, 1 << 22, 0]),
        entry(0x8000_0008, 0, [0x3030, 0xabcdef, 0x2f03f, 0x1234]),
        entry(0x8000_001d, 0, [(63 << 14) | 0x163, 0x3c0003f, 1023, 2]),
        entry(0x8000_001e, 0, [239, 0x7ef, 0x341, 0]),
        entry(0x8000_0026, 0, [0xe0000001, 0x12000002, 0x100, 239]),
        entry(0x8000_0026, 1, [6, 64, 0x401, 239]),
    ])
    .unwrap()
}

fn values(cpuid: &CpuId, function: u32, index: u32) -> [u32; 4] {
    let e = cpuid
        .as_slice()
        .iter()
        .find(|e| e.function == function && e.index == index)
        .unwrap();
    [e.eax, e.ebx, e.ecx, e.edx]
}

#[test]
fn every_configured_cpu_has_representable_matching_legacy_and_extended_geometry() {
    let base = fixture(b"GenuineIntel");
    for count in 1..=255u8 {
        let capacity = u32::from(count).min(64);
        let shift = capacity.next_power_of_two().trailing_zeros();
        for id in 0..u32::from(count) {
            let projected = Topology::new(count).unwrap().project(&base, id).unwrap();
            let version = values(&projected, 1, 0);
            assert_eq!(version[1] & 0xffff, 0x800);
            assert_eq!(version[1] >> 24, id);
            assert_eq!((version[1] >> 16) & 255, capacity);
            assert_eq!((version[3] >> 28) & 1, u32::from(capacity > 1));
            assert_eq!(values(&projected, 0xb, 0), [0, 1, 0x100, id]);
            assert_eq!(values(&projected, 0xb, 1), [shift, capacity, 0x201, id]);
            assert_eq!(values(&projected, 0xb, 2), [0, 0, 2, id]);
            let private = values(&projected, 4, 0);
            let shared = values(&projected, 4, 1);
            assert_eq!((private[0] >> 26) + 1, capacity);
            assert_eq!(((private[0] >> 14) & 4095) + 1, 1);
            assert_eq!(((shared[0] >> 14) & 4095) + 1, capacity);
            assert_eq!(&private[1..], &values(&base, 4, 0)[1..]);
            assert_eq!(&shared[1..], &values(&base, 4, 1)[1..]);
        }
    }
}

#[test]
fn amd_and_hygon_geometry_keeps_system_unique_nodes_and_single_thread_cores() {
    for vendor in [b"AuthenticAMD", b"HygonGenuine"] {
        let base = fixture(vendor);
        for count in [1, 2, 3, 64, 65, 127, 128, 129, 255] {
            let capacity = u32::from(count).min(64);
            let shift = capacity.next_power_of_two().trailing_zeros();
            for id in 0..u32::from(count) {
                let projected = Topology::new(count).unwrap().project(&base, id).unwrap();
                let size = values(&projected, 0x8000_0008, 0);
                assert_eq!(size[2] & 255, capacity - 1);
                assert_eq!((size[2] >> 12) & 15, shift);
                assert_eq!(size[2] & 0x30000, 0x20000);
                assert_eq!(
                    values(&projected, 0x8000_001e, 0),
                    [id, id & ((1 << shift) - 1), id >> shift, 0]
                );
                assert_eq!(
                    (values(&projected, 0x8000_0001, 0)[2] >> 1) & 1,
                    u32::from(capacity > 1)
                );
                let cache = values(&projected, 0x8000_001d, 0);
                assert_eq!(cache[0] >> 26, 0, "AMD reserves the Intel core-count field");
                assert_eq!(((cache[0] >> 14) & 4095) + 1, capacity);
                assert_eq!(
                    values(&projected, 0x8000_0026, 0),
                    [0, 0x12000001, 0x100, id]
                );
                assert_eq!(
                    values(&projected, 0x8000_0026, 1),
                    [shift, capacity, 0x401, id]
                );
                assert_eq!(values(&projected, 0x8000_0026, 2), [0, 0, 2, id]);
            }
        }
    }
}

#[test]
fn v2_topology_replaces_host_die_levels_and_preserves_native_isa_records() {
    let mut entries = fixture(b"GenuineIntel").as_slice().to_vec();
    entries.extend([
        entry(0x1f, 0, [1, 2, 0x100, 55]),
        entry(0x1f, 1, [6, 64, 0x501, 55]),
        entry(0x1f, 2, [8, 128, 0x502, 55]),
    ]);
    entries[0].eax = 0x1f;
    let base = CpuId::from_entries(&entries).unwrap();
    let projected = Topology::new(4).unwrap().project(&base, 3).unwrap();
    assert_eq!(values(&projected, 0x1f, 0), [0, 1, 0x100, 3]);
    assert_eq!(values(&projected, 0x1f, 1), [2, 4, 0x201, 3]);
    assert_eq!(values(&projected, 0x1f, 2), [0, 0, 2, 3]);
    for function in [2, 7, 0xd, 0x15] {
        let select = |cpuid: &CpuId| {
            cpuid
                .as_slice()
                .iter()
                .filter(|e| e.function == function)
                .map(|e| {
                    (
                        e.function, e.index, e.flags, e.eax, e.ebx, e.ecx, e.edx, e.padding,
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(select(&base), select(&projected));
    }
}

#[test]
fn native_kvm_signature_enables_detection_without_changing_feature_mask() {
    let mut entries = fixture(b"GenuineIntel").as_slice().to_vec();
    entries.extend([
        entry(
            0x4000_0000,
            0,
            [0x4000_0001, 0x4b4d_564b, 0x564b_4d56, 0x4d],
        ),
        entry(0x4000_0001, 0, [0x1007efb, 0, 0, 0]),
    ]);
    let base = CpuId::from_entries(&entries).unwrap();
    let projected = Topology::new(4).unwrap().project(&base, 3).unwrap();
    assert_eq!(
        values(&projected, 1, 0)[2],
        values(&base, 1, 0)[2] | (1 << 31)
    );
    for function in [0x4000_0000, 0x4000_0001] {
        assert_eq!(values(&projected, function, 0), values(&base, function, 0));
    }
    let sdk = sdk_profile(&base, 7).unwrap();
    let sdk_version = values(&sdk, 1, 0);
    assert_eq!(
        sdk_version[1],
        (values(&base, 1, 0)[1] & 0x00ff_ffff) | (7 << 24)
    );
    assert_eq!(sdk_version[3], values(&base, 1, 0)[3]);
    assert_eq!(sdk_version[2], values(&base, 1, 0)[2] | (1 << 31));
    assert_eq!(sdk.as_slice().len(), base.as_slice().len());
    let signature_index = entries.len() - 2;
    entries[signature_index].eax = 0;
    let legacy = CpuId::from_entries(&entries).unwrap();
    assert_ne!(
        values(
            &Topology::new(4).unwrap().project(&legacy, 2).unwrap(),
            1,
            0
        )[2] & (1 << 31),
        0
    );
    entries[signature_index].ebx = 0;
    let unrelated = CpuId::from_entries(&entries).unwrap();
    assert_eq!(
        values(
            &Topology::new(4).unwrap().project(&unrelated, 3).unwrap(),
            1,
            0
        )[2],
        values(&unrelated, 1, 0)[2]
    );
}

#[test]
fn zero_count_outside_id_and_missing_vendor_record_reject_without_mutation() {
    let base = fixture(b"GenuineIntel");
    assert!(Topology::new(0).is_err());
    assert!(Topology::new(1).unwrap().project(&base, 1).is_err());
    assert!(
        Topology::new(4)
            .unwrap()
            .project(&CpuId::from_entries(&[]).unwrap(), 0)
            .is_err()
    );
    assert_eq!(
        values(&base, 1, 0),
        [0x50657, 0xa5100800, 0x5a51, 0x178bfbff]
    );
}

#[test]
fn unavailable_optional_topology_leaves_remain_unadvertised() {
    let mut entries = fixture(b"GenuineIntel").as_slice().to_vec();
    entries.push(entry(0x1f, 0, [0; 4]));
    let base = CpuId::from_entries(&entries).unwrap();
    let projected = Topology::new(4).unwrap().project(&base, 3).unwrap();
    assert_eq!(values(&projected, 0x1f, 0), [0; 4]);
    assert_eq!(values(&projected, 0x15, 0), values(&base, 0x15, 0));
    assert_eq!(values(&projected, 0, 0)[0], 0x16);
}
