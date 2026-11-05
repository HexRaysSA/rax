use super::*;

fn profile() -> Profile {
    Profile {
        cpu_signature: 0x0005_0657,
        cpu_features: 0x178b_fbff,
        local_apic_version: 0x14,
        io_apic_id: 0,
        io_apic_version: 0x11,
        io_apic_address: 0xfec0_0000,
        isa_irq0_pin: 0,
    }
}

#[test]
fn configured_cpu_count_and_bsp_survive_every_supported_count() {
    for count in 1..=255 {
        let table = configuration(count, &profile()).unwrap();
        assert_eq!(&table[..4], b"PCMP");
        assert_eq!(
            u16::from_le_bytes(table[4..6].try_into().unwrap()) as usize,
            table.len()
        );
        assert_eq!(
            table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)),
            0
        );
        assert_eq!(
            u16::from_le_bytes(table[34..36].try_into().unwrap()),
            u16::from(count) + 19
        );
        for id in 0..count {
            let entry = &table[44 + usize::from(id) * 20..][..20];
            assert_eq!(&entry[..4], &[0, id, 0x14, if id == 0 { 3 } else { 1 }]);
            assert_eq!(&entry[4..8], &profile().cpu_signature.to_le_bytes());
            assert_eq!(&entry[8..12], &profile().cpu_features.to_le_bytes());
            assert_eq!(&entry[12..], &[0; 8]);
        }
        assert!(CONFIGURATION_TABLE + table.len() as u64 <= BIOS_END);
    }
}

#[test]
fn zero_cpus_and_missing_firmware_backing_reject_before_writing() {
    let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(FLOATING_POINTER), 4096)]).unwrap();
    memory
        .write_slice(&[0xa5; 4096], GuestAddress(FLOATING_POINTER))
        .unwrap();
    assert!(publish(&memory, 0, &profile()).is_err());
    assert!(publish(&memory, 255, &profile()).is_err());
    let mut bytes = [0; 4096];
    memory
        .read_slice(&mut bytes, GuestAddress(FLOATING_POINTER))
        .unwrap();
    assert_eq!(bytes, [0xa5; 4096]);
}

#[test]
fn publication_has_independent_pointer_and_configuration_checksums() {
    let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(FLOATING_POINTER), 65536)]).unwrap();
    publish(&memory, 4, &profile()).unwrap();
    let mut pointer = [0; 16];
    memory
        .read_slice(&mut pointer, GuestAddress(FLOATING_POINTER))
        .unwrap();
    assert_eq!(&pointer[..4], b"_MP_");
    assert_eq!(&pointer[4..8], &(CONFIGURATION_TABLE as u32).to_le_bytes());
    assert_eq!(&pointer[8..10], &[1, 4]);
    assert_eq!(&pointer[11..], &[0; 5]);
    assert_eq!(
        pointer
            .iter()
            .fold(0u8, |sum, byte| sum.wrapping_add(*byte)),
        0
    );
    let mut header = [0; 44];
    memory
        .read_slice(&mut header, GuestAddress(CONFIGURATION_TABLE))
        .unwrap();
    let length = u16::from_le_bytes(header[4..6].try_into().unwrap());
    assert_eq!(length, 276);
    let mut actual = vec![0; usize::from(length)];
    memory
        .read_slice(&mut actual, GuestAddress(CONFIGURATION_TABLE))
        .unwrap();
    assert_eq!(
        actual.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)),
        0
    );
}

#[test]
fn native_and_software_pit_wiring_preserve_every_other_isa_route() {
    for count in 1..=255 {
        for pin in [0, 2] {
            let mut profile = profile();
            profile.isa_irq0_pin = pin;
            let table = configuration(count, &profile).unwrap();
            let records = &table[44 + usize::from(count) * 20 + 16..];
            for (record, irq) in records
                .chunks_exact(8)
                .zip((0..16u8).filter(|irq| *irq != 2))
            {
                assert_eq!(
                    record,
                    [3, 0, 0, 0, 0, irq, 0, if irq == 0 { pin } else { irq }]
                );
            }
            assert_eq!(
                &records[15 * 8..],
                &[4, 3, 0, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 255, 1]
            );
        }
    }
    let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(FLOATING_POINTER), 65536)]).unwrap();
    memory
        .write_slice(&[0xa5; 64], GuestAddress(FLOATING_POINTER))
        .unwrap();
    for pin in [1, 3, 23, 24, 255] {
        let mut profile = profile();
        profile.isa_irq0_pin = pin;
        assert!(publish(&memory, 4, &profile).is_err());
        let mut actual = [0; 64];
        memory
            .read_slice(&mut actual, GuestAddress(FLOATING_POINTER))
            .unwrap();
        assert_eq!(actual, [0xa5; 64]);
    }
}
