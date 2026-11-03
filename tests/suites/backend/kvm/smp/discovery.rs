//! Actual native PC firmware publication and hardware-field comparisons.
use super::*;

// GNU as2.42; CPUID1, native LAPIC/IOAPIC reads, then ACPI shutdown.
const DISCOVERY: &[u8] = &[
    0xfa, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0xa2, 0x89, 0x04, 0x25, 0x00, 0x00, 0x21, 0x00, 0x89,
    0x14, 0x25, 0x04, 0x00, 0x21, 0x00, 0x48, 0xb8, 0x30, 0x00, 0xe0, 0xfe, 0x00, 0x00, 0x00, 0x00,
    0x8b, 0x00, 0x89, 0x04, 0x25, 0x08, 0x00, 0x21, 0x00, 0x48, 0xb8, 0x00, 0x00, 0xc0, 0xfe, 0x00,
    0x00, 0x00, 0x00, 0xc7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8b, 0x58, 0x10, 0x89, 0x1c, 0x25, 0x0c,
    0x00, 0x21, 0x00, 0xc7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x58, 0x10, 0x89, 0x1c, 0x25, 0x10,
    0x00, 0x21, 0x00, 0x66, 0xba, 0x04, 0x06, 0x66, 0xb8, 0x00, 0x20, 0x66, 0xef, 0xf4,
];

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn run_discovery(count: u8, name: &str) {
    if std::env::var(CHILD).as_deref() != Ok(name) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                name,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, name)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    let path =
        std::env::temp_dir().join(format!("rax-kvm-discovery-{}-{count}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let kernel = Kernel(path);
    let mut image = vec![0; 0x200];
    image.extend_from_slice(DISCOVERY);
    file.write_all(&image).unwrap();
    drop(file);
    let mut config = VmConfig::from_sources(
        CliConfig {
            arch: Some(ArchKind::X86_64),
            backend: Some(BackendKind::Kvm),
            vcpus: Some(count),
            kernel: Some(kernel.0.clone()),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    config.memory = MemorySize(64 * 1024 * 1024);
    let mut vm = Vmm::new(config).unwrap();
    let mut bios = vec![0; 0x10000];
    vm.guest_mem()
        .memory()
        .read_slice(&mut bios, GuestAddress(0xf0000))
        .unwrap();
    let pointers: Vec<_> = (0..=bios.len() - 16)
        .step_by(16)
        .filter(|offset| &bios[*offset..*offset + 4] == b"_MP_")
        .collect();
    assert_eq!(
        pointers.len(),
        1,
        "cold native Vmm::new did not publish one MP discovery pointer"
    );
    let pointer = &bios[pointers[0]..][..16];
    assert_eq!(&pointer[8..10], &[1, 4]);
    assert_eq!(pointer.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)), 0);
    assert_eq!(
        &pointer[11..],
        &[0; 5],
        "explicit table, virtual wire mode, no IMCR"
    );
    let address = word(pointer, 4) as usize;
    assert!((0xf0000..0x100000).contains(&address));
    let start = address - 0xf0000;
    let header = &bios[start..][..44];
    assert_eq!(&header[..4], b"PCMP");
    assert_eq!(header[6], 4);
    let length = u16::from_le_bytes(header[4..6].try_into().unwrap()) as usize;
    assert!(start + length <= bios.len());
    let table = &bios[start..start + length];
    assert_eq!(table.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)), 0);
    assert_eq!(word(table, 36), 0xfee00000);
    assert_eq!(&table[40..44], &[0; 4]);
    let entries = u16::from_le_bytes(table[34..36].try_into().unwrap());
    let mut cursor = 44;
    let mut cpus = Vec::new();
    let mut buses = Vec::new();
    let mut ioapics = Vec::new();
    let mut io_routes = Vec::new();
    let mut local_routes = Vec::new();
    for _ in 0..entries {
        let kind = table[cursor];
        let size = if kind == 0 { 20 } else { 8 };
        let entry = &table[cursor..cursor + size];
        match kind {
            0 => cpus.push(entry.to_vec()),
            1 => buses.push(entry.to_vec()),
            2 => ioapics.push(entry.to_vec()),
            3 => io_routes.push(entry.to_vec()),
            4 => local_routes.push(entry.to_vec()),
            _ => panic!("unexpected MP entry kind {kind}"),
        }
        cursor += size;
    }
    assert_eq!(cursor, table.len());
    assert_eq!(cpus.len(), usize::from(count));
    assert_eq!(buses, [b"\x01\x00ISA   ".to_vec()]);
    assert_eq!(ioapics.len(), 1);
    assert_eq!(word(&ioapics[0], 4), 0xfec00000);
    assert_eq!(ioapics[0][3], 1);
    let ioapic_id = ioapics[0][1];
    assert_eq!(io_routes.len(), 15);
    for irq in (0..16u8).filter(|irq| *irq != 2) {
        assert!(
            io_routes
                .iter()
                .any(|entry| entry == &[3, 0, 0, 0, 0, irq, ioapic_id, irq])
        );
    }
    assert_eq!(
        local_routes,
        [vec![4, 3, 0, 0, 0, 0, 0, 0], vec![4, 1, 0, 0, 0, 0, 255, 1]]
    );
    vm.run().unwrap();
    let values: [u32; 5] = std::array::from_fn(|i| {
        vm.guest_mem()
            .memory()
            .read_obj(GuestAddress(0x210000 + i as u64 * 4))
            .unwrap()
    });
    println!(
        "native_discovery_cpus={count} guest_signature={:#x} features={:#x} lapic_version={:#x} ioapic_version={:#x} ioapic_id={:#x}",
        values[0], values[1], values[2], values[3], values[4]
    );
    for (id, entry) in cpus.iter().enumerate() {
        assert_eq!(
            &entry[..4],
            &[0, id as u8, values[2] as u8, if id == 0 { 3 } else { 1 }]
        );
        assert_eq!(word(entry, 4), values[0]);
        assert_eq!(word(entry, 8), values[1]);
        assert_eq!(&entry[12..], &[0; 8]);
    }
    assert_eq!(ioapics[0][2], values[3] as u8);
    assert_eq!(ioapics[0][1], (values[4] >> 24) as u8);
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn one_native_cpu_has_firmware_discovery_matching_native_registers() {
    run_discovery(
        1,
        "discovery::one_native_cpu_has_firmware_discovery_matching_native_registers",
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn two_native_cpus_have_firmware_discovery_matching_native_registers() {
    run_discovery(
        2,
        "discovery::two_native_cpus_have_firmware_discovery_matching_native_registers",
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn four_native_cpus_have_firmware_discovery_matching_native_registers() {
    run_discovery(
        4,
        "discovery::four_native_cpus_have_firmware_discovery_matching_native_registers",
    );
}
