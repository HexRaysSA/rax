#[derive(Debug)]
enum Error {
    InvalidConfig(String),
}
type Result<T> = std::result::Result<T, Error>;
mod old {
    use super::{Error, Result};
    const FLOATING_POINTER: u64 = 0x000f_0000;
    const CONFIGURATION_TABLE: u64 = FLOATING_POINTER + 16;
    const BIOS_END: u64 = 0x0010_0000;

    pub(crate) struct Profile {
        pub cpu_signature: u32,
        pub cpu_features: u32,
        pub local_apic_version: u8,
        pub io_apic_id: u8,
        pub io_apic_version: u8,
        pub io_apic_address: u32,
    }

    fn checksum(bytes: &mut [u8], offset: usize) {
        bytes[offset] = 0;
        bytes[offset] =
            0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
    }

    pub fn configuration(count: u8, profile: &Profile) -> Result<Vec<u8>> {
        if count == 0 {
            return Err(Error::InvalidConfig(
                "MP discovery requires at least one CPU".into(),
            ));
        }
        // MP 1.4 sections4.2/4.3: 44-byte header, 20-byte CPU records, then
        // ISA bus, I/O APIC, fifteen I/O and two local interrupt records (8 each).
        let length = 44 + 20 * usize::from(count) + 19 * 8;
        let mut table = Vec::with_capacity(length);
        table.extend_from_slice(b"PCMP");
        table.extend_from_slice(&(length as u16).to_le_bytes());
        table.extend_from_slice(&[4, 0]);
        table.extend_from_slice(b"RAXVMM  ");
        table.extend_from_slice(b"RAX PC      ");
        table.extend_from_slice(&[0; 6]); // No OEM extension.
        table.extend_from_slice(&(u16::from(count) + 19).to_le_bytes());
        table.extend_from_slice(&0xfee0_0000u32.to_le_bytes());
        table.extend_from_slice(&[0; 4]); // No extended configuration records.

        for id in 0..count {
            table.extend_from_slice(&[
                0,
                id,
                profile.local_apic_version,
                if id == 0 { 3 } else { 1 }, // Enabled; CPU0 is the BSP.
            ]);
            table.extend_from_slice(&profile.cpu_signature.to_le_bytes());
            table.extend_from_slice(&profile.cpu_features.to_le_bytes());
            table.extend_from_slice(&[0; 8]);
        }
        table.extend_from_slice(&[1, 0]);
        table.extend_from_slice(b"ISA   ");
        table.extend_from_slice(&[2, profile.io_apic_id, profile.io_apic_version, 1]);
        table.extend_from_slice(&profile.io_apic_address.to_le_bytes());

        // KVM's default routes connect each GSI to the same-numbered IOAPIC
        // input. In particular IRQ0 uses input0, unlike a QEMU PC's remapped
        // input2. IRQ2 is the PIC cascade rather than an independent ISA device.
        for irq in 0..16u8 {
            if irq == 2 {
                continue;
            }
            table.extend_from_slice(&[3, 0, 0, 0, 0, irq, profile.io_apic_id, irq]);
        }
        // Virtual wire mode: PIC ExtINT reaches BSP LINT0; NMI reaches LINT1
        // on every processor. No IMCR or ACPI controller is advertised.
        table.extend_from_slice(&[4, 3, 0, 0, 0, 0, 0, 0]);
        table.extend_from_slice(&[4, 1, 0, 0, 0, 0, 255, 1]);
        debug_assert_eq!(table.len(), length);
        checksum(&mut table, 7);
        Ok(table)
    }
}
mod new {
    use super::{Error, Result};
    const FLOATING_POINTER: u64 = 0x000f_0000;
    const CONFIGURATION_TABLE: u64 = FLOATING_POINTER + 16;
    const BIOS_END: u64 = 0x0010_0000;

    pub(crate) struct Profile {
        pub cpu_signature: u32,
        pub cpu_features: u32,
        pub local_apic_version: u8,
        pub io_apic_id: u8,
        pub io_apic_version: u8,
        pub io_apic_address: u32,
        pub isa_irq0_pin: u8,
    }

    fn checksum(bytes: &mut [u8], offset: usize) {
        bytes[offset] = 0;
        bytes[offset] =
            0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
    }

    pub fn configuration(count: u8, profile: &Profile) -> Result<Vec<u8>> {
        if count == 0 {
            return Err(Error::InvalidConfig(
                "MP discovery requires at least one CPU".into(),
            ));
        }
        if !matches!(profile.isa_irq0_pin, 0 | 2) {
            return Err(Error::InvalidConfig(
                "unsupported PC PIT input for MP discovery".into(),
            ));
        }
        // MP 1.4 sections4.2/4.3: 44-byte header, 20-byte CPU records, then
        // ISA bus, I/O APIC, fifteen I/O and two local interrupt records (8 each).
        let length = 44 + 20 * usize::from(count) + 19 * 8;
        let mut table = Vec::with_capacity(length);
        table.extend_from_slice(b"PCMP");
        table.extend_from_slice(&(length as u16).to_le_bytes());
        table.extend_from_slice(&[4, 0]);
        table.extend_from_slice(b"RAXVMM  ");
        table.extend_from_slice(b"RAX PC      ");
        table.extend_from_slice(&[0; 6]); // No OEM extension.
        table.extend_from_slice(&(u16::from(count) + 19).to_le_bytes());
        table.extend_from_slice(&0xfee0_0000u32.to_le_bytes());
        table.extend_from_slice(&[0; 4]); // No extended configuration records.

        for id in 0..count {
            table.extend_from_slice(&[
                0,
                id,
                profile.local_apic_version,
                if id == 0 { 3 } else { 1 }, // Enabled; CPU0 is the BSP.
            ]);
            table.extend_from_slice(&profile.cpu_signature.to_le_bytes());
            table.extend_from_slice(&profile.cpu_features.to_le_bytes());
            table.extend_from_slice(&[0; 8]);
        }
        table.extend_from_slice(&[1, 0]);
        table.extend_from_slice(b"ISA   ");
        table.extend_from_slice(&[2, profile.io_apic_id, profile.io_apic_version, 1]);
        table.extend_from_slice(&profile.io_apic_address.to_le_bytes());

        // KVM's default PIT route uses input0; the software/HVF PC uses input2.
        // IRQ2 is the PIC cascade rather than an independent ISA device.
        for irq in 0..16u8 {
            if irq == 2 {
                continue;
            }
            let pin = if irq == 0 { profile.isa_irq0_pin } else { irq };
            table.extend_from_slice(&[3, 0, 0, 0, 0, irq, profile.io_apic_id, pin]);
        }
        // Virtual wire mode: PIC ExtINT reaches BSP LINT0; NMI reaches LINT1
        // on every processor. No IMCR or ACPI controller is advertised.
        table.extend_from_slice(&[4, 3, 0, 0, 0, 0, 0, 0]);
        table.extend_from_slice(&[4, 1, 0, 0, 0, 0, 255, 1]);
        debug_assert_eq!(table.len(), length);
        checksum(&mut table, 7);
        Ok(table)
    }
}

fn main() {
    for count in 1..=255 {
        let old = old::Profile {
            cpu_signature: 0x306c3,
            cpu_features: 0xbfebfbff,
            local_apic_version: 0x14,
            io_apic_id: 0,
            io_apic_version: 0x11,
            io_apic_address: 0xfec00000,
        };
        let mut new = new::Profile {
            cpu_signature: old.cpu_signature,
            cpu_features: old.cpu_features,
            local_apic_version: old.local_apic_version,
            io_apic_id: old.io_apic_id,
            io_apic_version: old.io_apic_version,
            io_apic_address: old.io_apic_address,
            isa_irq0_pin: 0,
        };
        let original = old::configuration(count, &old).unwrap();
        let current = new::configuration(count, &new).unwrap();
        assert_eq!(original, current, "KVM byte preservation for {count} CPUs");
        new.isa_irq0_pin = 2;
        let software = new::configuration(count, &new).unwrap();
        let offset = 44 + usize::from(count) * 20 + 16 + 7;
        let diffs: Vec<_> = current
            .iter()
            .zip(&software)
            .enumerate()
            .filter_map(|(index, (a, b))| (a != b).then_some(index))
            .collect();
        assert_eq!(diffs, [7, offset]);
        assert_eq!(software[offset], 2);
        assert_eq!(software.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)), 0);
    }
    println!(
        "{{\"native_pin_zero_identical_tables\":255,\"software_pin_two_exact_delta_tables\":255}}"
    );
}
