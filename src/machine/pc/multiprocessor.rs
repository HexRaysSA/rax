//! Intel MP 1.4 discovery for the existing PC interrupt controllers.
//!
//! Keep these tables in the E820-reserved BIOS window. They describe CPU and
//! interrupt wiring without advertising ACPI power or timer devices.
use crate::error::{Error, Result};
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

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
    bytes[offset] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
}

fn configuration(count: u8, profile: &Profile) -> Result<Vec<u8>> {
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

/// Publish while constructing a cold VM, before any CPU can execute.
pub(crate) fn publish(memory: &GuestMemoryMmap, count: u8, profile: &Profile) -> Result<()> {
    let table = configuration(count, profile)?;
    let extent = 16 + table.len();
    if FLOATING_POINTER + extent as u64 > BIOS_END
        || !memory.check_range(GuestAddress(FLOATING_POINTER), extent)
    {
        return Err(Error::InvalidConfig(
            "MP discovery tables do not fit in reserved BIOS memory".into(),
        ));
    }
    let mut pointer = [0; 16];
    pointer[..4].copy_from_slice(b"_MP_");
    pointer[4..8].copy_from_slice(&(CONFIGURATION_TABLE as u32).to_le_bytes());
    pointer[8] = 1; // Length in 16-byte paragraphs.
    pointer[9] = 4; // MP 1.4; explicit table and virtual wire mode.
    checksum(&mut pointer, 10);
    memory.write_slice(&table, GuestAddress(CONFIGURATION_TABLE))?;
    memory.write_slice(&pointer, GuestAddress(FLOATING_POINTER))?;
    Ok(())
}

#[cfg(test)]
#[path = "multiprocessor_tests.rs"]
mod tests;
