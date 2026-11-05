//! I/O APIC policy uses an outer tag while retaining historical positional bytes.
use super::*;
use crate::devices::bus::MmioDevice;
use crate::devices::ioapic::{IOAPIC_BASE, IoApic};
use std::sync::Mutex;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

fn cpu() -> X86_64Vcpu {
    let memory = Arc::new(
        GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), 65536),
            (GuestAddress(IOAPIC_BASE), 4096),
        ])
        .unwrap(),
    );
    memory
        .write_slice(
            &0x1234_5678u32.to_le_bytes(),
            GuestAddress(IOAPIC_BASE + 16),
        )
        .unwrap();
    X86_64Vcpu::new(0, memory)
}

fn select_version(cpu: &mut X86_64Vcpu) -> u32 {
    cpu.mmu
        .write_phys(IOAPIC_BASE, &1u32.to_le_bytes())
        .unwrap();
    let mut bytes = [0; 4];
    cpu.mmu.read_phys(IOAPIC_BASE + 16, &mut bytes).unwrap();
    u32::from_le_bytes(bytes)
}

#[test]
fn new_policy_appends_only_its_tag_and_requires_a_target_controller() {
    let mut source = cpu();
    let historical = source.save_context().unwrap();
    source.attach_ioapic(Arc::new(Mutex::new(IoApic::new())));
    let current = source.save_context().unwrap();
    assert!(historical.starts_with(TAG));
    assert!(current.starts_with(IOAPIC_TAG));
    assert_eq!(&historical[8..], &current[8..]);
    let mut target = cpu();
    let before = target.save_context().unwrap();
    assert!(target.restore_context(&current).is_err());
    assert_eq!(target.save_context().unwrap(), before);
    target.attach_ioapic(Arc::new(Mutex::new(IoApic::new())));
    target.restore_context(&current).unwrap();
    assert_eq!(select_version(&mut target), 0x0017_0020);
    assert!(target.save_context().unwrap().starts_with(IOAPIC_TAG));
}

#[test]
fn historical_records_retain_ram_policy_and_recapture_the_historical_tag() {
    let source = cpu();
    let historical = source.save_context().unwrap();
    let mut target = cpu();
    target.attach_ioapic(Arc::new(Mutex::new(IoApic::new())));
    assert_eq!(select_version(&mut target), 0x0017_0020);
    target.restore_context(&historical).unwrap();
    assert_eq!(select_version(&mut target), 0x1234_5678);
    assert!(target.save_context().unwrap().starts_with(TAG));
}

#[test]
fn cpu_restore_keeps_the_target_ioapic_identity_and_its_owned_state() {
    let mut source = cpu();
    source.attach_ioapic(Arc::new(Mutex::new(IoApic::new())));
    let raw = source.save_context().unwrap();
    let device = Arc::new(Mutex::new(IoApic::new()));
    device
        .lock()
        .unwrap()
        .write(IOAPIC_BASE, &0u32.to_le_bytes());
    device
        .lock()
        .unwrap()
        .write(IOAPIC_BASE + 16, &0x0f00_0000u32.to_le_bytes());
    let mut target = cpu();
    target.attach_ioapic(device.clone());
    target.restore_context(&raw).unwrap();
    target
        .mmu
        .write_phys(IOAPIC_BASE, &0u32.to_le_bytes())
        .unwrap();
    let mut value = [0; 4];
    target.mmu.read_phys(IOAPIC_BASE + 16, &mut value).unwrap();
    assert_eq!(u32::from_le_bytes(value), 0x0f00_0000);
    assert_eq!(device.lock().unwrap().apic_id(), 15);
}
