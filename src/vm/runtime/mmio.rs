//! Select the originating CPU's LAPIC for a complete public MMIO transaction.
use super::*;
use crate::devices::bus::MmioRmwOp;

fn with_cpu<T>(
    bus: &mut MmioBus,
    apics: &[Arc<std::sync::Mutex<LocalApic>>],
    cpu: usize,
    address: u64,
    size: usize,
    action: impl FnOnce(&mut MmioBus) -> Result<T>,
) -> Result<T> {
    let end = u128::from(address) + size as u128;
    if size == 0 || address >= LAPIC_BASE + LAPIC_SIZE || end <= u128::from(LAPIC_BASE) {
        return action(bus);
    }
    let apic = apics
        .get(cpu)
        .ok_or_else(|| Error::InvalidConfig("MMIO CPU has no local APIC".into()))?;
    bus.with_device_override(
        MmioRange {
            base: LAPIC_BASE,
            len: LAPIC_SIZE,
        },
        Box::new(LapicDevice::new(apic.clone())),
        action,
    )
}
pub(super) fn read(
    bus: &mut MmioBus,
    apics: &[Arc<std::sync::Mutex<LocalApic>>],
    cpu: usize,
    address: u64,
    bytes: &mut [u8],
) -> Result<()> {
    with_cpu(bus, apics, cpu, address, bytes.len(), |bus| {
        bus.read(address, bytes)
    })
}
pub(super) fn write(
    bus: &mut MmioBus,
    apics: &[Arc<std::sync::Mutex<LocalApic>>],
    cpu: usize,
    address: u64,
    bytes: &[u8],
) -> Result<()> {
    with_cpu(bus, apics, cpu, address, bytes.len(), |bus| {
        bus.write(address, bytes)
    })
}
pub(super) fn rmw(
    bus: &mut MmioBus,
    apics: &[Arc<std::sync::Mutex<LocalApic>>],
    cpu: usize,
    address: u64,
    size: u8,
    operation: MmioRmwOp,
) -> Result<Vec<u8>> {
    with_cpu(bus, apics, cpu, address, usize::from(size), |bus| {
        bus.read_modify_write(address, size, operation)
    })
}
