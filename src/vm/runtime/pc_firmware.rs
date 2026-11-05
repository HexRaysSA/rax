//! Cold direct-kernel PC firmware for backends using the software controllers.
use super::*;
use crate::machine::pc::multiprocessor::{self, Profile};
use std::sync::Mutex;
use vm_memory::GuestMemoryMmap;

pub(super) fn publish(
    vm: &dyn Vm,
    memory: &GuestMemoryMmap,
    count: u8,
    devices: Option<&crate::machine::pc::PcDevices>,
    apics: &[Arc<Mutex<LocalApic>>],
) -> Result<()> {
    if vm.uses_native_x86_irqchip() {
        return Ok(());
    }
    let Some((cpu_signature, cpu_features)) = vm.x86_firmware_identity()? else {
        return Ok(());
    };
    let devices =
        devices.ok_or_else(|| Error::InvalidConfig("PC controllers are missing".into()))?;
    if count == 0 || apics.len() != usize::from(count) {
        return Err(Error::InvalidConfig("PC firmware CPU set differs".into()));
    }
    // Construction has not entered any CPU. Read each controller separately;
    // do not hold model locks while querying a backend or publishing RAM.
    let local_apic_version = apics[0]
        .lock()
        .map_err(|_| Error::Emulator("PC firmware local APIC lock poisoned".into()))?
        .read_register(0x30) as u8;
    let (io_apic_id, io_apic_version) = {
        let io = devices
            .ioapic
            .lock()
            .map_err(|_| Error::Emulator("PC firmware I/O APIC lock poisoned".into()))?;
        (io.apic_id(), io.version())
    };
    let profile = Profile {
        cpu_signature,
        cpu_features,
        local_apic_version,
        io_apic_id,
        io_apic_version,
        io_apic_address: crate::devices::ioapic::IOAPIC_BASE as u32,
        isa_irq0_pin: 2,
    };
    multiprocessor::publish(memory, count, &profile)
}
