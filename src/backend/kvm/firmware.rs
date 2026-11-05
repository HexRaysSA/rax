//! Discovery of the native KVM PC CPU/interrupt-controller profile.
use super::KvmVm;
use crate::error::{Error, Result};
use crate::machine::pc::multiprocessor::{self, Profile};
use kvm_bindings::{KVM_IRQCHIP_IOAPIC, kvm_irqchip};
use vm_memory::GuestMemoryMmap;

impl KvmVm {
    /// Publish only for a cold direct-kernel PC boot, before native CPUs exist.
    pub(crate) fn publish_pc_multiprocessor_tables(
        &self,
        memory: &GuestMemoryMmap,
        count: u8,
    ) -> Result<()> {
        let configured = self
            .profile
            .lock()
            .map_err(|_| Error::Emulator("native CPU profile lock poisoned".into()))?
            .count
            .unwrap_or(1);
        if count != configured {
            return Err(Error::InvalidConfig(
                "MP CPU count differs from the immutable native topology".into(),
            ));
        }
        let cpuid = super::cpuid::Topology::new(count)?.project(&self.cpuid, 0)?;
        let identity = cpuid
            .as_slice()
            .iter()
            .find(|entry| entry.function == 1 && entry.index == 0)
            .ok_or_else(|| Error::InvalidConfig("native CPUID leaf1 is missing".into()))?;
        let mut chip = kvm_irqchip {
            chip_id: KVM_IRQCHIP_IOAPIC,
            ..Default::default()
        };
        self.memory.vm_fd.get_irqchip(&mut chip)?;
        // SAFETY: the initialized record requested KVM_IRQCHIP_IOAPIC and the
        // successful synchronous ioctl filled that union member. The copy has
        // no borrowed pointers or native ownership; no CPU exists or runs yet.
        let ioapic = unsafe { chip.chip.ioapic };
        let io_apic_address = u32::try_from(ioapic.base_address).map_err(|_| {
            Error::InvalidConfig("native IOAPIC is outside MP address range".into())
        })?;
        let profile = Profile {
            cpu_signature: identity.eax,
            cpu_features: identity.edx,
            // Linux KVM's integrated LAPIC and 24-pin IOAPIC versions, also
            // compared with native guest MMIO reads by the owning tests.
            local_apic_version: 0x14,
            io_apic_id: (ioapic.id & 15) as u8,
            io_apic_version: 0x11,
            io_apic_address,
            isa_irq0_pin: 0,
        };
        multiprocessor::publish(memory, count, &profile)
    }
}
