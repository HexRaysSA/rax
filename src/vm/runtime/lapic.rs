//! Local APIC delivery never holds a controller lock across CPU callbacks.
use crate::config::{ArchKind, BackendKind};
use crate::error::{Error, Result};

use super::Vmm;

// Intel SDM Vol. 3A, local APIC processor-priority register.
const PROCESSOR_PRIORITY_REGISTER: u64 = 0xa0;

fn inject_local_nmi(
    cpu: &mut dyn crate::vm::vcpu::VCpu,
    controller: &std::sync::Mutex<crate::devices::lapic::LocalApic>,
) -> Result<bool> {
    let delivered = cpu.inject_nmi()?;
    if delivered {
        controller
            .lock()
            .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?
            .clear_pending_nmi();
    }
    Ok(delivered)
}

fn deliverable_vector(lapic: &crate::devices::lapic::LocalApic) -> Option<u8> {
    let priority = lapic.read_register(PROCESSOR_PRIORITY_REGISTER) & 0xf0;
    lapic
        .get_pending_vector()
        .filter(|vector| lapic.is_enabled() && u32::from(*vector & 0xf0) > priority)
}

impl Vmm {
    pub(super) fn poll_local_apic(&mut self, index: usize, delivered: bool) -> Result<()> {
        let controller = self
            .local_apics
            .get(index)
            .ok_or_else(|| Error::InvalidConfig("local APIC CPU index out of range".into()))?
            .clone();
        let (nmi, vector) = {
            let mut lapic = controller
                .lock()
                .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?;
            if lapic.tick().is_some() || lapic.has_pending_timer() {
                let vector = lapic.timer_vector();
                // Transfer the timer latch to IRR before dropping the lock.
                // A blocked CPU leaves the interrupt queued in that same IRR.
                lapic.set_irr(vector);
                lapic.clear_timer_pending();
            }
            (lapic.has_pending_nmi(), deliverable_vector(&lapic))
        };
        if delivered {
            return Ok(());
        }
        let cpu = self
            .vcpus
            .get_mut(index)
            .ok_or_else(|| Error::InvalidConfig("local APIC CPU index out of range".into()))?;
        if nmi && inject_local_nmi(cpu.as_mut(), &controller)? {
            return Ok(());
        }
        if let Some(vector) = vector {
            if cpu.can_inject_interrupt() && cpu.inject_interrupt(vector)? {
                controller
                    .lock()
                    .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?
                    .ack_interrupt(vector);
            }
        }
        Ok(())
    }

    pub(super) fn poll_bsp_nmi(&mut self) -> Result<bool> {
        if self.checkpoint_config.arch != ArchKind::X86_64
            || self.coordinator.online.first() != Some(&true)
        {
            return Ok(false);
        }
        let Some(controller) = self.local_apics.first() else {
            return Ok(false);
        };
        let pending = controller
            .lock()
            .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?
            .has_pending_nmi();
        if pending {
            let bsp = self
                .vcpus
                .first_mut()
                .ok_or_else(|| Error::InvalidConfig("no vcpu available".into()))?;
            return inject_local_nmi(bsp.as_mut(), controller);
        }
        Ok(false)
    }

    /// Observe controller-owned work after its normal injection attempt.
    pub(super) fn intel_hvf_events_waiting(&self, index: usize) -> Result<(bool, bool)> {
        if self.backend_kind != BackendKind::Hvf || self.checkpoint_config.arch != ArchKind::X86_64
        {
            return Ok((false, false));
        }
        let pic_waiting = index == 0
            && self
                .pic
                .lock()
                .map_err(|_| Error::Emulator("PIC lock poisoned".into()))?
                .has_pending();
        let lapic = self
            .local_apics
            .get(index)
            .ok_or_else(|| Error::InvalidConfig("local APIC CPU index out of range".into()))?
            .lock()
            .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?;
        Ok((
            pic_waiting || deliverable_vector(&lapic).is_some(),
            lapic.has_pending_nmi(),
        ))
    }
}
