//! Local APIC delivery never holds a controller lock across CPU callbacks.
use crate::error::{Error, Result};

use super::Vmm;

// Intel SDM Vol. 3A, local APIC processor-priority register.
const PROCESSOR_PRIORITY_REGISTER: u64 = 0xa0;

impl Vmm {
    pub(super) fn poll_local_apic(&mut self, index: usize) -> Result<()> {
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
            let priority = lapic.read_register(PROCESSOR_PRIORITY_REGISTER) & 0xf0;
            let vector = lapic
                .get_pending_vector()
                .filter(|vector| lapic.is_enabled() && u32::from(*vector & 0xf0) > priority);
            (lapic.has_pending_nmi(), vector)
        };
        let cpu = self
            .vcpus
            .get_mut(index)
            .ok_or_else(|| Error::InvalidConfig("local APIC CPU index out of range".into()))?;
        if nmi && cpu.inject_nmi()? {
            controller
                .lock()
                .map_err(|_| Error::Emulator("local APIC lock poisoned".into()))?
                .clear_pending_nmi();
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
}
