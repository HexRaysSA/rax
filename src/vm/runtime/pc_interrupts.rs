//! Software I/O APIC messages are accepted into the selected local controllers.
//! Lock order is PC I/O APIC -> all LAPICs in CPU order. No native CPU method,
//! guest callback or bus transaction runs while these model locks are held.
use super::*;

#[path = "pc_interrupts/routing.rs"]
mod routing;

#[cfg(test)]
#[path = "pc_interrupts/tests.rs"]
mod tests;

impl Vmm {
    pub(super) fn uses_retired_pc_interrupt_timing(&self) -> bool {
        self.checkpoint_config.arch == ArchKind::X86_64
            && self.timing_context.mode() == crate::vm::timing::ClockMode::Retired
    }

    /// Intel SDM 086 Vol. 3A, Table 7-2 gives NMIs priority over INTR.
    /// Return whether the BSP has already accepted an event at this boundary.
    pub(super) fn poll_bsp_interrupts(&mut self) -> Result<bool> {
        #[cfg(feature = "debug")]
        if !self.debugger_allows_cpu(0) {
            return Ok(false);
        }
        if self.poll_bsp_nmi()? {
            return Ok(true);
        }
        let bsp = self
            .vcpus
            .first_mut()
            .ok_or_else(|| Error::InvalidConfig("no vcpu available".into()))?;
        if bsp.can_inject_interrupt()
            && let Ok(mut pic) = self.pic.lock()
        {
            return pic.try_deliver_pending(|vector| bsp.inject_interrupt(vector));
        }
        Ok(false)
    }

    pub(super) fn service_pc_interrupts(&mut self, index: usize) -> Result<()> {
        // Offer the BSP its existing events before creating a PIT edge so
        // periodic IRQ0 does not starve an older PIC request.
        let mut delivered = index == 0 && self.poll_bsp_interrupts()?;
        if self.service_pc_pit()? && index == 0 && !delivered {
            delivered = self.poll_bsp_interrupts()?;
        }
        self.poll_local_apic(index, delivered)
    }

    pub(super) fn service_pc_pit(&self) -> Result<bool> {
        let pulsed = self.poll_pc_pit()?;
        if pulsed {
            self.route_pc_interrupts()?;
        }
        Ok(pulsed)
    }

    fn software_serial_level(&self) -> Result<Option<(u8, bool)>> {
        if self.checkpoint_config.arch != ArchKind::X86_64 || self.vm.uses_native_x86_irqchip() {
            return Ok(None);
        }
        let Some(irq) = self.serial_irq else {
            return Ok(None);
        };
        if irq >= crate::devices::ioapic::IOAPIC_NUM_RTE as u32 {
            return Err(Error::InvalidConfig(
                "PC serial IRQ exceeds I/O APIC pins".into(),
            ));
        }
        let pending = self
            .serial
            .lock()
            .map_err(|_| Error::Emulator("serial IRQ source lock poisoned".into()))?
            .has_pending_interrupt();
        Ok(Some((irq as u8, pending)))
    }

    /// Stopped device completion may change a UART line before capture. Publish
    /// that source level without consuming any queued controller message/EOI.
    pub(super) fn refresh_pc_irq_sources(&self) -> Result<()> {
        if let (Some(pc), Some((pin, asserted))) = (&self.pc_devices, self.software_serial_level()?)
        {
            pc.ioapic
                .lock()
                .map_err(|_| Error::Emulator("I/O APIC source lock poisoned".into()))?
                .set_irq(pin, asserted);
        }
        Ok(())
    }

    pub(super) fn route_pc_interrupts(&self) -> Result<()> {
        if self.checkpoint_config.arch != ArchKind::X86_64 || self.vm.uses_native_x86_irqchip() {
            return Ok(());
        }
        let Some(pc) = &self.pc_devices else {
            return Ok(());
        };
        let serial = self.software_serial_level()?;
        let mut apics = Vec::new();
        apics
            .try_reserve_exact(self.local_apics.len())
            .map_err(|error| Error::Emulator(format!("I/O APIC route allocation: {error}")))?;
        let mut ioapic = pc
            .ioapic
            .lock()
            .map_err(|_| Error::Emulator("I/O APIC route lock poisoned".into()))?;
        for apic in &self.local_apics {
            apics.push(
                apic.lock()
                    .map_err(|_| Error::Emulator("LAPIC route lock poisoned".into()))?,
            );
        }
        if let Some((pin, asserted)) = serial {
            ioapic.set_irq(pin, asserted);
        }
        routing::route_messages(&mut ioapic, &mut apics)
    }

    /// Publish one timer edge to the existing PIC coalescing path and the PC's
    /// IRQ0->GSI2 override. Return whether a controller received the pulse.
    /// All model locks precede timer/source mutation.
    pub(super) fn poll_pc_pit(&self) -> Result<bool> {
        if self.checkpoint_config.arch != ArchKind::X86_64 {
            return Ok(false);
        }
        #[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
        if self.vm.uses_native_x86_irqchip() {
            let vm = self
                .vm
                .as_any()
                .downcast_ref::<KvmVm>()
                .ok_or_else(|| Error::Emulator("missing native PC PIT route".into()))?;
            let mut pit = self
                .pit
                .lock()
                .map_err(|_| Error::Emulator("PIT route lock poisoned".into()))?;
            if !pit.tick() && !pit.has_pending_interrupt() {
                return Ok(false);
            }
            vm.pulse_pit()?;
            pit.clear_interrupt();
            return Ok(true);
        }
        let mut ioapic = self
            .pc_devices
            .as_ref()
            .map(|pc| {
                pc.ioapic
                    .lock()
                    .map_err(|_| Error::Emulator("I/O APIC PIT route lock poisoned".into()))
            })
            .transpose()?;
        let mut pic = self
            .pic
            .lock()
            .map_err(|_| Error::Emulator("PIC PIT route lock poisoned".into()))?;
        let mut pit = self
            .pit
            .lock()
            .map_err(|_| Error::Emulator("PIT route lock poisoned".into()))?;
        if pit.tick() || pit.has_pending_interrupt() {
            let pic_accepted = !pic.has_active_irq();
            if pic_accepted {
                pic.pulse_irq(0);
            }
            if let Some(ioapic) = &mut ioapic {
                ioapic.set_irq(2, true);
                ioapic.set_irq(2, false);
            }
            if pic_accepted || ioapic.is_some() {
                pit.clear_interrupt();
                return Ok(true);
            }
        }
        Ok(false)
    }
}
