//! Resolve a controller request before applying IRQ/FIQ exception masks.
use super::*;

impl AArch64Cpu {
    /// Preserve the target-owned aggregate wakeup handle. Only the uncommon
    /// pending path locks the controller to resolve its current selected group;
    /// no stale derived IRQ/FIQ classification survives checkpoint restoration.
    pub(super) fn pending_interrupt_kind(&self) -> Result<Option<ExceptionType>, ArmError> {
        if let Some(gic) = &self.gic {
            if self
                .gic_irq_line
                .as_ref()
                .is_some_and(|line| !line.load(std::sync::atomic::Ordering::Acquire))
            {
                return Ok(None);
            }
            let controller = gic.lock().map_err(|_| {
                ArmError::Configuration("GIC lock poisoned while resolving interrupt group".into())
            })?;
            return Ok(match controller.pending_group(self.gic_cpu_id) {
                Some(0) => Some(ExceptionType::Fiq),
                Some(1) => Some(ExceptionType::Irq),
                _ => None,
            });
        }
        Ok(self
            .sysregs
            .cntp_interrupt_pending()
            .then_some(ExceptionType::Irq))
    }

    pub(super) fn interrupt_target_el(&self, kind: ExceptionType) -> u8 {
        let (scr_bit, hcr_bit) = match kind {
            ExceptionType::Fiq => (2, 3),
            ExceptionType::Irq => (1, 4),
            _ => return 1,
        };
        let controls = self.pauth_controls();
        // TGE routes physical requests independently of the effective IMO/FMO
        // values, including E2H=1 (Arm XML2025-12 TakePhysicalIRQ/FIQException).
        let route_el2 = self.sysregs.hcr_el2 & ((1 << 27) | (1 << hcr_bit)) != 0;
        if controls.implemented_els & 8 != 0 && self.sysregs.scr_el3 & (1 << scr_bit) != 0 {
            3
        } else if controls.el2_enabled()
            && (route_el2 || (self.current_el == 2 && self.aarch32.is_some()))
        {
            2
        } else {
            1
        }
    }

    pub(super) fn interrupt_unmasked(&self, kind: ExceptionType) -> bool {
        let mask = match kind {
            ExceptionType::Fiq => 1,
            ExceptionType::Irq => 2,
            _ => return false,
        };
        // DDI0487B.a D1.14.2: PSTATE masks exceptions targeting this EL,
        // including EL0->EL1, but cannot mask an exception to a higher EL2/3.
        let target = self.interrupt_target_el(kind);
        target >= self.current_el
            && ((target > self.current_el && target > 1) || self.daif & mask == 0)
    }

    /// Direct stepping reports an interrupt without entering the guest vector.
    pub(crate) fn check_pending_interrupts(&mut self) -> Result<Option<CpuExit>, ArmError> {
        self.tick_system(0)?;
        Ok(self
            .pending_interrupt_kind()?
            .filter(|kind| self.interrupt_unmasked(*kind))
            .map(|_| CpuExit::InterruptPending))
    }
}
