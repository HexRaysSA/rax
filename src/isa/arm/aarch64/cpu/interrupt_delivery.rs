//! Resolve per-PE physical and virtual interrupts before applying PSTATE masks.
use super::*;
use crate::isa::arm::aarch64::hcr;

pub(super) enum InterruptDelivery {
    IrqOrFiq { target: u8, kind: ExceptionType },
    VirtualSError,
}

impl InterruptDelivery {
    pub(super) fn enter(self, cpu: &mut AArch64Cpu) -> Result<(), ArmError> {
        match self {
            Self::IrqOrFiq { target, kind } => {
                cpu.take_exception(target, kind, SyndromeRegister::new())
            }
            Self::VirtualSError => {
                // The classic software PE reports an all-zero ISS for virtual SError.
                let syndrome = SyndromeRegister::serror(0, false, 0);
                cpu.take_exception(1, ExceptionType::SError, syndrome)?;
                cpu.sysregs.hcr_el2 &= !hcr::VSE;
                Ok(())
            }
        }
    }
}

pub(super) struct PendingInterrupts {
    physical: Option<ExceptionType>,
    virtual_irq: bool,
    virtual_fiq: bool,
    virtual_serror: bool,
}

impl PendingInterrupts {
    pub(super) fn any(&self) -> bool {
        self.physical.is_some() || self.virtual_irq || self.virtual_fiq || self.virtual_serror
    }

    pub(super) fn deliverable(&self, cpu: &AArch64Cpu) -> Option<InterruptDelivery> {
        if let Some(kind) = self.physical.filter(|kind| cpu.interrupt_unmasked(*kind)) {
            return Some(InterruptDelivery::IrqOrFiq {
                target: cpu.interrupt_target_el(kind),
                kind,
            });
        }
        // Use the same virtual priority as the classic software PE oracle.
        if self.virtual_irq && cpu.daif & 2 == 0 {
            Some(InterruptDelivery::IrqOrFiq {
                target: 1,
                kind: ExceptionType::Irq,
            })
        } else if self.virtual_fiq && cpu.daif & 1 == 0 {
            Some(InterruptDelivery::IrqOrFiq {
                target: 1,
                kind: ExceptionType::Fiq,
            })
        } else if self.virtual_serror && cpu.daif & 4 == 0 {
            Some(InterruptDelivery::VirtualSError)
        } else {
            None
        }
    }
}

impl AArch64Cpu {
    pub(super) fn pending_interrupts(
        &self,
        include_virtual: bool,
    ) -> Result<PendingInterrupts, ArmError> {
        let hcr = self.sysregs.hcr_el2;
        const IRQ: u64 = hcr::VI | hcr::IMO;
        const FIQ: u64 = hcr::VF | hcr::FMO;
        const SERROR: u64 = hcr::VSE | hcr::AMO;
        let irq = hcr & IRQ == IRQ;
        let fiq = hcr & FIQ == FIQ;
        let serror = hcr & SERROR == SERROR;
        let virtual_enabled = include_virtual
            && (irq || fiq || serror)
            && self.current_el < 2
            && hcr & hcr::TGE == 0
            && self.pauth_controls().el2_enabled();
        Ok(PendingInterrupts {
            physical: self.pending_physical_interrupt()?,
            virtual_irq: virtual_enabled && irq,
            virtual_fiq: virtual_enabled && fiq,
            virtual_serror: virtual_enabled && serror,
        })
    }

    /// Preserve the target-owned aggregate wakeup handle. Only the uncommon
    /// pending path locks the controller to resolve its current selected group;
    /// no stale derived IRQ/FIQ classification survives checkpoint restoration.
    fn pending_physical_interrupt(&self) -> Result<Option<ExceptionType>, ArmError> {
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
    pub(super) fn check_pending_interrupts(
        &mut self,
        include_virtual: bool,
    ) -> Result<Option<CpuExit>, ArmError> {
        self.tick_system(0)?;
        Ok(self
            .pending_interrupts(include_virtual)?
            .deliverable(self)
            .map(|_| CpuExit::InterruptPending))
    }
}
