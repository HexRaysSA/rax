//! Userspace source levels for the managed, default x86 IRQ routing graph.
//!
//! Native PIC/IOAPIC records omit their per-source aggregation bitmaps. Record
//! the successful managed KVM_IRQ_LINE calls under VM exclusion and a single
//! line lock. SDK VM access makes this profile ineligible for checkpointing.
use super::{KvmVm, Vm};
use crate::error::{Error, Result};
use kvm_ioctls::VmFd;
use std::sync::atomic::Ordering;

pub(super) const PINS: usize = 24;

const PIT_GSI: u32 = 0;
const LAPIC_LVT_LINT0: usize = 0x350;
const LVT_MASKED: u32 = 1 << 16;
const LVT_DELIVERY_MODE: u32 = 7 << 8;
const LVT_NMI: u32 = 4 << 8;
pub(super) const APIC_BASE_ENABLE: u64 = 1 << 11;

#[derive(Default)]
pub(super) struct Lines {
    levels: [bool; PINS],
}

impl KvmVm {
    /// Deliver the managed PIT edge through the same default PIC/IOAPIC
    /// route as KVM's PIT, and service the per-CPU virtual-wire NMI inputs.
    /// The caller owns the PIT lock. Exclusion freezes the programmed LVTs
    /// and keeps a native CPU from observing a partially published edge.
    pub(crate) fn pulse_pit(&self) -> Result<()> {
        let _stopped = self.checkpoint_boundary()?;
        let handles = self
            .memory
            .managed_cpus
            .lock()
            .map_err(|_| Error::Emulator("native CPU membership lock poisoned".into()))?
            .values()
            .map(|cpu| {
                cpu.upgrade()
                    .ok_or_else(|| Error::Emulator("native PIT lost its CPU owner".into()))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut watchdog = Vec::new();
        for handle in &handles {
            let core = handle
                .lock()
                .map_err(|_| Error::Emulator("native PIT CPU owner lock poisoned".into()))?;
            let lapic = core.vcpu_fd.get_lapic()?;
            let lint0 = u32::from_le_bytes(std::array::from_fn(|byte| {
                lapic.regs[LAPIC_LVT_LINT0 + byte] as u8
            }));
            if lint0 & (LVT_MASKED | LVT_DELIVERY_MODE) == LVT_NMI
                && core.vcpu_fd.get_sregs()?.apic_base & APIC_BASE_ENABLE != 0
            {
                watchdog.push(core);
            }
        }
        let lines = self
            .memory
            .irq_lines
            .lock()
            .map_err(|_| Error::Emulator("native IRQ line ownership lock poisoned".into()))?;
        let publish = || -> Result<()> {
            // An independently asserted IRQ0 already holds the physical line
            // high. Pulsing another source must preserve that assertion.
            if !lines.levels[PIT_GSI as usize] {
                self.memory.vm_fd.set_irq_line(PIT_GSI, true)?;
                self.memory.vm_fd.set_irq_line(PIT_GSI, false)?;
            }
            for core in watchdog {
                core.vcpu_fd.nmi()?;
            }
            Ok(())
        };
        if let Err(error) = publish() {
            // The IRQ controller or a prefix of NMI targets may already have
            // accepted the edge. Repeating it would duplicate delivery.
            self.memory.poisoned.store(true, Ordering::Release);
            return Err(error);
        }
        Ok(())
    }
}

impl Lines {
    pub(super) fn level(&self, gsi: u32) -> Option<bool> {
        self.levels.get(gsi as usize).copied()
    }

    pub(super) fn record(&mut self, gsi: u32, level: bool) {
        // CREATE_IRQCHIP installs only GSIs 0..24. Unrouted IRQ_LINE calls
        // have no controller effect; retain their existing SDK return value.
        if let Some(saved) = self.levels.get_mut(gsi as usize) {
            *saved = level;
        }
    }

    pub(super) fn levels(&self) -> [bool; PINS] {
        self.levels
    }

    /// Restore this userspace source before installing controller/CPU banks.
    /// Replaying can inject transient edges; the enclosing stopped transaction
    /// must replace the affected banks before allowing entry.
    pub(super) fn restore(&mut self, vm: &VmFd, levels: &[bool; PINS]) -> Result<()> {
        for (gsi, level) in levels.iter().copied().enumerate() {
            vm.set_irq_line(gsi as u32, level)?;
            // Preserve the successfully installed prefix if a later ioctl
            // fails, so an enclosing rollback has accurate source ownership.
            self.levels[gsi] = level;
        }
        Ok(())
    }
}
