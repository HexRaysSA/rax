//! Userspace source levels for the managed, default x86 IRQ routing graph.
//!
//! Native PIC/IOAPIC records omit their per-source aggregation bitmaps. Record
//! the successful managed KVM_IRQ_LINE calls under VM exclusion and a single
//! line lock. SDK VM access makes this profile ineligible for checkpointing.
use crate::error::Result;
use kvm_ioctls::VmFd;

pub(super) const PINS: usize = 24;

#[derive(Default)]
pub(super) struct Lines {
    levels: [bool; PINS],
}

impl Lines {
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
