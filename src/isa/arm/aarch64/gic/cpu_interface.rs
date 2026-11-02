//! Group-specific CPU interface operations for the single-Security-state GIC.
use super::{CpuInterface, Gic, INTID_SPURIOUS, InterruptConfig, SPI_START};

impl CpuInterface {
    fn interrupt_group(&self, intid: u32, spis: &[InterruptConfig]) -> Option<u8> {
        let config = if intid < SPI_START {
            self.private_interrupts.get(intid as usize)
        } else {
            spis.get((intid - SPI_START) as usize)
        }?;
        Some(config.group)
    }

    fn highest_pending_in_group(&self, group: u8, spis: &[InterruptConfig]) -> u32 {
        if group <= 1 && self.interrupt_group(self.highest_pending_intid, spis) == Some(group) {
            self.highest_pending_intid
        } else {
            // IHI0069H2.2.1: the highest-priority interrupt belongs to a
            // different register group. Do not search for a lower-priority one.
            INTID_SPURIOUS
        }
    }
}

impl Gic {
    /// Group of the globally selected, preempting request for this PE.
    pub(crate) fn pending_group(&self, cpu_id: usize) -> Option<u8> {
        let cpu = self.cpu_interfaces.get(cpu_id)?;
        if !cpu.pending_interrupt() {
            return None;
        }
        cpu.interrupt_group(cpu.highest_pending_intid, &self.spis)
    }

    /// Read ICC_HPPIR0/1 without consuming a request.
    pub(crate) fn highest_pending_in_group(&mut self, cpu_id: usize, group: u8) -> u32 {
        self.update_all_cpus();
        self.cpu_interfaces
            .get(cpu_id)
            .map(|cpu| cpu.highest_pending_in_group(group, &self.spis))
            .unwrap_or(INTID_SPURIOUS)
    }

    /// Read ICC_IAR0/1. Wrong-bank reads return 1023 without activation.
    pub(crate) fn acknowledge_group(&mut self, cpu_id: usize, group: u8) -> u32 {
        self.update_all_cpus();
        if self.pending_group(cpu_id) != Some(group) {
            return INTID_SPURIOUS;
        }
        self.acknowledge(cpu_id)
    }

    /// Write ICC_EOIR0/1. IHI0069H4.1 restricts priority drop and
    /// deactivation to the register's group, in both EOImode settings.
    pub(crate) fn end_of_interrupt_group(&mut self, cpu_id: usize, intid: u32, group: u8) {
        let Some(cpu) = self.cpu_interfaces.get(cpu_id) else {
            return;
        };
        if group <= 1 && cpu.interrupt_group(intid, &self.spis) == Some(group) {
            self.end_of_interrupt(cpu_id, intid);
        }
    }
}
