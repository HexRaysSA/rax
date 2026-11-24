//! Group-specific CPU interface operations for the single-Security-state GIC.
use super::{CpuInterface, Gic, INTID_SPURIOUS, InterruptConfig, SPI_START};

impl CpuInterface {
    fn common_binary_point(&self) -> bool {
        self.ctlr_el1 & 1 != 0
    }

    pub(crate) fn binary_point(&self, group: u8) -> u8 {
        let bpr0 = self.bpr0 & 7;
        if group == 0 {
            bpr0
        } else if self.common_binary_point() {
            (bpr0 + 1).min(7)
        } else {
            // Older vCPU records can contain zero from the previous reset.
            (self.bpr1 & 7).max(1)
        }
    }

    pub(super) fn group_priority_mask(&self, group: u8) -> u8 {
        // IHI0069H 4.8.3: the Non-secure Group 1 binary point is offset
        // by one from Group 0 and from the common binary point.
        let subpriority_bits = if group == 0 || self.common_binary_point() {
            (self.bpr0 & 7) + 1
        } else {
            self.binary_point(1)
        };
        (u16::from(u8::MAX) << subpriority_bits) as u8
    }

    pub(super) fn preempting_group(&self) -> Option<u8> {
        let group = self.highest_pending_group?;
        let mask = self.group_priority_mask(group);
        let preempts = self.running_priority == 0xff
            || self.highest_pending_priority & mask < self.running_priority & mask;
        preempts.then_some(group)
    }

    pub(crate) fn running_priority_register(&self) -> u8 {
        // ICC_RPR reports the idle priority or bits [7:1] for an
        // eight-priority-bit interface, including older raw-priority records.
        if self.running_priority == 0xff {
            0xff
        } else {
            self.running_priority & !1
        }
    }

    fn interrupt_group(&self, intid: u32, spis: &[InterruptConfig]) -> Option<u8> {
        let config = if intid < SPI_START {
            self.private_interrupts.get(intid as usize)
        } else {
            spis.get((intid - SPI_START) as usize)
        }?;
        Some(config.group)
    }

    fn highest_pending_in_group(&self, group: u8) -> u32 {
        if self.highest_pending_group == Some(group) {
            self.highest_pending_intid
        } else {
            // IHI0069H2.2.1: the highest-priority interrupt belongs to a
            // different register group. Do not search for a lower-priority one.
            INTID_SPURIOUS
        }
    }
}

impl Gic {
    pub(crate) fn set_binary_point(&mut self, cpu_id: usize, group: u8, value: u64) {
        if let Some(cpu) = self.cpu_mut(cpu_id) {
            let value = (value & 7) as u8;
            if group == 0 {
                cpu.bpr0 = value;
            } else if !cpu.common_binary_point() {
                cpu.bpr1 = value.max(1);
            }
            self.update_all_cpus();
        }
    }

    pub(crate) fn set_cpu_control(&mut self, cpu_id: usize, value: u64) {
        if let Some(cpu) = self.cpu_mut(cpu_id) {
            cpu.eoi_mode = value & 2 != 0;
            cpu.ctlr_el1 = value;
            self.update_all_cpus();
        }
    }

    /// Group of the globally selected, preempting request for this PE.
    pub(crate) fn pending_group(&self, cpu_id: usize) -> Option<u8> {
        self.cpu_interfaces.get(cpu_id)?.preempting_group()
    }

    /// Read ICC_HPPIR0/1 without consuming a request.
    pub(crate) fn highest_pending_in_group(&mut self, cpu_id: usize, group: u8) -> u32 {
        self.update_all_cpus();
        self.cpu_interfaces
            .get(cpu_id)
            .map(|cpu| cpu.highest_pending_in_group(group))
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
