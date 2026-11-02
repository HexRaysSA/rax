// =============================================================================
// PL192 Vectored Interrupt Controller
// =============================================================================

pub(super) const PL192_INT_SOURCES: usize = 32;
pub(super) const PL192_DAISY_IRQ: u32 = PL192_INT_SOURCES as u32;
pub(super) const PL192_NO_IRQ: u32 = PL192_INT_SOURCES as u32 + 1;
pub(super) const PL192_PRIO_LEVELS: usize = 16;

/// ARM PrimeCell PL192 VIC, as used by the S5L8900 (two instances chained:
/// VIC1's parent output daisy-chains into VIC0, which drives the CPU).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Pl192 {
    pub vect_addr: [u32; PL192_INT_SOURCES],
    pub vect_priority: [u32; PL192_INT_SOURCES],
    pub rawintr: u32,
    pub intselect: u32,
    pub intenable: u32,
    pub softint: u32,
    pub protection: u32,
    pub sw_priority_mask: u32,
    pub daisy_priority: u32,
    pub irq_status: u32,
    pub fiq_status: u32,
    /// Address last latched for the acknowledged interrupt.
    pub address: u32,
    /// Daisy input level from the downstream controller (VIC1 → VIC0).
    pub daisy_input: bool,
    pub daisy_vectaddr: u32,
    pub(super) irq_line: bool,
    pub(super) fiq_line: bool,
    pub(super) current: u32,
    pub(super) current_highest: u32,
    pub(super) priority: u32,
    pub(super) priority_stack: [u32; PL192_PRIO_LEVELS + 1],
    pub(super) irq_stack: [u32; PL192_PRIO_LEVELS + 1],
    pub(super) stack_i: usize,
    pub(super) priority_mode: bool,
}

impl Pl192 {
    pub fn new() -> Self {
        Pl192 {
            vect_addr: [0; PL192_INT_SOURCES],
            vect_priority: [0xf; PL192_INT_SOURCES],
            rawintr: 0,
            intselect: 0,
            intenable: 0,
            softint: 0,
            protection: 0,
            sw_priority_mask: 0xffff,
            daisy_priority: 0xf,
            irq_status: 0,
            fiq_status: 0,
            address: 0,
            daisy_input: false,
            daisy_vectaddr: 0,
            irq_line: false,
            fiq_line: false,
            current: PL192_NO_IRQ,
            current_highest: PL192_NO_IRQ,
            stack_i: 0,
            priority_stack: [0x10; PL192_PRIO_LEVELS + 1],
            irq_stack: [PL192_NO_IRQ; PL192_PRIO_LEVELS + 1],
            priority: 0x10,
            priority_mode: false,
        }
    }

    pub fn set_priority_mode(&mut self, enabled: bool) {
        self.priority_mode = enabled;
    }

    fn priority_for(&self, irq: u32) -> u32 {
        match irq {
            0..=31 => self.vect_priority[irq as usize],
            PL192_DAISY_IRQ => self.daisy_priority,
            _ => 0x10,
        }
    }

    fn highest_pending(&self) -> u32 {
        let mut prio_irq = [PL192_NO_IRQ; PL192_PRIO_LEVELS];
        if self.daisy_input {
            prio_irq[self.daisy_priority as usize] = PL192_DAISY_IRQ;
        }
        for i in (0..PL192_INT_SOURCES).rev() {
            if (self.irq_status & (1 << i)) != 0 {
                prio_irq[self.vect_priority[i] as usize] = i as u32;
            }
        }
        for (priority, irq) in prio_irq.iter().enumerate() {
            if (self.sw_priority_mask & (1 << priority)) != 0 && *irq <= PL192_DAISY_IRQ {
                return *irq;
            }
        }
        PL192_NO_IRQ
    }

    fn mask_current_priority(&mut self) {
        if self.current <= PL192_DAISY_IRQ && self.stack_i + 1 < self.priority_stack.len() {
            self.stack_i += 1;
            self.priority = self.priority_for(self.current);
            self.priority_stack[self.stack_i] = self.priority;
            self.irq_stack[self.stack_i] = self.current;
        }
    }

    fn unmask_current_priority(&mut self) {
        if self.stack_i >= 1 {
            self.stack_i -= 1;
            self.priority = self.priority_stack[self.stack_i];
            self.current = self.irq_stack[self.stack_i];
        }
    }

    pub fn acknowledge(&mut self) -> (u32, bool) {
        let res = self.address;
        if !self.priority_mode {
            return (res, false);
        }
        let is_daisy = self.current_highest == PL192_DAISY_IRQ;
        self.current = self.current_highest;
        self.mask_current_priority();
        self.irq_line = false;
        self.update();
        (res, is_daisy)
    }

    pub fn finish_irq(&mut self) -> bool {
        if !self.priority_mode {
            return false;
        }
        let is_daisy = self.current == PL192_DAISY_IRQ;
        self.unmask_current_priority();
        self.update();
        is_daisy
    }

    /// Mask the downstream controller when its parent acknowledges a daisy IRQ.
    ///
    /// The devos50 PL192 model does not acknowledge the child's highest source
    /// here. It only pushes a child priority frame while leaving `current` at
    /// `PL192_NO_IRQ`; the guest then disables the source and finishes the child
    /// with its own VECTADDR write. Preserve that two-step ordering rather than
    /// turning the daisy acknowledge into a direct child-source acknowledge.
    pub fn acknowledge_daisy_child(&mut self) {
        if !self.priority_mode {
            return;
        }
        if self.stack_i + 1 < self.priority_stack.len() {
            self.stack_i += 1;
            self.priority = PL192_NO_IRQ;
            self.priority_stack[self.stack_i] = self.priority;
            self.irq_stack[self.stack_i] = self.current;
        }
        self.irq_line = false;
        self.update();
    }

    pub fn finish_daisy_child(&mut self) {
        if !self.priority_mode {
            return;
        }
        self.unmask_current_priority();
        self.update();
    }

    /// Recompute IRQ/FIQ status from raw/soft inputs and the masks.
    pub fn update(&mut self) {
        let active = (self.rawintr | self.softint) & self.intenable;
        self.irq_status = active & !self.intselect;
        self.fiq_status = active & self.intselect;
        self.fiq_line = self.fiq_status != 0;
        if self.irq_status != 0 || self.daisy_input {
            self.current_highest = self.highest_pending();
            self.address = match self.current_highest {
                0..=31 => self.vect_addr[self.current_highest as usize],
                PL192_DAISY_IRQ => self.daisy_vectaddr,
                _ => self.address,
            };
            if self.current_highest != self.current {
                if self.current_highest <= PL192_DAISY_IRQ {
                    if self.priority_for(self.current_highest) >= self.priority {
                        return;
                    }
                    self.irq_line = true;
                } else {
                    self.irq_line = false;
                }
            }
        } else {
            self.current_highest = PL192_NO_IRQ;
            self.irq_line = false;
        }
    }

    /// CPU IRQ line level contributed by this controller (excluding daisy).
    pub fn irq_asserted(&self) -> bool {
        if self.priority_mode {
            self.irq_line
        } else {
            self.irq_status != 0 || self.daisy_input
        }
    }

    pub fn fiq_asserted(&self) -> bool {
        self.fiq_line
    }

    pub fn debug_priority_state(&self) -> (u32, u32, u32, usize, bool, bool) {
        (
            self.current,
            self.current_highest,
            self.priority,
            self.stack_i,
            self.irq_line,
            self.fiq_line,
        )
    }

    pub fn set_line(&mut self, irq: u32, level: bool) {
        if irq >= PL192_INT_SOURCES as u32 {
            return;
        }
        if level {
            self.rawintr |= 1 << irq;
        } else {
            self.rawintr &= !(1 << irq);
        }
        self.update();
    }

    pub fn read(&mut self, offset: u32) -> u32 {
        if (0xfe0..0x1000).contains(&offset) {
            let id = [0x92u8, 0x11, 0x04, 0x00, 0x0D, 0xF0, 0x05, 0xB1];
            return id[((offset - 0xfe0) >> 2) as usize] as u32;
        }
        if (0x100..0x180).contains(&offset) {
            return self.vect_addr[((offset - 0x100) >> 2) as usize];
        }
        if (0x200..0x280).contains(&offset) {
            return self.vect_priority[((offset - 0x200) >> 2) as usize];
        }
        match offset {
            0x00 => self.irq_status,
            0x04 => self.fiq_status,
            0x08 => self.rawintr,
            0x0C => self.intselect,
            0x10 => self.intenable,
            0x18 => self.softint,
            0x20 => self.protection,
            0x24 => self.sw_priority_mask,
            0x28 => self.daisy_priority,
            0x14 => 0,                     // INTENCLEAR
            0xF00 => self.acknowledge().0, // VECTADDR (ack)
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        if (0x100..0x180).contains(&offset) {
            self.vect_addr[((offset - 0x100) >> 2) as usize] = value;
            self.update();
            return;
        }
        if (0x200..0x280).contains(&offset) {
            self.vect_priority[((offset - 0x200) >> 2) as usize] = value & 0xf;
            self.update();
            return;
        }
        match offset {
            0x0C => self.intselect = value,
            0x10 => self.intenable |= value,
            0x14 => self.intenable &= !value, // INTENCLEAR
            0x18 => self.softint |= value,
            0x1C => self.softint &= !value, // SOFTINTCLEAR
            0x20 => self.protection = value & 1,
            0x24 => self.sw_priority_mask = value & 0xffff,
            0x28 => self.daisy_priority = value & 0xf,
            0xF00 => {
                self.finish_irq();
                return;
            }
            _ => {}
        }
        self.update();
    }
}

impl Default for Pl192 {
    fn default() -> Self {
        Self::new()
    }
}
