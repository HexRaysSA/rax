// =============================================================================
// LCD controller (register file + framebuffer base)
// =============================================================================

/// S5L8900 LCD controller. Mostly a register file; the window-1 framebuffer
/// base (`0x60`) points at the BGRA framebuffer the display scans out.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct S5lLcd {
    #[serde(
        serialize_with = "crate::devices::checkpoint_serde::serialize_array",
        deserialize_with = "crate::devices::checkpoint_serde::array::<u32, _, 1024>"
    )]
    pub(super) regs: [u32; 0x400],
    /// Periodic vsync/refresh interrupt level (raised by `tick`).
    pub(super) irq: bool,
    pub(super) tick_acc: u64,
}

impl S5lLcd {
    pub fn new() -> Self {
        S5lLcd {
            regs: [0; 0x400],
            irq: false,
            tick_acc: 0,
        }
    }

    /// Advance the refresh timer; raise the vsync IRQ roughly periodically.
    /// Returns true when this call raised a fresh IRQ level.
    pub fn tick(&mut self, n: u64) -> bool {
        if self.irq {
            return false;
        }
        self.tick_acc = self.tick_acc.wrapping_add(n);
        if self.tick_acc >= 200_000 {
            self.tick_acc = 0;
            self.irq = true;
            return true;
        }
        false
    }

    pub fn irq_pending(&self) -> bool {
        self.irq
    }

    pub fn framebuffer_base(&self) -> u32 {
        self.regs[0x60 >> 2]
    }

    pub fn read(&self, offset: u32) -> u32 {
        let idx = (offset >> 2) as usize;
        self.regs.get(idx).copied().unwrap_or(0)
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        let idx = (offset >> 2) as usize;
        if idx < self.regs.len() {
            self.regs[idx] = value;
        }
        // Writing the interrupt-ack register (0x18) lowers the vsync IRQ.
        if offset == 0x18 {
            self.irq = false;
        }
    }
}

impl Default for S5lLcd {
    fn default() -> Self {
        Self::new()
    }
}
