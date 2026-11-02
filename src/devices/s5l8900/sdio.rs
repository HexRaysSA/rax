// =============================================================================
// SDIO controller (minimal register file)
// =============================================================================

/// S5L8900 SDIO register block. The reference machine only needs enough state
/// for the AppleS5L8900XSDIO driver to see command-ready/complete status.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct S5lSdio {
    pub(super) cmd: u32,
    pub(super) arg: u32,
    pub(super) csr: u32,
    pub(super) resp: [u32; 4],
    pub(super) irq_mask: u32,
}

impl S5lSdio {
    pub fn new() -> Self {
        Self {
            cmd: 0,
            arg: 0,
            csr: 0,
            resp: [0; 4],
            irq_mask: 0,
        }
    }

    pub fn read(&self, offset: u32) -> u32 {
        match offset {
            0x08 => self.cmd,
            0x0c => self.arg,
            0x18 => (1 << 0) | (1 << 4), // ready for command, command complete
            0x20 => self.resp[0],
            0x24 => self.resp[1],
            0x28 => self.resp[2],
            0x2c => self.resp[3],
            0x34 => self.csr,
            0x3c => self.irq_mask,
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        match offset {
            0x08 => self.cmd = value,
            0x0c => self.arg = value,
            0x34 => self.csr = value,
            0x3c => self.irq_mask = value,
            _ => {}
        }
    }
}

impl Default for S5lSdio {
    fn default() -> Self {
        Self::new()
    }
}
