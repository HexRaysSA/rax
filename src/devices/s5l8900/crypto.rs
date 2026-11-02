/// S5L8900 NAND ECC engine. Always reports success; raises an IRQ on START.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct S5lNandEcc {
    pub(super) irq: bool,
}

impl S5lNandEcc {
    pub fn new() -> Self {
        S5lNandEcc { irq: false }
    }

    pub fn irq_pending(&self) -> bool {
        self.irq
    }

    pub fn read(&self, offset: u32) -> u32 {
        match offset {
            0x10 => 0, // STATUS: success
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u32, _val: u32) {
        match offset {
            0xC => self.irq = true,   // START
            0x40 => self.irq = false, // CLEARINT
            _ => {}
        }
    }
}

impl Default for S5lNandEcc {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// S5L8900 AES crypto engine (MMIO @ 0x38C00000)
// =============================================================================

/// Which hardware key the AES engine decrypts with.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AesKeyType {
    /// Caller-supplied key written to the key registers.
    Custom,
    /// Per-device-class GID key (used for LLB/iBoot/kernelcache images).
    Gid,
    /// Per-device UID key.
    Uid,
}

/// The S5L8900 on-die AES block. iBoot programs the source/destination
/// addresses, the input size, the key selector, the key (for Custom) and the
/// IV through MMIO registers, then writes `AES_GO` to perform an in-memory
/// AES-CBC decrypt. The DMA (reading `inaddr` / writing `outaddr` in guest
/// physical memory) is performed by the vCPU step, which holds memory access;
/// this struct only holds the programmed register state. Register layout and
/// the placeholder UID key match the QEMU `s5l8900` reference port.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct S5lAes {
    pub inaddr: u32,
    pub outaddr: u32,
    pub insize: u32,
    pub outsize: u32,
    pub keytype: AesKeyType,
    pub keylen: u32,
    /// 0 = decrypt, 1 = encrypt (set on the second AES_KEYLEN write).
    pub operation: u32,
    pub custkey: [u8; 32],
    pub ivec: [u8; 16],
    pub status: u32,
    /// Set when AES_GO is written; consumed by the vCPU step.
    pub pending_go: bool,
    pub(super) keylen_writes: u8,
}

// Register offsets (QEMU s5l8900 reference).
pub(super) const AES_GO: u32 = 0x4;
pub(super) const AES_STATUS: u32 = 0xC;
pub(super) const AES_KEYLEN: u32 = 0x14;
pub(super) const AES_INSIZE: u32 = 0x18;
pub(super) const AES_INADDR: u32 = 0x20;
pub(super) const AES_OUTSIZE: u32 = 0x24;
pub(super) const AES_OUTADDR: u32 = 0x28;
pub(super) const AES_KEY_REG: u32 = 0x4C;
pub(super) const AES_KEYSIZE: u32 = 0x20;
pub(super) const AES_TYPE: u32 = 0x6C;
pub(super) const AES_IV_REG: u32 = 0x74;
pub(super) const AES_IVSIZE: u32 = 0x10;

/// QEMU placeholder UID key. Real per-device UID keys are not recoverable; a
/// real GID key may be supplied via `RAX_S5L_GID_KEY` for the engine.
pub const AES_UID_KEY: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
];

impl S5lAes {
    pub fn new() -> Self {
        S5lAes {
            inaddr: 0,
            outaddr: 0,
            insize: 0,
            outsize: 0,
            keytype: AesKeyType::Custom,
            keylen: 0,
            operation: 0,
            custkey: [0; 32],
            ivec: [0; 16],
            status: 0,
            pending_go: false,
            keylen_writes: 0,
        }
    }

    pub fn read(&self, offset: u32) -> u32 {
        match offset {
            AES_STATUS => self.status,
            AES_OUTSIZE => self.outsize,
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        match offset {
            AES_GO => self.pending_go = true,
            AES_KEYLEN => {
                if self.keylen_writes == 1 {
                    self.operation = value;
                }
                self.keylen_writes = self.keylen_writes.wrapping_add(1);
                self.keylen = value;
            }
            AES_INADDR => self.inaddr = value,
            AES_INSIZE => self.insize = value,
            AES_OUTSIZE => self.outsize = value,
            AES_OUTADDR => self.outaddr = value,
            AES_TYPE => {
                self.keytype = match value {
                    1 => AesKeyType::Gid,
                    2 => AesKeyType::Uid,
                    _ => AesKeyType::Custom,
                };
            }
            o if (AES_KEY_REG..AES_KEY_REG + AES_KEYSIZE).contains(&o) => {
                let idx = ((o - AES_KEY_REG) / 4) as usize * 4;
                let b = value.to_le_bytes();
                for (i, bi) in b.iter().enumerate() {
                    self.custkey[idx + i] |= bi;
                }
            }
            o if (AES_IV_REG..AES_IV_REG + AES_IVSIZE).contains(&o) => {
                let idx = ((o - AES_IV_REG) / 4) as usize * 4;
                let b = value.to_le_bytes();
                for (i, bi) in b.iter().enumerate() {
                    self.ivec[idx + i] |= bi;
                }
            }
            _ => {}
        }
    }

    /// Clear the volatile key/IV state after a GO (matches the hardware, which
    /// wipes the key registers each operation).
    pub fn finish(&mut self) {
        self.custkey = [0; 32];
        self.ivec = [0; 16];
        self.keylen_writes = 0;
        self.status = 0xf;
    }
}

impl Default for S5lAes {
    fn default() -> Self {
        Self::new()
    }
}
