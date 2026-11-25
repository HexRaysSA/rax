//! The Private Peripheral Bus as memory.
//!
//! When an embedder maps it ([`CortexMCpu::map_private_peripheral_bus`]),
//! loads and stores in `0xE000_0000..0xE010_0000` reach the core's NVIC,
//! SCB and SysTick models and the registers below instead of guest memory,
//! as firmware expects. Unmapped (the default), those addresses are ordinary
//! guest memory and the System Control Space is reached through the vCPU
//! state.
//!
//! | Address | Registers |
//! |---------|-----------|
//! | `0xE000_1000`, `0xE000_1004` | DWT_CTRL (4 comparators), DWT_CYCCNT: the cycle count while DEMCR.TRCENA and DWT_CTRL.CYCCNTENA are set |
//! | `0xE000_E004`, `0xE000_E008` | ICTR (read-only), ACTLR (stored) |
//! | `0xE000_E010..0xE000_E01F` | SysTick |
//! | `0xE000_E100..0xE000_E4EF` | NVIC ISER to IPR |
//! | `0xE000_ED00..0xE000_ED3F` | SCB, SHPR1-3 through the NVIC model |
//! | `0xE000_ED78..0xE000_ED8B` | CLIDR, CTR, CCSIDR (those of [`CortexMCpu::set_cache_identification`], none by default), CSSELR, CPACR |
//! | `0xE000_ED90..0xE000_EDBB` | MPU_TYPE (16 regions), CTRL, RNR, RBAR, RASR and their aliases: stored, not enforced |
//! | `0xE000_EDF0..0xE000_EDFF` | DHCSR (no debugger: 0), DEMCR (stored) |
//! | `0xE000_EF00` | STIR |
//! | `0xE000_EF34..0xE000_EF4B` | FPCCR, FPCAR, FPDSCR, MVFR0-2 |
//! | `0xE000_EF50..0xE000_EF7F` | cache maintenance: no effect, no cache is modelled |
//!
//! Every other address in the range reads as zero and ignores writes.
//!
//! Byte and halfword accesses: IPR and SHPR bytes are read-modify-write; a
//! narrow store to any other register writes the bytes it covers with zeros
//! elsewhere, which leaves the write-one-to-set and write-one-to-clear
//! registers' other bits unchanged.

use super::cpu::CortexMCpu;

/// The Private Peripheral Bus routed here.
pub const PPB_BASE: u32 = 0xE000_0000;
pub const PPB_END: u32 = 0xE010_0000;

/// MPU regions of the ARMv7-M MPU modelled (MPU_TYPE.DREGION).
const MPU_REGIONS: usize = 16;

/// FPCCR.ASPEN: an FP instruction sets CONTROL.FPCA.
pub(super) const FPCCR_ASPEN: u32 = 1 << 31;
/// FPCCR.LSPEN: lazy state preservation (reported, the state is stacked
/// eagerly).
const FPCCR_LSPEN: u32 = 1 << 30;
/// FPCCR bits a write changes (ASPEN, LSPEN; the status bits read back).
const FPCCR_WRITABLE: u32 = FPCCR_ASPEN | FPCCR_LSPEN | 0x0000_01FB;
/// FPDSCR: AHP, DN, FZ and RMode, the FPSCR of a new FP context.
pub(super) const FPDSCR_MASK: u32 = 0x07C0_0000;

/// DEMCR.TRCENA: the DWT and ITM are enabled.
const DEMCR_TRCENA: u32 = 1 << 24;
/// DWT_CTRL.CYCCNTENA.
const DWT_CYCCNTENA: u32 = 1;
/// DWT_CTRL.NUMCOMP: 4 comparators.
const DWT_NUMCOMP: u32 = 4 << 28;

/// The cache identification registers of a Cortex-M7, whose instruction
/// and data caches (0 to 64 KB each) the chip chooses. All zero: no cache.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheIdentification {
    pub clidr: u32,
    pub ctr: u32,
    /// CCSIDR with CSSELR.InD clear, and set.
    pub ccsidr_data: u32,
    pub ccsidr_instruction: u32,
}

/// MVFR0-2 of the Cortex-M7 double-precision FPU (FPv5-D16).
pub(super) const M7_MVFR: [u32; 3] = [0x1011_0221, 0x1200_0011, 0x0000_0040];

/// The registers of the Private Peripheral Bus outside the NVIC, SCB and
/// SysTick models.
#[derive(Clone, Debug)]
pub struct Ppb {
    caches: CacheIdentification,
    actlr: u32,
    csselr: u32,
    pub(super) cpacr: u32,
    mpu_ctrl: u32,
    mpu_rnr: u32,
    mpu_rbar: [u32; MPU_REGIONS],
    mpu_rasr: [u32; MPU_REGIONS],
    demcr: u32,
    dwt_ctrl: u32,
    /// DWT_CYCCNT at `cyccnt_since`, the cycle count of the last change of
    /// the counter or of its enables.
    cyccnt: u32,
    cyccnt_since: u64,
    pub(super) fpccr: u32,
    pub(super) fpcar: u32,
    pub(super) fpdscr: u32,
}

impl Default for Ppb {
    fn default() -> Self {
        Self {
            caches: CacheIdentification::default(),
            actlr: 0,
            csselr: 0,
            cpacr: 0,
            mpu_ctrl: 0,
            mpu_rnr: 0,
            mpu_rbar: [0; MPU_REGIONS],
            mpu_rasr: [0; MPU_REGIONS],
            demcr: 0,
            dwt_ctrl: DWT_NUMCOMP,
            cyccnt: 0,
            cyccnt_since: 0,
            fpccr: FPCCR_ASPEN | FPCCR_LSPEN,
            fpcar: 0,
            fpdscr: 0,
        }
    }
}

impl Ppb {
    /// The reset values, keeping the cache identification of the chip.
    pub(super) fn reset(&mut self) {
        *self = Self {
            caches: self.caches,
            ..Self::default()
        };
    }
}

impl CortexMCpu {
    /// Routes loads and stores in `0xE000_0000..0xE010_0000` to the core's
    /// System Control Space and the other Private Peripheral Bus registers
    /// (see [`ppb`](super::ppb)), or back to guest memory.
    pub fn map_private_peripheral_bus(&mut self, mapped: bool) {
        self.ppb_mapped = mapped;
    }

    /// The cache identification a Cortex-M7 reports (CLIDR, CTR, CCSIDR).
    /// Kept across resets. No cache is modelled: the maintenance operations
    /// have no effect.
    pub fn set_cache_identification(&mut self, caches: CacheIdentification) {
        self.ppb.caches = caches;
    }

    /// Whether `address` is a Private Peripheral Bus register here.
    pub(super) fn is_ppb(&self, address: u32) -> bool {
        self.ppb_mapped && (PPB_BASE..PPB_END).contains(&address)
    }

    /// A load of `size` bytes from the Private Peripheral Bus.
    pub(super) fn ppb_load(&mut self, address: u32, size: u32) -> u32 {
        let word = self.ppb_read(address & !3);
        let shift = 8 * (address & 3);
        let mask = if size == 4 {
            u32::MAX
        } else {
            (1 << (8 * size)) - 1
        };
        (word >> shift) & mask
    }

    /// A store of `size` bytes to the Private Peripheral Bus.
    pub(super) fn ppb_store(&mut self, address: u32, size: u32, value: u32) {
        let aligned = address & !3;
        if size == 4 {
            self.ppb_write(aligned, value);
            return;
        }
        let shift = 8 * (address & 3);
        let mask = ((1u32 << (8 * size)) - 1) << shift;
        let bytes = (value << shift) & mask;
        let priorities = (0xE000_E400..0xE000_E4F0).contains(&aligned)
            || (0xE000_ED18..0xE000_ED24).contains(&aligned);
        let word = if priorities {
            (self.ppb_read(aligned) & !mask) | bytes
        } else {
            bytes
        };
        self.ppb_write(aligned, word);
    }

    fn ppb_read(&mut self, address: u32) -> u32 {
        match address {
            0xE000_1000 => self.ppb.dwt_ctrl,
            0xE000_1004 => self.cyccnt(),
            // ICTR: INTLINESNUM, interrupt lines in blocks of 32, minus one.
            0xE000_E004 => (self.nvic().num_interrupts().div_ceil(32) as u32).saturating_sub(1),
            0xE000_E008 => self.ppb.actlr,
            0xE000_E010..=0xE000_E01C => self.systick_mut().read(address - 0xE000_E000),
            0xE000_E100..=0xE000_E4EC => self.nvic().read(address - 0xE000_E100),
            0xE000_ED18..=0xE000_ED20 => self
                .nvic()
                .read_shpr(((address - 0xE000_ED18) / 4) as usize),
            0xE000_ED00..=0xE000_ED3C => {
                let current = self.current_exception;
                self.scb().read(address - 0xE000_ED00, current, None)
            }
            0xE000_ED78 => self.ppb.caches.clidr,
            0xE000_ED7C => self.ppb.caches.ctr,
            0xE000_ED80 => {
                if self.ppb.csselr & 1 == 0 {
                    self.ppb.caches.ccsidr_data
                } else {
                    self.ppb.caches.ccsidr_instruction
                }
            }
            0xE000_ED84 => self.ppb.csselr,
            0xE000_ED88 => self.ppb.cpacr,
            0xE000_ED90 => (MPU_REGIONS as u32) << 8,
            0xE000_ED94 => self.ppb.mpu_ctrl,
            0xE000_ED98 => self.ppb.mpu_rnr,
            0xE000_ED9C | 0xE000_EDA4 | 0xE000_EDAC | 0xE000_EDB4 => {
                let region = self.ppb.mpu_rnr as usize % MPU_REGIONS;
                self.ppb.mpu_rbar[region] | region as u32
            }
            0xE000_EDA0 | 0xE000_EDA8 | 0xE000_EDB0 | 0xE000_EDB8 => {
                self.ppb.mpu_rasr[self.ppb.mpu_rnr as usize % MPU_REGIONS]
            }
            0xE000_EDFC => self.ppb.demcr,
            0xE000_EF34 if self.vfp.is_some() => self.ppb.fpccr,
            0xE000_EF38 if self.vfp.is_some() => self.ppb.fpcar,
            0xE000_EF3C if self.vfp.is_some() => self.ppb.fpdscr,
            0xE000_EF40 => self.vfp.as_ref().map_or(0, |v| v.mvfr0),
            0xE000_EF44 => self.vfp.as_ref().map_or(0, |v| v.mvfr1),
            0xE000_EF48 => self.vfp.as_ref().map_or(0, |v| v.mvfr2),
            _ => 0,
        }
    }

    fn ppb_write(&mut self, address: u32, value: u32) {
        match address {
            0xE000_1000 => {
                self.hold_cyccnt();
                self.ppb.dwt_ctrl = DWT_NUMCOMP | (value & DWT_CYCCNTENA);
            }
            0xE000_1004 => {
                self.hold_cyccnt();
                self.ppb.cyccnt = value;
            }
            0xE000_E008 => self.ppb.actlr = value,
            0xE000_E010..=0xE000_E01C => self.systick_mut().write(address - 0xE000_E000, value),
            0xE000_E100..=0xE000_E4EC => self.nvic_mut().write(address - 0xE000_E100, value),
            0xE000_ED18..=0xE000_ED20 => {
                self.nvic_mut()
                    .write_shpr(((address - 0xE000_ED18) / 4) as usize, value);
            }
            0xE000_ED00..=0xE000_ED3C => self.scb_mut().write(address - 0xE000_ED00, value),
            0xE000_ED84 => self.ppb.csselr = value & 1,
            0xE000_ED88 => {
                // CP10 and CP11 (bits 23:20) exist only with the FPU.
                if self.vfp.is_some() {
                    self.ppb.cpacr = value & 0x00F0_0000;
                }
            }
            0xE000_ED94 => self.ppb.mpu_ctrl = value & 7,
            0xE000_ED98 => self.ppb.mpu_rnr = value & 0xFF,
            0xE000_ED9C | 0xE000_EDA4 | 0xE000_EDAC | 0xE000_EDB4 => {
                // RBAR.VALID selects the region in RBAR.REGION.
                if value & 0x10 != 0 {
                    self.ppb.mpu_rnr = value & 0xF;
                }
                let region = self.ppb.mpu_rnr as usize % MPU_REGIONS;
                self.ppb.mpu_rbar[region] = value & !0x1F;
            }
            0xE000_EDA0 | 0xE000_EDA8 | 0xE000_EDB0 | 0xE000_EDB8 => {
                self.ppb.mpu_rasr[self.ppb.mpu_rnr as usize % MPU_REGIONS] = value;
            }
            0xE000_EDFC => {
                self.hold_cyccnt();
                self.ppb.demcr = value;
            }
            0xE000_EF00 => self.nvic_mut().write(0xE00, value),
            0xE000_EF34 if self.vfp.is_some() => {
                self.ppb.fpccr = (self.ppb.fpccr & !FPCCR_WRITABLE) | (value & FPCCR_WRITABLE);
            }
            0xE000_EF38 if self.vfp.is_some() => self.ppb.fpcar = value & !7,
            0xE000_EF3C if self.vfp.is_some() => self.ppb.fpdscr = value & FPDSCR_MASK,
            _ => {}
        }
    }

    /// DWT_CYCCNT: counts cycles while DEMCR.TRCENA and DWT_CTRL.CYCCNTENA,
    /// keeps its value otherwise.
    fn cyccnt(&self) -> u32 {
        let counting = self.ppb.demcr & DEMCR_TRCENA != 0 && self.ppb.dwt_ctrl & DWT_CYCCNTENA != 0;
        if counting {
            let elapsed = self.cycle_count.wrapping_sub(self.ppb.cyccnt_since);
            self.ppb.cyccnt.wrapping_add(elapsed as u32)
        } else {
            self.ppb.cyccnt
        }
    }

    /// Keeps DWT_CYCCNT's value before a change of it or of its enables.
    fn hold_cyccnt(&mut self) {
        self.ppb.cyccnt = self.cyccnt();
        self.ppb.cyccnt_since = self.cycle_count;
    }
}

#[cfg(test)]
#[path = "ppb_tests.rs"]
mod tests;
