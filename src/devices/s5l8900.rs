//! Samsung S5L8900 (Apple A-series predecessor) platform devices.
//!
//! The S5L8900 is the SoC in the first-generation iPod Touch / iPhone
//! (ARM1176JZF-S, ARMv6K). These models are ported from the QEMU iPod Touch
//! 1G reference machine and are sufficient to bring up Apple's iBoot
//! second-stage bootloader.

use std::collections::VecDeque;
use std::io::{self, Write};

pub(crate) mod context;

// =============================================================================
// NAND flash controller (FMSS) + ECC, backed by per-page files
// =============================================================================

mod nand;
pub use nand::{NAND_BYTES_PER_PAGE, NAND_BYTES_PER_SPARE, NAND_NUM_BANKS, S5lNand};

// =============================================================================
// UART (Samsung-style, S5L layout — identical register offsets to s3c64xx)
// =============================================================================

/// S5L8900 UART. Register layout matches the Samsung s3c/exynos UART. iBoot's
/// serial console polls UTRSTAT for TX-ready and writes characters to UTXH.
pub struct S5lUart {
    rx: VecDeque<u8>,
    ulcon: u32,
    ucon: u32,
    ufcon: u32,
    umcon: u32,
    ubrdiv: u32,
    udivslot: u32,
    uintp: u32,
    uintm: u32,
}

impl S5lUart {
    pub fn new() -> Self {
        S5lUart {
            rx: VecDeque::new(),
            ulcon: 0,
            ucon: 0,
            ufcon: 0,
            umcon: 0,
            ubrdiv: 0,
            udivslot: 0,
            uintp: 0,
            uintm: 0xF,
        }
    }

    pub fn queue_input(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            self.rx.extend(bytes);
            self.uintp |= 1;
        }
    }

    pub fn irq_pending(&self) -> bool {
        self.uintp & !self.uintm != 0
    }

    pub fn read(&mut self, offset: u32) -> u32 {
        match offset {
            0x00 => self.ulcon,
            0x04 => self.ucon,
            0x08 => self.ufcon,
            0x0C => self.umcon,
            0x10 => 0x6 | u32::from(!self.rx.is_empty()), // UTRSTAT: TX empty, RX ready
            0x14 => 0,                                    // UERSTAT
            0x18 => self.rx.len().min(63) as u32,         // UFSTAT
            0x1C => 0,                                    // UMSTAT
            0x24 => {
                // URXH
                let b = self.rx.pop_front().unwrap_or(0) as u32;
                if self.rx.is_empty() {
                    self.uintp &= !1;
                }
                b
            }
            0x28 => self.ubrdiv,
            0x2C => self.udivslot,
            0x30 | 0x34 => self.uintp, // UINTP / UINTSP
            0x38 => self.uintm,
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        match offset {
            0x00 => self.ulcon = value,
            0x04 => self.ucon = value,
            0x08 => self.ufcon = value,
            0x0C => self.umcon = value,
            0x20 => {
                // UTXH
                let _ = io::stdout().write_all(&[value as u8]);
                let _ = io::stdout().flush();
            }
            0x28 => self.ubrdiv = value,
            0x2C => self.udivslot = value,
            0x30 | 0x34 => {
                self.uintp &= !value;
                if !self.rx.is_empty() {
                    self.uintp |= 1;
                }
            }
            0x38 => self.uintm = value,
            _ => {}
        }
    }
}

impl Default for S5lUart {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod spi_dos_tests {
    use super::*;

    // Regression for issue #47: a guest can set a huge RXCNT and enable
    // CFG_AGD + RUN. `run()` must never push more than SPI_RX_FIFO_MAX bytes into
    // the host rx FIFO, otherwise an RXCNT near u32::MAX forces billions of
    // iterations and multi-GB host allocation (DoS). Requesting slightly more
    // than the cap makes the bound observable without allocating gigabytes.
    #[test]
    fn spi_rxcnt_does_not_overrun_rx_fifo() {
        let mut spi = S5lSpi::new(0);
        spi.write(SPI_CFG, CFG_AGD); // auto-get-data
        spi.write(SPI_RXCNT, (SPI_RX_FIFO_MAX + 1000) as u32);
        spi.write(SPI_TXDATA, 0xAA); // a TX byte so CTRL_RUN starts the engine
        spi.write(SPI_CTRL, CTRL_RUN); // triggers run()
        assert!(
            spi.rx.len() <= SPI_RX_FIFO_MAX,
            "rx FIFO must stay bounded by SPI_RX_FIFO_MAX; got {}",
            spi.rx.len(),
        );
    }
}

#[cfg(test)]
mod sysic_dos_tests {
    use super::*;

    // Regression for issue #42: the last register of each SYSIC GPIO
    // interrupt-group range (0x9C/0xBC/0xDC/0xFC) used to compute array index 7
    // into the 7-entry gpio_int_* arrays, so a guest MMIO access there panicked
    // (a host abort in aborting builds). They must now be handled as open-bus.
    #[test]
    fn sysic_gpio_group_endpoint_offsets_do_not_panic() {
        let mut sysic = S5lSysic::new();

        // Reads across every group register, including the once-OOB endpoints.
        for off in [
            0x80u32, 0x98, 0x9C, 0xA0, 0xB8, 0xBC, 0xC0, 0xD8, 0xDC, 0xE0, 0xF8, 0xFC,
        ] {
            let _ = sysic.read(off); // must not panic
        }
        // Writes across every writable group register, including the endpoints.
        for off in [0xA0u32, 0xB8, 0xBC, 0xC0, 0xD8, 0xDC, 0xE0, 0xF8, 0xFC] {
            sysic.write(off, 0xFFFF_FFFF); // must not panic
        }

        // The out-of-range endpoints read back as open-bus (0), not a group reg.
        assert_eq!(sysic.read(0x9C), 0);
        assert_eq!(sysic.read(0xBC), 0);
        assert_eq!(sysic.read(0xDC), 0);
        assert_eq!(sysic.read(0xFC), 0);

        // The highest valid register (index 6) still works.
        let mut sysic = S5lSysic::new();
        sysic.write(0xD8, 0x1234); // gpio_int_enabled[6]
        assert_eq!(sysic.read(0xD8), 0x1234);
    }
}

#[cfg(test)]
mod timer_tests {
    use super::*;

    #[test]
    fn timer_uses_programmed_count_without_immediate_irq() {
        let mut timer = S5lTimer::new();

        timer.write(0xA8, 100_000);
        timer.write(0xA4, 1);

        timer.tick_irq(0, 50_000, 0, 0);
        assert!(!timer.irq_pending());

        timer.set_micros(9_999);
        timer.tick_irq(0, 50_000, 9_999, 0);
        assert!(!timer.irq_pending());

        timer.set_micros(10_000);
        timer.tick_irq(0, 50_000, 10_000, 0);
        assert!(timer.irq_pending());

        timer.write(0xF8, 1);
        timer.set_micros(19_999);
        timer.tick_irq(0, 50_000, 19_999, 0);
        assert!(!timer.irq_pending());

        timer.set_micros(20_000);
        timer.tick_irq(0, 50_000, 20_000, 0);
        assert!(timer.irq_pending());
    }

    #[test]
    fn timer_clamps_tiny_programmed_count_like_qemu() {
        let mut timer = S5lTimer::new();

        timer.write(0xA8, 1);
        timer.write(0xA4, 1);

        timer.tick_irq(0, 50_000, 0, 0);
        timer.set_micros(99);
        timer.tick_irq(0, 50_000, 99, 0);
        assert!(!timer.irq_pending());

        timer.set_micros(100);
        timer.tick_irq(0, 50_000, 100, 0);
        assert!(timer.irq_pending());
    }

    #[test]
    fn timer_respects_minimum_instruction_spacing() {
        let mut timer = S5lTimer::new();

        timer.write(0xA8, 1);
        timer.write(0xA4, 1);

        timer.tick_irq(0, 50_000, 0, 50_000);
        timer.set_micros(100);
        timer.tick_irq(0, 50_000, 100, 50_000);
        assert!(!timer.irq_pending());

        timer.tick_irq(0, 50_000, 49_999, 50_000);
        assert!(!timer.irq_pending());

        timer.tick_irq(0, 50_000, 50_000, 50_000);
        assert!(timer.irq_pending());
    }
}

#[cfg(test)]
mod pl192_tests {
    use super::*;

    fn enable_irq(vic: &mut Pl192, irq: u32, priority: u32, vector: u32) {
        vic.set_priority_mode(true);
        vic.write(0x100 + irq * 4, vector);
        vic.write(0x200 + irq * 4, priority);
        vic.write(0x10, 1u32 << irq);
    }

    fn refresh_parent_daisy(parent: &mut Pl192, child: &Pl192) {
        parent.daisy_input = child.irq_asserted();
        parent.daisy_vectaddr = child.address;
        parent.update();
    }

    #[test]
    fn pl192_repeated_acknowledge_pushes_priority_stack_like_qemu() {
        let mut vic = Pl192::new();
        enable_irq(&mut vic, 16, 0xf, 0x1234_5678);
        vic.set_line(16, true);

        let (addr, is_daisy) = vic.acknowledge();
        assert_eq!(addr, 0x1234_5678);
        assert!(!is_daisy);
        assert_eq!(vic.stack_i, 1);

        let (addr, is_daisy) = vic.acknowledge();
        assert_eq!(addr, 0x1234_5678);
        assert!(!is_daisy);
        assert_eq!(vic.stack_i, 2);
        assert_eq!(vic.current, 16);
    }

    #[test]
    fn pl192_daisy_irq_surfaces_after_same_priority_direct_irq_finishes() {
        let mut parent = Pl192::new();
        let mut child = Pl192::new();
        parent.set_priority_mode(true);
        child.set_priority_mode(true);
        enable_irq(&mut parent, 16, 0xf, 0x1111_0000);
        parent.write(0x28, 0xf);
        enable_irq(&mut child, 5, 0xf, 0x2222_0000);

        parent.set_line(16, true);
        child.set_line(5, true);
        refresh_parent_daisy(&mut parent, &child);

        let (addr, is_daisy) = parent.acknowledge();
        assert_eq!(addr, 0x1111_0000);
        assert!(!is_daisy);

        parent.set_line(16, false);
        refresh_parent_daisy(&mut parent, &child);
        assert!(!parent.irq_asserted());

        assert!(!parent.finish_irq());
        refresh_parent_daisy(&mut parent, &child);
        assert!(parent.irq_asserted());

        let (addr, is_daisy) = parent.acknowledge();
        assert_eq!(addr, 0x2222_0000);
        assert!(is_daisy);
        child.acknowledge_daisy_child();
        assert_eq!(child.current, PL192_NO_IRQ);
        assert_eq!(child.current_highest, 5);
        assert_eq!(child.priority, PL192_NO_IRQ);
        assert_eq!(child.stack_i, 1);
        refresh_parent_daisy(&mut parent, &child);
        assert!(!parent.irq_asserted());

        // The guest masks the raw child source before writing VECTADDR. This is
        // the exact ADM completion ordering observed under the QEMU oracle.
        child.write(0x14, 1 << 5);
        assert_eq!(child.current_highest, PL192_NO_IRQ);
        assert_eq!(child.stack_i, 1);
        refresh_parent_daisy(&mut parent, &child);
        assert!(parent.finish_irq());
        child.finish_daisy_child();
        refresh_parent_daisy(&mut parent, &child);
        assert_eq!(parent.stack_i, 0);
        assert_eq!(child.stack_i, 0);
        assert!(!parent.irq_asserted());
    }
}

#[cfg(test)]
mod aes_engine_tests {
    use super::*;
    use crate::devices::crypto::{AesKey, aes_cbc_decrypt};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Program the AES engine through its MMIO registers exactly as iBoot does
    /// (custom key + IV written word-by-word, type/size set), then confirm the
    /// assembled key/IV decrypt a NIST CBC vector — i.e. the register-decode
    /// path feeds the crypto correctly.
    #[test]
    fn aes_engine_register_protocol_cbc() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c"); // AES-128
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        let ct = hex("7649abac8119b246cee98e9b12e9197d");
        let pt = hex("6bc1bee22e409f96e93d7e117393172a");

        let mut aes = S5lAes::new();
        // Type = Custom (0).
        aes.write(AES_TYPE, 0);
        // Custom key: 16 bytes written as 4 little-endian words at AES_KEY_REG.
        for (i, w) in key.chunks_exact(4).enumerate() {
            let v = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
            aes.write(AES_KEY_REG + (i as u32) * 4, v);
        }
        // IV: 16 bytes written as 4 words at AES_IV_REG.
        for (i, w) in iv.chunks_exact(4).enumerate() {
            let v = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
            aes.write(AES_IV_REG + (i as u32) * 4, v);
        }
        aes.write(AES_INSIZE, ct.len() as u32);
        aes.write(AES_GO, 1);
        assert!(aes.pending_go, "AES_GO must mark a pending operation");

        // The assembled custkey/IV must round-trip the vector.
        let k = AesKey::new(&aes.custkey[..16]).unwrap();
        let mut iv16 = [0u8; 16];
        iv16.copy_from_slice(&aes.ivec);
        let mut data = ct.clone();
        aes_cbc_decrypt(&k, &iv16, &mut data);
        assert_eq!(data, pt);

        // finish() wipes the volatile key/IV and reports done.
        aes.finish();
        assert_eq!(aes.custkey, [0u8; 32]);
        assert_eq!(aes.ivec, [0u8; 16]);
        assert_eq!(aes.status, 0xf);
    }

    #[test]
    fn aes_engine_uid_keytype() {
        let mut aes = S5lAes::new();
        aes.write(AES_TYPE, 2);
        assert!(matches!(aes.keytype, AesKeyType::Uid));
        aes.write(AES_TYPE, 1);
        assert!(matches!(aes.keytype, AesKeyType::Gid));
    }
}

#[cfg(test)]
#[path = "s5l8900/nand_bounds_tests.rs"]
mod nand_bounds_tests;

mod core;
pub use core::{GPIO_NUMINTGROUPS, S5lChipId, S5lClock, S5lDmac, S5lGpio, S5lSysic, S5lTimer};

mod usb;
pub use usb::S5lUsb;

mod interrupts;
#[cfg(test)]
use interrupts::PL192_NO_IRQ;
pub use interrupts::Pl192;

mod crypto;
#[cfg(test)]
use crypto::{AES_GO, AES_INSIZE, AES_IV_REG, AES_KEY_REG, AES_TYPE};
pub use crypto::{AES_UID_KEY, AesKeyType, S5lAes, S5lNandEcc};

mod i2c;
pub use i2c::{Lis302dl, Pcf50633, S5lI2c};

mod sdio;
pub use sdio::S5lSdio;

mod spi;
pub use spi::S5lSpi;
#[cfg(test)]
use spi::{CFG_AGD, CTRL_RUN, SPI_CFG, SPI_CTRL, SPI_RX_FIFO_MAX, SPI_RXCNT, SPI_TXDATA};

mod display;
pub use display::S5lLcd;
