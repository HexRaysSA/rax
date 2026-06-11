//! Samsung S5L8900 (Apple A-series predecessor) platform devices.
//!
//! The S5L8900 is the SoC in the first-generation iPod Touch / iPhone
//! (ARM1176JZF-S, ARMv6K). These models are ported from the QEMU iPod Touch
//! 1G reference machine and are sufficient to bring up Apple's iBoot
//! second-stage bootloader.

use std::collections::VecDeque;
use std::io::{self, Write};

// =============================================================================
// Clock controller (CLOCK0 / CLOCK1)
// =============================================================================

/// S5L8900 clock/PLL controller. Two instances exist (CLOCK0, CLOCK1); both
/// answer with the same register file. iBoot reads the PLL config to derive
/// the CPU/bus/peripheral frequencies.
pub struct S5lClock {
    config0: u32,
    config1: u32,
    config2: u32,
    pll0con: u32,
    pll1con: u32,
    pll2con: u32,
    pll3con: u32,
    plllock: u32,
}

impl S5lClock {
    pub fn new() -> Self {
        let mut config0 = 0u32;
        config0 |= 1 << 12; // clock PLL index 1
        config0 |= 1 << 24; // has memory divisor
        config0 |= 2 << 16; // memory divisor = 2

        let mut config1 = 0u32;
        config1 |= 1 << 12; // bus PLL index 1
        config1 |= 1 << 24; // has bus divisor
        config1 |= 3 << 16; // bus divisor = 3
        config1 |= 1 << 8; // unknown has divisor
        config1 |= 3; // unknown divisor 1 = 3
        config1 |= 1 << 20; // peripheral factor = 1
        config1 |= 1 << 14;
        config1 |= 1 << 28; // some PLL index = 1
        config1 |= 1 << 30;

        let mut config2 = 0u32;
        config2 |= 3 << 28; // peripheral PLL index 3
        config2 |= 1 << 24; // display has divisor
        config2 |= 1 << 16; // display divisor = 1

        S5lClock {
            config0,
            config1,
            config2,
            // MDIV, PDIV, SDIV per PLL
            pll0con: (80 << 8) | (8 << 24),
            pll1con: (103 << 8) | (6 << 24),
            pll2con: (156 << 8) | (53 << 24) | 2,
            pll3con: (72 << 8) | (8 << 24) | 1,
            plllock: 1 | 2 | 4 | 8,
        }
    }

    pub fn read(&self, offset: u32) -> u32 {
        match offset {
            0x00 => self.config0,
            0x04 => self.config1,
            0x08 => self.config2,
            0x20 => self.pll0con,
            0x24 => self.pll1con,
            0x28 => self.pll2con,
            0x2C => self.pll3con,
            0x40 => self.plllock,
            0x44 => 0x000a_003a, // PLLMODE (captured from real hardware)
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        if offset == 0x40 {
            self.plllock = value;
        }
    }
}

impl Default for S5lClock {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// System timer
// =============================================================================

/// S5L8900 timer block. iBoot uses the free-running tick counter (TICKSHIGH /
/// TICKSLOW) for microsecond delay loops. We drive it from a tick value the
/// vCPU advances with executed instructions, so guest busy-waits terminate.
pub struct S5lTimer {
    pub ticks: u64,
    status: u32,
    config: u32,
    bcount1: u32,
    bcount2: u32,
    irqstat: u32,
    /// Set when the timer reaches its reload and an IRQ is pending.
    irq: bool,
}

impl S5lTimer {
    pub fn new() -> Self {
        S5lTimer {
            ticks: 0,
            status: 0,
            config: 0,
            bcount1: 0,
            bcount2: 0,
            irqstat: 0,
            irq: false,
        }
    }

    /// Advance the free-running counter (called per executed instruction).
    pub fn tick(&mut self, n: u64) {
        self.ticks = self.ticks.wrapping_add(n);
    }

    pub fn irq_pending(&self) -> bool {
        self.irq
    }

    pub fn read(&mut self, offset: u32) -> u32 {
        match offset {
            0x80 => (self.ticks >> 32) as u32, // TICKSHIGH
            0x84 => self.ticks as u32,          // TICKSLOW
            0x10000 => !0,                      // IRQSTAT
            0xF8 => 0xFFFF_FFFF,                // IRQLATCH
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        match offset {
            0x10000 => self.irqstat = value,
            0xF8 => self.irq = false, // IRQLATCH: acknowledge
            // Timer 4 (0xA0) sub-registers.
            0xA0 => self.config = value,          // CONFIG
            0xA4 => self.status = value,          // STATE
            0xA8 => self.bcount1 = value,         // COUNT_BUFFER
            0xAC => self.bcount2 = value,         // COUNT_BUFFER2
            _ => {}
        }
    }
}

impl Default for S5lTimer {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Chip ID
// =============================================================================

/// S5L8900 chip-identification block.
pub struct S5lChipId;

impl S5lChipId {
    pub fn read(offset: u32) -> u32 {
        match offset {
            0x4 => 0x2 << 24, // CHIP_REVISION
            _ => 0,
        }
    }
}

// =============================================================================
// GPIO
// =============================================================================

/// S5L8900 GPIO controller. Only the button/level state register at 0x2c4 is
/// meaningfully read by early firmware.
pub struct S5lGpio {
    pub gpio_state: u32,
}

impl S5lGpio {
    pub fn new() -> Self {
        S5lGpio { gpio_state: 0 }
    }

    pub fn read(&self, offset: u32) -> u32 {
        match offset {
            0x2c4 => self.gpio_state,
            _ => 0,
        }
    }

    pub fn write(&mut self, _offset: u32, _value: u32) {}
}

impl Default for S5lGpio {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// System interrupt controller / power (SYSIC)
// =============================================================================

pub const GPIO_NUMINTGROUPS: usize = 7;

/// S5L8900 SYSIC: power management plus the GPIO interrupt aggregation groups.
pub struct S5lSysic {
    power_state: u32,
    pub gpio_int_level: [u32; GPIO_NUMINTGROUPS],
    pub gpio_int_status: [u32; GPIO_NUMINTGROUPS],
    pub gpio_int_enabled: [u32; GPIO_NUMINTGROUPS],
    pub gpio_int_type: [u32; GPIO_NUMINTGROUPS],
}

impl S5lSysic {
    pub fn new() -> Self {
        S5lSysic {
            power_state: 0,
            gpio_int_level: [0; GPIO_NUMINTGROUPS],
            gpio_int_status: [0; GPIO_NUMINTGROUPS],
            gpio_int_enabled: [0; GPIO_NUMINTGROUPS],
            gpio_int_type: [0; GPIO_NUMINTGROUPS],
        }
    }

    pub fn read(&self, offset: u32) -> u32 {
        match offset {
            0x44 => 2 << 0x18,                  // POWER_ID
            0x08 | 0x14 => self.power_state,    // POWER_SETSTATE / POWER_STATE
            0x7a | 0x7c => 1,
            0x80..=0x9C => self.gpio_int_level[((offset - 0x80) / 4) as usize],
            0xA0..=0xBC => self.gpio_int_status[((offset - 0xA0) / 4) as usize],
            0xC0..=0xDC => self.gpio_int_enabled[((offset - 0xC0) / 4) as usize],
            0xE0..=0xFC => self.gpio_int_type[((offset - 0xE0) / 4) as usize],
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        match offset {
            0x0C => {
                // POWER_ONCTRL: ignore a few devices so they read as already on.
                if value & 0x20 == 0 && value & 0x4 == 0 && value & 0x10 == 0 {
                    self.power_state = value;
                }
            }
            0x10 => self.power_state = value, // POWER_OFFCTRL
            0xA0..=0xBC => {
                let g = ((offset - 0xA0) / 4) as usize;
                self.gpio_int_status[g] &= !value; // write-1-to-clear
            }
            0xC0..=0xDC => self.gpio_int_enabled[((offset - 0xC0) / 4) as usize] = value,
            0xE0..=0xFC => self.gpio_int_type[((offset - 0xE0) / 4) as usize] = value,
            _ => {}
        }
    }
}

impl Default for S5lSysic {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// PL192 Vectored Interrupt Controller
// =============================================================================

const PL192_INT_SOURCES: usize = 32;

/// ARM PrimeCell PL192 VIC, as used by the S5L8900 (two instances chained:
/// VIC1's parent output daisy-chains into VIC0, which drives the CPU).
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
        }
    }

    /// Recompute IRQ/FIQ status from raw/soft inputs and the masks.
    pub fn update(&mut self) {
        let active = (self.rawintr | self.softint) & self.intenable;
        self.irq_status = active & !self.intselect;
        self.fiq_status = active & self.intselect;
        // Latch the vector for the lowest-numbered pending IRQ (priority is
        // not modelled in detail — early firmware does not depend on it).
        if self.irq_status != 0 {
            let n = self.irq_status.trailing_zeros() as usize;
            self.address = self.vect_addr[n];
        } else if self.daisy_input {
            self.address = self.daisy_vectaddr;
        }
    }

    /// CPU IRQ line level contributed by this controller (excluding daisy).
    pub fn irq_asserted(&self) -> bool {
        self.irq_status != 0 || self.daisy_input
    }

    pub fn fiq_asserted(&self) -> bool {
        self.fiq_status != 0
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
            0x14 => 0, // INTENCLEAR
            0xF00 => self.address, // VECTADDR (ack)
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
            0xF00 => {} // VECTADDR finish: no priority stack modelled
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

// =============================================================================
// PCF50633 Power Management Unit (I2C slave at address 0x73)
// =============================================================================

/// PCF50633 PMU. iBoot reads PMU registers over I2C to decide power/boot
/// behaviour — notably register 0x67, which gates the serial console.
pub struct Pcf50633 {
    /// Current register index; auto-increments on each read.
    cmd: u8,
}

impl Pcf50633 {
    pub fn new() -> Self {
        Pcf50633 { cmd: 0 }
    }

    /// I2C write: the first byte selects the register index.
    pub fn send(&mut self, data: u8) {
        self.cmd = data;
    }

    /// I2C read: return the current register's value, then post-increment.
    pub fn recv(&mut self) -> u8 {
        let res: u8 = match self.cmd {
            0x67 => 1, // enable the debug UARTs (serial console)
            _ => 0,    // battery/charge/RTC registers: 0 is acceptable early
        };
        self.cmd = self.cmd.wrapping_add(1);
        res
    }
}

impl Default for Pcf50633 {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// I2C controller (Samsung S5L IIC)
// =============================================================================

const IICCON_ACKEN: u8 = 1 << 7;
const IICSTAT_START: u8 = 1 << 5;
const IICSTAT_TXRXEN: u8 = 1 << 4;
const IICSTAT_LASTBIT: u8 = 1 << 0;

/// S5L8900 I2C master controller. Models enough of the register protocol for
/// iBoot's polled PMU transactions: the `iicreg20` "transfer active" flag the
/// firmware spins on, and data routing to the attached PMU slave.
pub struct S5lI2c {
    control: u8,
    status: u8,
    address: u8,
    data: u8,
    line_ctrl: u8,
    iicreg20: u32,
    active: bool,
    addressed: u8,
    /// The PMU slave (present on I2C1; None on buses without one).
    pmu: Option<Pcf50633>,
}

impl S5lI2c {
    pub fn new(pmu: bool) -> Self {
        S5lI2c {
            control: 0,
            status: 0,
            address: 0,
            data: 0,
            line_ctrl: 0,
            iicreg20: 0,
            active: false,
            addressed: 0,
            pmu: pmu.then(Pcf50633::new),
        }
    }

    fn slave_recv(&mut self) -> u8 {
        match (self.addressed, self.pmu.as_mut()) {
            (0x73, Some(pmu)) => pmu.recv(),
            _ => 0,
        }
    }

    fn slave_send(&mut self, data: u8) {
        if let (0x73, Some(pmu)) = (self.addressed, self.pmu.as_mut()) {
            pmu.send(data);
        }
    }

    pub fn read(&mut self, offset: u32) -> u32 {
        match offset {
            0x00 => self.control as u32,
            0x04 => self.status as u32,
            0x08 => self.address as u32,
            0x0c => {
                // I2CDS read: fetch the next byte from the slave.
                self.iicreg20 |= 0x100;
                self.data = self.slave_recv();
                self.data as u32
            }
            0x10 => self.line_ctrl as u32,
            0x20 => {
                // IICREG20: transfer-status flags, cleared on read.
                let tmp = self.iicreg20;
                self.iicreg20 &= !0x100;
                self.iicreg20 &= !0x2000;
                tmp
            }
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        let v = value as u8;
        match offset {
            0x00 => {
                // I2CCON
                if value & !(IICCON_ACKEN as u32) != 0 {
                    self.iicreg20 |= 0x100;
                }
                if (value & 0x10) != 0 && self.status == 0x90 {
                    self.iicreg20 |= 0x2000;
                }
                self.control = v;
            }
            0x04 => {
                // I2CSTAT: mode + start/stop control.
                let mode = (self.status >> 6) & 0x3;
                if (value as u8) & IICSTAT_TXRXEN != 0 {
                    match mode {
                        0 | 1 => {
                            // Slave receive/transmit: pull a byte.
                            self.data = self.slave_recv();
                        }
                        2 | 3 => {
                            if (value as u8) & IICSTAT_START != 0 {
                                self.status &= !IICSTAT_LASTBIT;
                                self.iicreg20 |= 0x100;
                                self.active = true;
                                self.addressed = self.data >> 1;
                            } else {
                                self.active = false;
                                self.status |= IICSTAT_TXRXEN;
                            }
                        }
                        _ => {}
                    }
                }
                self.status = v;
            }
            0x08 => self.address = v,
            0x0c => {
                // I2CDS write: send a byte to the slave.
                self.iicreg20 |= 0x100;
                self.data = v;
                self.slave_send(v);
            }
            0x10 => self.line_ctrl = v,
            _ => {}
        }
    }
}

impl Default for S5lI2c {
    fn default() -> Self {
        Self::new(false)
    }
}

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
