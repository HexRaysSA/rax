// =============================================================================
// Clock controller (CLOCK0 / CLOCK1)
// =============================================================================

/// S5L8900 clock/PLL controller. Two instances exist (CLOCK0, CLOCK1); both
/// answer with the same register file. iBoot reads the PLL config to derive
/// the CPU/bus/peripheral frequencies.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct S5lClock {
    pub(super) config0: u32,
    pub(super) config1: u32,
    pub(super) config2: u32,
    pub(super) pll0con: u32,
    pub(super) pll1con: u32,
    pub(super) pll2con: u32,
    pub(super) pll3con: u32,
    pub(super) plllock: u32,
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
/// TICKSLOW) for microsecond delay loops. The vCPU drives it from a virtual
/// timer clock that advances during execution and while the guest is idle.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct S5lTimer {
    /// Free-running microsecond counter. iBoot treats the timer as a µs clock
    /// (it divides by 1_000_000 to get seconds). The value is updated coarsely
    /// (every N instructions) from a host clock so it tracks real time yet
    /// stays stable across a guest's few-instruction atomic counter read
    /// (read-low / read-high / read-low again, which assumes the timer is
    /// slower than the CPU).
    pub(super) micros: u64,
    pub(super) status: u32,
    pub(super) config: u32,
    pub(super) bcount1: u32,
    pub(super) bcount2: u32,
    pub(super) irqstat: u32,
    /// Set when the timer reaches its reload and an IRQ is pending.
    pub(super) irq: bool,
    /// Whether the periodic timer (timer 4) is running.
    pub(super) started: bool,
    /// Guest timer value (in the same units as `micros`) for the next periodic IRQ.
    pub(super) next_irq_micros: u64,
    /// Guest instruction count before another periodic IRQ may be raised.
    pub(super) next_irq_insn: u64,
}

impl S5lTimer {
    pub fn new() -> Self {
        S5lTimer {
            micros: 0,
            status: 0,
            config: 0,
            bcount1: 0,
            bcount2: 0,
            irqstat: 0,
            irq: false,
            started: false,
            next_irq_micros: 0,
            next_irq_insn: 0,
        }
    }

    /// Set the µs counter from the host clock (called periodically, NOT every
    /// instruction, so the value is stable across a guest atomic read).
    pub fn set_micros(&mut self, micros: u64) {
        // Monotonic: never let the counter go backwards.
        if micros > self.micros {
            self.micros = micros;
        }
    }

    /// Raise the periodic system-tick IRQ, paced by the timer count programmed
    /// by the guest. QEMU uses a 10 MHz output clock for this timer and clamps
    /// very small reloads to 1000 ticks, so `bcount1 / 10` gives microseconds.
    pub fn tick_irq(
        &mut self,
        ready: u64,
        fallback_interval: u64,
        now_insn: u64,
        min_insn_interval: u64,
    ) {
        if !self.started || self.micros < ready {
            return;
        }
        let interval = self.programmed_interval_micros(fallback_interval);
        if self.next_irq_micros == 0 {
            self.next_irq_micros = self.micros.saturating_add(interval);
            self.next_irq_insn = now_insn.saturating_add(min_insn_interval);
            return;
        }
        if self.micros >= self.next_irq_micros && now_insn >= self.next_irq_insn {
            self.irq = true;
            let base = self.micros.max(ready);
            self.next_irq_micros = base.saturating_add(interval);
            self.next_irq_insn = now_insn.saturating_add(min_insn_interval);
        }
    }

    fn programmed_interval_micros(&self, fallback_interval: u64) -> u64 {
        if self.bcount1 != 0 {
            (u64::from(self.bcount1).max(1000) / 10).max(1)
        } else {
            fallback_interval.max(1)
        }
    }

    pub fn irq_pending(&self) -> bool {
        self.irq
    }

    pub fn debug_state(&self) -> (u64, u32, u32, u32, u32, bool, bool, u64, u64) {
        (
            self.micros,
            self.status,
            self.config,
            self.bcount1,
            self.bcount2,
            self.irq,
            self.started,
            self.next_irq_micros,
            self.next_irq_insn,
        )
    }

    pub fn read(&mut self, offset: u32) -> u32 {
        let t = self.micros;
        match offset {
            0x80 => (t >> 32) as u32, // TICKSHIGH
            0x84 => t as u32,         // TICKSLOW
            0x10000 => !0,            // IRQSTAT
            0xF8 => 0xFFFF_FFFF,      // IRQLATCH
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        match offset {
            0x10000 => self.irqstat = value,
            0xF8 => self.irq = false, // IRQLATCH: acknowledge
            // Timer 4 (0xA0) sub-registers.
            0xA0 => self.config = value, // CONFIG
            0xA4 => {
                // STATE: bit0 = start. Arm/disarm the periodic IRQ.
                self.status = value;
                self.started = value & 1 != 0;
                self.next_irq_micros = 0;
                self.next_irq_insn = 0;
                if !self.started {
                    self.irq = false;
                }
            }
            0xA8 => self.bcount1 = value, // COUNT_BUFFER
            0xAC => self.bcount2 = value, // COUNT_BUFFER2
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
// PL080 DMA controller (DMAC0 / DMAC1)
// =============================================================================

/// ARM PL080 DMA controller. iBoot uses DMAC0 (0x38200000) to stream NAND
/// pages from the flash-controller FIFO (0x38A00080) into RAM. We model the
/// register file and per-channel descriptors here; the backend performs the
/// actual memory movement when a channel is enabled (it needs access to guest
/// memory and the peripheral read path, which live on the bridge).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct S5lDmac {
    pub src: [u32; 8],
    pub dst: [u32; 8],
    pub lli: [u32; 8],
    pub control: [u32; 8],
    pub config: [u32; 8],
    /// Controller-global DMACConfiguration (0x030).
    pub global_config: u32,
    /// IntTCStatus / RawIntTCStatus (terminal-count interrupt, per channel).
    pub tc_status: u32,
    /// EnbldChns (0x01C): which channels are currently enabled.
    pub enbld: u32,
    /// Channel whose transfer the backend should run, set on a channel-enable
    /// write and consumed via `take_pending()`.
    pub(super) pending: Option<u8>,
}

impl S5lDmac {
    pub fn new() -> Self {
        S5lDmac {
            src: [0; 8],
            dst: [0; 8],
            lli: [0; 8],
            control: [0; 8],
            config: [0; 8],
            global_config: 0,
            tc_status: 0,
            enbld: 0,
            pending: None,
        }
    }

    /// Take the channel scheduled by the last channel-enable write, if any.
    pub fn take_pending(&mut self) -> Option<u8> {
        self.pending.take()
    }

    /// Mark channel `ch`'s transfer complete: zero the remaining size, disable
    /// the channel, and raise its terminal-count interrupt status.
    pub fn complete(&mut self, ch: usize) {
        let tc_irq = self.control[ch] & (1 << 31) != 0;
        self.control[ch] &= !0xFFF;
        self.config[ch] &= !1;
        self.enbld &= !(1 << ch);
        if tc_irq {
            self.tc_status |= 1 << ch;
        }
    }

    /// Channel IRQ line level: any terminal-count status whose channel has the
    /// terminal-count interrupt mask (Config bit15) set.
    pub fn irq_pending(&self) -> bool {
        let mut mask = 0u32;
        for ch in 0..8 {
            if self.config[ch] & (1 << 15) != 0 {
                mask |= 1 << ch;
            }
        }
        self.tc_status & mask != 0
    }

    pub fn read(&self, offset: u32) -> u32 {
        match offset {
            0x000 => self.tc_status,     // IntStatus
            0x004 => self.tc_status,     // IntTCStatus
            0x00C => 0,                  // IntErrorStatus
            0x014 => self.tc_status,     // RawIntTCStatus
            0x018 => 0,                  // RawIntErrorStatus
            0x01C => self.enbld,         // EnbldChns
            0x030 => self.global_config, // DMACConfiguration
            _ if (0x100..0x200).contains(&offset) => {
                let ch = ((offset - 0x100) / 0x20) as usize;
                match (offset - 0x100) % 0x20 {
                    0x00 => self.src[ch],
                    0x04 => self.dst[ch],
                    0x08 => self.lli[ch],
                    0x0C => self.control[ch],
                    0x10 => self.config[ch],
                    _ => 0,
                }
            }
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u32, val: u32) {
        match offset {
            0x008 => self.tc_status &= !val, // IntTCClear
            0x010 => {}                      // IntErrClr
            0x030 => self.global_config = val,
            _ if (0x100..0x200).contains(&offset) => {
                let ch = ((offset - 0x100) / 0x20) as usize;
                match (offset - 0x100) % 0x20 {
                    0x00 => self.src[ch] = val,
                    0x04 => self.dst[ch] = val,
                    0x08 => self.lli[ch] = val,
                    0x0C => self.control[ch] = val,
                    0x10 => {
                        self.config[ch] = val;
                        // Channel Enable (bit0): schedule the transfer.
                        if val & 1 != 0 {
                            self.enbld |= 1 << ch;
                            self.pending = Some(ch as u8);
                        } else {
                            self.enbld &= !(1 << ch);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

impl Default for S5lDmac {
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
#[derive(Clone, serde::Serialize, serde::Deserialize)]
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
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct S5lSysic {
    pub(super) power_state: u32,
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
            0x44 => 2 << 0x18,               // POWER_ID
            0x08 | 0x14 => self.power_state, // POWER_SETSTATE / POWER_STATE
            0x7a | 0x7c => 1,
            // Only GPIO_NUMINTGROUPS (7) interrupt groups exist, so the valid
            // register offsets stop at index 6 (base + 6*4). The endpoints must be
            // 0x98/0xB8/0xD8/0xF8, not 0x9C/0xBC/0xDC/0xFC — the latter compute
            // index 7 and a guest LDR there would panic (and abort an embedding
            // built with an aborting panic strategy). Out-of-range offsets fall
            // through to open-bus (0). (#42)
            0x80..=0x98 => self.gpio_int_level[((offset - 0x80) / 4) as usize],
            0xA0..=0xB8 => self.gpio_int_status[((offset - 0xA0) / 4) as usize],
            0xC0..=0xD8 => self.gpio_int_enabled[((offset - 0xC0) / 4) as usize],
            0xE0..=0xF8 => self.gpio_int_type[((offset - 0xE0) / 4) as usize],
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
            // Endpoints stop at index 6 (0xB8/0xD8/0xF8); 0xBC/0xDC/0xFC would
            // index past the 7-entry arrays and panic on a guest MMIO write. (#42)
            0xA0..=0xB8 => {
                let g = ((offset - 0xA0) / 4) as usize;
                self.gpio_int_status[g] &= !value; // write-1-to-clear
            }
            0xC0..=0xD8 => self.gpio_int_enabled[((offset - 0xC0) / 4) as usize] = value,
            0xE0..=0xF8 => self.gpio_int_type[((offset - 0xE0) / 4) as usize] = value,
            _ => {}
        }
    }
}

impl Default for S5lSysic {
    fn default() -> Self {
        Self::new()
    }
}
