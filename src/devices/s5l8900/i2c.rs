// =============================================================================
// PCF50633 Power Management Unit (I2C slave at address 0x73)
// =============================================================================

/// PCF50633 PMU. iBoot reads PMU registers over I2C to decide power/boot
/// behaviour — notably register 0x67, which gates the serial console.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Pcf50633 {
    /// Current register index; auto-increments on each read.
    pub(super) cmd: u8,
}

impl Pcf50633 {
    pub fn new() -> Self {
        Pcf50633 { cmd: 0 }
    }

    /// I2C write: the first byte selects the register index.
    pub fn send(&mut self, data: u8) {
        if std::env::var("RAX_S5L_PMULOG").is_ok() {
            eprintln!("PMU send reg {data:#x}");
        }
        self.cmd = data;
    }

    /// I2C read: return the current register's value, then post-increment.
    pub fn recv(&mut self) -> u8 {
        let rtc = Pcf50633Rtc::now();
        let res: u8 = match self.cmd {
            0x4B => 0,          // MBCS1: battery power source
            0x57 => 0,          // ADCC1: battery charge voltage
            0x59 => rtc.second, // RTCSC: seconds, BCD
            0x5A => rtc.minute, // RTCMN: minutes, BCD
            0x5B => rtc.hour,   // RTCHR: hours, BCD
            0x5C => 0,          // RTCWD: QEMU leaves weekday unimplemented
            0x5D => rtc.day,    // RTCDT: day, BCD
            0x5E => rtc.month,  // RTCMT: month, BCD
            0x5F => rtc.year,   // RTCYR: year since 2000, BCD
            0x67 => 1,          // enable the debug UARTs (serial console)
            0x69 => 0,          // boot/panic fail count
            0x76 => 0,          // observed but unknown in the reference model
            _ => 0,
        };
        if std::env::var("RAX_S5L_PMULOG").is_ok() {
            eprintln!("PMU recv reg {:#x} -> {res:#x}", self.cmd);
        }
        self.cmd = self.cmd.wrapping_add(1);
        res
    }
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
pub(super) struct Pcf50633Rtc {
    pub(super) second: u8,
    pub(super) minute: u8,
    pub(super) hour: u8,
    pub(super) day: u8,
    pub(super) month: u8,
    pub(super) year: u8,
}

impl Pcf50633Rtc {
    fn now() -> Self {
        #[cfg(unix)]
        {
            let mut now: libc::time_t = 0;
            // SAFETY: time receives a live, aligned stack time_t pointer and does not retain it.
            let time = unsafe { libc::time(&mut now) };
            if time != -1 {
                // SAFETY: libc::tm integer fields and its nullable zone pointer admit all-zero bits.
                let mut tm: libc::tm = unsafe { std::mem::zeroed() };
                // SAFETY: disjoint live stack values supply valid input/output pointers; localtime_r retains neither.
                let tm_ptr = unsafe { libc::localtime_r(&time, &mut tm) };
                if !tm_ptr.is_null() {
                    return Self {
                        second: int_to_bcd(tm.tm_sec),
                        minute: int_to_bcd(tm.tm_min),
                        hour: int_to_bcd(tm.tm_hour),
                        day: int_to_bcd(tm.tm_mday),
                        month: int_to_bcd(tm.tm_mon + 1),
                        year: int_to_bcd(tm.tm_year - 100),
                    };
                }
            }
        }

        // Keep a valid fallback date for non-Unix hosts or failed libc calls.
        Self {
            second: 0x00,
            minute: 0x00,
            hour: 0x12,
            day: 0x12,
            month: 0x06,
            year: 0x26,
        }
    }
}

fn int_to_bcd(value: i32) -> u8 {
    let value = value.clamp(0, 99) as u8;
    ((value / 10) << 4) | (value % 10)
}

impl Default for Pcf50633 {
    fn default() -> Self {
        Self::new()
    }
}

/// LIS302DL accelerometer stub on I2C0. The kernel only needs the identity
/// register during probe; unmodeled registers read as zero like the reference.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Lis302dl {
    pub(super) cmd: u8,
}

impl Lis302dl {
    pub fn new() -> Self {
        Lis302dl { cmd: 0 }
    }

    pub fn send(&mut self, data: u8) {
        self.cmd = data;
    }

    pub fn recv(&mut self) -> u8 {
        match self.cmd {
            0x0F => 0x3B, // WHOAMI
            _ => 0,
        }
    }
}

impl Default for Lis302dl {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// I2C controller (Samsung S5L IIC)
// =============================================================================

pub(super) const IICCON_ACKEN: u8 = 1 << 7;
pub(super) const IICSTAT_START: u8 = 1 << 5;
pub(super) const IICSTAT_TXRXEN: u8 = 1 << 4;
pub(super) const IICSTAT_LASTBIT: u8 = 1 << 0;
pub(super) const IICSTAT_MR_MODE: u8 = 0x2;
pub(super) const IICSTAT_MT_MODE: u8 = 0x3;

/// S5L8900 I2C master controller. Models enough of the register protocol for
/// iBoot's polled PMU transactions: the `iicreg20` "transfer active" flag the
/// firmware spins on, and data routing to the attached PMU slave.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct S5lI2c {
    pub(super) control: u8,
    pub(super) status: u8,
    pub(super) address: u8,
    pub(super) data: u8,
    pub(super) line_ctrl: u8,
    pub(super) iicreg20: u32,
    pub(super) active: bool,
    pub(super) irq: bool,
    pub(super) addressed: u8,
    pub(super) accel: Option<Lis302dl>,
    /// The PMU slave (present on I2C1; None on buses without one).
    pub(super) pmu: Option<Pcf50633>,
}

impl S5lI2c {
    pub fn new(pmu: bool, accel: bool) -> Self {
        S5lI2c {
            control: 0,
            status: 0,
            address: 0,
            data: 0,
            line_ctrl: 0,
            iicreg20: 0,
            active: false,
            irq: false,
            addressed: 0,
            accel: accel.then(Lis302dl::new),
            pmu: pmu.then(Pcf50633::new),
        }
    }

    fn update_irq(&mut self) {
        // The reference QEMU model computes a level from IICCON/IICSTAT but
        // then unconditionally raises the controller IRQ for transfer progress.
        // It is lowered only at the start of the next I2C register write.
        self.irq = true;
    }

    fn log_pmu_bus(&self, message: &str) {
        if self.pmu.is_some() && std::env::var("RAX_S5L_I2CLOG").is_ok() {
            eprintln!("{message}");
        }
    }

    pub fn irq_pending(&self) -> bool {
        self.irq
    }

    pub fn advance_irq_sample(&mut self) {}

    fn slave_recv(&mut self) -> u8 {
        match self.addressed {
            0x1d => self.accel.as_mut().map(|accel| accel.recv()).unwrap_or(0),
            0x73 => self.pmu.as_mut().map(|pmu| pmu.recv()).unwrap_or(0),
            _ => 0,
        }
    }

    fn slave_send(&mut self, data: u8) {
        match self.addressed {
            0x1d => {
                if let Some(accel) = self.accel.as_mut() {
                    accel.send(data);
                }
            }
            0x73 => {
                if let Some(pmu) = self.pmu.as_mut() {
                    pmu.send(data);
                }
            }
            _ => {}
        }
    }

    pub fn read(&mut self, offset: u32) -> u32 {
        match offset {
            0x00 => self.control as u32,
            0x04 => self.status as u32,
            0x08 => self.address as u32,
            0x0c => {
                // I2CDS read: fetch the next byte from the slave.
                let before = self.data;
                self.iicreg20 |= 0x100;
                self.data = self.slave_recv();
                self.update_irq();
                if self.pmu.is_some() && std::env::var("RAX_S5L_I2CLOG").is_ok() {
                    eprintln!(
                        "I2C1 read I2CDS addressed={:#x} before={:#x} -> {:#x} status={:#x} control={:#x} active={}",
                        self.addressed, before, self.data, self.status, self.control, self.active
                    );
                }
                self.data as u32
            }
            0x10 => self.line_ctrl as u32,
            0x20 => {
                // IICREG20: transfer-status flags, cleared on read.
                let tmp = self.iicreg20;
                self.iicreg20 &= !0x100;
                self.iicreg20 &= !0x2000;
                if self.pmu.is_some() && std::env::var("RAX_S5L_I2CLOG").is_ok() {
                    eprintln!(
                        "I2C1 read IICREG20 -> {tmp:#x} after={:#x} status={:#x} control={:#x} active={} addressed={:#x} irq={}",
                        self.iicreg20,
                        self.status,
                        self.control,
                        self.active,
                        self.addressed,
                        self.irq
                    );
                }
                tmp
            }
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        let v = value as u8;
        self.irq = false;
        match offset {
            0x00 => {
                // I2CCON
                if self.pmu.is_some() && std::env::var("RAX_S5L_I2CLOG").is_ok() {
                    eprintln!(
                        "I2C1 write I2CCON value={:#x} old_control={:#x} status={:#x} active={} addressed={:#x}",
                        v, self.control, self.status, self.active, self.addressed
                    );
                }
                if value & !(IICCON_ACKEN as u32) != 0 {
                    self.iicreg20 |= 0x100;
                }
                if (value & 0x10) != 0 && self.status == 0x90 {
                    self.iicreg20 |= 0x2000;
                }
                self.control = v;
                self.update_irq();
                if self.pmu.is_some() && std::env::var("RAX_S5L_I2CLOG").is_ok() {
                    eprintln!(
                        "I2C1 after I2CCON status={:#x} control={:#x} iicreg20={:#x} active={} irq={}",
                        self.status,
                        self.control,
                        self.iicreg20,
                        self.active,
                        self.irq_pending()
                    );
                }
            }
            0x04 => {
                // I2CSTAT: mode + start/stop control.
                let old_mode = (self.status >> 6) & 0x3;
                let new_mode = (v >> 6) & 0x3;
                if self.pmu.is_some() && std::env::var("RAX_S5L_I2CLOG").is_ok() {
                    eprintln!(
                        "I2C1 write I2CSTAT value={:#x} old_status={:#x} old_mode={} new_mode={} active={} data={:#x} addressed={:#x}",
                        v, self.status, old_mode, new_mode, self.active, self.data, self.addressed
                    );
                }
                if !self.active && old_mode != new_mode {
                    self.status = v;
                } else if self.active && old_mode != new_mode {
                    self.active = false;
                    self.status = v | IICSTAT_TXRXEN;
                    return;
                }
                let mode = (self.status >> 6) & 0x3;
                if (value as u8) & IICSTAT_TXRXEN != 0 {
                    match mode {
                        0 | 1 => {
                            // Slave receive/transmit: pull a byte.
                            self.data = self.slave_recv();
                        }
                        IICSTAT_MR_MODE | IICSTAT_MT_MODE => {
                            if (value as u8) & IICSTAT_START != 0 {
                                self.status &= !IICSTAT_LASTBIT;
                                self.iicreg20 |= 0x100;
                                self.active = true;
                                self.addressed = self.data >> 1;
                                if self.pmu.is_some() && std::env::var("RAX_S5L_I2CLOG").is_ok() {
                                    eprintln!(
                                        "I2C1 start mode={} addressed={:#x} rw={} data={:#x}",
                                        mode,
                                        self.addressed,
                                        self.data & 1,
                                        self.data
                                    );
                                }
                            } else {
                                self.active = false;
                                self.status |= IICSTAT_TXRXEN;
                                self.log_pmu_bus("I2C1 stop transfer");
                            }
                        }
                        _ => {}
                    }
                }
                self.status = v;
                self.update_irq();
            }
            0x08 => self.address = v,
            0x0c => {
                // I2CDS write: send a byte to the slave.
                self.iicreg20 |= 0x100;
                self.data = v;
                let mode = (self.status >> 6) & 0x3;
                if self.pmu.is_some() && std::env::var("RAX_S5L_I2CLOG").is_ok() {
                    eprintln!(
                        "I2C1 write I2CDS value={:#x} status={:#x} mode={} control={:#x} active={} addressed={:#x} will_send={}",
                        v,
                        self.status,
                        mode,
                        self.control,
                        self.active,
                        self.addressed,
                        self.active && mode == IICSTAT_MT_MODE
                    );
                }
                if self.active && mode == IICSTAT_MT_MODE {
                    self.slave_send(v);
                }
                self.update_irq();
            }
            0x10 => self.line_ctrl = v,
            _ => {}
        }
    }
}

impl Default for S5lI2c {
    fn default() -> Self {
        Self::new(false, false)
    }
}
