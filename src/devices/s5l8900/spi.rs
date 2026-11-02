use std::collections::VecDeque;
// =============================================================================
// SPI controller (Apple/S5L SPI) + attached peripherals
// =============================================================================

/// An SSI peripheral attached to an SPI bus. `transfer` exchanges one byte.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(super) enum SpiPeripheral {
    /// No device — reads back zero.
    None,
    /// The LCD panel (on SPI1): responds to ID/info commands.
    LcdPanel { cur_cmd: u8 },
    /// The multitouch controller (on SPI2): enough of the HBPP protocol for boot.
    Multitouch(MultitouchSpi),
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct MultitouchSpi {
    pub(super) cur_cmd: u8,
    #[serde(deserialize_with = "super::context::bytes")]
    pub(super) out: Vec<u8>,
    #[serde(deserialize_with = "super::context::bytes")]
    pub(super) input: Vec<u8>,
    pub(super) pos: usize,
    pub(super) hbpp_ack: [u8; 2],
    pub(super) trace: bool,
}

impl MultitouchSpi {
    fn new() -> Self {
        Self {
            cur_cmd: 0,
            out: Vec::new(),
            input: Vec::new(),
            pos: 0,
            hbpp_ack: [0, 0],
            trace: std::env::var("RAX_S5L_MT_SPI_LOG").is_ok(),
        }
    }

    fn hex_prefix(bytes: &[u8], max_len: usize) -> String {
        let mut out = String::new();
        for b in bytes.iter().take(max_len) {
            out.push_str(&format!("{b:02x}"));
        }
        if bytes.len() > max_len {
            out.push_str("...");
        }
        out
    }

    fn checksum_response(out: &mut [u8]) {
        if out.len() < 16 {
            return;
        }
        let checksum: u16 = out.iter().take(14).map(|&b| b as u16).sum();
        out[14] = checksum as u8;
        out[15] = (checksum >> 8) as u8;
    }

    fn report_size(report_id: u8) -> u16 {
        match report_id {
            0x70 => 0x1,
            0xd1 => 0x1,
            0xd3 => 0x5,
            0xd0 => 0x1,
            0xa1 => 0x1,
            0xd9 => 0x8,
            _ => 0,
        }
    }

    fn start_command(&mut self, cmd: u8) {
        self.cur_cmd = cmd;
        self.input.clear();
        self.pos = 0;
        self.out.clear();

        match cmd {
            0x18 => self.out = vec![0x18, 0xe1],
            0x1a => {
                self.out = if self.hbpp_ack == [0, 0] {
                    vec![0x4b, 0xc1]
                } else {
                    self.hbpp_ack.to_vec()
                };
            }
            0x1c => self.out = vec![0; 8],
            0x1d => self.out = vec![0; 12],
            0x1e => self.out = vec![0; 16],
            0x1f => self.out = vec![0x1f, 0],
            0x30 => {
                self.out = vec![0; 20];
                self.out[0] = 0x30;
            }
            0x47 => self.out = vec![0x47, 0],
            0xe1 => {
                self.out = vec![0; 16];
                self.out[0] = 0xe1;
                Self::checksum_response(&mut self.out);
            }
            0xe2 => {
                self.out = vec![0; 16];
                self.out[0] = 0xe2;
                self.out[2] = 0x01; // interface version
                self.out[3] = 0x94; // max packet size 0x294
                self.out[4] = 0x02;
                Self::checksum_response(&mut self.out);
            }
            0xe3 | 0xe4 | 0xe6 => {
                self.out = vec![0; 16];
                self.out[0] = cmd;
                Self::checksum_response(&mut self.out);
            }
            0xea => self.out = vec![0; 16],
            _ => self.out = vec![0],
        }
        if self.trace {
            tracing::info!(
                cmd = format!("{cmd:#x}"),
                out_len = self.out.len(),
                "multitouch spi command start"
            );
        }
    }

    fn prepare_report_info(&mut self, report_id: u8) {
        self.out.fill(0);
        self.out[0] = 0xe3;
        self.out[2] = 0;
        let len = Self::report_size(report_id);
        self.out[3] = len as u8;
        self.out[4] = (len >> 8) as u8;
        Self::checksum_response(&mut self.out);
    }

    fn prepare_short_control_read(&mut self, report_id: u8) {
        self.out.fill(0);
        self.out[0] = 0xe6;
        match report_id {
            0xd1 => self.out[3] = 81, // family ID
            0xd3 => {
                self.out[3] = 0x01; // little endian
                self.out[4] = 15; // sensor rows
                self.out[5] = 10; // sensor columns
                self.out[6] = 51; // BCD version
                self.out[7] = 0;
            }
            0xd0 | 0xa1 => self.out[3] = 0,
            0xd9 => {
                self.out[3..7].copy_from_slice(&5000u32.to_le_bytes());
                self.out[7..11].copy_from_slice(&7500u32.to_le_bytes());
            }
            _ => {}
        }
        Self::checksum_response(&mut self.out);
    }

    fn transfer(&mut self, value: u8) -> u8 {
        if self.cur_cmd == 0 {
            self.start_command(value);
        }

        self.input.push(value);
        match self.cur_cmd {
            0x30 if self.input.len() == 10 => {
                let len = ((self.input[2] as usize) << 10) | (((self.input[3] as usize) << 2) + 5);
                self.out = vec![0; len.max(1)];
                self.pos = 0;
            }
            0xe3 if self.input.len() == 2 => self.prepare_report_info(self.input[1]),
            0xe6 if self.input.len() == 2 => self.prepare_short_control_read(self.input[1]),
            _ => {}
        }

        let ret = self.out.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        if self.pos >= self.out.len() {
            if self.trace {
                tracing::info!(
                    cmd = format!("{:#x}", self.cur_cmd),
                    in_len = self.input.len(),
                    in_hex = Self::hex_prefix(&self.input, 32),
                    out_len = self.out.len(),
                    out_hex = Self::hex_prefix(&self.out, 32),
                    hbpp_ack = format!("{:02x}{:02x}", self.hbpp_ack[0], self.hbpp_ack[1]),
                    "multitouch spi command done"
                );
            }
            if self.cur_cmd == 0x1e {
                self.hbpp_ack = [0x4a, 0xd1];
            }
            self.cur_cmd = 0;
            self.pos = 0;
        }
        ret
    }
}

impl SpiPeripheral {
    fn transfer(&mut self, value: u8) -> u8 {
        match self {
            SpiPeripheral::None => 0,
            SpiPeripheral::Multitouch(mt) => mt.transfer(value),
            SpiPeripheral::LcdPanel { cur_cmd } => {
                if *cur_cmd == 0 && matches!(value, 0x95 | 0xDA | 0xDB | 0xDC) {
                    *cur_cmd = value;
                    return 0;
                }
                if *cur_cmd != 0 {
                    let res = match *cur_cmd {
                        0x95 => 0x01,
                        0xDA => 0x71, // panel ID byte 0
                        0xDB => 0xC2, // panel ID byte 1
                        0xDC => 0x00,
                        _ => 0,
                    };
                    *cur_cmd = 0;
                    return res;
                }
                0
            }
        }
    }
}

pub(super) const SPI_CTRL: u32 = 0x000;
pub(super) const SPI_CFG: u32 = 0x004;
pub(super) const SPI_STATUS: u32 = 0x008;
pub(super) const SPI_PIN: u32 = 0x00c;
pub(super) const SPI_TXDATA: u32 = 0x010;
pub(super) const SPI_RXDATA: u32 = 0x020;
pub(super) const SPI_RXCNT: u32 = 0x034;

pub(super) const CTRL_RUN: u32 = 1 << 0;
pub(super) const CTRL_TX_RESET: u32 = 1 << 2;
pub(super) const CTRL_RX_RESET: u32 = 1 << 3;
pub(super) const CFG_AGD: u32 = 1 << 0;
pub(super) const CFG_IE_RXREADY: u32 = 1 << 7;
pub(super) const CFG_IE_TXEMPTY: u32 = 1 << 8;
pub(super) const CFG_IE_COMPLETE: u32 = 1 << 21;
pub(super) const STATUS_RXREADY: u32 = 1 << 0;
pub(super) const STATUS_TXEMPTY: u32 = 1 << 1;
pub(super) const STATUS_COMPLETE: u32 = 1 << 22;
pub(super) const STATUS_TXFIFO_SHIFT: u32 = 4;
pub(super) const STATUS_RXFIFO_SHIFT: u32 = 8;
pub(super) const STATUS_TXFIFO_MASK: u32 = 31 << STATUS_TXFIFO_SHIFT;
pub(super) const STATUS_RXFIFO_MASK: u32 = 31 << STATUS_RXFIFO_SHIFT;

/// Hard cap on buffered receive bytes. RXCNT is a guest-controlled 32-bit MMIO
/// register, and `run()` pushes one byte into the host `rx` VecDeque per count;
/// without a bound a single `CFG_AGD`/RUN write with RXCNT near `u32::MAX` would
/// force billions of iterations and multi-GB host allocation (DoS). The guest
/// drains received bytes through RXDATA, which re-triggers `run()` to refill, so
/// any real transfer still completes — just in FIFO-sized chunks. (issue #47)
pub(super) const SPI_RX_FIFO_MAX: usize = 0x10000;

/// Apple/S5L SPI master. iBoot drives it in polled mode: reset FIFOs, push TX
/// bytes, set RXCNT, RUN, then poll STATUS for COMPLETE and drain RXDATA.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct S5lSpi {
    #[serde(
        serialize_with = "crate::devices::checkpoint_serde::serialize_array",
        deserialize_with = "crate::devices::checkpoint_serde::array::<u32, _, 64>"
    )]
    pub(super) regs: [u32; 64],
    #[serde(deserialize_with = "super::context::queue")]
    pub(super) tx: VecDeque<u8>,
    #[serde(deserialize_with = "super::context::queue")]
    pub(super) rx: VecDeque<u8>,
    pub(super) peripheral: SpiPeripheral,
}

impl S5lSpi {
    /// `index` selects the attached peripheral (0=none, 1=LCD panel,
    /// 2=multitouch), matching the S5L8900 machine wiring.
    pub fn new(index: u8) -> Self {
        let peripheral = match index {
            1 => SpiPeripheral::LcdPanel { cur_cmd: 0 },
            2 => SpiPeripheral::Multitouch(MultitouchSpi::new()),
            _ => SpiPeripheral::None,
        };
        S5lSpi {
            regs: [0; 64],
            tx: VecDeque::new(),
            rx: VecDeque::new(),
            peripheral,
        }
    }

    fn word_size(&self) -> usize {
        match (self.regs[(SPI_CFG >> 2) as usize] >> 13) & 0x3 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 1,
        }
    }

    fn run(&mut self) {
        let ctrl_i = (SPI_CTRL >> 2) as usize;
        let status_i = (SPI_STATUS >> 2) as usize;
        let cfg_i = (SPI_CFG >> 2) as usize;
        let rxcnt_i = (SPI_RXCNT >> 2) as usize;
        if self.regs[ctrl_i] & CTRL_RUN == 0 {
            return;
        }
        while let Some(tx) = self.tx.pop_front() {
            let rx = self.peripheral.transfer(tx);
            if self.tx.is_empty() {
                self.regs[status_i] |= STATUS_TXEMPTY;
            }
            // Stop receiving once the host FIFO is full (see SPI_RX_FIFO_MAX); the
            // guest must drain RXDATA to make room, which re-triggers run().
            if self.regs[rxcnt_i] > 0 && self.rx.len() < SPI_RX_FIFO_MAX {
                self.rx.push_back(rx);
                self.regs[rxcnt_i] -= 1;
                self.regs[status_i] |= STATUS_RXREADY;
            }
        }
        // Auto-get-data: fetch the remaining receive bytes with sentinels, but
        // never grow the host rx FIFO past SPI_RX_FIFO_MAX in a single run so a
        // guest-controlled RXCNT cannot drive an unbounded loop/allocation.
        while self.regs[rxcnt_i] > 0
            && self.regs[cfg_i] & CFG_AGD != 0
            && self.rx.len() < SPI_RX_FIFO_MAX
        {
            let rx = self.peripheral.transfer(0xff);
            self.rx.push_back(rx);
            self.regs[rxcnt_i] -= 1;
            self.regs[status_i] |= STATUS_RXREADY;
        }
        if self.regs[rxcnt_i] == 0 && self.tx.is_empty() {
            self.regs[status_i] |= STATUS_COMPLETE;
            self.regs[ctrl_i] &= !CTRL_RUN;
        }
    }

    /// SPI interrupt line level: asserted when a status bit whose
    /// interrupt-enable bit is set in CFG is active (matches the QEMU
    /// `apple_spi_update_irq`). The panel-init driver does an IRQ-driven blocking
    /// transfer (enables IE_COMPLETE and sleeps until the controller signals),
    /// so this IRQ is what wakes it.
    pub fn irq_pending(&self) -> bool {
        let cfg = self.regs[(SPI_CFG >> 2) as usize];
        let status = self.regs[(SPI_STATUS >> 2) as usize];
        let mut mask = 0;
        if cfg & CFG_IE_RXREADY != 0 {
            mask |= STATUS_RXREADY;
        }
        if cfg & CFG_IE_TXEMPTY != 0 {
            mask |= STATUS_TXEMPTY;
        }
        if cfg & CFG_IE_COMPLETE != 0 {
            mask |= STATUS_COMPLETE;
        }
        status & mask != 0
    }

    pub fn read(&mut self, offset: u32) -> u32 {
        let idx = (offset >> 2) as usize;
        if idx >= self.regs.len() {
            return 0;
        }
        let mut r = self.regs[idx];
        let mut run = false;
        match offset {
            SPI_RXDATA => {
                let ws = self.word_size();
                let mut bytes = [0u8; 4];
                for b in bytes.iter_mut().take(ws) {
                    *b = self.rx.pop_front().unwrap_or(0);
                }
                r = u32::from_le_bytes(bytes);
                if self.rx.is_empty() {
                    run = true;
                }
            }
            SPI_STATUS => {
                let mut val = (self.tx.len() as u32) << STATUS_TXFIFO_SHIFT;
                val |= (self.rx.len() as u32) << STATUS_RXFIFO_SHIFT;
                val &= STATUS_TXFIFO_MASK | STATUS_RXFIFO_MASK;
                r &= !(STATUS_TXFIFO_MASK | STATUS_RXFIFO_MASK);
                r |= val;
            }
            _ => {}
        }
        if run {
            self.run();
        }
        r
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        let idx = (offset >> 2) as usize;
        if idx >= self.regs.len() {
            return;
        }
        let mut run = false;
        match offset {
            SPI_CTRL => {
                if value & CTRL_TX_RESET != 0 {
                    self.tx.clear();
                }
                if value & CTRL_RX_RESET != 0 {
                    self.rx.clear();
                }
                if value & CTRL_RUN != 0 && !self.tx.is_empty() {
                    run = true;
                }
                // The TX/RX FIFO-reset bits are self-clearing: the panel-init
                // SPI driver sets them and then polls for them to clear before
                // proceeding, so they must read back as 0.
                self.regs[idx] = value & !(CTRL_TX_RESET | CTRL_RX_RESET);
            }
            SPI_STATUS => {
                // Write-1-to-clear.
                self.regs[idx] &= !value;
                run = true;
            }
            SPI_TXDATA..=0x013 => {
                let ws = self.word_size();
                for b in value.to_le_bytes().iter().take(ws) {
                    self.tx.push_back(*b);
                }
                self.regs[idx] = value;
            }
            SPI_CFG => {
                self.regs[idx] = value;
                run = true;
            }
            SPI_PIN => self.regs[idx] = value,
            _ => self.regs[idx] = value,
        }
        if run {
            self.run();
        }
    }
}
