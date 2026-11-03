//! GSC memory transactions and shared physical LR/SC reservations.
use super::*;

impl Memory for GscBridge {
    fn atomic(
        &mut self,
        address: u64,
        size: u8,
        operation: crate::isa::riscv::memory::AtomicOp,
    ) -> MemResult<u128> {
        operation.validate(address, size)?;
        self.reservation_ram(address, usize::from(size))?;
        let old = crate::isa::riscv::memory::shared::atomic(
            &self.mem,
            &self.exclusive,
            address,
            size,
            operation,
        )?;
        if let Some(new) = operation.replacement(old, size) {
            self.trace_ram_write(address, &new.to_le_bytes()[..usize::from(size)]);
        }
        Ok(old)
    }

    fn load_reserved(&mut self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        self.reservation_ram(addr, buf.len())?;
        crate::isa::riscv::memory::shared::load(&self.mem, &self.exclusive, addr, buf)
    }

    fn store_conditional(&mut self, addr: u64, data: &[u8], eligible: bool) -> MemResult<bool> {
        self.reservation_ram(addr, data.len())?;
        crate::isa::riscv::memory::shared::store(&self.mem, &self.exclusive, addr, data, eligible)
    }

    fn clear_reservation(&mut self) {
        self.exclusive.clear();
    }

    fn probe(&self, addr: u64, size: usize, _write: bool) -> MemResult<()> {
        if in_core_local(addr) || in_mmio(addr) || self.mem.check_range(GuestAddress(addr), size) {
            Ok(())
        } else {
            Err(MemError::OutOfBounds { addr, size })
        }
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> MemResult<()> {
        if in_core_local(addr) {
            let v = if addr == CORE_IRQ_CLAIM {
                if self.uart_irq_pending() {
                    CORE_IRQ_UART0
                } else {
                    CORE_IRQ_NONE
                }
            } else if addr == CORE_IRQ_EPOCH {
                0
            } else {
                self.shared
                    .lock()
                    .unwrap()
                    .store
                    .get(&addr)
                    .copied()
                    .unwrap_or(self.cfg.open_bus)
            };
            self.note(addr, false, v);
            fill_le_word(buf, v);
            return Ok(());
        }
        if in_mmio(addr) {
            // The PMU reset-source register is stateful (cold = POR, warm =
            // software reset; cleared by CLRRST), so the firmware classifies the
            // reset cause instead of seeing "Other" and rebooting forever.
            if addr == PMU_RSTSRC_REG {
                let v = self.shared.lock().unwrap().rstsrc;
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if addr == PMU_CHIP_ID_REG || addr == PMU_CHIP_ID_ALT_REG {
                self.note(addr, false, PMU_CHIP_ID);
                fill_le_word(buf, PMU_CHIP_ID);
                return Ok(());
            }
            if addr == PMU_WAKE_EXIT_SRC_REG {
                self.note(addr, false, 0);
                fill_le_word(buf, 0);
                return Ok(());
            }
            // Flash controller ERROR (+0x9c) and STATUS (+0x18/+0x1c) read 0 (op
            // complete, no error). Read commands fill DOUT0/1; program/erase
            // commands update either the mapped XIP image or the separate blank
            // INFO-bank store.
            if matches!(addr, FLASH_ERROR | FLASH_STATUS0 | FLASH_STATUS1) {
                let v = if addr == FLASH_ERROR {
                    self.shared.lock().unwrap().flash_error
                } else {
                    0
                };
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if matches!(
                addr,
                FLASH_DOUT0_LO | FLASH_DOUT0_HI | FLASH_DOUT1_LO | FLASH_DOUT1_HI
            ) {
                let lane = usize::from(matches!(addr, FLASH_DOUT1_LO | FLASH_DOUT1_HI));
                let word = usize::from(matches!(addr, FLASH_DOUT0_HI | FLASH_DOUT1_HI));
                let v = self.shared.lock().unwrap().flash_dout[lane][word];
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if let Some(v) = self.globalsec_region_word(addr) {
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if addr == GSC_EVENT_USB_RESET {
                let v = 0x8000_0000;
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if addr == USB_SOFT_RESET || is_usb_w1c_status(addr) {
                self.note(addr, false, 0);
                fill_le_word(buf, 0);
                return Ok(());
            }
            if addr == RBOX_STATUS {
                let sh = self.shared.lock().unwrap();
                let control0_ack = sh.store.get(&RBOX_CONTROL0).copied().unwrap_or(0) & 1;
                let control1 = sh.store.get(&RBOX_CONTROL1).copied().unwrap_or(1) & 1;
                let control1_ack = (control1 ^ 1) << 5;
                let v = control0_ack | control1_ack;
                drop(sh);
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if addr == RBOX_INIT_READY {
                self.note(addr, false, 1);
                fill_le_word(buf, 1);
                return Ok(());
            }
            if addr == RBOX_CMD_STATUS {
                self.note(addr, false, 0);
                fill_le_word(buf, 0);
                return Ok(());
            }
            if is_rbox_w1c_status(addr) {
                let v = self
                    .shared
                    .lock()
                    .unwrap()
                    .store
                    .get(&addr)
                    .copied()
                    .unwrap_or(0);
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if let Some(off) = ap_spi_data_offset(addr) {
                let mut word = [0u8; 4];
                {
                    let sh = self.shared.lock().unwrap();
                    for (i, b) in buf.iter_mut().enumerate() {
                        *b = sh.ap_spi_data.get(off + i).copied().unwrap_or(0);
                    }
                    for (i, b) in word.iter_mut().enumerate() {
                        *b = sh.ap_spi_data.get(off + i).copied().unwrap_or(0);
                    }
                }
                self.note(addr, false, u32::from_le_bytes(word));
                return Ok(());
            }
            // GscFifo dual-port command/response RAM: byte-accurate reads so the
            // firmware reads the staged TPM command (and its own response) from
            // the real FIFO window.
            if let Some(off) = fifo_ram_offset(addr) {
                let sh = self.shared.lock().unwrap();
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = sh.fifo_ram.get(off + i).copied().unwrap_or(0);
                }
                return Ok(());
            }
            if addr == AP_SPI_XACT {
                let v = self
                    .shared
                    .lock()
                    .unwrap()
                    .store
                    .get(&addr)
                    .copied()
                    .unwrap_or(0)
                    & !AP_SPI_XACT_START;
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if is_ap_spi_w1c_status(addr) {
                let v = self
                    .shared
                    .lock()
                    .unwrap()
                    .store
                    .get(&addr)
                    .copied()
                    .unwrap_or(0);
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if is_ap_spi(addr) {
                let v = self
                    .shared
                    .lock()
                    .unwrap()
                    .store
                    .get(&addr)
                    .copied()
                    .unwrap_or(0);
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if addr == GSC_FIFO_CONTROL {
                let v = self
                    .shared
                    .lock()
                    .unwrap()
                    .store
                    .get(&addr)
                    .copied()
                    .unwrap_or(0)
                    & !GSC_FIFO_RESET_BUSY_MASK;
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if addr == GSC_FIFO_IRQ_STATUS {
                self.note(addr, false, 0);
                fill_le_word(buf, 0);
                return Ok(());
            }
            if is_gsc_fifo_w1c_status(addr) {
                let v = self
                    .shared
                    .lock()
                    .unwrap()
                    .store
                    .get(&addr)
                    .copied()
                    .unwrap_or(0);
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if self.in_uart(addr) {
                let off = addr - self.cfg.uart_base;
                if off == UART_RDATA {
                    let v = {
                        let mut sh = self.shared.lock().unwrap();
                        if sh.uart_irq_armed {
                            sh.uart_rx.pop_front().map(u32::from)
                        } else {
                            None
                        }
                    }
                    .unwrap_or(self.cfg.open_bus);
                    self.note(addr, false, v);
                    fill_le_word(buf, v);
                    return Ok(());
                }
                if off == UART_STATE {
                    let rx_empty = {
                        let sh = self.shared.lock().unwrap();
                        !sh.uart_irq_armed || sh.uart_rx.is_empty()
                    };
                    let mut v = self.cfg.uart_state & !UART_STATE_TX_BUSY;
                    if rx_empty {
                        v |= UART_STATE_RX_EMPTY;
                    } else {
                        v &= !UART_STATE_RX_EMPTY;
                    }
                    self.note(addr, false, v);
                    fill_le_word(buf, v);
                    return Ok(());
                }
            }
            if addr == TRNG_READ_DATA {
                let v = {
                    let mut sh = self.shared.lock().unwrap();
                    if sh.trng_state == 0 {
                        sh.trng_state = 0x6d5a_56a5;
                    }
                    let mut x = sh.trng_state;
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    sh.trng_state = x;
                    x
                };
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if is_gpio_input_bank(addr) {
                let v = self.ready.get(&addr).copied().unwrap_or_else(|| {
                    self.shared
                        .lock()
                        .unwrap()
                        .store
                        .get(&addr)
                        .copied()
                        .unwrap_or(0)
                });
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if is_gpio_w1c_status(addr) {
                let v = self
                    .shared
                    .lock()
                    .unwrap()
                    .store
                    .get(&addr)
                    .copied()
                    .unwrap_or(0);
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if is_gpio_cfg(addr) {
                let v = self
                    .shared
                    .lock()
                    .unwrap()
                    .store
                    .get(&addr)
                    .copied()
                    .unwrap_or(0);
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if (FUSE_BASE..FUSE_TOP).contains(&addr) {
                let v = self
                    .shared
                    .lock()
                    .unwrap()
                    .store
                    .get(&addr)
                    .copied()
                    .unwrap_or(FUSE_DEFAULT);
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            // Free-running 64-bit timer/counter: the firmware reads `now` as
            // `PAIR64(+0x1C, +0x14)`. Derive it from the retired-instruction
            // count so the firmware's millisecond timestamps advance. The busy
            // status (`+0x78`) always reads "ready" (0). Other timer registers
            // (enable/prescale/masks) fall through to the persistent store,
            // which already holds the values the init routine wrote.
            if matches!(
                addr,
                TIMER_COUNT_LO | TIMER_COUNT_HI | TIMER2_COUNT_LO | TIMER2_COUNT_HI
            ) {
                let ticks = self.timer_ticks();
                let v = if addr == TIMER_COUNT_LO || addr == TIMER2_COUNT_LO {
                    ticks as u32
                } else {
                    (ticks >> 32) as u32
                };
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            if addr == TIMER_BUSY || addr == TIMER2_BUSY {
                self.note(addr, false, 0);
                fill_le_word(buf, 0);
                return Ok(());
            }
            // DRBG/CSRNG keymgr: report "operation done, success" (`+0x10`
            // bits[2:0] == 1) and a non-zero PRNG for the 256-bit output files,
            // so the firmware's instantiate/generate succeeds instead of
            // failing and downstream key/entropy material is non-zero.
            if addr == DRBG_STATUS {
                self.note(addr, false, 1);
                fill_le_word(buf, 1);
                return Ok(());
            }
            if (DRBG_OUT_LO..DRBG_OUT_LO + DRBG_OUT_LEN).contains(&addr)
                || (DRBG_OUT_HI..DRBG_OUT_HI + DRBG_OUT_LEN).contains(&addr)
            {
                let v = self.drbg_word(addr);
                self.note(addr, false, v);
                fill_le_word(buf, v);
                return Ok(());
            }
            // UART registers go through the normal ready/store path so the
            // firmware sees a consistent device (STATE is a fixed "TX ready" in
            // the ready map; WDATA writes are tapped for console output below).
            let word = if let Some(&v) = self.ready.get(&addr) {
                v
            } else {
                // Persistent register read with the generic spin-breaker: an
                // unmodeled register polled many times with no intervening
                // write is almost certainly a "wait for ready" loop, so return
                // all-ones once to break it.
                let mut sh = self.shared.lock().unwrap();
                let base = sh.store.get(&addr).copied().unwrap_or(self.cfg.open_bus);
                let c = sh.read_counts.entry(addr).or_insert(0);
                *c += 1;
                if *c >= SPIN_THRESHOLD {
                    *c = 0;
                    // Alternate the break value so "wait for set" (needs ones)
                    // and "wait for clear" (needs zeros) loops both resolve.
                    let phase = sh.spin_phase.entry(addr).or_insert(false);
                    *phase = !*phase;
                    if *phase { 0xffff_ffff } else { 0x0000_0000 }
                } else {
                    base
                }
            };
            self.note(addr, false, word);
            fill_le_word(buf, word);
            return Ok(());
        }
        self.exclusive
            .read(&self.mem, addr, buf)
            .map_err(|_| MemError::OutOfBounds {
                addr,
                size: buf.len(),
            })
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> MemResult<()> {
        if in_core_local(addr) {
            let mut word = [0u8; 4];
            let n = data.len().min(4);
            word[..n].copy_from_slice(&data[..n]);
            let value = u32::from_le_bytes(word);
            self.shared.lock().unwrap().store.insert(addr, value);
            self.note(addr, true, value);
            return Ok(());
        }
        if in_mmio(addr) {
            let mut word = [0u8; 4];
            let n = data.len().min(4);
            word[..n].copy_from_slice(&data[..n]);
            let value = u32::from_le_bytes(word);
            let mut flash_op = None;
            let mut ap_spi_xact = None;
            if let Some(off) = ap_spi_data_offset(addr) {
                {
                    let mut sh = self.shared.lock().unwrap();
                    sh.read_counts.clear();
                    if sh.ap_spi_data.len() != AP_SPI_DATA_LEN {
                        sh.ap_spi_data.resize(AP_SPI_DATA_LEN, 0);
                    }
                    for (i, b) in data.iter().copied().enumerate() {
                        if off + i < AP_SPI_DATA_LEN {
                            sh.ap_spi_data[off + i] = b;
                        }
                    }
                }
                self.note(addr, true, value);
                return Ok(());
            }
            // GscFifo dual-port RAM: byte-accurate writes (the firmware writes
            // its TPM response into this real FIFO window).
            if let Some(off) = fifo_ram_offset(addr) {
                let mut sh = self.shared.lock().unwrap();
                sh.read_counts.clear();
                if sh.fifo_ram.len() != GSC_FIFO_RAM_LEN {
                    sh.fifo_ram.resize(GSC_FIFO_RAM_LEN, 0);
                }
                for (i, b) in data.iter().copied().enumerate() {
                    if off + i < GSC_FIFO_RAM_LEN {
                        sh.fifo_ram[off + i] = b;
                    }
                }
                self.note(addr, true, value);
                return Ok(());
            }
            {
                let mut sh = self.shared.lock().unwrap();
                // A write is forward progress: reset the spin-breaker window.
                sh.read_counts.clear();
                let stored = if is_gpio_w1c_status(addr) {
                    sh.store.get(&addr).copied().unwrap_or(0) & !value
                } else if is_rbox_w1c_status(addr) {
                    sh.store.get(&addr).copied().unwrap_or(0) & !value
                } else if is_ap_spi_w1c_status(addr) {
                    sh.store.get(&addr).copied().unwrap_or(0) & !value
                } else if addr == AP_SPI_XACT && value & AP_SPI_XACT_START != 0 {
                    value & !AP_SPI_XACT_START
                } else if is_gsc_fifo_w1c_status(addr) {
                    sh.store.get(&addr).copied().unwrap_or(0) & !value
                } else if addr == USB_SOFT_RESET || is_usb_w1c_status(addr) {
                    0
                } else {
                    value
                };
                sh.store.insert(addr, stored);
                // Machine-timer alarm compare: the firmware writes the 64-bit
                // deadline (low `+0x2C`, high `+0x34`); init disarms with -1.
                // The run loop raises MTIP once the counter reaches it.
                if addr == TIMER_COMPARE_LO {
                    sh.timer_compare = (sh.timer_compare & 0xffff_ffff_0000_0000) | value as u64;
                } else if addr == TIMER_COMPARE_HI {
                    sh.timer_compare =
                        (sh.timer_compare & 0x0000_0000_ffff_ffff) | ((value as u64) << 32);
                }
                if addr == PMU_CLRRST_REG {
                    // CLRRST: clear the reported reset-source bits.
                    sh.rstsrc &= !value;
                }
                if addr == PMU_RESET_REG && value == PMU_RESET_MAGIC {
                    sh.reset_requested = true;
                }
                if addr == AP_SPI_XACT && value & AP_SPI_XACT_START != 0 {
                    ap_spi_xact = Some(value);
                }
                // Flash controller programming sequence.
                if addr == FLASH_PE_EN {
                    sh.flash_pe_en = value == FLASH_PE_EN_MAGIC;
                } else if addr == FLASH_READ_TRANS {
                    sh.flash_read_trans = value;
                } else if addr == FLASH_TRANS {
                    sh.flash_trans = value;
                } else if addr == FLASH_WR_DATA0 {
                    sh.flash_wr_data[0] = value;
                } else if addr == FLASH_WR_DATA1 {
                    sh.flash_wr_data[1] = value;
                } else if is_flash_control(addr) && sh.flash_pe_en {
                    flash_op = Some((
                        addr,
                        value,
                        sh.flash_trans,
                        sh.flash_read_trans,
                        sh.flash_wr_data,
                    ));
                    sh.flash_pe_en = false;
                    sh.store.insert(addr, 0);
                }
            }
            if let Some((control, opcode, trans, read_trans, wr_data)) = flash_op {
                let dout = self.execute_flash_op(control, opcode, trans, read_trans, wr_data);
                let mut sh = self.shared.lock().unwrap();
                sh.flash_dout[flash_control_index(control)] = dout;
                sh.flash_error = 0;
                sh.store.insert(control, 0);
            }
            if let Some(xact) = ap_spi_xact {
                let stored = self.execute_ap_spi_transaction(xact);
                self.shared
                    .lock()
                    .unwrap()
                    .store
                    .insert(AP_SPI_XACT, stored);
            }
            self.note(addr, true, value);
            // Console sniffer: any byte-sized printable write to an MMIO
            // register is a candidate UART TX — log it so the real console base
            // can be discovered.
            if self.cfg.trace != Trace::Off {
                let b = value & 0xff;
                let printable = (0x20..0x7f).contains(&b) || b == 0x0a || b == 0x0d || b == 0x09;
                if value <= 0xff && printable {
                    eprintln!(
                        "[gsc] {:#010x} CONSOLE? {:#010x} <- {:#04x} '{}'",
                        self.pc.load(Ordering::Relaxed),
                        addr,
                        b,
                        b as u8 as char
                    );
                }
            }
            if self.in_uart(addr) && addr - self.cfg.uart_base == UART_WDATA {
                self.console_out((value & 0xff) as u8);
            }
            return Ok(());
        }
        self.trace_ram_write(addr, data);
        crate::vm::memory::reservations::write(&self.mem, addr, data).map_err(|_| {
            MemError::OutOfBounds {
                addr,
                size: data.len(),
            }
        })
    }
}

impl GscBridge {
    fn trace_ram_write(&self, addr: u64, data: &[u8]) {
        if self.cfg.trace != Trace::Off
            && (self.cfg.flash_img_base..self.cfg.flash_img_base + 0x10_0000).contains(&addr)
        {
            let mut word = [0u8; 4];
            let n = data.len().min(4);
            word[..n].copy_from_slice(&data[..n]);
            let value = u32::from_le_bytes(word);
            eprintln!(
                "[gsc] {:#010x} XIP WR {:#010x} size={} value={:#010x}",
                self.pc.load(Ordering::Relaxed),
                addr,
                data.len(),
                value
            );
        }
    }

    fn reservation_ram(&self, addr: u64, size: usize) -> MemResult<()> {
        let end = u128::from(addr) + size as u128;
        let overlaps = |start: u64, limit: u64| {
            u128::from(addr) < u128::from(limit) && end > u128::from(start)
        };
        if overlaps(MMIO_LO, MMIO_HI)
            || in_core_local(addr)
            || (size > 0 && in_core_local(addr.saturating_add(size as u64 - 1)))
        {
            self.exclusive.clear();
            return Err(MemError::OutOfBounds { addr, size });
        }
        Ok(())
    }
}
