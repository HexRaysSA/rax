//! Physical device bridge, MMU translation and DMA.
use super::*;

impl S5lBridge {
    pub(super) fn translate(
        mem: &GuestMemoryMmap,
        inner: &mut BridgeInner,
        va: u32,
        access: V6Access,
    ) -> std::result::Result<u32, MemoryError> {
        let walk = |pa: u32| -> Option<u32> {
            let mut buf = [0u8; 4];
            mem.read_slice(&mut buf, GuestAddress(pa as u64)).ok()?;
            Some(u32::from_le_bytes(buf))
        };
        match mmu_v6::translate_v6(&inner.mmu, va, inner.privileged, access, walk) {
            Ok(t) => Ok(t.pa),
            Err(V6Fault { fsr, domain }) => {
                inner.last_fault = LastFault {
                    addr: va,
                    fsr,
                    domain,
                    access: match access {
                        V6Access::Read => 0,
                        V6Access::Write => 1,
                        V6Access::Execute => 2,
                    } | if inner.privileged { 4 } else { 0 },
                };
                Err(MemoryError::PermissionDenied(va))
            }
        }
    }
}

impl BridgeInner {
    pub(super) fn should_trace_vic_access(&self, offset: u32) -> bool {
        if self.vic_trace_budget == 0 {
            return false;
        }
        if !(self.kernel_started || std::env::var_os("RAX_S5L_VIC_TRACE_EARLY").is_some()) {
            return false;
        }
        let interesting_offset = offset == 0xF00
            || offset <= 0x2c
            || offset == 0x30
            || offset == 0x34
            || offset == 0x300
            || (0x100..0x180).contains(&offset)
            || (0x200..0x280).contains(&offset);
        if !interesting_offset {
            return false;
        }
        if self.cur_insn >= self.vic_trace_start_insn {
            return true;
        }
        if self.vic_trace_adm {
            let adm_mask = 1 << ADM_VIC1_LINE;
            let (v0_current, v0_highest, _, _, _, _) = self.vic0.debug_priority_state();
            return self.adm_irq
                || self.vic1_adm_daisy_latched
                || self.vic1_adm_daisy_in_service
                || (self.vic1.rawintr & adm_mask) != 0
                || v0_current == 32
                || v0_highest == 32;
        }
        false
    }

    pub(super) fn trace_vic_access(
        &mut self,
        vic: &'static str,
        op: &'static str,
        offset: u32,
        value: Option<u32>,
        result: Option<u32>,
        before: VicTraceSnapshot,
        after: VicTraceSnapshot,
    ) {
        if self.vic_trace_budget == 0 {
            return;
        }
        self.vic_trace_budget -= 1;
        info!(
            pc = format!("{:#x}", self.cur_pc),
            insns = self.cur_insn,
            vic,
            op,
            offset = format!("{offset:#x}"),
            value = value.map(|v| format!("{v:#x}")).unwrap_or_default(),
            result = result.map(|v| format!("{v:#x}")).unwrap_or_default(),
            before_raw = format!("{:#x}", before.raw),
            before_en = format!("{:#x}", before.enabled),
            before_sel = format!("{:#x}", before.selected),
            before_irq = format!("{:#x}", before.irq),
            before_fiq = format!("{:#x}", before.fiq),
            before_addr = format!("{:#x}", before.addr),
            before_daisy = before.daisy_input,
            before_daisy_addr = format!("{:#x}", before.daisy_vectaddr),
            before_mask = format!("{:#x}", before.priority_mask),
            before_cur = before.current,
            before_high = before.highest,
            before_prio = before.priority,
            before_depth = before.depth,
            before_irq_line = before.irq_line,
            before_fiq_line = before.fiq_line,
            after_raw = format!("{:#x}", after.raw),
            after_en = format!("{:#x}", after.enabled),
            after_sel = format!("{:#x}", after.selected),
            after_irq = format!("{:#x}", after.irq),
            after_fiq = format!("{:#x}", after.fiq),
            after_addr = format!("{:#x}", after.addr),
            after_daisy = after.daisy_input,
            after_daisy_addr = format!("{:#x}", after.daisy_vectaddr),
            after_mask = format!("{:#x}", after.priority_mask),
            after_cur = after.current,
            after_high = after.highest,
            after_prio = after.priority,
            after_depth = after.depth,
            after_irq_line = after.irq_line,
            after_fiq_line = after.fiq_line,
            adm_irq = self.adm_irq,
            adm_latched = self.vic1_adm_daisy_latched,
            adm_in_service = self.vic1_adm_daisy_in_service,
            "vic_trace"
        );
    }

    pub(super) fn refresh_vic_daisy(&mut self) {
        self.vic0.daisy_input = self.vic1.irq_asserted() || self.vic1_adm_daisy_latched;
        self.vic0.daisy_vectaddr = if self.vic1_adm_daisy_latched && !self.vic1.irq_asserted() {
            self.vic1.vect_addr[ADM_VIC1_LINE as usize]
        } else {
            self.vic1.address
        };
        self.vic0.update();
    }

    /// Propagate the ADM completion level through VIC1 and its VIC0 daisy
    /// parent immediately. The reference QEMU model raises/lowers this line
    /// synchronously inside the ADM_CTRL2 MMIO write; deferring it until the
    /// next global IRQ resample can let the equal-priority DMAC0 completion win.
    pub(super) fn set_adm_irq(&mut self, level: bool) {
        let was_raw = (self.vic1.rawintr & (1 << ADM_VIC1_LINE)) != 0;
        self.adm_irq = level;
        self.vic1.set_line(ADM_VIC1_LINE, level);
        if level && !was_raw {
            self.vic1_adm_daisy_latched = true;
            self.vic1_adm_daisy_in_service = false;
        } else if !level {
            self.vic1_adm_daisy_latched = false;
            self.vic1_adm_daisy_in_service = false;
        }
        self.refresh_vic_daisy();
    }

    /// Device-window read at a PHYSICAL address. Returns None when the address
    /// is plain memory (RAM/firmware) and should fall through to the mmap.
    pub(super) fn dev_read(&mut self, pa: u32) -> Option<u32> {
        let off = |base: u32| pa - base;
        match pa {
            _ if (CLOCK0_BASE..CLOCK0_BASE + 0x1000).contains(&pa) => {
                Some(self.clock0.read(off(CLOCK0_BASE)))
            }
            _ if (CLOCK1_BASE..CLOCK1_BASE + 0x1000).contains(&pa) => {
                Some(self.clock1.read(off(CLOCK1_BASE)))
            }
            _ if (VIC0_BASE..VIC0_BASE + 0x1000).contains(&pa) => {
                let offset = off(VIC0_BASE);
                let trace = self.should_trace_vic_access(offset);
                let before0 = trace.then(|| VicTraceSnapshot::capture(&self.vic0));
                let before1 = trace.then(|| VicTraceSnapshot::capture(&self.vic1));
                let (value, is_daisy) = if offset == 0xF00 {
                    let (value, is_daisy) = self.vic0.acknowledge();
                    (value, is_daisy)
                } else {
                    (self.vic0.read(offset), false)
                };
                if is_daisy {
                    if self.vic1_adm_daisy_latched {
                        self.vic1_adm_daisy_in_service = true;
                    }
                    self.vic1.acknowledge_daisy_child();
                    self.refresh_vic_daisy();
                }
                if let Some(before0) = before0 {
                    self.trace_vic_access(
                        "VIC0",
                        "read",
                        offset,
                        None,
                        Some(value),
                        before0,
                        VicTraceSnapshot::capture(&self.vic0),
                    );
                    if is_daisy {
                        self.trace_vic_access(
                            "VIC1",
                            "ack_daisy",
                            0xF00,
                            None,
                            None,
                            before1.expect("VIC1 trace snapshot"),
                            VicTraceSnapshot::capture(&self.vic1),
                        );
                    }
                }
                Some(value)
            }
            _ if (VIC1_BASE..VIC1_BASE + 0x1000).contains(&pa) => {
                let offset = off(VIC1_BASE);
                let trace = self.should_trace_vic_access(offset);
                let before = trace.then(|| VicTraceSnapshot::capture(&self.vic1));
                let value = self.vic1.read(offset);
                if let Some(before) = before {
                    self.trace_vic_access(
                        "VIC1",
                        "read",
                        offset,
                        None,
                        Some(value),
                        before,
                        VicTraceSnapshot::capture(&self.vic1),
                    );
                }
                Some(value)
            }
            _ if (SYSIC_BASE..SYSIC_BASE + 0x1000).contains(&pa) => {
                Some(self.sysic.read(off(SYSIC_BASE)))
            }
            _ if (TIMER1_BASE..TIMER1_BASE + 0x10004).contains(&pa) => {
                Some(self.timer.read(off(TIMER1_BASE)))
            }
            _ if (GPIO_BASE..GPIO_BASE + 0x10000).contains(&pa) => {
                Some(self.gpio.read(off(GPIO_BASE)))
            }
            _ if (CHIPID_BASE..CHIPID_BASE + 0x10).contains(&pa) => {
                Some(S5lChipId::read(off(CHIPID_BASE)))
            }
            _ if (I2C0_BASE..I2C0_BASE + 0x1000).contains(&pa) => {
                Some(self.i2c0.read(off(I2C0_BASE)))
            }
            _ if (I2C1_BASE..I2C1_BASE + 0x1000).contains(&pa) => {
                Some(self.i2c1.read(off(I2C1_BASE)))
            }
            _ if (SPI0_BASE..SPI0_BASE + 0x100).contains(&pa) => {
                Some(self.spi0.read(off(SPI0_BASE)))
            }
            _ if (SPI1_BASE..SPI1_BASE + 0x100).contains(&pa) => {
                Some(self.spi1.read(off(SPI1_BASE)))
            }
            _ if (SPI2_BASE..SPI2_BASE + 0x100).contains(&pa) => {
                Some(self.spi2.read(off(SPI2_BASE)))
            }
            _ if (LCD_BASE..LCD_BASE + 0x1000).contains(&pa) => Some(self.lcd.read(off(LCD_BASE))),
            _ if (NAND_BASE..NAND_BASE + 0x1000).contains(&pa) => {
                self.nand.set_kernel_started(self.kernel_started);
                Some(self.nand.read(off(NAND_BASE)))
            }
            _ if (NAND_ECC_BASE..NAND_ECC_BASE + 0x1000).contains(&pa) => {
                Some(self.nand_ecc.read(off(NAND_ECC_BASE)))
            }
            _ if (SDIO_BASE..SDIO_BASE + 0x1000).contains(&pa) => {
                Some(self.sdio.read(off(SDIO_BASE)))
            }
            _ if (DMAC0_BASE..DMAC0_BASE + 0x1000).contains(&pa) => {
                Some(self.dmac0.read(off(DMAC0_BASE)))
            }
            _ if (DMAC1_BASE..DMAC1_BASE + 0x1000).contains(&pa) => {
                Some(self.dmac1.read(off(DMAC1_BASE)))
            }
            _ if (USB_OTG_BASE..USB_OTG_BASE + 0x10000).contains(&pa) => {
                Some(self.usb.otg_read(off(USB_OTG_BASE)))
            }
            _ if (USB_PHYS_BASE..USB_PHYS_BASE + 0x1000).contains(&pa) => {
                Some(self.usb.phy_read(off(USB_PHYS_BASE)))
            }
            _ if (MBX_BASE..MBX_BASE + MBX_SIZE).contains(&pa) => Some(match off(MBX_BASE) {
                0x12C => 0x100,
                0xF00 => (1 << 24) | 0x1_0000,
                0x1020 => 0x1_0000,
                _ => 0,
            }),
            _ if (ADM_BASE..ADM_BASE + 0x1000).contains(&pa) => Some(match off(ADM_BASE) {
                0x0 => 0x2,  // CTRL: device ready
                0x4 => 0x10, // CTRL2: upload event finished
                _ => 0,
            }),
            _ if (UART0_BASE..UART0_BASE + 0x1000).contains(&pa) => Some(
                self.uart
                    .get()
                    .and_then(|u| u.lock().ok().map(|mut u| u.read(off(UART0_BASE))))
                    .unwrap_or(0),
            ),
            _ if (ENGINE_8900_BASE..ENGINE_8900_BASE + 0x100).contains(&pa) => Some(0),
            _ if (AES_BASE..AES_BASE + 0x100).contains(&pa) => Some(self.aes.read(off(AES_BASE))),
            // Plain memory.
            _ if is_memory(pa) => None,
            // Unmapped MMIO: open bus (read as zero).
            _ => {
                if self.openbus_log_budget > 0 {
                    self.openbus_log_budget -= 1;
                    debug!(pa = format!("{pa:#x}"), "openbus read");
                }
                Some(0)
            }
        }
    }

    /// Device-window write. Returns true if the write was consumed by a device
    /// (or open bus); false if it should fall through to plain memory.
    pub(super) fn dev_write(&mut self, pa: u32, value: u32) -> bool {
        let off = |base: u32| pa - base;
        if std::env::var("RAX_S5L_WLOG").is_ok()
            && ((0x3CC0_0000..0x3CC1_1000).contains(&pa)
                || (ADM_BASE..ADM_BASE + 0x1000).contains(&pa))
        {
            debug!(pa = format!("{pa:#x}"), val = format!("{value:#x}"), "wlog");
        }
        match pa {
            _ if (CLOCK0_BASE..CLOCK0_BASE + 0x1000).contains(&pa) => {
                self.clock0.write(off(CLOCK0_BASE), value);
                true
            }
            _ if (CLOCK1_BASE..CLOCK1_BASE + 0x1000).contains(&pa) => {
                self.clock1.write(off(CLOCK1_BASE), value);
                true
            }
            _ if (VIC0_BASE..VIC0_BASE + 0x1000).contains(&pa) => {
                let offset = off(VIC0_BASE);
                let trace = self.should_trace_vic_access(offset);
                let before0 = trace.then(|| VicTraceSnapshot::capture(&self.vic0));
                let before1 = trace.then(|| VicTraceSnapshot::capture(&self.vic1));
                let mut is_daisy = false;
                if offset == 0xF00 {
                    is_daisy = self.vic0.finish_irq();
                    if is_daisy {
                        self.vic1.finish_daisy_child();
                        if self.vic1_adm_daisy_in_service {
                            self.vic1_adm_daisy_latched = false;
                            self.vic1_adm_daisy_in_service = false;
                        }
                        self.refresh_vic_daisy();
                    }
                } else {
                    self.vic0.write(offset, value);
                }
                if let Some(before0) = before0 {
                    self.trace_vic_access(
                        "VIC0",
                        "write",
                        offset,
                        Some(value),
                        None,
                        before0,
                        VicTraceSnapshot::capture(&self.vic0),
                    );
                    if is_daisy {
                        self.trace_vic_access(
                            "VIC1",
                            "finish_daisy",
                            0xF00,
                            Some(value),
                            None,
                            before1.expect("VIC1 trace snapshot"),
                            VicTraceSnapshot::capture(&self.vic1),
                        );
                    }
                }
                true
            }
            _ if (VIC1_BASE..VIC1_BASE + 0x1000).contains(&pa) => {
                let offset = off(VIC1_BASE);
                let trace = self.should_trace_vic_access(offset);
                let before = trace.then(|| VicTraceSnapshot::capture(&self.vic1));
                self.vic1.write(offset, value);
                if offset == 0xF00 && self.vic1_adm_daisy_in_service {
                    self.vic1_adm_daisy_latched = false;
                    self.vic1_adm_daisy_in_service = false;
                    self.refresh_vic_daisy();
                }
                if let Some(before) = before {
                    self.trace_vic_access(
                        "VIC1",
                        "write",
                        offset,
                        Some(value),
                        None,
                        before,
                        VicTraceSnapshot::capture(&self.vic1),
                    );
                }
                true
            }
            _ if (SYSIC_BASE..SYSIC_BASE + 0x1000).contains(&pa) => {
                self.sysic.write(off(SYSIC_BASE), value);
                true
            }
            _ if (TIMER1_BASE..TIMER1_BASE + 0x10004).contains(&pa) => {
                self.timer.write(off(TIMER1_BASE), value);
                true
            }
            _ if (GPIO_BASE..GPIO_BASE + 0x10000).contains(&pa) => {
                self.gpio.write(off(GPIO_BASE), value);
                true
            }
            _ if (CHIPID_BASE..CHIPID_BASE + 0x10).contains(&pa) => true,
            _ if (I2C0_BASE..I2C0_BASE + 0x1000).contains(&pa) => {
                self.i2c0.write(off(I2C0_BASE), value);
                true
            }
            _ if (I2C1_BASE..I2C1_BASE + 0x1000).contains(&pa) => {
                self.i2c1.write(off(I2C1_BASE), value);
                true
            }
            _ if (SPI0_BASE..SPI0_BASE + 0x100).contains(&pa) => {
                self.spi0.write(off(SPI0_BASE), value);
                true
            }
            _ if (SPI1_BASE..SPI1_BASE + 0x100).contains(&pa) => {
                self.spi1.write(off(SPI1_BASE), value);
                true
            }
            _ if (SPI2_BASE..SPI2_BASE + 0x100).contains(&pa) => {
                self.spi2.write(off(SPI2_BASE), value);
                true
            }
            _ if (LCD_BASE..LCD_BASE + 0x1000).contains(&pa) => {
                self.lcd.write(off(LCD_BASE), value);
                true
            }
            _ if (NAND_BASE..NAND_BASE + 0x1000).contains(&pa) => {
                self.nand.write(off(NAND_BASE), value);
                true
            }
            _ if (NAND_ECC_BASE..NAND_ECC_BASE + 0x1000).contains(&pa) => {
                self.nand_ecc.write(off(NAND_ECC_BASE), value);
                true
            }
            _ if (SDIO_BASE..SDIO_BASE + 0x1000).contains(&pa) => {
                self.sdio.write(off(SDIO_BASE), value);
                true
            }
            _ if (DMAC0_BASE..DMAC0_BASE + 0x1000).contains(&pa) => {
                self.dmac0.write(off(DMAC0_BASE), value);
                true
            }
            _ if (DMAC1_BASE..DMAC1_BASE + 0x1000).contains(&pa) => {
                self.dmac1.write(off(DMAC1_BASE), value);
                true
            }
            _ if (USB_OTG_BASE..USB_OTG_BASE + 0x10000).contains(&pa) => {
                self.usb.otg_write(off(USB_OTG_BASE), value);
                true
            }
            _ if (USB_PHYS_BASE..USB_PHYS_BASE + 0x1000).contains(&pa) => {
                self.usb.phy_write(off(USB_PHYS_BASE), value);
                true
            }
            _ if (MBX_BASE..MBX_BASE + MBX_SIZE).contains(&pa) => true,
            _ if (ADM_BASE..ADM_BASE + 0x1000).contains(&pa) => {
                match off(ADM_BASE) {
                    0x88 => {
                        self.adm_data2 = value;
                        if std::env::var("RAX_S5L_ADM_TRACE").is_ok() {
                            debug!(addr = format!("{value:#x}"), "adm_data2");
                        }
                    }
                    0x8C => {
                        self.adm_data3 = value;
                        if std::env::var("RAX_S5L_ADM_TRACE").is_ok() {
                            debug!(addr = format!("{value:#x}"), "adm_data3");
                        }
                    }
                    0x0 | 0x4 => {
                        if std::env::var("RAX_S5L_ADM_TRACE").is_ok() {
                            debug!(
                                off = format!("{:#x}", off(ADM_BASE)),
                                val = format!("{value:#x}"),
                                adm_irq = self.adm_irq,
                                "adm_write"
                            );
                        }
                        self.adm_req = Some((off(ADM_BASE) << 28) | (value & 0xFF));
                    }
                    _ => {}
                }
                true
            }
            _ if (UART0_BASE..UART0_BASE + 0x1000).contains(&pa) => {
                if let Some(u) = self.uart.get() {
                    if let Ok(mut u) = u.lock() {
                        u.write(off(UART0_BASE), value);
                    }
                }
                true
            }
            _ if (ENGINE_8900_BASE..ENGINE_8900_BASE + 0x100).contains(&pa) => {
                // Writing the image header address to offset 0 triggers
                // in-place AES-CBC decryption (serviced by the vCPU step).
                if off(ENGINE_8900_BASE) == 0 {
                    self.engine_8900_req = Some(value);
                }
                true
            }
            _ if (AES_BASE..AES_BASE + 0x100).contains(&pa) => {
                self.aes.write(off(AES_BASE), value);
                true
            }
            _ if is_memory(pa) => false,
            _ => {
                if self.openbus_log_budget > 0 {
                    self.openbus_log_budget -= 1;
                    debug!(
                        pa = format!("{pa:#x}"),
                        val = format!("{value:#x}"),
                        "openbus write"
                    );
                }
                true
            }
        }
    }

    pub(super) fn read_pa(
        &mut self,
        mem: &GuestMemoryMmap,
        pa: u32,
        buf: &mut [u8],
    ) -> std::result::Result<(), MemoryError> {
        if is_nor_range(pa, buf.len()) {
            return self.nor.read(mem, pa, buf);
        }

        if buf.len() <= 4 && !is_memory(pa) {
            if let Some(v) = self.dev_read(pa) {
                if self.openbus_log_budget > 0 && self.devlog {
                    self.openbus_log_budget -= 1;
                    debug!(pa = format!("{pa:#x}"), val = format!("{v:#x}"), "dev read");
                }
                let bytes = v.to_le_bytes();
                buf.copy_from_slice(&bytes[..buf.len()]);
                return Ok(());
            }
        }
        mem.read_slice(buf, GuestAddress(pa as u64))
            .map_err(|_| MemoryError::BusError(pa))
    }

    pub(super) fn write_pa(
        &mut self,
        mem: &GuestMemoryMmap,
        pa: u32,
        data: &[u8],
    ) -> std::result::Result<(), MemoryError> {
        // Optional write-watchpoint (RAX_S5L_WATCH=hexaddr:hexlen): log writes
        // that land in [addr, addr+len) so heap/free-list corruption can be
        // traced to the offending store.
        if let Some((wa, wl)) = *watch_range() {
            if range_overlaps(pa, data.len(), wa, wl) {
                info!(
                    pa = format!("{pa:#x}"),
                    len = data.len(),
                    watch = format!("{wa:#x}:{wl:#x}"),
                    watch_offset = ?watch_offset(pa, data.len(), wa),
                    data = bytes_hex(data),
                    before = ?phys_bytes_hex(mem, pa, data.len()),
                    pc = format!("{:#x}", self.cur_pc),
                    insns = self.cur_insn,
                    "physical watch write"
                );
            }
        }
        if is_nor_range(pa, data.len()) {
            self.nor.write(pa - NOR_BASE, data);
            return Ok(());
        }

        if data.len() <= 4 && !is_memory(pa) {
            // QEMU dispatches MMIO subword accesses with the guest's exact
            // offset and the unshifted access value. This matters for SYSIC's
            // halfword status offsets (0x7a/0x7c), and it avoids synthetic
            // read-modify-write cycles on registers whose reads have effects.
            let mut bytes = [0u8; 4];
            bytes[..data.len()].copy_from_slice(data);
            if self.dev_write(pa, u32::from_le_bytes(bytes)) {
                // A channel-enable write to a DMAC schedules a transfer; run it
                // now (here we have the guest-memory handle the transfer needs).
                if let Some(ch) = self.dmac0.take_pending() {
                    self.dma_run(mem, 0, ch as usize);
                }
                if let Some(ch) = self.dmac1.take_pending() {
                    self.dma_run(mem, 1, ch as usize);
                }
                return Ok(());
            }
        }
        mem.write_slice(data, GuestAddress(pa as u64))
            .map_err(|_| MemoryError::BusError(pa))
    }

    /// Perform a PL080 channel transfer synchronously. The reference QEMU
    /// PL080 model moves one DMA element at a time, using source width for each
    /// read and destination width for each write, then reloads an optional LLI.
    /// Mirroring that shape matters for peripherals such as SPI FIFOs: a
    /// byte-wide peripheral write is a FIFO push, not just a byte in a bulk RAM
    /// copy.
    pub(super) fn dma_run(&mut self, mem: &GuestMemoryMmap, controller: usize, ch: usize) {
        let trace = match std::env::var("RAX_S5L_DMA_TRACE") {
            Ok(value) if value.eq_ignore_ascii_case("all") => true,
            Ok(value) if value.eq_ignore_ascii_case("dmac0") => controller == 0,
            Ok(value) if value.eq_ignore_ascii_case("dmac1") => controller == 1,
            Ok(value) => value.parse::<usize>() == Ok(controller),
            Err(_) => false,
        };
        let dump_path = std::env::var("RAX_S5L_DMADUMP").ok();
        let dump_limit = s5l_dmadump_limit();
        let mut dump_remaining = dump_path
            .as_deref()
            .map(|path| dmadump_remaining_for_path(Path::new(path), dump_limit))
            .unwrap_or(0);
        let mut dump = dump_path
            .as_ref()
            .filter(|_| dump_remaining != 0)
            .map(|_| Vec::<u8>::new());
        let (mut src, mut dst, mut lli, mut ctl, cfg) = self.dma_descriptor(controller, ch);
        let mut total = 0usize;
        let mut descriptors = 0usize;

        loop {
            descriptors += 1;
            if descriptors > 4096 {
                info!(
                    controller,
                    ch,
                    lli = format!("{lli:#x}"),
                    "dma lli chain too long"
                );
                break;
            }

            let mut count = ctl & 0xFFF;
            let swidth = 1u32 << ((ctl >> 18) & 7).min(2);
            let dwidth = 1u32 << ((ctl >> 21) & 7).min(2);
            let s_inc = (ctl >> 26) & 1 != 0;
            let d_inc = (ctl >> 27) & 1 != 0;

            if trace {
                info!(
                    controller,
                    ch,
                    src = format!("{src:#x}"),
                    dst = format!("{dst:#x}"),
                    lli = format!("{lli:#x}"),
                    ctl = format!("{ctl:#x}"),
                    cfg = format!("{cfg:#x}"),
                    count,
                    swidth,
                    dwidth,
                    s_inc,
                    d_inc,
                    "dma descriptor"
                );
            }

            while count != 0 {
                let mut buf = [0u8; 4];
                let mut n = 0usize;
                while n < dwidth as usize {
                    let end = (n + swidth as usize).min(buf.len());
                    let _ = self.read_pa(mem, src, &mut buf[n..end]);
                    if s_inc {
                        src = src.wrapping_add(swidth);
                    }
                    n += swidth as usize;
                }

                let xsize = dwidth.max(swidth) as usize;
                let mut n = 0usize;
                while n < xsize {
                    let end = (n + dwidth as usize).min(buf.len());
                    let _ = self.write_pa(mem, dst.wrapping_add(n as u32), &buf[n..end]);
                    if d_inc {
                        dst = dst.wrapping_add(dwidth);
                    }
                    n += dwidth as usize;
                }

                if let Some(dump) = dump.as_mut() {
                    let bytes = &buf[..xsize.min(buf.len())];
                    let len = bytes.len().min(dump_remaining);
                    dump.extend_from_slice(&bytes[..len]);
                    dump_remaining -= len;
                }
                count -= 1;
                total += xsize;
            }

            ctl &= !0xFFF;
            self.dma_store_descriptor(controller, ch, src, dst, lli, ctl);
            if lli == 0 {
                break;
            }

            let next_src = self.dma_read_u32(mem, lli);
            let next_dst = self.dma_read_u32(mem, lli.wrapping_add(4));
            let next_lli = self.dma_read_u32(mem, lli.wrapping_add(8));
            let next_ctl = self.dma_read_u32(mem, lli.wrapping_add(12));
            src = next_src;
            dst = next_dst;
            lli = next_lli;
            ctl = next_ctl;
            self.dma_store_descriptor(controller, ch, src, dst, lli, ctl);
        }

        debug!(
            controller,
            ch = ch,
            src = format!("{src:#x}"),
            dst = format!("{dst:#x}"),
            bytes = total,
            "dma_run"
        );
        if let Some(path) = dump_path {
            let header =
                format!("--- dmac{controller} ch{ch} src={src:#x} dst={dst:#x} bytes={total}\n");
            let payload = dump.as_deref().unwrap_or(&[]);
            let _ = append_limited_dmadump(path, header.as_bytes(), payload, dump_limit);
        }
        self.dma_complete(controller, ch);
    }

    pub(super) fn dma_complete(&mut self, controller: usize, ch: usize) {
        if controller == 0 {
            self.dmac0.complete(ch);
        } else {
            self.dmac1.complete(ch);
        }
    }

    pub(super) fn dma_descriptor(&self, controller: usize, ch: usize) -> (u32, u32, u32, u32, u32) {
        if controller == 0 {
            (
                self.dmac0.src[ch],
                self.dmac0.dst[ch],
                self.dmac0.lli[ch],
                self.dmac0.control[ch],
                self.dmac0.config[ch],
            )
        } else {
            (
                self.dmac1.src[ch],
                self.dmac1.dst[ch],
                self.dmac1.lli[ch],
                self.dmac1.control[ch],
                self.dmac1.config[ch],
            )
        }
    }

    pub(super) fn dma_store_descriptor(
        &mut self,
        controller: usize,
        ch: usize,
        src: u32,
        dst: u32,
        lli: u32,
        control: u32,
    ) {
        let dmac = if controller == 0 {
            &mut self.dmac0
        } else {
            &mut self.dmac1
        };
        dmac.src[ch] = src;
        dmac.dst[ch] = dst;
        dmac.lli[ch] = lli;
        dmac.control[ch] = control;
    }

    pub(super) fn dma_read_u32(&mut self, mem: &GuestMemoryMmap, pa: u32) -> u32 {
        let mut bytes = [0u8; 4];
        let _ = self.read_pa(mem, pa, &mut bytes);
        u32::from_le_bytes(bytes)
    }
}

impl S5lBridge {
    pub(super) fn access(
        &self,
        addr: u32,
        access: V6Access,
        data: Option<&[u8]>,
        out: Option<&mut [u8]>,
    ) -> std::result::Result<(), MemoryError> {
        let mut inner = self.inner.borrow_mut();
        let pa = Self::translate(&self.mem, &mut inner, addr, access)?;
        if let Some(buf) = out {
            inner.read_pa(&self.mem, pa, buf)
        } else if let Some(d) = data {
            let vwatch = vwatch_range()
                .and_then(|(wa, wl)| range_overlaps(addr, d.len(), wa, wl).then_some((wa, wl)));
            let before = vwatch.and_then(|_| phys_bytes_hex(&self.mem, pa, d.len()));
            let result = inner.write_pa(&self.mem, pa, d);
            if let Some((wa, wl)) = vwatch {
                info!(
                    va = format!("{addr:#x}"),
                    pa = format!("{pa:#x}"),
                    len = d.len(),
                    access = ?access,
                    watch = format!("{wa:#x}:{wl:#x}"),
                    watch_offset = ?watch_offset(addr, d.len(), wa),
                    data = bytes_hex(d),
                    before = ?before,
                    after = ?phys_bytes_hex(&self.mem, pa, d.len()),
                    pc = format!("{:#x}", inner.cur_pc),
                    insns = inner.cur_insn,
                    ok = result.is_ok(),
                    "virtual watch write"
                );
            }
            result
        } else {
            Ok(())
        }
    }
}

impl ArmMemory for S5lBridge {
    fn read_word(&self, addr: u32) -> std::result::Result<u32, MemoryError> {
        let mut b = [0u8; 4];
        self.access(addr, V6Access::Read, None, Some(&mut b))?;
        Ok(u32::from_le_bytes(b))
    }

    fn read_halfword(&self, addr: u32) -> std::result::Result<u16, MemoryError> {
        let mut b = [0u8; 2];
        self.access(addr, V6Access::Read, None, Some(&mut b))?;
        Ok(u16::from_le_bytes(b))
    }

    fn read_byte(&self, addr: u32) -> std::result::Result<u8, MemoryError> {
        let mut b = [0u8; 1];
        self.access(addr, V6Access::Read, None, Some(&mut b))?;
        Ok(b[0])
    }

    fn write_word(&mut self, addr: u32, value: u32) -> std::result::Result<(), MemoryError> {
        self.access(addr, V6Access::Write, Some(&value.to_le_bytes()), None)
    }

    fn write_halfword(&mut self, addr: u32, value: u16) -> std::result::Result<(), MemoryError> {
        self.access(addr, V6Access::Write, Some(&value.to_le_bytes()), None)
    }

    fn write_byte(&mut self, addr: u32, value: u8) -> std::result::Result<(), MemoryError> {
        self.access(addr, V6Access::Write, Some(&[value]), None)
    }
}
