//! S5L platform execution support.
use super::*;

impl S5L8900Vcpu {
    /// Service a pending 8900-engine decryption request, if any.
    pub(super) fn service_engine_8900(&mut self) {
        let req = self.bridge.inner.borrow_mut().engine_8900_req.take();
        if let Some(addr) = req {
            self.decrypt_8900(addr);
        }
    }

    pub(super) fn phys_r32(&self, pa: u32) -> u32 {
        let mut b = [0u8; 4];
        let _ = self.bridge.mem.read_slice(&mut b, GuestAddress(pa as u64));
        u32::from_le_bytes(b)
    }

    pub(super) fn phys_r(&self, pa: u32, len: usize) -> Vec<u8> {
        let mut b = vec![0u8; len];
        let _ = self.bridge.mem.read_slice(&mut b, GuestAddress(pa as u64));
        b
    }

    pub(super) fn phys_w(&self, pa: u32, data: &[u8]) {
        let _ = self.bridge.mem.write_slice(data, GuestAddress(pa as u64));
    }

    /// Service a pending ADM (Apple Data Mover) command. The ADM is the
    /// high-level NAND DMA: iBoot writes a command structure into a data
    /// section in RAM, then pokes a control register; the ADM reads it, sets
    /// the NAND controller up for the page read, and deposits the page spare.
    pub(super) fn service_adm(&mut self) {
        let req = self.bridge.inner.borrow_mut().adm_req.take();
        let Some(req) = req else { return };
        let off = req >> 28;
        let value = req & 0xFF;
        let (data2, data3) = {
            let i = self.bridge.inner.borrow();
            (i.adm_data2, i.adm_data3)
        };

        if off == 0 {
            // ADM_CTRL: start-up — mark device started and banks present.
            if value == 0x3 {
                self.phys_w(data2, &0x50u32.to_le_bytes());
                let mut chip = Vec::with_capacity(32);
                for _ in 0..8 {
                    chip.extend_from_slice(&0xA514_D3ADu32.to_le_bytes());
                }
                self.phys_w(data3, &chip);
            }
            return;
        }
        // ADM_CTRL2: devos50's reference only executes a command on the exact
        // value 0x2. The kernel also writes 0x6 while loading ADM/FMC firmware;
        // treating that as a command creates a spurious ADM interrupt storm.
        // A write without bit1 set acknowledges/clears the completion interrupt
        // (mirrors qemu_irq_lower when (value & 0x2) == 0).
        if value & 0x2 == 0 {
            let mut inner = self.bridge.inner.borrow_mut();
            inner.set_adm_irq(false);
            if std::env::var("RAX_S5L_ADM_TRACE").is_ok() {
                debug!(value = format!("{value:#x}"), "adm_irq_clear");
            }
            if std::env::var_os("RAX_S5L_ADMIRQ_TRACE").is_some()
                && inner.kernel_started
                && self.insn_count >= self.adm_irq_trace_start_insn
            {
                let (v0_cur, v0_high, v0_prio, v0_depth, v0_irq_line, _) =
                    inner.vic0.debug_priority_state();
                let (v1_cur, v1_high, v1_prio, v1_depth, v1_irq_line, _) =
                    inner.vic1.debug_priority_state();
                info!(
                    value = format!("{value:#x}"),
                    v0_raw = format!("{:#x}", inner.vic0.rawintr),
                    v0_en = format!("{:#x}", inner.vic0.intenable),
                    v0_irq = format!("{:#x}", inner.vic0.irq_status),
                    v0_cur,
                    v0_high,
                    v0_prio,
                    v0_depth,
                    v0_irq_line,
                    v1_raw = format!("{:#x}", inner.vic1.rawintr),
                    v1_en = format!("{:#x}", inner.vic1.intenable),
                    v1_irq = format!("{:#x}", inner.vic1.irq_status),
                    v1_cur,
                    v1_high,
                    v1_prio,
                    v1_depth,
                    v1_irq_line,
                    insns = self.insn_count,
                    "adm completion cleared"
                );
            }
            return;
        }
        if value != 0x2 {
            if std::env::var("RAX_S5L_ADM_TRACE").is_ok() {
                debug!(value = format!("{value:#x}"), "adm_ctrl2_ignored");
            }
            return;
        }
        let cmd = self.phys_r32(data2 + 0x1104 + 0x24);
        let num_pages = {
            let v = self.phys_r32(data2 + 0x1104 + 0x28) as u16;
            v.swap_bytes()
        };
        let bswap = |p: u32| p.swap_bytes();
        let mut first_page = None;
        let mut first_bank = None;
        let mut adm_page_dump = None;

        match cmd {
            0x300 if num_pages == 1 => {
                let mut bank = (self.phys_r32(data2 + 0x1104 + 0x44) & 0xFF) as u32;
                let mut page = bswap(self.phys_r32(data2 + 0x1104 + 0x244));
                let kernel_started = self.bridge.inner.borrow().kernel_started;
                if kernel_started && !self.wmr_init_active && bank == 0 && page == 0 {
                    let remapped_page = std::env::var("RAX_S5L_LOGICAL0_PAGE")
                        .ok()
                        .and_then(|value| value.parse::<u32>().ok());
                    if let Some(remapped_page) = remapped_page {
                        debug!(
                            from_bank = bank,
                            from_page = page,
                            to_bank = 0u32,
                            to_page = remapped_page,
                            "adm single-page logical0 remap"
                        );
                        bank = 0;
                        page = remapped_page;
                    }
                }
                first_bank = Some(bank);
                first_page = Some(page);
                let mut inner = self.bridge.inner.borrow_mut();
                inner.nand.set_kernel_started(kernel_started);
                inner.nand.reading_multiple_pages = false;
                inner.nand.set_bank(bank);
                inner.nand.write(0x30, 0x800 - 1); // FMDNUM
                inner.nand.write(0xC, page << 16); // FMADDR0
                inner.nand.write(0x10, (page >> 16) & 0xFF); // FMADDR1
                inner.nand.write(0x8, 0x30); // CMD = READ
                inner.nand.set_buffered_page(page);
                let spare = inner.nand.spare_buffer.clone();
                if kernel_started {
                    let dump_len = std::env::var("RAX_S5L_ADM_PAGE_DUMP")
                        .ok()
                        .map(|value| value.parse::<usize>().unwrap_or(512))
                        .unwrap_or(0);
                    if dump_len != 0 {
                        adm_page_dump = Some((
                            bank,
                            page,
                            inner.nand.buffered_page_prefix(dump_len).to_vec(),
                            inner.nand.spare_buffer[..NAND_BYTES_PER_SPARE.min(0x20)].to_vec(),
                        ));
                    }
                }
                drop(inner);
                self.phys_w(data3, &spare[..NAND_BYTES_PER_SPARE]);
            }
            0x300 | 0x200 => {
                // Scattered / multi-page read: queue the page/bank list.
                let n = num_pages as usize;
                let mut inner = self.bridge.inner.borrow_mut();
                let kernel_started = inner.kernel_started;
                inner.nand.set_kernel_started(kernel_started);
                inner.nand.reading_multiple_pages = true;
                for i in 0..n.min(512) {
                    let page = if cmd == 0x200 {
                        // Same starting page across all 8 banks per group.
                        let base = bswap(self.phys_r32(data2 + 0x1104 + 0x244));
                        base + (i / 8) as u32
                    } else {
                        bswap(self.phys_r32(data2 + 0x1104 + 0x244 + 4 * i as u32))
                    };
                    let bank = if cmd == 0x200 {
                        (i % 8) as u32
                    } else {
                        (self.phys_r32(data2 + 0x1104 + 0x44 + i as u32) & 0xFF) as u32
                    };
                    if i == 0 {
                        first_bank = Some(bank);
                        first_page = Some(page);
                    }
                    inner.nand.pages_to_read[i] = page;
                    inner.nand.banks_to_read[i] = bank;
                }
                inner.nand.fmdnum = num_pages as u32 * 0x800;
                inner.nand.cur_bank_reading = -1;
                drop(inner);
                // Mark each scattered page's spare slot as readable.
                for i in 0..n {
                    let mut sbuf = [0u8; 0xC];
                    sbuf[10] = 0xFF;
                    self.phys_w(data3 + i as u32 * 0xC, &sbuf);
                }
            }
            0x500 => {
                // Page write. QEMU arms the NAND FIFO here; the follow-up PL080
                // transfer writes page words into FMFIFO.
                let bank = (self.phys_r32(data2 + 0x1104 + 0x44) & 0xFF) as u32;
                let page = bswap(self.phys_r32(data2 + 0x1104 + 0x244));
                first_bank = Some(bank);
                first_page = Some(page);
                let mut inner = self.bridge.inner.borrow_mut();
                let kernel_started = inner.kernel_started;
                inner.nand.set_kernel_started(kernel_started);
                inner.nand.begin_page_write(bank, page);
            }
            _ => {}
        }
        if let Some((dump_bank, dump_page, page_data, spare_data)) = adm_page_dump {
            info!(
                cmd = format!("{cmd:#x}"),
                num_pages,
                bank = dump_bank,
                page = dump_page,
                data = hex_bytes(&page_data),
                spare = hex_bytes(&spare_data),
                pc = format!("{:#x}", self.cpu.regs[15]),
                lr = format!("{:#x}", self.cpu.regs[14]),
                insns = self.insn_count,
                "kernel adm page dump"
            );
        }
        // Raise the ADM completion interrupt (VIC1 line 5 / global IRQ 0x25).
        // iBoot's NAND/FTL driver issues the command then blocks waiting for it.
        debug!(
            cmd = format!("{cmd:#x}"),
            num_pages, first_bank, first_page, "adm_cmd"
        );
        if std::env::var_os("RAX_S5L_ADM_DUMP").is_some()
            && self.bridge.inner.borrow().kernel_started
        {
            let cmd_base = data2 + 0x1104;
            let cmd_head = self.phys_r(cmd_base, 0x80);
            let page_words = self.phys_r(cmd_base + 0x244, num_pages.max(1) as usize * 4);
            let bank_bytes = self.phys_r(cmd_base + 0x44, num_pages.max(1) as usize);
            let spare = self.phys_r(data3, NAND_BYTES_PER_SPARE.min(0x20));
            info!(
                cmd = format!("{cmd:#x}"),
                num_pages,
                first_bank,
                first_page,
                cmd_base = format!("{cmd_base:#x}"),
                data2 = format!("{data2:#x}"),
                data3 = format!("{data3:#x}"),
                head = hex_bytes(&cmd_head),
                pages = hex_bytes(&page_words),
                banks = hex_bytes(&bank_bytes),
                spare = hex_bytes(&spare),
                pc = format!("{:#x}", self.cpu.regs[15]),
                lr = format!("{:#x}", self.cpu.regs[14]),
                insns = self.insn_count,
                "kernel adm command dump"
            );
        }
        if std::env::var_os("RAX_S5L_ADM_STACK_TRACE").is_some()
            && self.bridge.inner.borrow().kernel_started
        {
            let sp = self.cpu.regs[13];
            let mut frames = Vec::new();
            for i in 0..256u32 {
                if let Ok(w) = self.bridge.read_word(sp.wrapping_add(i * 4)) {
                    let a = w & !1;
                    if (0xC000_0000..0xC060_0000).contains(&a) {
                        frames.push(format!("{a:#x}"));
                    }
                }
            }
            info!(
                cmd = format!("{cmd:#x}"),
                num_pages,
                first_bank,
                first_page,
                pc = format!("{:#x}", self.cpu.regs[15]),
                lr = format!("{:#x}", self.cpu.regs[14]),
                sp = format!("{sp:#x}"),
                r0 = format!("{:#x}", self.cpu.regs[0]),
                r1 = format!("{:#x}", self.cpu.regs[1]),
                r2 = format!("{:#x}", self.cpu.regs[2]),
                r3 = format!("{:#x}", self.cpu.regs[3]),
                data2 = format!("{data2:#x}"),
                data3 = format!("{data3:#x}"),
                stack = frames.join(" "),
                trail = self.recent_pc_trail(32),
                insns = self.insn_count,
                "kernel adm stack trace"
            );
        }
        let mut inner = self.bridge.inner.borrow_mut();
        inner.set_adm_irq(true);
        if std::env::var_os("RAX_S5L_ADMIRQ_TRACE").is_some()
            && inner.kernel_started
            && self.insn_count >= self.adm_irq_trace_start_insn
        {
            let (v0_cur, v0_high, v0_prio, v0_depth, v0_irq_line, _) =
                inner.vic0.debug_priority_state();
            let (v1_cur, v1_high, v1_prio, v1_depth, v1_irq_line, _) =
                inner.vic1.debug_priority_state();
            info!(
                cmd = format!("{cmd:#x}"),
                num_pages,
                first_bank,
                first_page,
                v0_raw = format!("{:#x}", inner.vic0.rawintr),
                v0_en = format!("{:#x}", inner.vic0.intenable),
                v0_irq = format!("{:#x}", inner.vic0.irq_status),
                v0_cur,
                v0_high,
                v0_prio,
                v0_depth,
                v0_irq_line,
                v1_raw = format!("{:#x}", inner.vic1.rawintr),
                v1_en = format!("{:#x}", inner.vic1.intenable),
                v1_irq = format!("{:#x}", inner.vic1.irq_status),
                v1_cur,
                v1_high,
                v1_prio,
                v1_depth,
                v1_irq_line,
                insns = self.insn_count,
                "adm completion raised"
            );
        }
    }

    pub(super) fn prefetch_abort(&mut self, pc: u32) -> StepOutcome {
        let f = self.bridge.inner.borrow().last_fault;
        if self.should_log_kernel_fault(pc) {
            info!(
                pc = format!("{pc:#x}"),
                fsr = format!("{:#x}", f.fsr),
                sp = format!("{:#x}", self.cpu.regs[13]),
                lr = format!("{:#x}", self.cpu.regs[14]),
                cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                spsr_abt = format!("{:#x}", self.cpu.spsr_abt.to_u32()),
                sp_abt = format!("{:#x}", self.cpu.regs_abt[0]),
                lr_abt = format!("{:#x}", self.cpu.regs_abt[1]),
                insns = self.insn_count,
                "kernel prefetch abort"
            );
        }
        if self.fault_log_budget > 0 {
            self.fault_log_budget -= 1;
            debug!(
                pc = format!("{pc:#x}"),
                fsr = format!("{:#x}", f.fsr),
                lr = format!("{:#x}", self.cpu.regs[14]),
                insns = self.insn_count,
                "prefetch abort"
            );
        }
        self.cpu.cp15.ifsr = f.fsr | (f.domain << 4);
        self.cpu.cp15.ifar = pc;
        self.take_exception(ExceptionType::PrefetchAbort(pc));
        StepOutcome::Progress
    }

    pub(super) fn should_log_kernel_fault(&mut self, pc: u32) -> bool {
        if pc < 0xC000_0000 && std::env::var("RAX_S5L_FAULT_INFO").is_err() {
            return false;
        }
        if self.kernel_fault_log_remaining == 0 {
            return false;
        }
        self.kernel_fault_log_remaining -= 1;
        true
    }

    pub(super) fn fix_usb_wrangler_phy_registered_race(&mut self, pc: u32) -> bool {
        if pc != KERNEL_USB_WRANGLER_PHY_REGISTERED_NOTIFIER || self.no_usb_wrangler_race_fix {
            return false;
        }

        let wrangler = self.cpu.regs[5];
        let notifier = self
            .bridge
            .read_word(wrangler.wrapping_add(0x6c))
            .unwrap_or(0);
        if notifier != 0 {
            return false;
        }

        info!(
            wrangler = format!("{wrangler:#x}"),
            phy = format!("{:#x}", self.cpu.regs[4]),
            insns = self.insn_count,
            "kernel usb wrangler null notifier race"
        );
        self.cpu.regs[15] = KERNEL_USB_WRANGLER_PHY_REGISTERED_AFTER_NOTIFIER;
        true
    }

    pub(super) fn force_iomedia_bsd_resource_check(&mut self, pc: u32) -> bool {
        if pc != KERNEL_IO_SERVICE_CHECK_RESOURCES || !self.force_iobsd {
            return false;
        }

        let service = self.cpu.regs[0];
        let vtable = self.bridge.read_word(service).unwrap_or(0);
        let force_all = self.force_iobsd_all
            && self.cpu.regs[14] == KERNEL_IO_SERVICE_START_CANDIDATE_AFTER_CHECK_RESOURCES;
        if !force_all && vtable != KERNEL_IOMEDIA_BSD_CLIENT_VTABLE {
            return false;
        }

        let lr = self.cpu.regs[14];
        self.cpu.regs[0] = 1;
        self.cpu.cpsr.t = lr & 1 != 0;
        self.cpu.regs[15] = lr & !1;

        info!(
            service = format!("{service:#x}"),
            vtable = format!("{vtable:#x}"),
            lr = format!("{lr:#x}"),
            force_all,
            insns = self.insn_count,
            "kernel forced IOService resource check"
        );
        true
    }

    pub(super) fn seed_sparse_vfl_mask(&mut self) {
        if std::env::var("RAX_S5L_NO_SPARSE_VFL_MASK").is_ok() {
            return;
        }

        let bank = self.cpu.regs[8] as usize;
        if bank >= self.sparse_vfl_mask_seeded.len() || self.sparse_vfl_mask_seeded[bank] {
            return;
        }

        let blocks = {
            let mut inner = self.bridge.inner.borrow_mut();
            inner.nand.sparse_vfl_context_blocks(bank as i64)
        };
        if blocks.is_empty() {
            return;
        }

        let mask_base = self.cpu.regs[5];
        let mut changed = false;
        for block in &blocks {
            let mask_addr = mask_base.wrapping_add(*block / 8);
            let Ok(mask_byte) = self.bridge.read_byte(mask_addr) else {
                continue;
            };
            let new_mask_byte = mask_byte | (1 << (*block & 7));
            if new_mask_byte != mask_byte
                && self.bridge.write_byte(mask_addr, new_mask_byte).is_ok()
            {
                changed = true;
            }
        }

        self.sparse_vfl_mask_seeded[bank] = true;
        if changed {
            info!(
                bank,
                mask_base = format!("{mask_base:#x}"),
                blocks = ?blocks,
                "seeded sparse VFL mask"
            );
        }
    }

    pub(super) fn seed_img2_security_state(&mut self) {
        if self.security_state_seeded
            || self.cpu.regs[0] != 1
            || std::env::var("RAX_S5L_NO_SECURITY_SEED").is_ok()
        {
            return;
        }

        let flags = self.phys_r32(IBOOT_SECURITY_STATE_WORD);
        if flags & IBOOT_SECURITY_IMG2_LOAD_OK == 0 {
            let new_flags = flags | IBOOT_SECURITY_IMG2_LOAD_OK;
            self.phys_w(IBOOT_SECURITY_STATE_WORD, &new_flags.to_le_bytes());
            info!(
                before = format!("{flags:#x}"),
                after = format!("{new_flags:#x}"),
                "seeded iBoot IMG2 security state"
            );
        }
        self.security_state_seeded = true;
    }
}
