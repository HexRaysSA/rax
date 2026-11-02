//! S5L platform diagnostics.
use super::*;

impl S5L8900Vcpu {
    pub(super) fn recent_pc_trail(&self, limit: usize) -> String {
        let mut trail = Vec::new();
        for i in 0..self.pc_ring.len() {
            let idx = (self.pc_ring_idx + i) % self.pc_ring.len();
            let pc = self.pc_ring[idx];
            if pc != 0 {
                trail.push(format!("{pc:#x}"));
            }
        }
        let start = trail.len().saturating_sub(limit);
        trail[start..].join(" ")
    }

    pub(super) fn log_undefined_instruction(
        &self,
        reason: &'static str,
        pc: u32,
        raw: u32,
        insn_len: u32,
        mnemonic: Option<Mnemonic>,
    ) {
        if std::env::var_os("RAX_S5L_UNDEF_TRACE").is_none() {
            return;
        }

        info!(
            reason,
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            insn_len,
            mnemonic = ?mnemonic,
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r4 = format!("{:#x}", self.cpu.regs[4]),
            r5 = format!("{:#x}", self.cpu.regs[5]),
            r6 = format!("{:#x}", self.cpu.regs[6]),
            r7 = format!("{:#x}", self.cpu.regs[7]),
            r8 = format!("{:#x}", self.cpu.regs[8]),
            r9 = format!("{:#x}", self.cpu.regs[9]),
            r10 = format!("{:#x}", self.cpu.regs[10]),
            r11 = format!("{:#x}", self.cpu.regs[11]),
            r12 = format!("{:#x}", self.cpu.regs[12]),
            sp = format!("{:#x}", self.cpu.regs[13]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            spsr_und = format!("{:#x}", self.cpu.spsr_und.to_u32()),
            sp_und = format!("{:#x}", self.cpu.regs_und[0]),
            lr_und = format!("{:#x}", self.cpu.regs_und[1]),
            trail = self.recent_pc_trail(96),
            insns = self.insn_count,
            "undefined instruction trace"
        );
    }

    pub(super) fn heartbeat(&mut self) {
        if self.heartbeat_clock.elapsed() >= std::time::Duration::from_secs(2) {
            let heartbeat_info = std::env::var_os("RAX_S5L_HEARTBEAT_INFO").is_some();
            let mmu = self.bridge.inner.borrow().mmu.enabled;
            if heartbeat_info {
                info!(
                    insns = self.insn_count,
                    pc = format!("{:#x}", self.cpu.regs[15]),
                    lr = format!("{:#x}", self.cpu.regs[14]),
                    cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                    mmu,
                    "s5l8900 emulator heartbeat"
                );
            } else {
                debug!(
                    insns = self.insn_count,
                    pc = format!("{:#x}", self.cpu.regs[15]),
                    lr = format!("{:#x}", self.cpu.regs[14]),
                    cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                    mmu,
                    "s5l8900 emulator heartbeat"
                );
            }
            // Debug aid: dump the call stack (likely iBoot return addresses
            // found on the stack) to reveal the active loop.
            if std::env::var("RAX_S5L_STACKDUMP").is_ok() {
                let sp = self.cpu.regs[13];
                let mut frames = Vec::new();
                for i in 0..256u32 {
                    if let Ok(w) = self.bridge.read_word(sp.wrapping_add(i * 4)) {
                        let a = w & !1; // strip Thumb bit
                        if (0x1800_0000..0x1802_0000).contains(&a)
                            || (0xC000_0000..0xC060_0000).contains(&a)
                        {
                            frames.push(format!("{a:#x}"));
                        }
                    }
                }
                if heartbeat_info {
                    info!(
                        sp = format!("{sp:#x}"),
                        pc = format!("{:#x}", self.cpu.regs[15]),
                        stack = frames.join(" "),
                        "stack dump"
                    );
                } else {
                    debug!(
                        sp = format!("{sp:#x}"),
                        pc = format!("{:#x}", self.cpu.regs[15]),
                        stack = frames.join(" "),
                        "stack dump"
                    );
                }
            }
            // Debug aid: dump an arbitrary physical region (RAX_S5L_MEMDUMP=
            // <hexaddr>:<hexlen>:<path>) — e.g. iBoot's log/heap area.
            if let Ok(spec) = std::env::var("RAX_S5L_MEMDUMP") {
                let parts: Vec<&str> = spec.split(':').collect();
                if parts.len() == 3 {
                    if let (Ok(addr), Ok(len)) = (
                        u64::from_str_radix(parts[0].trim_start_matches("0x"), 16),
                        usize::from_str_radix(parts[1].trim_start_matches("0x"), 16),
                    ) {
                        let mut buf = vec![0u8; len];
                        if self
                            .bridge
                            .mem
                            .read_slice(&mut buf, GuestAddress(addr))
                            .is_ok()
                        {
                            let _ = std::fs::write(parts[2], &buf);
                        }
                    }
                }
            }
            // Debug aid: dump an arbitrary virtual region using the current MMU
            // translation (RAX_S5L_VMEMDUMP=<hexaddr>:<hexlen>:<path>).
            if let Ok(specs) = std::env::var("RAX_S5L_VMEMDUMP") {
                for spec in specs.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    let parts: Vec<&str> = spec.split(':').collect();
                    if parts.len() == 3 {
                        if let (Ok(addr), Ok(len)) = (
                            u32::from_str_radix(parts[0].trim_start_matches("0x"), 16),
                            usize::from_str_radix(parts[1].trim_start_matches("0x"), 16),
                        ) {
                            let mut buf = Vec::with_capacity(len);
                            for off in 0..len as u32 {
                                buf.push(
                                    self.bridge.read_byte(addr.wrapping_add(off)).unwrap_or(0),
                                );
                            }
                            let _ = std::fs::write(parts[2], &buf);
                        }
                    }
                }
            }
            // Debug aid: dump the LCD framebuffer (physical 0x0fe00000,
            // 320x480 BGRA) to a file so the rendered boot image can be
            // inspected. Gated by RAX_S5L_FBDUMP=<path>.
            if let Ok(path) = std::env::var("RAX_S5L_FBDUMP") {
                let mut buf = vec![0u8; 320 * 480 * 4];
                if self
                    .bridge
                    .mem
                    .read_slice(&mut buf, GuestAddress(0x0fe0_0000))
                    .is_ok()
                {
                    let _ = std::fs::write(&path, &buf);
                }
            }
            self.heartbeat_clock.reset();
        }
    }

    pub(super) fn trace_iboot_printf(&self) {
        let fmt_addr = self.cpu.regs[0];
        let Some(fmt) = self.guest_iboot_cstr(fmt_addr, 384) else {
            return;
        };
        info!(
            fmt = fmt,
            fmt_addr = format!("{fmt_addr:#x}"),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            insns = self.insn_count,
            "iboot printf"
        );
    }

    pub(super) fn trace_vfl_scan(&self) {
        let block = self.cpu.regs[4];
        let mask_base = self.cpu.regs[5];
        let mask_addr = mask_base.wrapping_add(block / 8);
        let mask_byte = self.bridge.read_byte(mask_addr).unwrap_or(0);
        let should_probe = (mask_byte & (1 << (block & 7))) != 0;

        if block <= 48 || should_probe {
            info!(
                block,
                mask_addr = format!("{mask_addr:#x}"),
                mask_byte = format!("{mask_byte:#x}"),
                should_probe,
                insns = self.insn_count,
                "iboot vfl scan"
            );
        }
    }

    pub(super) fn trace_kernel_pc(&mut self, pc: u32, raw: u32) {
        if !self.kernel_entry_logged {
            self.kernel_entry_logged = true;
            info!(
                pc = format!("{pc:#x}"),
                raw = format!("{raw:#010x}"),
                r0 = format!("{:#x}", self.cpu.regs[0]),
                r1 = format!("{:#x}", self.cpu.regs[1]),
                r2 = format!("{:#x}", self.cpu.regs[2]),
                r3 = format!("{:#x}", self.cpu.regs[3]),
                sp = format!("{:#x}", self.cpu.regs[13]),
                lr = format!("{:#x}", self.cpu.regs[14]),
                cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                spsr_irq = format!("{:#x}", self.cpu.spsr_irq.to_u32()),
                spsr_abt = format!("{:#x}", self.cpu.spsr_abt.to_u32()),
                sp_usr = format!("{:#x}", self.cpu.regs_usr[0]),
                sp_irq = format!("{:#x}", self.cpu.regs_irq[0]),
                sp_svc = format!("{:#x}", self.cpu.regs_svc[0]),
                sp_abt = format!("{:#x}", self.cpu.regs_abt[0]),
                ttbr0 = format!("{:#x}", self.cpu.cp15.ttbr0),
                dacr = format!("{:#x}", self.cpu.cp15.dacr),
                dfsr = format!("{:#x}", self.cpu.cp15.dfsr),
                dfar = format!("{:#x}", self.cpu.cp15.dfar),
                insns = self.insn_count,
                "kernel entry"
            );
        }

        if self.kernel_trace_remaining == 0 {
            return;
        }
        self.kernel_trace_remaining -= 1;
        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            sp = format!("{:#x}", self.cpu.regs[13]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            spsr_abt = format!("{:#x}", self.cpu.spsr_abt.to_u32()),
            sp_usr = format!("{:#x}", self.cpu.regs_usr[0]),
            sp_irq = format!("{:#x}", self.cpu.regs_irq[0]),
            sp_svc = format!("{:#x}", self.cpu.regs_svc[0]),
            sp_abt = format!("{:#x}", self.cpu.regs_abt[0]),
            insns = self.insn_count,
            "kernel trace"
        );
    }

    pub(super) fn trace_kernel_sleh_abort_frame(&mut self) {
        if self.kernel_exception_log_remaining == 0 {
            return;
        }
        self.kernel_exception_log_remaining -= 1;

        let frame = self.cpu.regs[0];
        let word = |off: u32| self.bridge.read_word(frame.wrapping_add(off)).unwrap_or(0);
        let saved_r0 = word(0x00);
        let saved_r1 = word(0x04);
        let saved_r2 = word(0x08);
        let saved_r3 = word(0x0c);
        let saved_pc = word(0x3c);
        let saved_cpsr = word(0x40);
        let fsr = word(0x44);
        let far = word(0x48);

        info!(
            frame = format!("{frame:#x}"),
            kind = self.cpu.regs[1],
            saved_r0 = format!("{saved_r0:#x}"),
            saved_r1 = format!("{saved_r1:#x}"),
            saved_r2 = format!("{saved_r2:#x}"),
            saved_r3 = format!("{saved_r3:#x}"),
            saved_sp = format!("{:#x}", word(0x34)),
            saved_lr = format!("{:#x}", word(0x38)),
            saved_pc = format!("{saved_pc:#x}"),
            saved_pc_raw = format!("{:#010x}", self.bridge.read_word(saved_pc).unwrap_or(0)),
            saved_cpsr = format!("{saved_cpsr:#x}"),
            fsr = format!("{fsr:#x}"),
            far = format!("{far:#x}"),
            sp = format!("{:#x}", self.cpu.regs[13]),
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            trail = self.recent_pc_trail(24),
            insns = self.insn_count,
            "kernel sleh abort frame"
        );

        self.trace_kernel_abort_dump(frame, saved_pc, saved_cpsr);
    }

    pub(super) fn trace_kernel_abort_dump(&self, frame: u32, saved_pc: u32, saved_cpsr: u32) {
        if std::env::var("RAX_S5L_ABORT_DUMP").is_err() {
            return;
        }

        let word = |off: u32| self.bridge.read_word(frame.wrapping_add(off)).unwrap_or(0);
        let saved_regs = (0..=12)
            .map(|i| format!("r{i}={:#x}", word(i * 4)))
            .collect::<Vec<_>>()
            .join(" ");
        let saved_sp = word(0x34);
        let saved_lr = word(0x38);
        let pc_base = saved_pc.wrapping_sub(0x20);
        let thumb = saved_cpsr & (1 << 5) != 0;

        info!(
            frame = format!("{frame:#x}"),
            saved_regs,
            saved_sp = format!("{saved_sp:#x}"),
            saved_lr = format!("{saved_lr:#x}"),
            saved_pc = format!("{saved_pc:#x}"),
            mode = if thumb { "thumb" } else { "arm" },
            pc_words = self.guest_word_window(pc_base, 20),
            pc_halfwords = self.guest_halfword_window(saved_pc.wrapping_sub(0x10), 24),
            r0_words = self.guest_word_window(word(0x00), 4),
            r1_words = self.guest_word_window(word(0x04), 4),
            r2_words = self.guest_word_window(word(0x08), 8),
            r3_words = self.guest_word_window(word(0x0c), 8),
            r4_words = self.guest_word_window(word(0x10), 12),
            r5_words = self.guest_word_window(word(0x14), 32),
            r6_words = self.guest_word_window(word(0x18), 8),
            r7_words = self.guest_word_window(word(0x1c), 8),
            r8_words = self.guest_word_window(word(0x20), 8),
            sp_words = self.guest_word_window(saved_sp, 12),
            lr_words = self.guest_word_window(saved_lr.wrapping_sub(0x20), 12),
            r9_words = self.guest_word_window(word(0x24), 8),
            "kernel abort dump"
        );

        if let Ok(path) = std::env::var("RAX_S5L_ABORT_DUMP_FILE") {
            let start = saved_pc & !0xfff;
            let mut buf = Vec::with_capacity(0x1000);
            for off in 0..0x1000u32 {
                buf.push(self.bridge.read_byte(start.wrapping_add(off)).unwrap_or(0));
            }
            if std::fs::write(&path, &buf).is_ok() {
                info!(
                    path,
                    start = format!("{start:#x}"),
                    len = buf.len(),
                    "dumped abort page"
                );
            }
        }
    }

    pub(super) fn trace_admfmc_perform_io(&mut self, pc: u32) {
        if pc != KERNEL_ADMFMC_DISPATCH && pc != KERNEL_ADMFMC_PERFORM_IO
            || self.admfmc_trace_remaining == 0
        {
            return;
        }
        if !self.bridge.inner.borrow().kernel_started {
            return;
        }
        self.admfmc_trace_remaining -= 1;

        if pc == KERNEL_ADMFMC_DISPATCH {
            let fmc = self.cpu.regs[0];
            let gate = self.cpu.regs[1];
            let req = self.cpu.regs[2];
            let req_word = |off: u32| self.bridge.read_word(req.wrapping_add(off)).unwrap_or(0);
            let op = req_word(0x00);
            let flags = req_word(0x04);
            let span = req_word(0x08);
            let base = req_word(0x0c);
            let pages = req_word(0x10);
            let data = req_word(0x14);
            let data_offset = req_word(0x18);
            let banks = req_word(0x1c);
            let aux0 = req_word(0x20);
            let aux1 = req_word(0x24);
            let sp = self.cpu.regs[13];

            info!(
                pc = format!("{pc:#x}"),
                fmc = format!("{fmc:#x}"),
                gate = format!("{gate:#x}"),
                req = format!("{req:#x}"),
                op = format!("{op:#x}"),
                flags = format!("{flags:#x}"),
                span = format!("{span:#x}"),
                base = format!("{base:#x}"),
                pages = format!("{pages:#x}"),
                data = format!("{data:#x}"),
                data_offset = format!("{data_offset:#x}"),
                banks = format!("{banks:#x}"),
                aux0 = format!("{aux0:#x}"),
                aux1 = format!("{aux1:#x}"),
                req_words = self.guest_word_window(req, 12),
                page_words = self.guest_word_window(pages, 16),
                bank_halfwords = self.guest_halfword_window(banks, 16),
                bank_bytes = self.guest_byte_window(banks, 32),
                data_words = self.guest_word_window(data, 8),
                sp = format!("{sp:#x}"),
                stack_words = self.guest_word_window(sp, 64),
                stack_refs = self.stack_code_refs(sp, 256),
                r3 = format!("{:#x}", self.cpu.regs[3]),
                r4 = format!("{:#x}", self.cpu.regs[4]),
                r5 = format!("{:#x}", self.cpu.regs[5]),
                r6 = format!("{:#x}", self.cpu.regs[6]),
                r7 = format!("{:#x}", self.cpu.regs[7]),
                r8 = format!("{:#x}", self.cpu.regs[8]),
                r9 = format!("{:#x}", self.cpu.regs[9]),
                r10 = format!("{:#x}", self.cpu.regs[10]),
                r11 = format!("{:#x}", self.cpu.regs[11]),
                r12 = format!("{:#x}", self.cpu.regs[12]),
                lr = format!("{:#x}", self.cpu.regs[14]),
                trail = self.recent_pc_trail(48),
                insns = self.insn_count,
                "admfmc dispatch trace"
            );
            return;
        }

        let fmc = self.cpu.regs[0];
        let req = self.cpu.regs[1];
        let req_word = |off: u32| self.bridge.read_word(req.wrapping_add(off)).unwrap_or(0);
        let op = req_word(0x00);
        let flags = req_word(0x04);
        let span = req_word(0x08);
        let base = req_word(0x0c);
        let pages = req_word(0x10);
        let data = req_word(0x14);
        let data_offset = req_word(0x18);
        let banks = req_word(0x1c);
        let aux0 = req_word(0x20);
        let aux1 = req_word(0x24);

        info!(
            pc = format!("{pc:#x}"),
            fmc = format!("{fmc:#x}"),
            req = format!("{req:#x}"),
            op = format!("{op:#x}"),
            flags = format!("{flags:#x}"),
            span = format!("{span:#x}"),
            base = format!("{base:#x}"),
            pages = format!("{pages:#x}"),
            data = format!("{data:#x}"),
            data_offset = format!("{data_offset:#x}"),
            banks = format!("{banks:#x}"),
            aux0 = format!("{aux0:#x}"),
            aux1 = format!("{aux1:#x}"),
            req_words = self.guest_word_window(req, 12),
            page_words = self.guest_word_window(pages, 16),
            bank_halfwords = self.guest_halfword_window(banks, 16),
            bank_bytes = self.guest_byte_window(banks, 32),
            data_words = self.guest_word_window(data, 8),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            sp = format!("{:#x}", self.cpu.regs[13]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            insns = self.insn_count,
            "admfmc perform io trace"
        );
    }

    pub(super) fn trace_pc_sample(&mut self, pc: u32, raw: u32) {
        if self.pc_sample_interval == 0
            || self.pc_sample_remaining == 0
            || self.insn_count < self.pc_sample_next_insn
        {
            return;
        }

        self.pc_sample_remaining -= 1;
        self.pc_sample_next_insn = self.insn_count.saturating_add(self.pc_sample_interval);
        let regs: Vec<String> = (0..16)
            .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
            .collect();
        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            regs = regs.join(" "),
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            spsr_irq = format!("{:#x}", self.cpu.spsr_irq.to_u32()),
            spsr_abt = format!("{:#x}", self.cpu.spsr_abt.to_u32()),
            sp_usr = format!("{:#x}", self.cpu.regs_usr[0]),
            sp_irq = format!("{:#x}", self.cpu.regs_irq[0]),
            sp_svc = format!("{:#x}", self.cpu.regs_svc[0]),
            trail = self.recent_pc_trail(48),
            insns = self.insn_count,
            "pc sample"
        );
    }

    pub(super) fn stack_code_refs(&self, sp: u32, words: u32) -> String {
        let mut refs = Vec::new();
        for i in 0..words {
            if let Ok(w) = self.bridge.read_word(sp.wrapping_add(i * 4)) {
                let a = w & !1;
                if (0x1800_0000..0x1803_0000).contains(&a)
                    || (0xC000_0000..0xC060_0000).contains(&a)
                {
                    refs.push(format!("{a:#x}"));
                }
            }
        }
        refs.join(" ")
    }

    pub(super) fn guest_word_window(&self, addr: u32, words: u32) -> String {
        if addr == 0 {
            return String::from("<null>");
        }

        (0..words)
            .map(|i| {
                let a = (addr & !3).wrapping_add(i * 4);
                match self.bridge.read_word(a) {
                    Ok(w) => format!("{a:#x}:{w:#010x}"),
                    Err(_) => format!("{a:#x}:<fault>"),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub(super) fn guest_byte_window(&self, addr: u32, bytes: u32) -> String {
        if addr == 0 {
            return String::from("<null>");
        }

        (0..bytes)
            .map(|i| {
                let a = addr.wrapping_add(i);
                match self.bridge.read_byte(a) {
                    Ok(b) => format!("{b:02x}"),
                    Err(_) => String::from("??"),
                }
            })
            .collect::<Vec<_>>()
            .join("")
    }

    pub(super) fn guest_halfword_window(&self, addr: u32, halfwords: u32) -> String {
        if addr == 0 {
            return String::from("<null>");
        }

        (0..halfwords)
            .map(|i| {
                let a = (addr & !1).wrapping_add(i * 2);
                match self.bridge.read_halfword(a) {
                    Ok(w) => format!("{a:#x}:{w:#06x}"),
                    Err(_) => format!("{a:#x}:<fault>"),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub(super) fn trace_kernel_iopanic(&mut self) {
        if self.kernel_exception_log_remaining == 0 {
            return;
        }
        self.kernel_exception_log_remaining -= 1;

        info!(
            fmt = format!("{:#x}", self.cpu.regs[0]),
            fmt_str = ?self.guest_cstr(self.cpu.regs[0], 256),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r1_str = ?self.guest_cstr(self.cpu.regs[1], 256),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r2_str = ?self.guest_cstr(self.cpu.regs[2], 256),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r3_str = ?self.guest_cstr(self.cpu.regs[3], 256),
            r0_obj = self.iokit_object_summary(self.cpu.regs[0]),
            r1_obj = self.iokit_object_summary(self.cpu.regs[1]),
            r2_obj = self.iokit_object_summary(self.cpu.regs[2]),
            r3_obj = self.iokit_object_summary(self.cpu.regs[3]),
            sp = format!("{:#x}", self.cpu.regs[13]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            sp_words = self.guest_word_window(self.cpu.regs[13], 32),
            stack_refs = self.stack_code_refs(self.cpu.regs[13], 128),
            trail = self.recent_pc_trail(64),
            insns = self.insn_count,
            "kernel iopanic"
        );
    }

    pub(super) fn trace_kernel_panic(&mut self) {
        if self.kernel_exception_log_remaining == 0 {
            return;
        }
        self.kernel_exception_log_remaining -= 1;

        info!(
            fmt = format!("{:#x}", self.cpu.regs[0]),
            fmt_str = ?self.guest_cstr(self.cpu.regs[0], 256),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r1_str = ?self.guest_cstr(self.cpu.regs[1], 256),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r2_str = ?self.guest_cstr(self.cpu.regs[2], 256),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r3_str = ?self.guest_cstr(self.cpu.regs[3], 256),
            sp = format!("{:#x}", self.cpu.regs[13]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            sp_words = self.guest_word_window(self.cpu.regs[13], 32),
            stack_refs = self.stack_code_refs(self.cpu.regs[13], 128),
            trail = self.recent_pc_trail(64),
            insns = self.insn_count,
            "kernel panic"
        );
    }

    pub(super) fn trace_fsboot_pc(&self, pc: u32) {
        let Some((_, label)) = IBOOT_FSBOOT_TRACE_PCS
            .iter()
            .find(|(trace_pc, _)| *trace_pc == pc)
        else {
            return;
        };

        info!(
            pc = format!("{pc:#x}"),
            label,
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r4 = format!("{:#x}", self.cpu.regs[4]),
            r5 = format!("{:#x}", self.cpu.regs[5]),
            r8 = format!("{:#x}", self.cpu.regs[8]),
            r10 = format!("{:#x}", self.cpu.regs[10]),
            sp = format!("{:#x}", self.cpu.regs[13]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            r0_str = ?self.guest_iboot_cstr(self.cpu.regs[0], 160),
            r1_str = ?self.guest_iboot_cstr(self.cpu.regs[1], 160),
            r2_str = ?self.guest_iboot_cstr(self.cpu.regs[2], 160),
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            insns = self.insn_count,
            "fsboot trace"
        );
    }

    pub(super) fn guest_iboot_cstr(&self, addr: u32, max_len: usize) -> Option<String> {
        if !(IBOOT_BASE..IBOOT_IMAGE_LIMIT).contains(&addr) {
            return None;
        }

        self.guest_cstr(addr, max_len)
    }

    pub(super) fn guest_cstr(&self, addr: u32, max_len: usize) -> Option<String> {
        if addr == 0 {
            return None;
        }

        let mut bytes = Vec::new();
        for off in 0..max_len as u32 {
            let b = self.bridge.read_byte(addr.wrapping_add(off)).ok()?;
            if b == 0 {
                break;
            }
            bytes.push(match b {
                b'\n' => b' ',
                b'\r' => b' ',
                0x20..=0x7e => b,
                _ => b'.',
            });
        }

        (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).into_owned())
    }
}
