//! Single-instruction execution and precise exception boundaries.
use super::*;

impl S5L8900Vcpu {
    pub(super) fn step(&mut self) -> StepOutcome {
        self.sync_mmu();
        let pc = self.cpu.regs[15];
        if self.lcd_irq && !self.lcd_irq_armed && pc == KERNEL_BSD_INIT_AFTER_VFS_MOUNTROOT {
            self.arm_lcd_refresh("vfs_mountroot returned");
        } else if self.lcd_irq
            && !self.lcd_irq_armed
            && self.lcd_irq_arm_after_rootdev
            && self.insn_count & 0xFFFF == 0
            && self.bridge.read_word(KERNEL_ROOTDEV_GLOBAL).unwrap_or(0) != 0
        {
            self.arm_lcd_refresh("root device selected");
        }
        self.tick_lcd_refresh(1);
        {
            self.timer_irq_clock = self.timer_irq_clock.saturating_add(1);
            let mut inner = self.bridge.inner.borrow_mut();
            // The synthesized system-tick IRQ drives iBoot's cooperative
            // scheduler. tick_irq self-gates on the timer's `started` flag, so
            // it only fires once iBoot has armed TIMER_4 (i.e. the scheduler is
            // up). This is what wakes tasks blocked in task_sleep.
            // Pace the µs timer from retired instructions by default. The
            // interpreter runs much slower than the real S5L8900 CPU, so using
            // host wall time lets XNU timeout callouts overtake interrupt and
            // configuration work. The explicit zero diagnostic mode below
            // retains coarse updates from the selected VM elapsed clock
            // (host elapsed time in Wall mode).
            if self.det_timer != 0 || self.insn_count & 0xFF == 0 {
                inner.timer.set_micros(self.timer_ticks());
            }
            if self.timer_irq {
                inner.timer.tick_irq(
                    self.timer_irq_ready,
                    self.timer_irq_interval,
                    self.insn_count,
                    self.timer_irq_interval,
                );
            }
        }

        let (irq_pending, fiq_pending) = self.sync_irqs();
        if irq_pending || fiq_pending {
            self.cpu.is_halted = false;
        }
        // Only deliver external exceptions once the guest has actually
        // installed its vectors at the active vector base. iBoot runs from
        // 0x18000000 and maps virtual 0 -> its in-place vector table only after
        // early init; before that the vectors read back as zeros and the CPU
        // would walk off into low memory. The real vector instruction is
        // `LDR pc, [pc, #0x18]` (0xe59ff018), so gate on seeing it. This
        // replaces the fragile fixed-instruction-count readiness heuristic.
        let irq_vector_ready = {
            let vbar = self.cpu.cp15.sctlr.vector_base();
            matches!(
                self.bridge.read_word(vbar.wrapping_add(0x18)),
                Ok(ARM_LDR_PC_PC_0X18)
            )
        };
        let fiq_vector_ready = self.fiq_vector_ready(irq_vector_ready);
        self.trace_i2c1_irq_handoff(irq_pending, irq_vector_ready);
        self.trace_fiq_gate(fiq_pending, irq_vector_ready, fiq_vector_ready);
        self.advance_irq_samples();
        if fiq_pending && !self.cpu.cpsr.f && fiq_vector_ready {
            let from = self.cpu.regs[15];
            let from_cpsr = self.cpu.cpsr.to_u32();
            let vbar = self.cpu.cp15.sctlr.vector_base();
            self.take_exception(ExceptionType::Fiq);
            if self.fault_log_budget > 0 {
                self.fault_log_budget -= 1;
                debug!(
                    from = format!("{from:#x}"),
                    from_cpsr = format!("{from_cpsr:#x}"),
                    spsr_fiq = format!("{:#x}", self.cpu.spsr_fiq.to_u32()),
                    vbar = format!("{vbar:#x}"),
                    to = format!("{:#x}", self.cpu.regs[15]),
                    fiq_sp = format!("{:#x}", self.cpu.regs[13]),
                    insns = self.insn_count,
                    "fiq delivered"
                );
            }
            return StepOutcome::Progress;
        }

        if irq_pending && !self.cpu.cpsr.i && irq_vector_ready {
            let from = self.cpu.regs[15];
            let from_cpsr = self.cpu.cpsr.to_u32();
            let vbar = self.cpu.cp15.sctlr.vector_base();
            self.take_exception(ExceptionType::Irq);
            if self.fault_log_budget > 0 {
                self.fault_log_budget -= 1;
                debug!(
                    from = format!("{from:#x}"),
                    from_cpsr = format!("{from_cpsr:#x}"),
                    spsr_irq = format!("{:#x}", self.cpu.spsr_irq.to_u32()),
                    vbar = format!("{vbar:#x}"),
                    to = format!("{:#x}", self.cpu.regs[15]),
                    irq_sp = format!("{:#x}", self.cpu.regs[13]),
                    insns = self.insn_count,
                    "irq delivered"
                );
            }
            return StepOutcome::Progress;
        }

        if self.cpu.is_halted {
            self.timer_irq_clock = self
                .timer_irq_clock
                .saturating_add(self.timer_irq_interval.max(1));
            let micros = self.timer_ticks();
            {
                let mut inner = self.bridge.inner.borrow_mut();
                inner.timer.set_micros(micros);
                if self.timer_irq {
                    inner.timer.tick_irq(
                        self.timer_irq_ready,
                        self.timer_irq_interval,
                        self.timer_irq_clock,
                        self.timer_irq_interval,
                    );
                }
                if self.idle_trace
                    && self.insn_count >= self.idle_trace_start_insn
                    && self.last_idle_trace_insn != self.timer_irq_clock
                {
                    self.last_idle_trace_insn = self.timer_irq_clock;
                    let (
                        timer_micros,
                        timer_status,
                        timer_config,
                        bcount1,
                        bcount2,
                        timer_irq,
                        timer_started,
                        next_irq_micros,
                        next_irq_insn,
                    ) = inner.timer.debug_state();
                    info!(
                        pc = format!("{:#x}", self.cpu.regs[15]),
                        lr = format!("{:#x}", self.cpu.regs[14]),
                        cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                        insns = self.insn_count,
                        timer_irq_clock = self.timer_irq_clock,
                        timer_micros,
                        timer_status = format!("{timer_status:#x}"),
                        timer_config = format!("{timer_config:#x}"),
                        bcount1 = format!("{bcount1:#x}"),
                        bcount2 = format!("{bcount2:#x}"),
                        timer_irq,
                        timer_started,
                        next_irq_micros,
                        next_irq_insn,
                        vic0_raw = format!("{:#x}", inner.vic0.rawintr),
                        vic0_en = format!("{:#x}", inner.vic0.intenable),
                        vic0_irq = format!("{:#x}", inner.vic0.irq_status),
                        vic1_raw = format!("{:#x}", inner.vic1.rawintr),
                        vic1_en = format!("{:#x}", inner.vic1.intenable),
                        vic1_irq = format!("{:#x}", inner.vic1.irq_status),
                        "s5l idle trace"
                    );
                }
            }
            // QEMU's LCD refresh is a display timer, not CPU-instruction
            // progress. Keep it able to wake the guest once the kernel blocks
            // waiting for post-root work.
            self.tick_lcd_refresh(200_000);
            return StepOutcome::Idle;
        }

        // Debug aid: once iBoot has reached its console wait, inject serial
        // input (RAX_S5L_INPUT) into the UART RX so its recovery console can be
        // driven (e.g. a boot command). Seeded once.
        if !self.input_seeded && self.insn_count > 50_000_000 {
            if let Some(bytes) = self.input_payload.as_ref() {
                if let Some(u) = self.uart.get() {
                    if let Ok(mut u) = u.lock() {
                        u.queue_input(bytes);
                    }
                }
                self.input_seeded = true;
            }
        }

        if self.fix_usb_wrangler_phy_registered_race(pc) {
            return StepOutcome::Progress;
        }
        if self.force_iomedia_bsd_resource_check(pc) {
            return StepOutcome::Progress;
        }
        if self.printf_trace && pc == IBOOT_PRINTF {
            self.trace_iboot_printf();
        }
        if pc == IBOOT_SECURITY_STATE_CHECK {
            self.seed_img2_security_state();
        }
        if pc == IBOOT_VFL_MASK_TEST {
            self.seed_sparse_vfl_mask();
            if self.vfl_scan_trace {
                self.trace_vfl_scan();
            }
        }
        if self.fsboot_trace {
            self.trace_fsboot_pc(pc);
        }
        self.pc_ring[self.pc_ring_idx] = pc;
        self.pc_ring_idx = (self.pc_ring_idx + 1) % self.pc_ring.len();
        let is_thumb = self.cpu.cpsr.t;

        let mut insn_len = 4u32;
        // Decode bytes in MEMORY order (the decoder reads hw1 from bytes[0..2],
        // hw2 from bytes[2..4]). For ARM and 16-bit Thumb this is just the
        // little-endian word/halfword.
        let mut decode_bytes = [0u8; 4];
        let raw = if is_thumb {
            let hw1 = match self.bridge.read_halfword(pc) {
                Ok(v) => v,
                Err(_) => return self.prefetch_abort(pc),
            };
            decode_bytes[0..2].copy_from_slice(&hw1.to_le_bytes());
            if (hw1 >> 11) >= 0x1D {
                let hw2 = match self.bridge.read_halfword(pc.wrapping_add(2)) {
                    Ok(v) => v,
                    Err(_) => return self.prefetch_abort(pc),
                };
                decode_bytes[2..4].copy_from_slice(&hw2.to_le_bytes());
                ((hw1 as u32) << 16) | hw2 as u32
            } else {
                insn_len = 2;
                hw1 as u32
            }
        } else {
            let w = match self.bridge.read_word(pc) {
                Ok(v) => v,
                Err(_) => return self.prefetch_abort(pc),
            };
            decode_bytes.copy_from_slice(&w.to_le_bytes());
            w
        };

        // Derail detector: a long run of all-zero instruction words means the
        // CPU has branched into zeroed memory. Dump the recent PC history so
        // the bad branch can be located, then stop.
        if raw == 0 && pc < 0x1800_0000 {
            self.zero_slide += 1;
            if self.zero_slide == 48 && self.derail_trace {
                let mut trail = Vec::new();
                for i in 0..self.pc_ring.len() {
                    let idx = (self.pc_ring_idx + i) % self.pc_ring.len();
                    let p = self.pc_ring[idx];
                    if p >= 0x1800_0000 {
                        trail.push(format!("{p:#x}"));
                    }
                }
                debug!(
                    trail = trail.join(" "),
                    insns = self.insn_count,
                    "derail trail"
                );
                self.shutdown = true;
                return StepOutcome::Idle;
            }
        } else {
            self.zero_slide = 0;
        }

        if pc >= 0xC000_0000 {
            self.bridge.inner.borrow_mut().kernel_started = true;
            self.trace_kernel_pc(pc, raw);
            self.trace_pc_sample(pc, raw);
            self.trace_storage_call(pc);
            self.trace_partition_scan(pc);
            self.trace_fdisk_partition(pc);
            self.trace_root_boot(pc);
            self.trace_apple_arm_function(pc, raw);
            self.trace_iokit_message_path(pc, raw);
            self.trace_pmqueue(pc, raw);
            self.trace_sdio_power(pc, raw);
            self.trace_iokit_object_watch(pc, raw);
            self.trace_ioreg_free(pc, raw);
            self.trace_iokit_lifetime(pc, raw);
            self.trace_admfmc_perform_io(pc);
            self.trace_nandftl_start(pc);
            self.track_wmr_init(pc);
            self.trace_wmr_init(pc);
        }
        if pc == KERNEL_SLEH_ABORT {
            self.trace_kernel_sleh_abort_frame();
        } else if pc == KERNEL_IOPANIC {
            self.trace_kernel_iopanic();
        } else if pc == KERNEL_PANIC {
            self.trace_kernel_panic();
        }

        if self.trace_all && self.insn_count >= self.trace_start_insn && self.trace_log_budget > 0 {
            self.trace_log_budget -= 1;
            info!(
                pc = format!("{pc:#x}"),
                raw = format!("{raw:#010x}"),
                lr = format!("{:#x}", self.cpu.regs[14]),
                cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                spsr_irq = format!("{:#x}", self.cpu.spsr_irq.to_u32()),
                insns = self.insn_count,
                "insn"
            );
        }
        if self.trace_pcs.contains(&pc)
            && self.trace_log_budget > 0
            && self.insn_count >= self.trace_start_insn
        {
            self.trace_log_budget -= 1;
            let regs: Vec<String> = (0..16)
                .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
                .collect();
            info!(
                pc = format!("{pc:#x}"),
                raw = format!("{raw:#010x}"),
                regs = regs.join(" "),
                cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                insns = self.insn_count,
                "trace-pc hit"
            );
        }

        let state = if is_thumb {
            ExecutionState::Thumb
        } else {
            ExecutionState::Aarch32
        };
        let slice: &[u8] = if insn_len == 2 {
            &decode_bytes[..2]
        } else {
            &decode_bytes
        };
        self.decoder.set_state(state);
        let insn = match self.decoder.decode(slice) {
            Ok(i) => i,
            Err(_) => {
                self.log_undefined_instruction("decode", pc, raw, insn_len, None);
                self.take_exception(ExceptionType::UndefinedInstruction);
                return StepOutcome::Progress;
            }
        };

        {
            let mut inner = self.bridge.inner.borrow_mut();
            inner.cur_pc = pc;
            inner.cur_insn = self.insn_count;
        }
        let vbar = self.cpu.cp15.sctlr.vector_base();
        let advance_it = is_thumb && self.cpu.cpsr.in_it_block();
        let mut exec = Executor::with_vbar(&mut self.cpu, &mut self.bridge, vbar);
        exec.exclusive_monitor = self.excl.clone();
        let result = exec.execute(&insn);
        self.excl = exec.exclusive_monitor.clone();
        if !matches!(
            result,
            ExecResult::Undefined
                | ExecResult::MemoryFault(_)
                | ExecResult::FpAccessTrap { .. }
                | ExecResult::Exception(ExceptionType::UndefinedInstruction)
        ) {
            self.insn_count = self.insn_count.wrapping_add(1);
        }

        // Service any decryption request the just-executed store triggered.
        if self.bridge.inner.borrow().engine_8900_req.is_some() {
            self.service_engine_8900();
        }
        // Service an AES-engine GO the just-executed store triggered.
        if self.bridge.inner.borrow().aes.pending_go {
            self.service_aes();
        }
        // Service any ADM/NAND DMA command the just-executed store triggered.
        if self.bridge.inner.borrow().adm_req.is_some() {
            self.service_adm();
        }

        match result {
            ExecResult::Continue => {
                self.cpu.regs[15] = self.cpu.regs[15].wrapping_add(insn_len);
                if advance_it {
                    self.cpu.cpsr.advance_it_state();
                }
                StepOutcome::Progress
            }
            ExecResult::Branch(target) => {
                if insn.mnemonic == Mnemonic::RFE {
                    // RFE restored CPSR (including T) itself.
                    self.cpu.regs[15] = target & !1;
                } else if target & 1 != 0 {
                    self.cpu.cpsr.t = true;
                    self.cpu.regs[15] = target & !1;
                } else {
                    self.cpu.regs[15] = target;
                }
                if advance_it {
                    self.cpu.cpsr.advance_it_state();
                }
                StepOutcome::Progress
            }
            ExecResult::Exception(exc) => {
                self.take_exception(exc);
                StepOutcome::Progress
            }
            ExecResult::FpAccessTrap {
                target_el,
                syndrome,
                undefined,
            } => {
                // Access traps complete no guest instruction or device access.
                if target_el != 2 {
                    return StepOutcome::Fault(Error::InvalidConfig(format!(
                        "AArch32-only machine cannot enter EL{target_el}"
                    )));
                }
                self.take_exception(ExceptionType::HypervisorTrap {
                    syndrome,
                    undefined,
                });
                StepOutcome::Progress
            }
            ExecResult::Halt => {
                self.cpu.regs[15] = pc.wrapping_add(insn_len);
                if advance_it {
                    self.cpu.cpsr.advance_it_state();
                }
                self.cpu.is_halted = true;
                StepOutcome::Idle
            }
            ExecResult::Undefined => {
                self.log_undefined_instruction("execute", pc, raw, insn_len, Some(insn.mnemonic));
                self.take_exception(ExceptionType::UndefinedInstruction);
                StepOutcome::Progress
            }
            ExecResult::MemoryFault(_) => {
                let f = self.bridge.inner.borrow().last_fault;
                if self.should_log_kernel_fault(self.cpu.regs[15]) {
                    info!(
                        pc = format!("{:#x}", self.cpu.regs[15]),
                        raw = format!("{raw:#010x}"),
                        addr = format!("{:#x}", f.addr),
                        fsr = format!("{:#x}", f.fsr),
                        domain = f.domain,
                        access = format!("{:#x}", f.access),
                        r0 = format!("{:#x}", self.cpu.regs[0]),
                        r1 = format!("{:#x}", self.cpu.regs[1]),
                        r2 = format!("{:#x}", self.cpu.regs[2]),
                        r3 = format!("{:#x}", self.cpu.regs[3]),
                        r4 = format!("{:#x}", self.cpu.regs[4]),
                        r5 = format!("{:#x}", self.cpu.regs[5]),
                        r6 = format!("{:#x}", self.cpu.regs[6]),
                        r7 = format!("{:#x}", self.cpu.regs[7]),
                        sp = format!("{:#x}", self.cpu.regs[13]),
                        lr = format!("{:#x}", self.cpu.regs[14]),
                        cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                        spsr_abt = format!("{:#x}", self.cpu.spsr_abt.to_u32()),
                        sp_abt = format!("{:#x}", self.cpu.regs_abt[0]),
                        lr_abt = format!("{:#x}", self.cpu.regs_abt[1]),
                        trail = self.recent_pc_trail(24),
                        insns = self.insn_count,
                        "kernel data abort"
                    );
                }
                if self.fault_log_budget > 0 {
                    self.fault_log_budget -= 1;
                    debug!(
                        pc = format!("{:#x}", self.cpu.regs[15]),
                        addr = format!("{:#x}", f.addr),
                        fsr = format!("{:#x}", f.fsr),
                        insns = self.insn_count,
                        "data abort"
                    );
                }
                self.cpu.cp15.dfsr =
                    f.fsr | (f.domain << 4) | if f.access & 3 == 1 { 1 << 11 } else { 0 };
                self.cpu.cp15.dfar = f.addr;
                self.take_exception(ExceptionType::DataAbort(f.addr));
                StepOutcome::Progress
            }
        }
    }
}
