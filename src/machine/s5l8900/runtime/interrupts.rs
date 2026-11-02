//! S5L platform interrupts.
use super::*;

impl S5L8900Vcpu {
    pub(super) fn sync_mmu(&mut self) {
        let cp = &self.cpu.cp15;
        let mut inner = self.bridge.inner.borrow_mut();
        inner.mmu = V6MmuConfig {
            enabled: cp.sctlr.m(),
            ttbr0: cp.ttbr0 as u32,
            ttbr1: cp.ttbr1 as u32,
            ttbcr_n: cp.ttbcr & 0x7,
            dacr: cp.dacr,
            afe: false,
        };
        inner.privileged = self.cpu.cpsr.mode != ProcessorMode::User as u8;
    }

    /// Recompute VIC line levels from device state; return CPU IRQ/FIQ assertions.
    pub(super) fn sync_irqs(&mut self) -> (bool, bool) {
        let uart_lvl = self
            .uart
            .get()
            .and_then(|u| u.lock().ok().map(|u| u.irq_pending()))
            .unwrap_or(false);
        let mut inner = self.bridge.inner.borrow_mut();
        let timer_lvl = inner.timer.irq_pending();
        let lcd_lvl = inner.lcd.irq_pending();
        let spi0_lvl = inner.spi0.irq_pending();
        let spi1_lvl = inner.spi1.irq_pending();
        let spi2_lvl = inner.spi2.irq_pending();
        let dmac0_lvl = inner.dmac0.irq_pending();
        let dmac1_lvl = inner.dmac1.irq_pending();
        let i2c0_raw = inner.i2c0.irq_pending();
        let i2c1_raw = inner.i2c1.irq_pending();
        let i2c_irq_enabled = self.i2c_irq || !inner.kernel_started;
        let i2c0_lvl = i2c_irq_enabled && i2c0_raw;
        let i2c1_lvl = i2c_irq_enabled && i2c1_raw;
        let nand_ecc_lvl = inner.nand_ecc.irq_pending();
        let adm_lvl = inner.adm_irq;
        let usb_lvl = inner.usb.irq_pending();
        let priority_mode = inner.kernel_started;
        inner.vic0.set_priority_mode(priority_mode);
        inner.vic1.set_priority_mode(priority_mode);
        inner.vic0.set_line(TIMER1_IRQ, timer_lvl);
        inner
            .vic0
            .set_line(LCD_IRQ, lcd_lvl || (USB_OTG_IRQ == LCD_IRQ && usb_lvl));
        if USB_OTG_IRQ != LCD_IRQ {
            inner.vic0.set_line(USB_OTG_IRQ, usb_lvl);
        }
        inner.vic0.set_line(UART0_IRQ, uart_lvl);
        inner.vic0.set_line(SPI0_IRQ, spi0_lvl);
        inner.vic0.set_line(SPI1_IRQ, spi1_lvl);
        inner.vic0.set_line(SPI2_IRQ, spi2_lvl);
        inner.vic0.set_line(DMAC0_IRQ, dmac0_lvl);
        inner.vic0.set_line(DMAC1_IRQ, dmac1_lvl);
        inner.vic0.set_line(I2C0_IRQ, i2c0_lvl);
        inner.vic0.set_line(I2C1_IRQ, i2c1_lvl);
        inner.vic1.set_line(NAND_ECC_VIC1_LINE, nand_ecc_lvl);
        inner.set_adm_irq(adm_lvl);
        for (group, &global_irq) in GPIO_GROUP_IRQS.iter().enumerate() {
            // The QEMU reference raises a SYSIC GPIO group line whenever a
            // device sets that group's status bit, and lowers it on the
            // guest's write-1-to-clear of GPIO_INTSTAT.
            let gpio_lvl = inner.sysic.gpio_int_status[group] != 0;
            if global_irq < 32 {
                inner.vic0.set_line(global_irq, gpio_lvl);
            } else {
                inner.vic1.set_line(global_irq - 32, gpio_lvl);
            }
        }
        // VIC1 daisy-chains into VIC0.
        inner.refresh_vic_daisy();
        let daisy = inner.vic0.daisy_input;
        let cpu_irq = inner.vic0.irq_asserted();
        let cpu_fiq = inner.vic0.fiq_asserted();
        if self.adm_irq_trace_budget != 0
            && inner.kernel_started
            && self.insn_count >= self.adm_irq_trace_start_insn
        {
            let (v0_cur, v0_high, v0_prio, v0_depth, v0_irq_line, _) =
                inner.vic0.debug_priority_state();
            let (v1_cur, v1_high, v1_prio, v1_depth, v1_irq_line, _) =
                inner.vic1.debug_priority_state();
            let trace = (adm_lvl as u128)
                | ((dmac0_lvl as u128) << 1)
                | ((daisy as u128) << 2)
                | ((cpu_irq as u128) << 3)
                | ((cpu_fiq as u128) << 4)
                | (((inner.vic0.rawintr as u128) & 0xffff) << 8)
                | (((inner.vic0.intenable as u128) & 0xffff) << 24)
                | (((inner.vic1.rawintr as u128) & 0xffff) << 40)
                | (((inner.vic1.intenable as u128) & 0xffff) << 56)
                | (((v0_cur as u128) & 0x3f) << 72)
                | (((v0_high as u128) & 0x3f) << 78)
                | (((v0_prio as u128) & 0x1f) << 84)
                | (((v1_cur as u128) & 0x3f) << 89)
                | (((v1_high as u128) & 0x3f) << 95)
                | (((v1_prio as u128) & 0x1f) << 101);
            if trace != self.last_adm_irq_trace {
                self.last_adm_irq_trace = trace;
                self.adm_irq_trace_budget -= 1;
                info!(
                    pc = format!("{:#x}", self.cpu.regs[15]),
                    cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                    adm_lvl,
                    dmac0_lvl,
                    daisy,
                    cpu_irq,
                    cpu_fiq,
                    v0_raw = format!("{:#x}", inner.vic0.rawintr),
                    v0_en = format!("{:#x}", inner.vic0.intenable),
                    v0_irq = format!("{:#x}", inner.vic0.irq_status),
                    v0_addr = format!("{:#x}", inner.vic0.address),
                    v0_cur,
                    v0_high,
                    v0_prio,
                    v0_depth,
                    v0_irq_line,
                    v1_raw = format!("{:#x}", inner.vic1.rawintr),
                    v1_en = format!("{:#x}", inner.vic1.intenable),
                    v1_irq = format!("{:#x}", inner.vic1.irq_status),
                    v1_addr = format!("{:#x}", inner.vic1.address),
                    v1_cur,
                    v1_high,
                    v1_prio,
                    v1_depth,
                    v1_irq_line,
                    insns = self.insn_count,
                    "adm irq trace"
                );
            }
        }
        if self.irq_trace
            && inner.kernel_started
            && self.irq_trace_budget != 0
            && self.insn_count >= self.irq_trace_start_insn
        {
            let timer_bit = if self.irq_trace_timer {
                timer_lvl as u128
            } else {
                0
            };
            let vic0_raw_trace = if self.irq_trace_timer {
                inner.vic0.rawintr
            } else {
                inner.vic0.rawintr & !(1 << TIMER1_IRQ)
            };
            let trace = timer_bit
                | ((lcd_lvl as u128) << 1)
                | ((spi0_lvl as u128) << 2)
                | ((spi1_lvl as u128) << 3)
                | ((spi2_lvl as u128) << 4)
                | ((dmac0_lvl as u128) << 5)
                | ((dmac1_lvl as u128) << 6)
                | ((i2c0_lvl as u128) << 7)
                | ((i2c1_lvl as u128) << 8)
                | ((nand_ecc_lvl as u128) << 9)
                | ((adm_lvl as u128) << 10)
                | ((usb_lvl as u128) << 11)
                | ((uart_lvl as u128) << 12)
                | ((daisy as u128) << 13)
                | ((cpu_irq as u128) << 14)
                | ((cpu_fiq as u128) << 15)
                | ((vic0_raw_trace as u128) << 16)
                | ((inner.vic0.intenable as u128) << 48)
                | ((inner.vic1.rawintr as u128) << 80);
            if trace != self.last_irq_trace {
                self.last_irq_trace = trace;
                self.irq_trace_budget -= 1;
                let (
                    timer_micros,
                    timer_status,
                    timer_config,
                    timer_bcount1,
                    timer_bcount2,
                    timer_irq,
                    timer_started,
                    timer_next_irq_micros,
                    timer_next_irq_insn,
                ) = inner.timer.debug_state();
                info!(
                    pc = format!("{:#x}", self.cpu.regs[15]),
                    lr = format!("{:#x}", self.cpu.regs[14]),
                    cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
                    insns = self.insn_count,
                    timer_lvl,
                    lcd_lvl,
                    spi0_lvl,
                    spi1_lvl,
                    spi2_lvl,
                    dmac0_lvl,
                    dmac1_lvl,
                    i2c0_lvl,
                    i2c1_lvl,
                    i2c0_raw,
                    i2c1_raw,
                    nand_ecc_lvl,
                    adm_lvl,
                    usb_lvl,
                    uart_lvl,
                    daisy,
                    cpu_irq,
                    cpu_fiq,
                    vic0_raw = format!("{:#x}", inner.vic0.rawintr),
                    vic0_en = format!("{:#x}", inner.vic0.intenable),
                    vic0_irq = format!("{:#x}", inner.vic0.irq_status),
                    vic0_addr = format!("{:#x}", inner.vic0.address),
                    vic1_raw = format!("{:#x}", inner.vic1.rawintr),
                    vic1_en = format!("{:#x}", inner.vic1.intenable),
                    vic1_irq = format!("{:#x}", inner.vic1.irq_status),
                    vic1_addr = format!("{:#x}", inner.vic1.address),
                    timer_micros,
                    timer_status = format!("{timer_status:#x}"),
                    timer_config = format!("{timer_config:#x}"),
                    timer_bcount1 = format!("{timer_bcount1:#x}"),
                    timer_bcount2 = format!("{timer_bcount2:#x}"),
                    timer_irq,
                    timer_started,
                    timer_next_irq_micros,
                    timer_next_irq_insn,
                    "irq_trace"
                );
            }
        }
        (cpu_irq, cpu_fiq)
    }

    pub(super) fn advance_irq_samples(&mut self) {
        let mut inner = self.bridge.inner.borrow_mut();
        inner.i2c0.advance_irq_sample();
        inner.i2c1.advance_irq_sample();
    }

    pub(super) fn trace_i2c1_irq_handoff(&mut self, cpu_irq: bool, vectors_ready: bool) {
        if self.i2c_irq_trace_budget == 0 {
            return;
        }
        let inner = self.bridge.inner.borrow();
        let mask = 1u32 << I2C1_IRQ;
        let i2c1_raw = inner.i2c1.irq_pending();
        let vic_raw = inner.vic0.rawintr & mask != 0;
        let vic_enabled = inner.vic0.intenable & mask != 0;
        let vic_status = inner.vic0.irq_status & mask != 0;
        let interesting = i2c1_raw || vic_raw || vic_enabled || vic_status;
        if !interesting {
            return;
        }
        let (v0_cur, v0_high, v0_prio, v0_depth, v0_irq_line, _) =
            inner.vic0.debug_priority_state();
        let trace = (i2c1_raw as u128)
            | ((vic_raw as u128) << 1)
            | ((vic_enabled as u128) << 2)
            | ((vic_status as u128) << 3)
            | ((cpu_irq as u128) << 4)
            | ((self.cpu.cpsr.i as u128) << 5)
            | ((vectors_ready as u128) << 6)
            | ((self.cpu.is_halted as u128) << 7)
            | ((inner.kernel_started as u128) << 8)
            | ((inner.vic0.rawintr as u128) << 16)
            | ((inner.vic0.intenable as u128) << 48)
            | ((inner.vic0.irq_status as u128) << 80)
            | (((v0_cur as u128) & 0x3f) << 112)
            | (((v0_high as u128) & 0x3f) << 118)
            | (((v0_prio as u128) & 0x0f) << 124);
        if trace == self.last_i2c1_irq_trace {
            return;
        }
        self.last_i2c1_irq_trace = trace;
        self.i2c_irq_trace_budget -= 1;
        eprintln!(
            "I2C1 irq handoff pc={:#x} cpsr={:#x} insns={} raw={} vic_raw={} vic_en={} vic_irq={} cpu_irq={} cpsr_i={} vectors_ready={} halted={} kernel_started={} vic0_raw={:#x} vic0_en={:#x} vic0_irq={:#x} vic0_addr={:#x} v0_cur={} v0_high={} v0_prio={} v0_depth={} v0_irq_line={}",
            self.cpu.regs[15],
            self.cpu.cpsr.to_u32(),
            self.insn_count,
            i2c1_raw,
            vic_raw,
            vic_enabled,
            vic_status,
            cpu_irq,
            self.cpu.cpsr.i,
            vectors_ready,
            self.cpu.is_halted,
            inner.kernel_started,
            inner.vic0.rawintr,
            inner.vic0.intenable,
            inner.vic0.irq_status,
            inner.vic0.address,
            v0_cur,
            v0_high,
            v0_prio,
            v0_depth,
            v0_irq_line
        );
    }

    pub(super) fn fiq_vector_ready(&self, irq_vector_ready: bool) -> bool {
        let vbar = self.cpu.cp15.sctlr.vector_base();
        match self.bridge.read_word(vbar.wrapping_add(0x1c)) {
            Ok(ARM_LDR_PC_PC_0X18) => true,
            Ok(ARM_MOV_PC_R9) => irq_vector_ready && self.fiq_r9_target_ready(self.cpu.regs_fiq[1]),
            _ => false,
        }
    }

    pub(super) fn fiq_r9_target_ready(&self, target: u32) -> bool {
        let target = target & !1;
        (0xC000_0000..0xC080_0000).contains(&target) && self.bridge.read_word(target & !3).is_ok()
    }

    pub(super) fn trace_fiq_gate(&mut self, fiq_pending: bool, irq_ready: bool, fiq_ready: bool) {
        if self.fiq_trace_budget == 0 || self.insn_count < self.fiq_trace_start_insn || !fiq_pending
        {
            return;
        }

        let pc = self.cpu.regs[15];
        let lr = self.cpu.regs[14];
        let sp = self.cpu.regs[13];
        let cpsr = self.cpu.cpsr.to_u32();
        let vbar = self.cpu.cp15.sctlr.vector_base();
        let irq_word = self.bridge.read_word(vbar.wrapping_add(0x18)).unwrap_or(0);
        let fiq_word = self.bridge.read_word(vbar.wrapping_add(0x1c)).unwrap_or(0);
        let vector_words = self.guest_word_window(vbar, 8);
        let fiq_r9_target_ready = self.fiq_r9_target_ready(self.cpu.regs_fiq[1]);
        let fiq_regs_banked = self
            .cpu
            .regs_fiq
            .iter()
            .enumerate()
            .map(|(i, value)| format!("r{}={:#x}", i + 8, *value))
            .collect::<Vec<_>>()
            .join(" ");
        let fiq_sp_banked = self.cpu.regs_fiq[5];
        let fiq_lr_banked = self.cpu.regs_fiq[6];
        let (
            kernel_started,
            v0_raw,
            v0_en,
            v0_intselect,
            v0_irq,
            v0_fiq,
            v0_addr,
            v0_cur,
            v0_high,
            v0_prio,
            v0_depth,
            v0_irq_line,
            v0_fiq_line,
        ) = {
            let inner = self.bridge.inner.borrow();
            let (v0_cur, v0_high, v0_prio, v0_depth, v0_irq_line, v0_fiq_line) =
                inner.vic0.debug_priority_state();
            (
                inner.kernel_started,
                inner.vic0.rawintr,
                inner.vic0.intenable,
                inner.vic0.intselect,
                inner.vic0.irq_status,
                inner.vic0.fiq_status,
                inner.vic0.address,
                v0_cur,
                v0_high,
                v0_prio,
                v0_depth,
                v0_irq_line,
                v0_fiq_line,
            )
        };

        let trace = (fiq_pending as u128)
            | ((self.cpu.cpsr.f as u128) << 1)
            | ((irq_ready as u128) << 2)
            | ((fiq_ready as u128) << 3)
            | (((fiq_word as u128) & 0xffff_ffff) << 16)
            | (((v0_raw as u128) & 0xffff_ffff) << 48)
            | (((v0_en as u128) & 0xffff_ffff) << 80)
            | (((pc as u128) & 0xffff) << 112);
        if trace == self.last_fiq_trace {
            return;
        }
        self.last_fiq_trace = trace;
        self.fiq_trace_budget -= 1;

        info!(
            pc = format!("{pc:#x}"),
            lr = format!("{lr:#x}"),
            sp = format!("{sp:#x}"),
            cpsr = format!("{cpsr:#x}"),
            insns = self.insn_count,
            kernel_started,
            irq_ready,
            fiq_ready,
            vbar = format!("{vbar:#x}"),
            irq_word = format!("{irq_word:#x}"),
            fiq_word = format!("{fiq_word:#x}"),
            vectors = vector_words,
            fiq_r9_target_ready,
            fiq_regs_banked,
            fiq_sp_banked = format!("{fiq_sp_banked:#x}"),
            fiq_lr_banked = format!("{fiq_lr_banked:#x}"),
            v0_raw = format!("{v0_raw:#x}"),
            v0_en = format!("{v0_en:#x}"),
            v0_intselect = format!("{v0_intselect:#x}"),
            v0_irq = format!("{v0_irq:#x}"),
            v0_fiq = format!("{v0_fiq:#x}"),
            v0_addr = format!("{v0_addr:#x}"),
            v0_cur,
            v0_high,
            v0_prio,
            v0_depth,
            v0_irq_line,
            v0_fiq_line,
            trail = self.recent_pc_trail(24),
            "fiq gate trace"
        );
    }

    pub(super) fn take_exception(&mut self, exc: ExceptionType) {
        let vbar = self.cpu.cp15.sctlr.vector_base();
        let mut exec = Executor::with_vbar(&mut self.cpu, &mut self.bridge, vbar);
        exec.exclusive_monitor = self.excl.clone();
        exec.take_exception(exc);
        self.excl = exec.exclusive_monitor.clone();
    }

    pub(super) fn tick_lcd_refresh(&mut self, ticks: u64) {
        if !self.lcd_irq || !self.lcd_irq_armed || self.lcd_irq_budget == 0 {
            return;
        }
        let raised = {
            let mut inner = self.bridge.inner.borrow_mut();
            inner.lcd.tick(ticks)
        };
        if raised {
            self.lcd_irq_budget = self.lcd_irq_budget.saturating_sub(1);
            if self.lcd_irq_budget == 0 {
                info!(insns = self.insn_count, "LCD refresh IRQ budget exhausted");
            }
        }
    }

    pub(super) fn arm_lcd_refresh(&mut self, reason: &'static str) {
        self.lcd_irq_armed = true;
        info!(insns = self.insn_count, reason, "armed LCD refresh IRQ");
    }
}
