//! System stepping, fault delivery, timers and JIT entry points.
use super::*;

impl AArch64Cpu {
    /// Cycles the counter advances per emulated instruction.
    const TIMER_TICKS_PER_INSN: u64 = 16;

    /// Execute one instruction with full system semantics.
    pub fn step_system(&mut self) -> Result<CpuExit, ArmError> {
        self.step_system_fault_policy(false)
    }

    /// Retain IRQ, timer and system-call semantics but expose instruction
    /// errors to an embedding caller at the faulting PC for diagnosis/retry.
    pub fn step_system_with_fault_exit(&mut self) -> Result<CpuExit, ArmError> {
        self.step_system_fault_policy(true)
    }

    fn step_system_fault_policy(&mut self, fault_exit: bool) -> Result<CpuExit, ArmError> {
        // Drain any pending self-modifying-code invalidation before consulting
        // the region cache (never mid-region — writes during a run defer here).
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        self.jit_drain_smc();
        self.tick_system(Self::TIMER_TICKS_PER_INSN);

        if self.halted {
            return Ok(CpuExit::Halt);
        }

        let irq_line = self
            .gic_irq_line
            .as_ref()
            .map(|l| l.load(std::sync::atomic::Ordering::Acquire))
            .unwrap_or(false);

        // WFE may complete spuriously (real hardware wakes it via the timer
        // event stream, which is not modelled): never actually sleep on it,
        // just yield once so spin loops (LDXR; WFE) keep making progress.
        if self.wfe {
            self.wfe = false;
            self.event_register = false;
            return Ok(CpuExit::Wfe);
        }

        if self.wfi {
            if irq_line {
                self.wfi = false;
            } else {
                // Idle: skip the counter ahead to the next timer deadline so
                // a sleeping guest doesn't burn host time waiting for ticks.
                self.fast_forward_timers();
                return Ok(CpuExit::Wfi);
            }
        }

        // Deliver a pending IRQ if PSTATE.I allows.
        if irq_line && (self.daif & 0x2) == 0 {
            self.take_irq()?;
            return Ok(CpuExit::Continue);
        }

        // SMIR JIT fast path: if a compiled region covers the current PC, run it
        // (it advances PC to its recorded exit) and continue — bypassing the
        // per-instruction interpreter and its PC pre-increment. IRQ/timer state
        // is re-checked on the next step.
        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        if let Some(region) = self.jit_lookup(self.pc) {
            self.jit_run_region(&region);
            return Ok(CpuExit::Continue);
        }

        self.pc_ring[self.pc_ring_idx] = self.pc;
        self.pc_ring_idx = (self.pc_ring_idx + 1) % self.pc_ring.len();

        #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
        let pc_before = self.pc;
        match self.execute_instruction() {
            Ok(CpuExit::Svc(imm)) => {
                // PC already points past the SVC: that is the preferred
                // return address.
                self.enter_sync_exception(SyndromeRegister::svc(imm as u16), None)?;
                Ok(CpuExit::Continue)
            }
            Ok(CpuExit::Breakpoint(imm)) if !self.breakpoints.contains(&self.pc) => {
                // Guest BRK instruction (not a host debugger breakpoint):
                // the preferred return address is the BRK itself.
                self.pc = self.pc.wrapping_sub(4);
                self.enter_sync_exception(SyndromeRegister::brk(imm as u16), None)?;
                Ok(CpuExit::Continue)
            }
            Ok(exit) => {
                // Loop-head hotness sampling: a backward branch (PC decreased)
                // is a loop back-edge; promote + run the head once it is hot.
                #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
                self.jit_sample_backedge(pc_before);
                Ok(exit)
            }
            Err(err) if fault_exit => Err(err),
            Err(err) => self.deliver_fault(err),
        }
    }

    /// Advance the generic timer and mirror its output lines into GIC PPIs
    /// (27 = virtual timer, 30 = non-secure physical timer).
    pub(crate) fn tick_system(&mut self, cycles: u64) {
        self.sysregs.tick_timers(cycles);

        let levels = (
            self.sysregs.cntv_interrupt_pending(),
            self.sysregs.cntp_interrupt_pending(),
        );
        if levels != self.timer_levels {
            if let Some(ref gic) = self.gic {
                if let Ok(mut gic) = gic.lock() {
                    gic.set_ppi_level(0, 27, levels.0);
                    gic.set_ppi_level(0, 30, levels.1);
                }
            }
            self.timer_levels = levels;
        }
    }

    /// During WFI, jump the counter to the nearest armed timer deadline (or
    /// nudge it forward when no timer is armed).
    pub(crate) fn fast_forward_timers(&mut self) {
        let cntpct = self.sysregs.cntpct_el0;
        let cntvoff = self.sysregs.cntvoff_el2;
        let mut target: Option<u64> = None;

        // CNTP deadline in physical-counter terms.
        if self.sysregs.cntp_ctl_el0 & 0x3 == 0x1 && self.sysregs.cntp_cval_el0 > cntpct {
            target = Some(self.sysregs.cntp_cval_el0);
        }
        // CNTV deadline converted to physical-counter terms.
        if self.sysregs.cntv_ctl_el0 & 0x3 == 0x1 {
            let phys = self.sysregs.cntv_cval_el0.wrapping_add(cntvoff);
            if phys > cntpct {
                target = Some(target.map_or(phys, |t| t.min(phys)));
            }
        }

        let jump = match target {
            Some(t) => t.saturating_sub(cntpct),
            // No armed timer: advance ~1ms of counter time per idle pass.
            None => self.sysregs.cntfrq_el0 / 1000,
        };
        self.tick_system(jump);
    }

    /// Take an IRQ exception now.
    pub(crate) fn take_irq(&mut self) -> Result<(), ArmError> {
        let target = exception_target_el(
            ExceptionType::Irq,
            self.current_el,
            self.sysregs.hcr_el2,
            self.sysregs.scr_el3,
        );
        self.take_exception(target, ExceptionType::Irq, SyndromeRegister::new())
    }

    /// FP/SIMD access trap (CPACR.FPEN): vector to the EL1 handler with
    /// EC=0x07 so the kernel can do its lazy FP context switch. Called from
    /// inside instruction execution, where PC has already been advanced.
    pub(crate) fn take_fp_access_trap(&mut self) -> Result<CpuExit, ArmError> {
        self.pc = self.pc.wrapping_sub(4);
        self.enter_sync_exception(SyndromeRegister::simd_fp_trap(), None)?;
        Ok(CpuExit::Continue)
    }

    /// Convert an execution error into the corresponding guest exception.
    /// PC has been restored to the faulting instruction by
    /// `execute_instruction`.
    pub(crate) fn deliver_fault(&mut self, err: ArmError) -> Result<CpuExit, ArmError> {
        use crate::isa::arm::common::cpu::AccessType;

        // Boot debugging: surface the first faults (and any fault storm).
        self.fault_log_budget = self.fault_log_budget.saturating_sub(1);
        if self.fault_log_budget > 0 {
            tracing::debug!(
                pc = format!("{:#x}", self.pc),
                el = self.current_el,
                insns = self.insn_count,
                err = ?err,
                level = self.last_fault_level.load(std::sync::atomic::Ordering::Relaxed),
                sctlr = format!("{:#x}", self.sysregs.el1.sctlr),
                tcr = format!("{:#x}", self.sysregs.el1.tcr),
                ttbr0 = format!("{:#x}", self.sysregs.el1.ttbr0),
                ttbr1 = format!("{:#x}", self.sysregs.el1.ttbr1),
                "guest fault"
            );
        }

        match err {
            ArmError::MemoryError(info) => {
                let level = self
                    .last_fault_level
                    .load(std::sync::atomic::Ordering::Relaxed);
                let fsc = fsc_for_fault(info.fault_type, level);
                let from_lower = self.current_el == 0;
                let syndrome = if info.access == AccessType::InstructionFetch {
                    SyndromeRegister::instruction_abort(from_lower, fsc, false)
                } else {
                    SyndromeRegister::data_abort(
                        from_lower,
                        fsc,
                        info.access == AccessType::Write || info.access == AccessType::Atomic,
                        false, // cm
                        false, // s1ptw
                        false, // isv
                        0,     // sas
                        false, // sse
                        0,     // srt
                        false, // sf
                        false, // ar
                        false, // vncr
                        false, // fnv
                        false, // ea
                        0,     // set
                    )
                };
                self.enter_sync_exception(syndrome, Some(info.address))?;
                Ok(CpuExit::Continue)
            }
            ArmError::UndefinedInstruction(_) => {
                self.enter_sync_exception(SyndromeRegister::unknown(), None)?;
                Ok(CpuExit::Continue)
            }
            ArmError::Unimplemented(what) => {
                // Trap-on-unknown: report it once at debug level, then let
                // the guest's undef handler decide.
                tracing::debug!(what, pc = format!("{:#x}", self.pc), "UNDEF injection");
                self.enter_sync_exception(SyndromeRegister::unknown(), None)?;
                Ok(CpuExit::Continue)
            }
            other => Err(other),
        }
    }

    /// Note a guest write at `va` (called from the memory-store path). If it
    /// lands in a page covered by a cached region, flag the cache stale so the
    /// next `step_system` drains it (self-modifying-code correctness). The
    /// fast `is_empty()` guard keeps the common no-JIT-code-pages case cheap.
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    pub(crate) fn jit_note_write(&mut self, va: u64) {
        if !self.jit.code_pages.is_empty() && self.jit.code_pages.contains(&(va & !0xFFF)) {
            self.jit.smc_dirty = true;
        }
    }

    /// Cache-key discriminator: the active translation regime (TTBR0 frame + EL
    /// + MMU-enable). A region is only reused while these are unchanged, so a
    /// context switch can never run a stale region.
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    pub(crate) fn jit_mode_tag(&self) -> u64 {
        (self.sysregs.el1.ttbr0 & !0xFFF)
            | (self.current_el as u64)
            | (((self.sysregs.el1.sctlr & 1) as u64) << 2)
    }

    /// Read up to `max` bytes of guest instruction stream from `entry`, stopping
    /// at the first unmapped word (fault-free; tolerates a short mapped tail).
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    pub(crate) fn jit_read_window(&self, entry: u64, max: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(max);
        let mut a = entry;
        while bytes.len() + 4 <= max {
            match self.mem_read_u32(a) {
                Ok(w) => {
                    bytes.extend_from_slice(&w.to_le_bytes());
                    a = a.wrapping_add(4);
                }
                Err(_) => break,
            }
        }
        bytes
    }

    /// Marshal live architectural state into the native register file.
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    pub(crate) fn jit_marshal_to(&self) -> crate::smir::lower::runtime::Aarch64GuestRegs {
        let mut gr = crate::smir::lower::runtime::Aarch64GuestRegs::default();
        gr.load_fn = rax_a64_mem_load as usize as u64;
        gr.store_fn = rax_a64_mem_store as usize as u64;
        gr.vec_load_fn = rax_a64_vec_load as usize as u64;
        gr.vec_store_fn = rax_a64_vec_store as usize as u64;
        for i in 0..NUM_GPRS {
            gr.x[i] = self.x[i];
        }
        gr.sp = self.current_sp();
        gr.pc = self.pc; // fallback resume PC; a native-exit stub overwrites it
        gr.nzcv = ((self.nzcv as u64) & 0xF) << 28; // u8 [N,Z,C,V] -> PSTATE 31:28
        gr.fpcr = mask_fpcr(self.fpcr) as u64;
        gr.fpsr = mask_fpsr(self.fpsr) as u64;
        for i in 0..NUM_SIMD_REGS {
            gr.v[2 * i] = self.v[i] as u64;
            gr.v[2 * i + 1] = (self.v[i] >> 64) as u64;
        }
        gr
    }

    /// Marshal the native register file back, resuming at the recorded PC.
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    pub(crate) fn jit_marshal_from(&mut self, gr: &crate::smir::lower::runtime::Aarch64GuestRegs) {
        for i in 0..NUM_GPRS {
            self.x[i] = gr.x[i];
        }
        self.set_current_sp(gr.sp);
        self.nzcv = ((gr.nzcv >> 28) & 0xF) as u8;
        self.fpcr = mask_fpcr(gr.fpcr as u32);
        self.fpsr = mask_fpsr(gr.fpsr as u32);
        for i in 0..NUM_SIMD_REGS {
            self.v[i] = (gr.v[2 * i] as u128) | ((gr.v[2 * i + 1] as u128) << 64);
        }
        self.pc = gr.pc;
    }

    /// Fast-path lookup: a runnable compiled region at `pc` in the current mode.
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    pub(crate) fn jit_lookup(&self, pc: u64) -> Option<std::sync::Arc<JitRegion>> {
        if self.jit.disabled {
            return None;
        }
        let mt = self.jit_mode_tag();
        match self.jit.cache.get(&(pc, mt)) {
            Some(Some(r)) => Some(r.clone()),
            _ => None,
        }
    }

    /// After an interpreted instruction: if it was a backward branch (PC
    /// decreased — a loop back-edge), bump the head's hotness and, once hot,
    /// compile + run the region. RAX_NO_JIT disables promotion.
    #[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
    pub(crate) fn jit_sample_backedge(&mut self, pc_before: u64) {
        {
            use std::sync::OnceLock;
            static OFF: OnceLock<bool> = OnceLock::new();
            if *OFF.get_or_init(|| std::env::var_os("RAX_NO_JIT").is_some()) {
                return;
            }
        }
        if self.jit.disabled {
            return;
        }
        let head = self.pc;
        if head >= pc_before {
            return; // forward / fallthrough — not a loop back-edge
        }
        let mt = self.jit_mode_tag();
        if self.jit.cache.contains_key(&(head, mt)) {
            return; // already promoted or memoized-ineligible
        }
        let hot = {
            let c = self.jit.hot.entry(head).or_insert(0);
            *c = c.saturating_add(1);
            *c
        };
        if hot < A64_JIT_HOT_THRESHOLD {
            return;
        }
        self.jit.hot.remove(&head);
        let region = self.jit_compile_region().map(std::sync::Arc::new);
        if std::env::var_os("RAX_JIT_LOG").is_some() {
            eprintln!(
                "[JIT-a64] promote @ {head:#x} -> {}",
                if region.is_some() {
                    "compiled"
                } else {
                    "ineligible"
                }
            );
        }
        match &region {
            Some(r) => {
                let r = r.clone();
                self.jit.cache.insert((head, mt), region);
                // Track the guest-code pages this region covers (its ≤512 B lift
                // window), so a later write into them invalidates it (SMC). Add
                // the next page only when the window can straddle into it.
                self.jit.code_pages.insert(head & !0xFFF);
                if (head & 0xFFF) + 512 > 0x1000 {
                    self.jit.code_pages.insert((head & !0xFFF) + 0x1000);
                }
                self.jit_run_region(&r);
            }
            None => {
                // Soft-cap the memo so a long run can't grow it unbounded.
                if self.jit.cache.len() >= 16384 {
                    self.jit.cache.clear();
                }
                self.jit.cache.insert((head, mt), None);
            }
        }
    }
}
