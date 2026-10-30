//! The architecture-neutral [`VCpu`] interface of the x86-64 software vCPU.

use super::*;

impl VCpu for X86_64Vcpu {
    fn is_bootstrap_processor(&self) -> Result<bool> {
        Ok(self.apic_base & crate::isa::x86_64::identity::APIC_BASE_BSP != 0)
    }
    fn run(&mut self) -> Result<VcpuExit> {
        self.run_loop()
    }

    fn get_state(&self) -> Result<CpuState> {
        // Compute materialized rflags without modifying self
        let rflags = self.compute_materialized_rflags();
        let mut regs = self.regs.clone();
        regs.rflags = rflags;
        let mut sregs = self.sregs.clone();
        sregs.cr8 = u64::from(self.mmu.task_priority()? >> 4);
        Ok(CpuState::X86_64(X86_64CpuState { regs, sregs }))
    }

    fn validate_checkpoint_state(
        &self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
    ) -> Result<()> {
        if !matches!(state, CpuState::X86_64(_)) {
            return Err(Error::Emulator(
                "expected x86_64 state for x86_64 vCPU".to_string(),
            ));
        }
        Self::validate_emulator_state(emulator)
    }

    fn capture_backend_context(&self) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        Ok(Some(crate::vm::snapshot::BackendContext {
            kind: crate::vm::snapshot::X86_64_CONTEXT,
            data: self.save_context()?,
        }))
    }

    fn capture_checkpoint_resources(&self) -> Result<Vec<crate::vm::snapshot::CheckpointResource>> {
        self.checkpoint_media()
    }

    fn x86_configuration(&self) -> Option<crate::isa::x86_64::X86_64Config> {
        Some(X86_64Vcpu::x86_configuration(self))
    }

    fn set_x86_configuration(&mut self, config: crate::isa::x86_64::X86_64Config) -> Result<()> {
        X86_64Vcpu::set_x86_configuration(self, config)
    }

    fn checkpoint_resource_references(
        &self,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<Vec<crate::vm::snapshot::ResourceKey>> {
        match context {
            None => Ok(Vec::new()),
            Some(context) if context.kind == crate::vm::snapshot::X86_64_CONTEXT => {
                self.context_resource_references(&context.data)
            }
            Some(_) => Err(Error::InvalidConfig(
                "checkpoint context producer differs from software x86".into(),
            )),
        }
    }

    fn validate_checkpoint_context(
        &self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.validate_checkpoint_state(state, emulator)?;
        if let Some(context) = context {
            if context.kind != crate::vm::snapshot::X86_64_CONTEXT {
                return Err(Error::InvalidConfig(
                    "checkpoint context producer differs from software x86".into(),
                ));
            }
            self.validate_context_projection(state, emulator, &context.data)?;
        }
        Ok(())
    }

    fn prepare_checkpoint_replacement(
        &self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
        resources: &crate::vm::snapshot::PreparedResources,
    ) -> Result<Option<Box<dyn VCpu>>> {
        self.validate_checkpoint_context(state, emulator, context)?;
        context
            .map(|context| {
                self.prepare_context(&context.data, resources)
                    .map(|cpu| Box::new(cpu) as Box<dyn VCpu>)
            })
            .transpose()
    }

    fn restore_checkpoint_context(
        &mut self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.validate_checkpoint_context(state, emulator, context)?;
        if let Some(context) = context {
            self.restore_context(&context.data)
        } else {
            self.set_state(state)?;
            self.set_emulator_state(emulator)
        }
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        let state = match state {
            CpuState::X86_64(state) => state,
            _ => {
                return Err(Error::Emulator(
                    "expected x86_64 state for x86_64 vCPU".to_string(),
                ));
            }
        };
        if state.sregs.cr8 > 15 {
            return Err(Error::InvalidConfig("invalid CR8 priority class".into()));
        }
        self.mmu.import_cr8(state.sregs.cr8)?;
        self.regs = state.regs.clone();
        self.sregs = state.sregs.clone();
        self.mmu.set_data_access_state(self.regs.rflags, self.pkru);
        // `state.regs.rflags` is the architectural value (`get_state`
        // materializes pending flags); flags still derived lazily from an
        // earlier ALU result would otherwise override it. A snapshot restore
        // reinstates its saved lazy flags with `set_emulator_state` afterwards.
        self.lazy_flags = Default::default();
        self.jit_vsib_resume_pc = None;
        // External state injection is a serializing boundary and does not carry
        // the emulator-private STI/MOV-SS interrupt shadow.
        self.interrupt_inhibit = false;
        // Injecting CPU state is a serializing event: drop the decode cache so we
        // re-decode from (possibly externally rewritten) code memory. Not hot -
        // set_state is only called at init / snapshot restore / GDB, never in run().
        self.decode_cache.iter_mut().for_each(|e| {
            e.rip = 0;
            e.bytes_len = 0;
        });
        Ok(())
    }

    fn step_insn(&mut self) -> Result<Option<VcpuExit>> {
        if let Some(exit) = self.jit_callout_exit.take() {
            return Ok(Some(exit));
        }
        #[cfg(feature = "debug")]
        if !self.single_step && !self.halted {
            if let Some(addr) = self.debug_breakpoint_at_current_rip() {
                return Ok(Some(VcpuExit::GdbBreakpoint { addr }));
            }
        }
        #[cfg(feature = "debug")]
        let before = self.insn_count;
        let exit = self.step_with_faults()?;
        #[cfg(feature = "debug")]
        if self.single_step && exit.is_none() && self.insn_count != before {
            return Ok(Some(VcpuExit::GdbStep));
        }
        Ok(exit)
    }

    fn supports_stepping(&self) -> bool {
        true
    }

    fn translate_addr(&mut self, vaddr: u64, access: crate::vm::vcpu::MemAccess) -> Result<u64> {
        let at = match access {
            crate::vm::vcpu::MemAccess::Read => crate::isa::x86_64::mmu::AccessType::Read,
            crate::vm::vcpu::MemAccess::Write => crate::isa::x86_64::mmu::AccessType::Write,
            crate::vm::vcpu::MemAccess::Exec => crate::isa::x86_64::mmu::AccessType::Execute,
        };
        self.mmu.set_data_access_state(self.regs.rflags, self.pkru);
        self.mmu.translate(vaddr, at, &self.sregs)
    }

    fn reset(&mut self) -> Result<()> {
        self.reset_state();
        Ok(())
    }

    fn deliver_init(&mut self) -> Result<()> {
        self.deliver_init_signal()
    }

    fn current_pc(&self) -> u64 {
        self.regs.rip
    }

    fn wake(&mut self) {
        self.halted = false;
    }

    fn supports_mem_hooks(&self) -> bool {
        true
    }

    fn set_mem_recording(&mut self, on: bool) {
        self.mmu.set_mem_recording(on);
    }

    fn drain_mem_records(&mut self, out: &mut Vec<crate::vm::vcpu::MemRecord>) {
        self.mmu.drain_mem_records(out);
    }

    fn attach_local_apic(
        &mut self,
        lapic: Arc<std::sync::Mutex<crate::devices::lapic::LocalApic>>,
    ) {
        self.mmu.attach_local_apic(lapic);
    }

    fn set_pci_bridge(
        &mut self,
        bridge: std::sync::Arc<std::sync::Mutex<crate::devices::pci::PciStub>>,
        ap_base: u64,
        ap_end: u64,
    ) {
        self.mmu.set_pci_bridge(bridge, ap_base, ap_end);
    }

    fn attach_x86_64_bios(&mut self, cdrom: Option<Arc<Vec<u8>>>, mem_bytes: u64) {
        self.bios_cdrom = cdrom;
        self.bios_mem_bytes = mem_bytes;
    }

    fn x86_bios_binding(&self) -> Option<(Option<Arc<Vec<u8>>>, u64)> {
        Some((self.bios_cdrom.clone(), self.bios_mem_bytes))
    }

    fn complete_io_in(&mut self, data: &[u8]) {
        if let Some(pending) = self.io_pending.take() {
            let sz = pending.size as usize;
            // Batched `rep ins` block: write `count` consecutive elements from
            // `data` to memory starting at the staged address (forward).
            if pending.count > 1 {
                if let IoInTarget::Mem { addr } = pending.target {
                    for i in 0..pending.count as usize {
                        let off = i * sz;
                        if off + sz > data.len() {
                            break;
                        }
                        let value = match pending.size {
                            1 => data[off] as u64,
                            2 => u16::from_le_bytes([data[off], data[off + 1]]) as u64,
                            _ => u32::from_le_bytes([
                                data[off],
                                data[off + 1],
                                data[off + 2],
                                data[off + 3],
                            ]) as u64,
                        };
                        let _ = self.write_mem(addr + off as u64, value, pending.size);
                    }
                }
                return;
            }

            let value = match pending.size {
                1 => data.first().copied().unwrap_or(0) as u64,
                2 if data.len() >= 2 => u16::from_le_bytes([data[0], data[1]]) as u64,
                4 if data.len() >= 4 => {
                    u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64
                }
                _ => 0,
            };

            match pending.target {
                IoInTarget::Reg => match pending.size {
                    1 => self.regs.rax = (self.regs.rax & !0xFF) | value,
                    2 => self.regs.rax = (self.regs.rax & !0xFFFF) | value,
                    4 => self.regs.rax = value,
                    _ => {}
                },
                IoInTarget::Mem { addr } => {
                    let _ = self.write_mem(addr, value, pending.size);
                }
            }
        }
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn can_inject_interrupt(&self) -> bool {
        // IF is set/cleared only by STI/CLI/POPF/IRET (written straight to
        // regs.rflags), never by the lazy ALU-flag engine - so read it directly.
        // A successful IF 0->1 STI additionally blocks maskable injection
        // through the following instruction boundary.
        (self.regs.rflags & flags::bits::IF) != 0 && !self.interrupt_inhibit
    }

    fn inject_interrupt(&mut self, vector: u8) -> Result<bool> {
        // Check if interrupts are enabled
        if !self.can_inject_interrupt() {
            return Ok(false);
        }

        // Inject the external interrupt
        // External interrupts don't push an error code
        self.inject_external_event(vector, None)?;

        // Clear the halted state if we were halted
        self.halted = false;

        Ok(true)
    }

    fn inject_nmi(&mut self) -> Result<bool> {
        // NMI is vector 2 and ignores IF flag
        // TODO: Track NMI blocking (NMIs are blocked until IRET after an NMI)
        self.inject_external_event(2, None)?;
        self.halted = false;
        tracing::debug!("Injected NMI");
        Ok(true)
    }

    #[cfg(feature = "debug")]
    fn set_single_step(&mut self, enabled: bool) {
        self.single_step = enabled;
    }

    #[cfg(feature = "debug")]
    fn is_single_step(&self) -> bool {
        self.single_step
    }

    #[cfg(feature = "debug")]
    fn set_debugger_active(&mut self, active: bool) {
        self.debugger_active = active;

        #[cfg(all(
            feature = "smir-jit",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        if active {
            self.jit_cache.clear();
            self.jit_hot.clear();
        }
    }

    #[cfg(feature = "debug")]
    fn debugger_controls(&self) -> Option<crate::vm::vcpu::DebuggerControls> {
        let mut breakpoints: Vec<_> = self.debug_breakpoints.iter().copied().collect();
        breakpoints.sort_unstable();
        Some(crate::vm::vcpu::DebuggerControls {
            active: self.debugger_active,
            single_step: self.single_step,
            breakpoints,
        })
    }

    #[cfg(feature = "debug")]
    fn bind_debugger_controls(
        &mut self,
        controls: &crate::vm::vcpu::DebuggerControls,
    ) -> Result<()> {
        // Build the complete host breakpoint set before changing the candidate.
        // Guest DR state, TF, registers, counts and pending exits remain intact.
        let mut breakpoints = std::collections::HashSet::new();
        breakpoints
            .try_reserve(controls.breakpoints.len())
            .map_err(|error| Error::Emulator(format!("debugger binding allocation: {error}")))?;
        breakpoints.extend(controls.breakpoints.iter().copied());
        self.set_debugger_active(controls.active);
        self.set_single_step(controls.single_step);
        self.debug_breakpoints = breakpoints;
        // Saved host stop notifications belong to the source frontend. The
        // current plan must execute against the imported guest frontier; guest
        // exceptions, natural INT3 and pending device exits remain intact.
        if matches!(
            self.jit_callout_exit.as_ref(),
            Some(VcpuExit::GdbStep | VcpuExit::GdbBreakpoint { .. })
        ) {
            self.jit_callout_exit = None;
        }
        Ok(())
    }

    #[cfg(feature = "debug")]
    fn debug_address_space(&self) -> Result<crate::vm::vcpu::DebugAddressSpace> {
        if self.mmu.has_flat_translation() {
            return Err(Error::InvalidConfig(
                "system debugger has no process-memory translation binding".into(),
            ));
        }
        Ok(crate::vm::vcpu::DebugAddressSpace::X86(
            crate::vm::vcpu::X86DebugPaging {
                cr0: self.sregs.cr0,
                cr3: self.sregs.cr3,
                cr4: self.sregs.cr4,
                efer: self.sregs.efer,
                physical_bits: self.cpuid(0x8000_0008, 0).0 & 255,
                pdpte: None,
                pse36: false,
                pat: false,
            },
        ))
    }
    #[cfg(feature = "debug")]
    fn debug_memory_changed(&mut self, _pages: &[u64]) -> Result<()> {
        // A physical write can alias any CPU's virtual code address. Invalidate
        // all derived code caches instead of guessing the other aliases.
        for entry in self.decode_cache.iter_mut() {
            entry.bytes_len = 0;
        }
        self.mmu.flush_tlb();
        #[cfg(all(
            feature = "smir-jit",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            self.jit_cache.clear();
            self.jit_hot.clear();
            self.jit_ineligible.clear();
            self.jit_ineligible_dirty.clear();
            self.jit_active_region_stale = true;
        }
        Ok(())
    }
    #[cfg(feature = "debug")]
    fn supports_debug_breakpoints(&self) -> bool {
        true
    }

    #[cfg(feature = "debug")]
    fn set_debug_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.debug_breakpoints.insert(addr);
        Ok(())
    }

    #[cfg(feature = "debug")]
    fn clear_debug_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.debug_breakpoints.remove(&addr);
        Ok(())
    }

    #[cfg(feature = "debug")]
    fn invalidate_code_cache(&mut self, addr: u64) {
        self.invalidate_code_page(addr & !0xFFF);
    }

    fn instruction_count(&self) -> u64 {
        // The accurate per-vCPU retired-instruction counter. (The process-global
        // counter, exposed via `get_total_instruction_count`, is only published
        // at run() yield boundaries and aggregates across vCPUs, so it is not a
        // faithful per-engine count for embedders or for single stepping.)
        self.insn_count
    }

    fn get_emulator_state(&self) -> Option<crate::vm::snapshot::EmulatorState> {
        self.snapshot_emulator_state()
    }

    fn set_emulator_state(&mut self, state: &crate::vm::snapshot::EmulatorState) -> Result<()> {
        self.restore_emulator_state(state)
    }
}

#[cfg(test)]
#[path = "cpu_vcpu_tests.rs"]
mod tests;

#[path = "cpu_startup.rs"]
mod startup;
