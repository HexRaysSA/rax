//! The architecture-neutral [`VCpu`] interface of the x86-64 software vCPU.

use super::*;

impl VCpu for X86_64Vcpu {
    fn run(&mut self) -> Result<VcpuExit> {
        self.run_loop()
    }

    fn get_state(&self) -> Result<CpuState> {
        // Compute materialized rflags without modifying self
        let rflags = self.compute_materialized_rflags();
        let mut regs = self.regs.clone();
        regs.rflags = rflags;
        Ok(CpuState::X86_64(X86_64CpuState {
            regs,
            sregs: self.sregs.clone(),
        }))
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
        self.regs = state.regs.clone();
        self.sregs = state.sregs.clone();
        // `state.regs.rflags` is the architectural value (`get_state`
        // materializes pending flags); flags still derived lazily from an
        // earlier ALU result would otherwise override it. A snapshot restore
        // reinstates its saved lazy flags with `set_emulator_state` afterwards.
        self.lazy_flags = Default::default();
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        {
            self.jit_vsib_resume_pc = None;
        }
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
        self.step_with_faults()
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
        self.mmu.translate(vaddr, at, &self.sregs)
    }

    fn reset(&mut self) -> Result<()> {
        self.reset_state();
        Ok(())
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
