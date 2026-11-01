//! Architecture-neutral vCPU operations over the AArch64 software adapter.

use super::*;
use crate::isa::arm::common::features::ArmFeatures;

impl VCpu for Aarch64Vcpu {
    fn required_private_checkpoint_kind(&self) -> Option<u32> {
        Some(crate::vm::snapshot::AARCH64_CONTEXT)
    }

    #[cfg(all(test, feature = "smir-jit", target_arch = "aarch64"))]
    fn bounded_native_test_count(&self) -> u64 {
        self.cpu.bounded_native_runs()
    }
    fn checkpoint_powered_off(&self) -> Option<bool> {
        Some(self.powered_off)
    }

    fn checkpoint_owned_gics(&self) -> Vec<Arc<Mutex<crate::isa::arm::aarch64::gic::Gic>>> {
        self.cpu.owned_checkpoint_gic().into_iter().collect()
    }

    fn capture_backend_context(&self) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        self.checkpoint_without_scope().map(Some)
    }

    fn capture_backend_context_for_remap(
        &self,
    ) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        self.checkpoint_for_remap().map(Some)
    }

    fn capture_backend_context_in_scope(
        &self,
        scope: &crate::vm::memory::checkpoint::CheckpointPublication<'_>,
    ) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        self.checkpoint_in_scope(scope).map(Some)
    }

    fn prepare_checkpoint_publication<'scope, 'bindings>(
        &mut self,
        scope: &'scope crate::vm::memory::checkpoint::CheckpointPublication<'bindings>,
    ) -> Result<crate::vm::memory::checkpoint::CpuPublication<'scope, 'bindings>> {
        self.publication(scope)
    }

    fn validate_checkpoint_context(
        &self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        if let Some(context) = context {
            if crate::codec::serialize(emulator).map_err(|e| Error::Emulator(e.to_string()))?
                != crate::codec::serialize(&crate::vm::snapshot::EmulatorState::default())
                    .map_err(|e| Error::Emulator(e.to_string()))?
            {
                return Err(Error::InvalidConfig(
                    "unexpected AArch64 generic emulator projection".into(),
                ));
            }
            self.prepare_private_checkpoint(state, context)?;
            Ok(())
        } else {
            self.validate_checkpoint_state(state, emulator)
        }
    }

    fn prepare_checkpoint_replacement(
        &self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
        _resources: &crate::vm::snapshot::PreparedResources,
    ) -> Result<Option<Box<dyn VCpu>>> {
        self.validate_checkpoint_context(state, emulator, context)?;
        context
            .map(|raw| {
                self.prepare_private_checkpoint(state, raw)
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
        let Some(context) = context else {
            return self.set_state(state);
        };
        let mut prepared = self.prepare_private_checkpoint(state, context)?;
        let bindings = crate::vm::memory::checkpoint::CheckpointBindings::new(
            &prepared.physical_memory,
            prepared.checkpoint_owned_gics(),
        );
        let scope = bindings.enter()?;
        prepared.publication(&scope)?.commit();
        *self = prepared;
        Ok(())
    }

    fn run(&mut self) -> Result<VcpuExit> {
        self.ensure_checkpoint_active()?;
        if self.powered_off {
            return Ok(VcpuExit::Hlt);
        }
        if self.shutdown {
            return Ok(VcpuExit::Shutdown);
        }

        if self.user.is_some() {
            for _ in 0..BATCH {
                if let Some(exit) = self.step_user()? {
                    return Ok(exit);
                }
            }
            // The end of a batch. User mode completes WFI/WFE as hints, so
            // `Hlt` here never reports a halted core.
            return Ok(VcpuExit::Hlt);
        }

        if self.fault_exits {
            for _ in 0..BATCH {
                if let Some(exit) = self.step_micro()? {
                    return Ok(exit);
                }
            }
            return Ok(VcpuExit::Debug);
        }

        // Pick up console input the VMM queued since the last batch.
        self.sync_uart_irq();

        for _ in 0..BATCH {
            match self.step_system_cpu(false) {
                Ok(CpuExit::Continue) => {
                    if let Some((reg, start, end)) = trace_reg() {
                        let n = self.cpu.instruction_count();
                        if n >= start && n <= end {
                            let v = self.cpu.get_gpr(reg);
                            if v != self.trace_reg_last {
                                let regs: Vec<String> = (0..31)
                                    .map(|i| format!("{:#x}", self.cpu.get_gpr(i)))
                                    .collect();
                                debug!(
                                    insns = n,
                                    pc = format!("{:#x}", self.cpu.get_pc()),
                                    value = format!("{v:#x}"),
                                    regs = regs.join(","),
                                    "trace: register changed"
                                );
                                self.trace_reg_last = v;
                            }
                        }
                    }
                    if watch_addr().is_some() && WATCH_HIT.swap(false, Ordering::Relaxed) {
                        let trail: Vec<String> = self
                            .cpu
                            .recent_pcs()
                            .iter()
                            .map(|p| format!("{p:#x}"))
                            .collect();
                        let regs: Vec<String> = (0..31)
                            .map(|i| format!("{:#x}", self.cpu.get_gpr(i)))
                            .collect();
                        debug!(
                            pc = format!("{:#x}", self.cpu.get_pc()),
                            insns = self.cpu.instruction_count(),
                            trail = trail.join(","),
                            regs = regs.join(","),
                            "watch: store attributed (pc is the NEXT instruction)"
                        );
                    }
                }
                Ok(CpuExit::Wfi) | Ok(CpuExit::Wfe) => {
                    // Idle: give the VMM loop a turn (console, checkpoints).
                    self.heartbeat();
                    return Ok(VcpuExit::Hlt);
                }
                Ok(CpuExit::Hvc(immediate)) | Ok(CpuExit::Smc(immediate)) => {
                    if let Some(exit) = self.handle_psci(immediate)? {
                        self.shutdown = matches!(exit, VcpuExit::Shutdown);
                        return Ok(exit);
                    }
                }
                Ok(CpuExit::Halt) | Ok(CpuExit::Shutdown) => {
                    self.shutdown = true;
                    return Ok(VcpuExit::Shutdown);
                }
                Ok(other) => {
                    return Ok(VcpuExit::Unknown(format!(
                        "aarch64 exit {:?} at pc={:#x}",
                        other,
                        self.cpu.get_pc()
                    )));
                }
                Err(e) => {
                    return Ok(VcpuExit::Unknown(format!(
                        "aarch64 emulation error at pc={:#x}: {e}",
                        self.cpu.get_pc()
                    )));
                }
            }
        }
        self.heartbeat();
        Ok(VcpuExit::Hlt)
    }

    fn get_state(&self) -> Result<CpuState> {
        use crate::vm::vcpu::Aarch64Registers;
        let mut regs = Aarch64Registers::default();
        for i in 0..31 {
            regs.x[i] = self.cpu.get_gpr(i as u8);
        }
        for i in 0..32 {
            let value = self.cpu.get_simd(i as u8);
            regs.v[i] = [value as u64, (value >> 64) as u64];
        }
        regs.pc = self.cpu.get_pc();
        regs.sp = self.cpu.get_sp();
        regs.pstate = self.cpu.pstate_bits();
        regs.fpcr = self.cpu.fpcr_value();
        regs.fpsr = self.cpu.fpsr_value();
        Ok(CpuState::aarch64(regs, self.cpu.export_sregs()))
    }

    fn validate_checkpoint_state(
        &self,
        state: &CpuState,
        _emulator: &crate::vm::snapshot::EmulatorState,
    ) -> Result<()> {
        let CpuState::Aarch64(state) = state else {
            return Err(Error::Emulator(
                "expected aarch64 state for aarch64 vCPU".to_string(),
            ));
        };
        AArch64Cpu::validate_saved_state(state.regs.pstate, &state.sregs)
            .map_err(|error| Error::Emulator(error.to_string()))?;
        self.cpu
            .validate_sregs(&state.sregs)
            .map_err(|error| Error::Emulator(error.to_string()))
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        let state = match state {
            CpuState::Aarch64(s) => s,
            _ => {
                return Err(Error::Emulator(
                    "expected aarch64 state for aarch64 vCPU".to_string(),
                ));
            }
        };
        AArch64Cpu::validate_saved_state(state.regs.pstate, &state.sregs)
            .map_err(|error| Error::Emulator(error.to_string()))?;
        self.cpu
            .validate_sregs(&state.sregs)
            .map_err(|error| Error::Emulator(error.to_string()))?;
        self.cpu.reset();
        self.cpu
            .import_sregs(&state.sregs)
            .map_err(|error| Error::Emulator(error.to_string()))?;
        self.cpu
            .set_pstate_bits(state.regs.pstate)
            .map_err(|error| Error::Emulator(error.to_string()))?;
        for i in 0..31 {
            self.cpu.set_gpr(i as u8, state.regs.x[i]);
        }
        for i in 0..32 {
            let [low, high] = state.regs.v[i];
            self.cpu
                .set_simd(i as u8, (low as u128) | ((high as u128) << 64));
        }
        self.cpu.set_fpcr_value(state.regs.fpcr);
        self.cpu.set_fpsr_value(state.regs.fpsr);
        self.cpu.set_pc(state.regs.pc);
        // `regs.sp` is the canonical current SP. The banked SPs in `sregs`
        // are restored first so non-current SPs survive, then current SP is
        // overlaid for compatibility with existing initial-state callers.
        self.cpu.set_sp(state.regs.sp);
        self.shutdown = false;
        self.powered_off = false;
        if let Some(user) = self.user.as_mut() {
            // `reset` restarted the core's instruction count.
            user.trap = None;
            user.not_retired = 0;
            self.insn_count
                .store(self.cpu.instruction_count(), Ordering::Relaxed);
        }
        Ok(())
    }

    fn update_state(&mut self, state: &CpuState) -> Result<()> {
        let state = match state {
            CpuState::Aarch64(s) => s,
            _ => {
                return Err(Error::Emulator(
                    "expected aarch64 state for aarch64 vCPU".to_string(),
                ));
            }
        };

        // This is deliberately an overlay, not `set_state`: C API register
        // writes must preserve instruction/cycle counters, device state,
        // pending exceptions, break/watchpoints, and implementation-private
        // execution state.  `state` originated from get_state(), so overlaying
        // every exported field also preserves unrelated architectural values.
        AArch64Cpu::validate_saved_state(state.regs.pstate, &state.sregs)
            .map_err(|error| Error::Emulator(error.to_string()))?;
        self.cpu
            .validate_sregs(&state.sregs)
            .map_err(|error| Error::Emulator(error.to_string()))?;
        self.cpu
            .import_sregs(&state.sregs)
            .map_err(|error| Error::Emulator(error.to_string()))?;
        self.cpu
            .set_pstate_bits(state.regs.pstate)
            .map_err(|error| Error::Emulator(error.to_string()))?;
        for i in 0..31 {
            self.cpu.set_gpr(i as u8, state.regs.x[i]);
        }
        for i in 0..32 {
            let [low, high] = state.regs.v[i];
            self.cpu
                .set_simd(i as u8, (low as u128) | ((high as u128) << 64));
        }
        self.cpu.set_fpcr_value(state.regs.fpcr);
        self.cpu.set_fpsr_value(state.regs.fpsr);
        self.cpu.set_pc(state.regs.pc);
        self.cpu.set_sp(state.regs.sp);
        Ok(())
    }

    fn aarch64_fp_features(&self) -> Option<u64> {
        Some(self.cpu.selected_fp_features().bits())
    }

    fn set_aarch64_fp_features(&mut self, features: u64) -> Result<()> {
        let features = ArmFeatures::from_bits(features)
            .ok_or_else(|| Error::InvalidConfig("unknown AArch64 feature bits".into()))?;
        self.cpu
            .select_fp_features(features)
            .map_err(|error| Error::InvalidConfig(error.to_string()))
    }

    fn start_aarch64_cpu(&mut self, entry: u64, context: u64, pstate: u64) -> Result<()> {
        self.cpu
            .enter_psci(entry, context, pstate)
            .map_err(|e| Error::Emulator(e.to_string()))?;
        self.powered_off = false;
        self.shutdown = false;
        self.insn_count.store(0, Ordering::Relaxed);
        Ok(())
    }

    fn complete_io_in(&mut self, _data: &[u8]) {
        // Device reads are serviced synchronously inside the bridge.
    }

    fn attach_pl011(&mut self, _base: u64, uart: Arc<Mutex<Pl011>>) {
        let _ = self.late.uart.set(uart);
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn instruction_count(&self) -> u64 {
        self.insn_count.load(Ordering::Relaxed)
    }

    fn run_retirement_budget(&mut self, budget: u64) -> Result<crate::vm::vcpu::RetirementRun> {
        use crate::vm::vcpu::budget::{self, ErrorRetirement};
        let policy = if self.user.is_some() {
            ErrorRetirement::NoRetirement
        } else {
            // System stepping publishes only completed CPU retirement before
            // firmware completion can fail. Preserve that work and its clock.
            ErrorRetirement::CounterDelta
        };
        budget::run(self, budget, policy)
    }

    fn supports_stepping(&self) -> bool {
        true
    }

    fn supports_mem_hooks(&self) -> bool {
        true
    }

    fn set_mem_recording(&mut self, on: bool) {
        self.recorder.set_enabled(on);
    }

    fn drain_mem_records(&mut self, out: &mut Vec<MemRecord>) {
        self.recorder.drain(out);
    }

    fn current_pc(&self) -> u64 {
        self.cpu.get_pc()
    }

    fn set_current_pc(&mut self, pc: u64) -> Result<()> {
        self.cpu.set_pc(pc);
        Ok(())
    }

    fn wake(&mut self) {
        self.cpu.clear_wait();
        self.cpu.clear_halt();
        self.shutdown = false;
    }

    fn translate_addr(&mut self, vaddr: u64, access: MemAccess) -> Result<u64> {
        let Some(user) = self.user.as_ref() else {
            return Ok(vaddr);
        };
        let access = match access {
            MemAccess::Read => MemoryAccessKind::Read,
            MemAccess::Write => MemoryAccessKind::Write,
            MemAccess::Exec => MemoryAccessKind::Fetch,
        };
        user.translation
            .translate(vaddr, access)
            .map_err(Error::from)
    }

    fn step_insn(&mut self) -> Result<Option<VcpuExit>> {
        self.ensure_checkpoint_active()?;
        self.step_instruction()
    }
}
