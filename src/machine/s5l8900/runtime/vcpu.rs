//! Public stepping, legacy batches and stable register projections.
use super::*;

impl S5L8900Vcpu {
    /// One platform attempt; do not run another guest instruction after a state-only transition.
    fn step_platform(&mut self) -> Result<Option<VcpuExit>> {
        self.finish_publication()?;
        if self.shutdown {
            return Ok(Some(VcpuExit::Shutdown));
        }
        let outcome = self.step();
        if self.shutdown {
            return Ok(Some(VcpuExit::Shutdown));
        }
        match outcome {
            StepOutcome::Progress => Ok(None),
            StepOutcome::Idle => Ok(Some(VcpuExit::Hlt)),
            StepOutcome::Fault(error) => Err(error),
        }
    }
}

impl VCpu for S5L8900Vcpu {
    fn required_private_checkpoint_kind(&self) -> Option<u32> {
        Some(crate::vm::snapshot::S5L8900_CONTEXT)
    }
    fn capture_backend_context(&self) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        Ok(Some(self.capture_parts(None, None)?.0))
    }
    fn capture_backend_context_in_scope(
        &self,
        scope: &crate::vm::memory::checkpoint::CheckpointPublication<'_>,
    ) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        Ok(Some(self.capture_parts(Some(scope), None)?.0))
    }
    fn prepare_checkpoint_capture(
        &self,
    ) -> Result<Option<crate::vm::vcpu::PreparedCheckpointCapture>> {
        Ok(Some(self.prepare_source()?))
    }
    fn capture_prepared_checkpoint_record(
        &self,
        _boundary: &crate::backend::CheckpointBoundary<'_>,
        scope: Option<&crate::vm::memory::checkpoint::CheckpointPublication<'_>>,
        prepared: Option<&crate::vm::vcpu::PreparedCheckpointCapture>,
    ) -> Result<(
        crate::vm::snapshot::CpuSnapshot,
        Option<crate::vm::snapshot::BackendContext>,
        Vec<crate::vm::snapshot::CheckpointResource>,
    )> {
        let (private, resources) = self.capture_parts(scope, prepared)?;
        Ok((
            crate::vm::snapshot::CpuSnapshot {
                state: self.get_state()?,
                emulator: Default::default(),
            },
            Some(private),
            resources,
        ))
    }
    fn capture_checkpoint_resources(&self) -> Result<Vec<crate::vm::snapshot::CheckpointResource>> {
        Ok(self.capture_parts(None, None)?.1)
    }
    fn checkpoint_resource_references(
        &self,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<Vec<crate::vm::snapshot::ResourceKey>> {
        self.resource_references(context)
    }
    fn checkpoint_owned_s3c_uarts(&self) -> Vec<Arc<Mutex<S3cUart>>> {
        self.uart.get().cloned().into_iter().collect()
    }
    fn prepare_checkpoint_replacement(
        &self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
        resources: &crate::vm::snapshot::PreparedResources,
    ) -> Result<Option<Box<dyn VCpu>>> {
        match context {
            Some(context) => Ok(Some(Box::new(
                self.prepare_private(state, emulator, context, resources)?,
            ))),
            None => Ok(None),
        }
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
        self.validate_checkpoint_state(state, emulator)?;
        match context {
            Some(raw) => self.admit_descriptor(state, emulator, raw),
            None => Ok(()),
        }
    }
    fn restore_checkpoint_context(
        &mut self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.validate_checkpoint_context(state, emulator, context)?;
        if context.is_some() {
            return Err(Error::InvalidConfig(
                "S5L descriptor import requires prepared resources and matching RAM publication"
                    .into(),
            ));
        }
        self.set_state(state)
    }
    fn finish_checkpoint_restore(
        &mut self,
        _boundary: &crate::backend::CheckpointBoundary<'_>,
        _context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.finish_publication()
    }

    fn supports_stepping(&self) -> bool {
        true
    }

    fn step_insn(&mut self) -> Result<Option<VcpuExit>> {
        self.finish_publication()?;
        if self.shutdown {
            return Ok(Some(VcpuExit::Shutdown));
        }
        let result = self.step_platform()?;
        self.heartbeat();
        Ok(result)
    }

    fn wake(&mut self) {
        self.cpu.is_halted = false;
        self.shutdown = false;
    }

    fn run(&mut self) -> Result<VcpuExit> {
        self.finish_publication()?;
        if self.shutdown {
            return Ok(VcpuExit::Shutdown);
        }
        for _ in 0..BATCH {
            if let Some(exit) = self.step_platform()? {
                self.heartbeat();
                return Ok(exit);
            }
        }
        self.heartbeat();
        Ok(VcpuExit::Hlt)
    }

    fn get_state(&self) -> Result<CpuState> {
        Ok(crate::backend::emulator::aarch32::public_state(&self.cpu))
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        let state = match state {
            CpuState::Aarch32(s) => s,
            _ => {
                return Err(Error::Emulator(
                    "expected aarch32 state for s5l8900 vCPU".to_string(),
                ));
            }
        };
        crate::backend::emulator::aarch32::apply_public_state(&mut self.cpu, state);
        Ok(())
    }

    fn complete_io_in(&mut self, _data: &[u8]) {}

    fn attach_s3c_uart(
        &mut self,
        uart: std::sync::Arc<std::sync::Mutex<crate::devices::s3c64xx::S3cUart>>,
    ) {
        // The S5L8900 UART is register-compatible with the Samsung s3c UART,
        // so it reuses the VMM's console plumbing (host stdin → guest serial).
        let _ = self.uart.set(uart);
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn instruction_count(&self) -> u64 {
        self.insn_count
    }
}
