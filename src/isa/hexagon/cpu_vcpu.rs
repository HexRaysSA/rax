//! The architecture-neutral [`VCpu`] interface of the Hexagon vCPU.

use super::*;

/// Packets per `run` batch before the vCPU yields to its caller.
const RUN_BATCH_PACKETS: u64 = 100_000;

impl HexagonVcpu {
    /// Executes (or resumes) one packet, counting it once it commits. A packet
    /// suspended at an MMIO exit commits when it is resumed and completes.
    fn step_counted(&mut self) -> Result<Option<VcpuExit>> {
        self.step_packet_atomic()
    }
}

impl VCpu for HexagonVcpu {
    fn required_private_checkpoint_kind(&self) -> Option<u32> {
        Some(crate::vm::snapshot::HEXAGON_CONTEXT)
    }
    fn capture_backend_context(&self) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        self.capture_private(false).map(Some)
    }
    fn capture_backend_context_for_remap(
        &self,
    ) -> Result<Option<crate::vm::snapshot::BackendContext>> {
        self.capture_private(true).map(Some)
    }
    fn validate_checkpoint_context(
        &self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.validate_checkpoint_state(state, emulator)?;
        if let Some(raw) = context {
            self.prepare_private(state, emulator, raw)?;
        }
        Ok(())
    }
    fn prepare_checkpoint_replacement(
        &self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
        _resources: &crate::vm::snapshot::PreparedResources,
    ) -> Result<Option<Box<dyn VCpu>>> {
        self.validate_checkpoint_state(state, emulator)?;
        context
            .map(|raw| {
                self.prepare_private(state, emulator, raw)
                    .map(|c| Box::new(c) as Box<dyn VCpu>)
            })
            .transpose()
    }
    fn prepare_checkpoint_publication<'scope, 'bindings>(
        &mut self,
        scope: &'scope crate::vm::memory::checkpoint::CheckpointPublication<'bindings>,
    ) -> Result<crate::vm::memory::checkpoint::CpuPublication<'scope, 'bindings>> {
        self.publication(scope)
    }
    fn restore_checkpoint_context(
        &mut self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        context: Option<&crate::vm::snapshot::BackendContext>,
    ) -> Result<()> {
        self.validate_checkpoint_state(state, emulator)?;
        match context {
            Some(raw) => self.restore_private(state, emulator, raw),
            None => {
                self.set_state(state)?;
                self.set_emulator_state(emulator)
            }
        }
    }
    fn run(&mut self) -> Result<VcpuExit> {
        self.finish_publication()?;
        if self.halted {
            return Ok(VcpuExit::Hlt);
        }
        for _ in 0..RUN_BATCH_PACKETS {
            if let Some(exit) = self.step_counted()? {
                return Ok(exit);
            }
        }
        // The end of a batch: yield as the other software vCPUs do. The VMM
        // loop treats `Hlt` as an idle point and runs the vCPU again.
        Ok(VcpuExit::Hlt)
    }

    fn step_insn(&mut self) -> Result<Option<VcpuExit>> {
        self.finish_publication()?;
        if self.halted {
            return Ok(Some(VcpuExit::Hlt));
        }
        self.step_counted()
    }

    /// One step is one VLIW packet.
    fn supports_stepping(&self) -> bool {
        true
    }

    fn current_pc(&self) -> u64 {
        u64::from(self.old_regs().pc())
    }

    fn set_current_pc(&mut self, pc: u64) -> Result<()> {
        let pc = pc as u32;
        if self.effects.initial.is_some() {
            if self.old_regs().pc() != pc {
                return Err(Error::InvalidConfig(
                    "Hexagon PC changes require a packet boundary".into(),
                ));
            }
            return Ok(());
        }
        self.set_pc(pc);
        Ok(())
    }

    fn wake(&mut self) {
        self.halted = false;
    }

    /// Packets committed.
    fn instruction_count(&self) -> u64 {
        self.packets
    }

    fn get_state(&self) -> Result<CpuState> {
        Ok(CpuState::hexagon(self.old_regs().clone()))
    }

    fn set_state(&mut self, state: &CpuState) -> Result<()> {
        let state = match state {
            CpuState::Hexagon(state) => state,
            _ => {
                return Err(Error::Emulator(
                    "expected hexagon state for hexagon vCPU".to_string(),
                ));
            }
        };
        self.discard_packet();
        self.lock_addr = None;
        self.regs = state.regs.clone();
        Ok(())
    }

    fn update_state(&mut self, state: &CpuState) -> Result<()> {
        let CpuState::Hexagon(state) = state else {
            return Err(Error::Emulator(
                "expected hexagon state for hexagon vCPU".into(),
            ));
        };
        if self.effects.initial.is_some() {
            let encode = |value: &HexagonRegisters| {
                crate::codec::serialize(value)
                    .map_err(|e| Error::InvalidConfig(format!("Hexagon register overlay: {e}")))
            };
            if encode(self.old_regs())? != encode(&state.regs)? {
                return Err(Error::InvalidConfig(
                    "Hexagon register changes require a packet boundary".into(),
                ));
            }
            return Ok(());
        }
        // Public register edits retain counters and local reservation rights.
        // Explicit set_state remains the legacy projection/reset operation.
        self.regs = state.regs.clone();
        Ok(())
    }

    fn complete_io_in(&mut self, data: &[u8]) {
        if let Some(pending) = self.pending_mmio.as_ref() {
            let val = match pending.size {
                1 if data.len() >= 1 => {
                    let raw = data[0] as u32;
                    if pending.signed {
                        (raw as i8 as i32) as u32
                    } else {
                        raw
                    }
                }
                2 if data.len() >= 2 => {
                    let raw = match self.endian {
                        Endianness::Little => u16::from_le_bytes([data[0], data[1]]) as u32,
                        Endianness::Big => u16::from_be_bytes([data[0], data[1]]) as u32,
                    };
                    if pending.signed {
                        (raw as i16 as i32) as u32
                    } else {
                        raw
                    }
                }
                4 if data.len() >= 4 => match self.endian {
                    Endianness::Little => u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
                    Endianness::Big => u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
                },
                _ => return,
            };

            let pending = self.pending_mmio.take().unwrap();
            if let Some(packet) = self.pending_packet.as_mut() {
                packet.new_r[pending.dst as usize] = Some(val);
            } else {
                self.regs.r[pending.dst as usize] = val;
            }
        }
    }

    fn id(&self) -> u32 {
        self.id
    }
}

#[cfg(test)]
#[path = "cpu_vcpu_tests.rs"]
mod tests;
