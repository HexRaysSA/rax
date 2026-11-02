//! Public stepping, legacy batches and stable register projections.
use super::*;

impl S5L8900Vcpu {
    /// One platform attempt; do not run another guest instruction after a state-only transition.
    fn step_platform(&mut self) -> Result<Option<VcpuExit>> {
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
    fn supports_stepping(&self) -> bool {
        true
    }

    fn step_insn(&mut self) -> Result<Option<VcpuExit>> {
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
        let mut regs = Aarch32Registers::default();
        for i in 0..13 {
            regs.r[i] = self.cpu.regs[i];
        }
        regs.sp = self.cpu.regs[13];
        regs.lr = self.cpu.regs[14];
        regs.pc = self.cpu.regs[15];
        regs.cpsr = self.cpu.cpsr.to_u32();
        Ok(CpuState::Aarch32(Aarch32CpuState {
            regs,
            sregs: Aarch32SystemRegisters::default(),
        }))
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
        let cpsr = crate::isa::arm::Psr::from_u32(state.regs.cpsr);
        if let Some(mode) = ProcessorMode::from_bits(cpsr.mode) {
            self.cpu.change_mode(mode);
        }
        for i in 0..13 {
            self.cpu.regs[i] = state.regs.r[i];
        }
        self.cpu.regs[13] = state.regs.sp;
        self.cpu.regs[14] = state.regs.lr;
        self.cpu.regs[15] = state.regs.pc;
        self.cpu.cpsr = cpsr;
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
