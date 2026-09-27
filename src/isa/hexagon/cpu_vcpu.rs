//! The architecture-neutral [`VCpu`] interface of the Hexagon vCPU.

use super::*;

/// Packets per `run` batch before the vCPU yields to its caller.
const RUN_BATCH_PACKETS: u64 = 100_000;

impl HexagonVcpu {
    /// Executes (or resumes) one packet, counting it once it commits. A packet
    /// suspended at an MMIO exit commits when it is resumed and completes.
    fn step_counted(&mut self) -> Result<Option<VcpuExit>> {
        let exit = self.step_packet()?;
        if self.pending_packet.is_none() {
            self.packets = self.packets.wrapping_add(1);
        }
        Ok(exit)
    }
}

impl VCpu for HexagonVcpu {
    fn run(&mut self) -> Result<VcpuExit> {
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
        u64::from(self.regs.pc())
    }

    fn wake(&mut self) {
        self.halted = false;
    }

    /// Packets committed.
    fn instruction_count(&self) -> u64 {
        self.packets
    }

    fn get_state(&self) -> Result<CpuState> {
        Ok(CpuState::hexagon(self.regs.clone()))
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
        self.regs = state.regs.clone();
        Ok(())
    }

    fn complete_io_in(&mut self, data: &[u8]) {
        if let Some(pending) = self.pending_mmio.take() {
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
