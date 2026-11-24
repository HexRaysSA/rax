//! Platform interrupt inputs, eligibility and trap entry.

use super::*;

impl RiscVCpu {
    /// Assert or deassert platform interrupt inputs. SEIP has a separate
    /// software injection bit, which this method leaves alone.
    pub fn set_interrupt_pending(&mut self, mask: u64, pending: bool) {
        if mask & MIP_SEIP != 0 {
            self.external_seip = pending;
        }
        let mask = mask & IMPLEMENTED_INTERRUPT_MASK & !MIP_SEIP;
        if pending {
            self.mip |= mask;
        } else {
            self.mip &= !mask;
        }
    }

    pub(super) fn interrupt_pending(&self) -> u64 {
        self.mip | (u64::from(self.external_seip) * MIP_SEIP)
    }

    pub(crate) fn locally_enabled_interrupt_pending(&self) -> bool {
        self.interrupt_pending() & self.mie & IMPLEMENTED_INTERRUPT_MASK != 0
    }

    pub(crate) fn machine_timer_interrupt_enabled(&self) -> bool {
        self.mie & MIP_MTIP != 0
    }

    /// Take one eligible interrupt before instruction fetch. Interpreted and
    /// native-region entry share this boundary and retirement behavior.
    pub(super) fn take_pending_interrupt(&mut self) -> bool {
        let pending = self.interrupt_pending() & self.mie & IMPLEMENTED_INTERRUPT_MASK;
        let machine = pending & !self.mideleg;
        let machine_enabled = self.priv_ < Priv::Machine || self.mstatus & MSTATUS_MIE != 0;
        let supervisor_enabled = self.priv_ < Priv::Supervisor
            || (self.priv_ == Priv::Supervisor && self.mstatus & MSTATUS_SIE != 0);
        let (target, eligible) = if machine_enabled && machine != 0 {
            (Priv::Machine, machine)
        } else if supervisor_enabled {
            (Priv::Supervisor, pending & self.mideleg & S_INTERRUPT_MASK)
        } else {
            return false;
        };
        let Some(cause) = [
            cause::INT_M_EXTERNAL,
            cause::INT_M_SOFTWARE,
            cause::INT_M_TIMER,
            cause::INT_S_EXTERNAL,
            cause::INT_S_SOFTWARE,
            cause::INT_S_TIMER,
        ]
        .into_iter()
        .find(|cause| eligible & (1 << cause) != 0) else {
            return false;
        };
        let trap = Trap {
            cause: self.interrupt_cause_bit() | cause,
            tval: 0,
        };
        if target == Priv::Machine {
            self.enter_machine_trap(trap, self.pc);
        } else {
            self.enter_supervisor_trap(trap, self.pc);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::riscv::FlatMemory;

    #[test]
    fn hardware_seip_wakes_wfi_and_traps_at_the_next_eligible_boundary() {
        const PC: u64 = 0x100;
        const VECTOR: u64 = 0x200;
        const WFI: u32 = 0x1050_0073;
        for xlen in [Xlen::Rv32, Xlen::Rv64] {
            let cfg = RiscVConfig {
                xlen,
                ..RiscVConfig::rv64gc()
            };
            let mut cpu = RiscVCpu::new(cfg, Box::new(FlatMemory::new(0, 4096)));
            cpu.write_memory(PC, &WFI.to_le_bytes()).unwrap();
            cpu.set_pc(PC);
            cpu.csr_write(Csr::Mideleg as u16, MIP_SEIP).unwrap();
            cpu.csr_write(Csr::Mie as u16, MIP_SEIP).unwrap();
            cpu.csr_write(Csr::Stvec as u16, VECTOR).unwrap();
            cpu.set_privilege(Priv::Supervisor);
            cpu.set_interrupt_pending(MIP_SEIP, true);

            // SIE=0 prevents the trap, while WFI sees individual enables.
            assert_eq!(cpu.step(), RiscVExit::Continue);
            assert_eq!(cpu.pc(), PC + 4);
            assert_eq!(cpu.instret(), 1);
            assert_eq!(cpu.csr_read(Csr::Mip as u16), Ok(MIP_SEIP));
            cpu.csr_write(Csr::Sstatus as u16, MSTATUS_SIE).unwrap();
            assert_eq!(cpu.step(), RiscVExit::Continue);
            assert_eq!(cpu.pc(), VECTOR);
            assert_eq!(cpu.instret(), 1);
            assert_eq!(cpu.csr_read(Csr::Sepc as u16), Ok(PC + 4));
            assert_eq!(
                cpu.csr_read(Csr::Scause as u16),
                Ok((1 << (xlen.bits() - 1)) | cause::INT_S_EXTERNAL)
            );
            assert_eq!(cpu.csr_read(Csr::Sip as u16), Ok(MIP_SEIP));

            // The platform line stays high during a hart-only reset.
            cpu.reset(PC);
            assert_eq!(cpu.csr_read(Csr::Mip as u16), Ok(MIP_SEIP));
            cpu.set_interrupt_pending(MIP_SEIP, false);
            assert_eq!(cpu.csr_read(Csr::Mip as u16), Ok(0));
        }
    }
}
