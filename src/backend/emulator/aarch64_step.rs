//! Instruction stepping and diagnostic-fault translation for the AArch64 adapter.
use super::*;

#[cfg(test)]
#[path = "aarch64_step/fp_access_tests.rs"]
mod fp_access_tests;
#[cfg(test)]
#[path = "aarch64_step/undefined_tests.rs"]
mod undefined_tests;

impl Aarch64Vcpu {
    pub(super) fn step_micro(&mut self, allow_jit: bool) -> Result<Option<VcpuExit>> {
        self.sync_uart_irq();
        let step = if allow_jit {
            self.cpu.step_system_with_fault_exit()
        } else {
            self.cpu.step_system_interpreted(true)
        };
        let result = match step {
            Ok(CpuExit::Continue) => Ok(None),
            Ok(CpuExit::Wfi | CpuExit::Wfe) => Ok(Some(VcpuExit::Hlt)),
            Ok(CpuExit::Hvc(immediate) | CpuExit::Smc(immediate)) => {
                if let Some(exit) = self.handle_psci(immediate)? {
                    self.shutdown = matches!(exit, VcpuExit::Shutdown);
                    Ok(Some(exit))
                } else {
                    Ok(None)
                }
            }
            Ok(CpuExit::Halt | CpuExit::Shutdown) => {
                self.shutdown = true;
                Ok(Some(VcpuExit::Shutdown))
            }
            Ok(other) => Err(Error::Emulator(format!(
                "unhandled AArch64 instruction exit at {:#x}: {other:?}",
                self.cpu.get_pc()
            ))),
            Err(ArmError::MemoryError(info)) => {
                use crate::error::{GuestMemoryFault, MemoryAccessKind, MemoryFaultKind};
                use crate::isa::arm::common::cpu::MemoryFaultType;
                let access = match info.access {
                    AccessType::Write | AccessType::Atomic => MemoryAccessKind::Write,
                    AccessType::Read => MemoryAccessKind::Read,
                    AccessType::InstructionFetch => MemoryAccessKind::Fetch,
                };
                let kind = match info.fault_type {
                    MemoryFaultType::Translation => MemoryFaultKind::Unmapped,
                    MemoryFaultType::Permission => MemoryFaultKind::Permission,
                    _ => MemoryFaultKind::Other,
                };
                Err(GuestMemoryFault {
                    address: info.address,
                    size: 0,
                    access,
                    kind,
                }
                .into())
            }
            Err(ArmError::UndefinedInstruction(instruction)) => Err(Error::InvalidInstruction {
                pc: self.cpu.get_pc(),
                diagnosis: format!("undefined AArch64 encoding {instruction:#x}"),
            }),
            Err(error) => Err(Error::Emulator(format!(
                "AArch64 instruction failed at {:#x}: {error}",
                self.cpu.get_pc()
            ))),
        };
        self.insn_count
            .store(self.cpu.instruction_count(), Ordering::Relaxed);
        result
    }

    pub(super) fn step_instruction(&mut self) -> Result<Option<VcpuExit>> {
        if self.powered_off {
            return Ok(Some(VcpuExit::Hlt));
        }
        if self.shutdown {
            return Ok(Some(VcpuExit::Shutdown));
        }
        if self.user.is_some() {
            return self.step_user();
        }
        if self.fault_exits {
            return self.step_micro(false);
        }
        // Pick up console input the VMM queued (mirrors one run() iteration).
        self.sync_uart_irq();
        let r = match self.cpu.step_system_interpreted(false) {
            Ok(CpuExit::Continue) => Ok(None),
            Ok(CpuExit::Wfi) | Ok(CpuExit::Wfe) => Ok(Some(VcpuExit::Hlt)),
            Ok(CpuExit::Hvc(immediate)) | Ok(CpuExit::Smc(immediate)) => {
                if let Some(exit) = self.handle_psci(immediate)? {
                    self.shutdown = matches!(exit, VcpuExit::Shutdown);
                    Ok(Some(exit))
                } else {
                    Ok(None)
                }
            }
            Ok(CpuExit::Halt) | Ok(CpuExit::Shutdown) => {
                self.shutdown = true;
                Ok(Some(VcpuExit::Shutdown))
            }
            Ok(other) => Ok(Some(VcpuExit::Unknown(format!(
                "aarch64 exit {:?} at pc={:#x}",
                other,
                self.cpu.get_pc()
            )))),
            Err(e) => Ok(Some(VcpuExit::Unknown(format!(
                "aarch64 emulation error at pc={:#x}: {e}",
                self.cpu.get_pc()
            )))),
        };
        self.insn_count
            .store(self.cpu.instruction_count(), Ordering::Relaxed);
        r
    }
}
