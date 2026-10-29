//! Instruction stepping and diagnostic-fault translation for the AArch64 adapter.
use super::*;

#[cfg(all(test, feature = "smir-jit", target_arch = "aarch64"))]
#[path = "aarch64_step/bounded_jit_tests.rs"]
mod bounded_jit_tests;
#[cfg(test)]
#[path = "aarch64_step/fp_access_tests.rs"]
mod fp_access_tests;
#[cfg(all(test, feature = "smir-jit", target_arch = "aarch64"))]
#[path = "aarch64_step/system_entry_tests.rs"]
mod system_entry_tests;
#[cfg(test)]
#[path = "aarch64_step/undefined_tests.rs"]
mod undefined_tests;

impl Aarch64Vcpu {
    /// Preserve the separately saved observation phase and publish completed
    /// CPU retirement before an adapter exit, firmware callback, or error.
    pub(super) fn step_system_cpu(
        &mut self,
        fault_exit: bool,
    ) -> core::result::Result<CpuExit, ArmError> {
        let before = self.cpu.instruction_count();
        let result = if self.recorder.enabled.load(Ordering::Relaxed) {
            // Compilation and source revalidation perform extra fetches. The
            // access-recording API promises the interpreter's exact accesses.
            self.cpu.step_system_interpreted(fault_exit)
        } else if fault_exit {
            self.cpu.step_system_with_fault_exit()
        } else {
            self.cpu.step_system()
        };
        let delta = self.cpu.instruction_count().wrapping_sub(before);
        self.insn_count.fetch_add(delta, Ordering::Relaxed);
        result
    }

    pub(super) fn step_micro(&mut self) -> Result<Option<VcpuExit>> {
        self.sync_uart_irq();
        let step = self.step_system_cpu(true);
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
            return self.step_micro();
        }
        // Pick up console input the VMM queued (mirrors one run() iteration).
        self.sync_uart_irq();
        let step = self.step_system_cpu(false);
        let r = match step {
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
        r
    }
}
