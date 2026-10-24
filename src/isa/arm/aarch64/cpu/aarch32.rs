//! ARM/Thumb execution after a checked exception-return width transition.

mod exceptions;
mod memory;
mod preflight;
mod state;

use super::AArch64Cpu;
use crate::isa::arm::aarch32::instructions::{ExceptionType, ExecResult, Executor};
use crate::isa::arm::common::cpu::{
    AccessType, ArmError, CpuExit, MemoryFaultInfo, MemoryFaultType,
};
use crate::isa::arm::common::isa::ExecutionState;
use crate::isa::arm::decoder::{Decoder, Mnemonic, ThumbDecoder};

impl AArch64Cpu {
    pub(super) fn execute_aarch32_instruction(&mut self) -> Result<CpuExit, ArmError> {
        let pstate = self.aarch32.expect("AArch32 dispatch checked the mode");
        let pc = self.pc as u32;
        self.last_instruction_size = if pstate.t { 2 } else { 4 };
        self.check_aarch32_translation_regime()?;
        self.tbi_tag.store(0, std::sync::atomic::Ordering::Relaxed);
        self.last_fault_level
            .store(0, std::sync::atomic::Ordering::Relaxed);
        if self.il {
            let target = self.pauth_controls().local_exception_target();
            // AArch32_CheckIllegalState takes UNDEF at AArch32 EL1, while
            // AArch64 handlers and Hyp receive Exception_IllegalState.
            let undef = target == 1
                && crate::isa::arm::aarch64::exception_return::uses_aarch32(
                    self.pauth_controls(),
                    self.sysregs.id_aa64pfr0_el1,
                    1,
                ) == Some(true);
            return Err(ArmError::ArchitecturalException {
                ec: if undef { 0 } else { 0x0e },
                iss: 0,
                target_el: Some(target),
            });
        }
        if pc & if pstate.t { 1 } else { 3 } != 0 {
            return Err(ArmError::MemoryError(MemoryFaultInfo {
                address: u64::from(pc),
                access: AccessType::InstructionFetch,
                fault_type: MemoryFaultType::Alignment,
                stage2: false,
            }));
        }
        let mut bytes = [0u8; 4];
        let size = if pstate.t {
            self.fetch_aarch32_halfword(pc, &mut bytes[..2])?;
            if ThumbDecoder::is_32bit_instruction(u16::from_le_bytes([bytes[0], bytes[1]])) {
                self.fetch_aarch32_halfword(pc.wrapping_add(2), &mut bytes[2..])?;
                4
            } else {
                2
            }
        } else {
            let word = self.read_instruction_word(u64::from(pc))?;
            bytes.copy_from_slice(&word.to_le_bytes());
            4
        };
        self.last_instruction_size = size as u8;
        if self.breakpoints.contains(&self.pc) {
            return Ok(CpuExit::Breakpoint(pc));
        }
        let raw = if pstate.t && size == 4 {
            (u32::from(u16::from_le_bytes([bytes[0], bytes[1]])) << 16)
                | u32::from(u16::from_le_bytes([bytes[2], bytes[3]]))
        } else if size == 2 {
            u32::from(u16::from_le_bytes([bytes[0], bytes[1]]))
        } else {
            u32::from_le_bytes(bytes)
        };
        let mut decoder = Decoder::new(if pstate.t {
            ExecutionState::Thumb
        } else {
            ExecutionState::Arm
        });
        let decoded = decoder
            .decode(&bytes[..size])
            .map_err(|_| ArmError::UndefinedInstruction(raw))?;
        if decoded.mnemonic == Mnemonic::SWP {
            return Err(ArmError::UndefinedInstruction(raw));
        }
        let mut state = self.aarch32_register_state();
        let in_it = pstate.t && state.cpsr.in_it_block();
        let mut monitor = std::mem::take(&mut self.aarch32_monitor);
        let (result, fault, status) = {
            let mut memory = memory::Aarch32Memory::new(self);
            let mut executor = Executor::new(&mut state, &mut memory);
            executor.exclusive_monitor = monitor;
            let executes = executor.condition_matches(&decoded);
            if executes {
                if let Err(error) = executor.mem.preflight(&decoded) {
                    self.aarch32_monitor = std::mem::take(&mut executor.exclusive_monitor);
                    return Err(error);
                }
                executor.mem.access = executor.exclusive_access(&decoded);
            }
            let result = executor.execute(&decoded);
            monitor = std::mem::take(&mut executor.exclusive_monitor);
            let status = executor
                .mem
                .access
                .and_then(|access| access.status)
                .filter(|_| executor.mem.exclusive_failed);
            executor.mem.finish(
                &mut monitor,
                matches!(result, ExecResult::Continue),
                executes && decoded.mnemonic == Mnemonic::CLREX,
            );
            (result, memory.fault.take(), status)
        };
        self.aarch32_monitor = monitor;
        if let Some(status) = status {
            state.regs[status] = 1;
        }
        let next_pc = pc.wrapping_add(size as u32);
        let exit = match result {
            ExecResult::Continue => {
                state.regs[15] = next_pc;
                CpuExit::Continue
            }
            ExecResult::Branch(target) => {
                if target & 1 != 0 {
                    state.cpsr.t = true;
                }
                state.regs[15] = target & !1;
                CpuExit::Continue
            }
            ExecResult::Exception(ExceptionType::SupervisorCall(immediate)) => {
                state.regs[15] = next_pc;
                CpuExit::Svc(immediate)
            }
            ExecResult::Exception(ExceptionType::Breakpoint(immediate)) => {
                return Err(ArmError::ArchitecturalException {
                    ec: 0x38,
                    iss: u32::from(immediate),
                    target_el: Some(self.pauth_controls().local_exception_target()),
                });
            }
            ExecResult::Halt => {
                state.regs[15] = next_pc;
                if decoded.mnemonic == Mnemonic::WFE {
                    if self.event_register {
                        self.event_register = false;
                        CpuExit::Continue
                    } else {
                        self.wfe = true;
                        CpuExit::Wfe
                    }
                } else {
                    self.wfi = true;
                    CpuExit::Wfi
                }
            }
            ExecResult::MemoryFault(error) => {
                // Preserve architecturally permitted partial register completion
                // of the existing AArch32 executor; PC and IT do not retire.
                self.commit_aarch32_register_state(&mut state)?;
                return Err(fault.unwrap_or_else(|| {
                    memory::architectural_error(error, preflight::data_access(decoded.mnemonic))
                }));
            }
            ExecResult::Undefined | ExecResult::Exception(ExceptionType::UndefinedInstruction) => {
                return Err(ArmError::UndefinedInstruction(raw));
            }
            other => {
                return Err(ArmError::Unimplemented(format!(
                    "AArch32 executor exit: {other:?}"
                )));
            }
        };
        if matches!(decoded.mnemonic, Mnemonic::SEV | Mnemonic::SEVL) {
            self.event_register = true;
        }
        if in_it {
            state.cpsr.advance_it_state();
        }
        let destination = super::super::aarch32_state::mode_el(state.cpsr.mode);
        if destination.is_none_or(|el| el > self.current_el) || state.cpsr.mode == 0x16 {
            return Err(ArmError::UndefinedInstruction(raw));
        }
        self.commit_aarch32_register_state(&mut state)?;
        self.insn_count += 1;
        self.cycle_count += 1;
        Ok(exit)
    }

    fn fetch_aarch32_halfword(&self, address: u32, bytes: &mut [u8]) -> Result<(), ArmError> {
        let va = u64::from(address);
        let pa = self.translate_address(va, false, true)?;
        self.memory.fetch(pa, bytes).map_err(|error| {
            self.physical_memory_error(error, va, pa, 2, AccessType::InstructionFetch)
        })
    }
}
