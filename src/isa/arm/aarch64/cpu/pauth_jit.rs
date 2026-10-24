//! Single-instruction native PAuth regions with precise system-step exits.

use super::*;
use crate::isa::arm::aarch64::Aarch64MemoryBridge;
use crate::isa::arm::aarch64::pauth_instruction::PauthInstruction;
use crate::smir::ir::context::{Aarch64RegState, ExitReason};
use crate::smir::ir::types::{BlockId, FunctionId, SourceArch};
use crate::smir::ir::{SmirBlock, SmirFunction, Terminator};
use crate::smir::lift::aarch64::Aarch64Lifter;
use crate::smir::lift::{ControlFlow, LiftContext, SmirLifter};
use crate::smir::lower::SmirLowerer;
use crate::smir::lower::aarch64::Aarch64Lowerer;
use crate::smir::lower::runtime::{Aarch64GuestRegs, Aarch64PauthRuntime, ExecMem};

impl AArch64Cpu {
    pub(super) fn jit_compile_pauth_instruction(&mut self, raw: u32) -> Option<JitRegion> {
        if self.pc & 3 != 0 {
            return None;
        }
        let instruction = PauthInstruction::decode(raw)?;
        let mut context = LiftContext::new(SourceArch::Aarch64);
        context.aarch64_features = Some(self.config.features);
        let lifted = Aarch64Lifter::strict()
            .lift_insn(self.pc, &raw.to_le_bytes(), &mut context)
            .ok()?;
        let mut block = SmirBlock::new(BlockId(0), self.pc);
        block.ops = lifted.ops;
        block.terminator = match lifted.control_flow {
            ControlFlow::NextInsn | ControlFlow::Fallthrough => {
                Terminator::Return { values: vec![] }
            }
            ControlFlow::IndirectBranch { target } => Terminator::IndirectBranch {
                target,
                possible_targets: vec![],
            },
            _ => return None,
        };
        crate::smir::ir::validate_aarch64_instructions(&block).ok()?;
        let mut function = SmirFunction::new(FunctionId(0), block.id, self.pc);
        function.add_block(block);
        let mut lowerer = Aarch64Lowerer::new();
        lowerer.set_pauth_helpers(true);
        let lowered = lowerer.lower_function(&function).ok()?;
        if !lowered.relocations.is_empty() {
            return None;
        }
        let code = lowerer.finalize().ok()?;
        let source = self.pc & !0xfff;
        Some(JitRegion {
            exec: ExecMem::new(&code).ok()?,
            entry_offset: lowered.entry_offset,
            uses_fp: false,
            uses_memory: matches!(instruction, PauthInstruction::Load { .. }),
            source_pages: vec![(source, self.translate_address(source, false, true).ok()?)],
            pauth_instruction: Some(raw),
        })
    }

    fn pauth_native_state(&self) -> Aarch64RegState {
        Aarch64RegState {
            x: self.x,
            sp: self.current_sp(),
            pc: self.pc,
            nzcv: (u32::from(self.nzcv) & 15) << 28,
            fpcr: self.fpcr,
            fpsr: self.fpsr,
            v: std::array::from_fn(|index| [self.v[index] as u64, (self.v[index] >> 64) as u64]),
            pstate: self.pstate_bits() & !0xf000_0000,
            system: Some(Box::new(self.export_sregs())),
            instruction_guarded: None,
            event_register: self.event_register,
        }
    }

    pub(super) fn jit_run_pauth_instruction(&mut self, region: &JitRegion, raw: u32) -> bool {
        self.jit.native_fault = None;
        if self.breakpoints.contains(&self.pc) {
            return false;
        }
        if PauthInstruction::decode(raw).is_none() || self.aarch32.is_some() {
            return false;
        }
        // Revalidate the instruction bytes as well as its mapping; stale code
        // cannot execute an older signing/authentication form at the same PA.
        self.tbi_tag.store(0, std::sync::atomic::Ordering::Relaxed);
        self.last_fault_level
            .store(0, std::sync::atomic::Ordering::Relaxed);
        match self.fetch_instruction() {
            Ok(current) if current == raw => {}
            Ok(_) => {
                self.clear_jit_cache();
                return false;
            }
            Err(error) => {
                self.jit.native_fault = Some(error);
                return true;
            }
        }
        for &(virtual_address, physical_address) in &region.source_pages {
            if self.translate_address(virtual_address, false, true).ok() != Some(physical_address) {
                return false;
            }
        }
        let initial = self.pauth_native_state();
        let mut generic = crate::smir::ir::memory::FlatMemory::new(0);
        let (result, state, retired) = {
            let mut memory = Aarch64MemoryBridge::for_current_pauth_instruction(self, &mut generic);
            let Ok(mut runtime) = Aarch64PauthRuntime::new(initial, &mut memory) else {
                return false;
            };
            runtime.instruction_limit = 1;
            let result = runtime.run(&mut Aarch64GuestRegs::default(), |registers| {
                region
                    .exec
                    .run_aarch64_identity(region.entry_offset, registers);
            });
            (result, runtime.registers, runtime.retired)
        };
        self.jit.pauth_native_runs = self.jit.pauth_native_runs.saturating_add(1);
        let Some(exported) = state.to_cpu_state() else {
            return false;
        };
        // Typed PAuth has no system-register writes. Preserve the live system
        // bank object (including timers and cache ownership); commit only the
        // GPR/SP/PSTATE/PC/event effects represented by this instruction.
        if self
            .set_pstate_bits_from_native(exported.regs.pstate)
            .is_err()
        {
            return false;
        }
        self.x = state.x;
        self.sp_el[0] = exported.sregs.sp_el0;
        self.sp_el[1] = exported.sregs.sp_el1;
        self.sp_el[2] = exported.sregs.execution.as_ref().unwrap().sp_el2;
        self.sp_el[3] = exported.sregs.execution.as_ref().unwrap().sp_el3;
        self.pc = state.pc;
        self.event_register = state.event_register;
        self.insn_count = self.insn_count.saturating_add(retired);
        self.cycle_count = self.cycle_count.saturating_add(retired);
        self.jit.native_fault = match result {
            Ok(()) | Err(ExitReason::InsnLimit) | Err(ExitReason::Unsupported { .. }) => None,
            Err(ExitReason::Aarch64Fault { error, .. }) => Some(error),
            Err(ExitReason::Aarch64Exception {
                ec, iss, target_el, ..
            }) => Some(ArmError::ArchitecturalException {
                ec,
                iss,
                target_el: Some(target_el),
            }),
            Err(ExitReason::Undefined { opcode, .. }) => {
                Some(ArmError::UndefinedInstruction(opcode))
            }
            Err(reason) => Some(ArmError::Internal(format!(
                "unexpected PAuth native exit: {reason:?}"
            ))),
        };
        retired != 0 || self.jit.native_fault.is_some()
    }
}
