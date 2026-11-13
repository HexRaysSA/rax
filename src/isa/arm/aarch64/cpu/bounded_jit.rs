//! Native instruction-sized regions for the software scheduler's budget-1 entry.
//!
//! No branch remains inside a region: both edges return through dispatcher exit
//! stubs. Entry checks precede native execution; register publication and exact
//! retirement follow success. Optimization sees only this instruction.

use super::*;
use crate::smir::ir::ops::{OpKind, SmirOp};
use crate::smir::ir::types::{BlockId, FunctionId, SourceArch};
use crate::smir::ir::{SmirBlock, SmirFunction, Terminator};
use crate::smir::lift::aarch64::Aarch64Lifter;
use crate::smir::lift::{ControlFlow, LiftContext, SmirLifter};
use crate::smir::lower::SmirLowerer;
use crate::smir::lower::aarch64::{Aarch64Lowerer, uses_aarch64_fp_trampoline};
use crate::smir::lower::runtime::{ExecMem, is_aarch64_native_clobber_safe_excluding};
use crate::smir::optimize::{OptLevel, optimize_function};
use std::collections::HashMap;

#[cfg(test)]
#[path = "bounded_jit_tests.rs"]
mod fault_tests;

impl AArch64Cpu {
    /// Cold or ineligible instructions retain the precise interpreter frontier.
    /// Each attempted hot PC has an independent bounded-mode cache key. A self
    /// branch returns after one retirement rather than spinning inside native code.
    pub(super) fn jit_step_bounded(&mut self) -> bool {
        if self.execution.disabled
            || self.aarch32.is_some()
            || self.fp_traps_enabled()
            || self.instruction_debug_armed()
        {
            return false;
        }
        use std::sync::OnceLock;
        static OFF: OnceLock<bool> = OnceLock::new();
        if *OFF.get_or_init(|| std::env::var_os("RAX_NO_JIT").is_some()) {
            return false;
        }
        // Existing EL0/system PAuth caches contain exactly one checked
        // instruction. Ordinary legacy regions must never enter a system step.
        if let Some(region) = self.jit_lookup(self.pc)
            && region.pauth_instruction.is_some()
        {
            return self.jit_run_bounded(&region);
        }
        let mut mode = self.jit_mode_tag();
        mode.bounded = true;
        let key = (self.pc, mode);
        let cached = self.jit.cache.get(&key).cloned();
        let region = match cached {
            Some(region) => region,
            None => {
                let hot = self.jit.hot.entry(self.pc).or_insert(0);
                *hot = hot.saturating_add(1);
                if *hot < A64_JIT_HOT_THRESHOLD {
                    return false;
                }
                self.jit.hot.remove(&self.pc);
                let region = self.jit_compile_bounded().map(std::sync::Arc::new);
                if self.jit.cache.len() >= 16384 {
                    self.clear_jit_cache();
                }
                self.jit.cache.insert(key, region.clone());
                if region.is_some() {
                    self.jit.code_pages.insert(self.pc & !0xfff);
                }
                region
            }
        };
        region.is_some_and(|region| self.jit_run_bounded(&region))
    }

    fn jit_compile_bounded(&mut self) -> Option<JitRegion> {
        let raw = self.fetch_instruction().ok()?;
        if crate::isa::arm::aarch64::pauth_instruction::PauthInstruction::decode(raw).is_some() {
            return self.jit_compile_pauth_instruction(raw);
        }
        let mut context = LiftContext::new(SourceArch::Aarch64);
        context.aarch64_features = Some(self.config.features);
        let lifted = Aarch64Lifter::strict()
            .lift_insn(self.pc, &raw.to_le_bytes(), &mut context)
            .ok()?;
        let mut block = SmirBlock::new(BlockId(0), self.pc);
        block.ops = lifted.ops;
        let mut exits = HashMap::new();
        let mut exit = |pc| {
            let id = BlockId(exits.len() as u32 + 1);
            exits.insert(id, pc);
            id
        };
        block.terminator = match lifted.control_flow {
            ControlFlow::NextInsn | ControlFlow::Fallthrough => Terminator::Branch {
                target: exit(self.pc.wrapping_add(4)),
            },
            ControlFlow::Branch { target } | ControlFlow::DirectBranch(target) => {
                Terminator::Branch {
                    target: exit(target),
                }
            }
            ControlFlow::CondBranch {
                cond,
                target,
                fallthrough,
            } => {
                let value = context.alloc_vreg();
                let index = block.ops.len().checked_sub(1)?;
                block.ops.insert(
                    index,
                    SmirOp::new(
                        context.next_op_id(),
                        self.pc,
                        OpKind::TestCondition { dst: value, cond },
                    ),
                );
                Terminator::CondBranch {
                    cond: value,
                    true_target: exit(target),
                    false_target: exit(fallthrough),
                }
            }
            ControlFlow::CondBranchReg {
                cond,
                taken,
                not_taken,
            } => Terminator::CondBranch {
                cond,
                true_target: exit(taken),
                false_target: exit(not_taken),
            },
            // Calls, returns, system operations and indirect transfers retain
            // their existing interpreter semantics and architectural exits.
            _ => return None,
        };
        let mut function = SmirFunction::new(FunctionId(0), block.id, self.pc);
        function.attrs.preserve_interpreter_frontiers = true;
        function.add_block(block);
        for (&id, &pc) in &exits {
            let mut frontier = SmirBlock::new(id, pc);
            frontier.terminator = Terminator::Return { values: vec![] };
            function.add_block(frontier);
        }
        let (fp_access, fp_features) =
            self.native_requirements(&function, self.pc, &raw.to_le_bytes())?;
        // The CPU owns entry and successful retirement for this one source
        // word. Remove framing only after its original feature requirements
        // have been captured, so O2 can fuse ordinary address calculations.
        for block in &mut function.blocks {
            if !exits.contains_key(&block.id) {
                crate::smir::ir::validate_aarch64_instructions(block).ok()?;
            }
            block.ops.retain(|op| {
                !matches!(
                    op.kind,
                    OpKind::ArmInstructionBegin { .. } | OpKind::ArmInstructionCommit { .. }
                )
            });
        }
        if std::env::var_os("RAX_JIT_NO_OPT").is_none() {
            optimize_function(&mut function, OptLevel::O2);
        }
        let allow_memory = self.execution.mem && !self.sp_alignment_enabled();
        let uses_memory = function
            .blocks
            .iter()
            .flat_map(|block| &block.ops)
            .any(|op| op.kind.reads_memory() || op.kind.writes_memory());
        if !is_aarch64_native_clobber_safe_excluding(&function, &exits, allow_memory) {
            return None;
        }
        let mut lowerer = Aarch64Lowerer::new();
        lowerer.set_native_exits(exits);
        lowerer.set_mem_helpers(allow_memory);
        let lowered = lowerer.lower_function(&function).ok()?;
        if !lowered.relocations.is_empty() {
            return None;
        }
        let code = lowerer.finalize().ok()?;
        let page = self.pc & !0xfff;
        Some(JitRegion {
            exec: ExecMem::new(&code).ok()?,
            entry_offset: lowered.entry_offset,
            uses_fp: uses_aarch64_fp_trampoline(&function),
            fp_access,
            fp_features,
            uses_memory,
            source_pages: vec![(page, self.translate_address(page, false, true).ok()?)],
            pauth_instruction: None,
            bounded_instruction: Some(raw),
        })
    }

    fn jit_run_bounded(&mut self, region: &JitRegion) -> bool {
        if self.fp_traps_enabled() {
            return false;
        }
        if let Some(raw) = region.pauth_instruction {
            let pc = self.pc;
            self.jit.bounded_active = true;
            let ran = self.jit_run_pauth_instruction(region, raw);
            self.jit.bounded_active = false;
            if ran {
                self.last_instruction_size = 4;
                self.note_bounded_pc(pc);
            }
            return ran;
        }
        let Some(raw) = region.bounded_instruction else {
            return false;
        };
        if self.execution.native_fault.is_some()
            || self.breakpoints.contains(&self.pc)
            || !region.fp_access.permitted(self.fp_access_controls())
            || !self.config.features.contains(region.fp_features)
            || (region.uses_memory && self.sp_alignment_enabled())
        {
            return false;
        }
        self.tbi_tag.store(0, std::sync::atomic::Ordering::Relaxed);
        self.last_fault_level
            .store(0, std::sync::atomic::Ordering::Relaxed);
        if self.fetch_instruction().ok() != Some(raw) {
            self.clear_jit_cache();
            return false;
        }
        if self.check_instruction_entry(raw).is_err() {
            return false;
        }
        for &(va, pa) in &region.source_pages {
            if self.translate_address(va, false, true).ok() != Some(pa) {
                return false;
            }
        }
        let pc = self.pc;
        let mut registers = self.jit_marshal_to();
        registers.ctx = self as *mut AArch64Cpu as u64;
        self.jit.bounded_active = true;
        if region.uses_fp {
            region
                .exec
                .run_aarch64_identity_fp(region.entry_offset, &mut registers);
        } else {
            region
                .exec
                .run_aarch64_identity(region.entry_offset, &mut registers);
        }
        self.jit.bounded_active = false;
        self.jit.bounded_runs = self.jit.bounded_runs.wrapping_add(1);
        self.last_instruction_size = 4;
        if let Some(mut error) = self.execution.native_fault.take() {
            if let ArmError::MemoryError(info) = &mut error {
                self.retag_fault_address(info);
            }
            self.execution.native_fault = Some(error);
            // Helpers changed only memory and fault metadata. The CPU still
            // holds its original registers: discard partially completed loads
            // and writeback without replaying a completed store/device access.
        } else {
            self.jit_marshal_from(&registers);
            self.btype = 0;
            self.insn_count = self.insn_count.wrapping_add(1);
            self.cycle_count = self.cycle_count.wrapping_add(1);
        }
        self.note_bounded_pc(pc);
        true
    }

    fn note_bounded_pc(&mut self, pc: u64) {
        self.pc_ring[self.pc_ring_idx] = pc;
        self.pc_ring_idx = (self.pc_ring_idx + 1) % self.pc_ring.len();
    }

    #[cfg(test)]
    pub(crate) fn bounded_native_runs(&self) -> u64 {
        self.jit.bounded_runs
    }
}
