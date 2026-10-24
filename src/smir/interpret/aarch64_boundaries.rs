//! Precise AArch64 instruction entry, retirement and resumable frontiers.

use super::arm_pauth::unsupported;
use super::{BlockResult, SmirInterpreter};
use crate::smir::ir::context::{ArchRegState, ExitReason, SmirContext};
use crate::smir::ir::memory::SmirMemory;
use crate::smir::ir::ops::OpKind;
use crate::smir::ir::{SmirBlock, types::SourceArch};

impl SmirInterpreter {
    pub(super) fn execute_aarch64_boundaries(
        &self,
        ctx: &mut SmirContext,
        memory: &mut dyn SmirMemory,
        block: &SmirBlock,
        limit: u64,
    ) -> BlockResult {
        if let Err(operation) = crate::smir::ir::validate_aarch64_instructions(block) {
            return BlockResult::Exit(unsupported(block.guest_pc, operation));
        }
        if ctx.source_arch != SourceArch::Aarch64 {
            return BlockResult::Exit(unsupported(block.guest_pc, "AArch64 instruction framing"));
        }
        for op in &block.ops {
            match op.kind {
                OpKind::ArmInstructionBegin { raw, features } => {
                    ctx.pc = op.guest_pc;
                    let ArchRegState::Aarch64(state) = &mut ctx.arch_regs else {
                        return BlockResult::Exit(unsupported(op.guest_pc, "AArch64 state"));
                    };
                    state.pc = op.guest_pc;
                    if ctx.insn_count >= limit {
                        return BlockResult::Exit(ExitReason::InsnLimit);
                    }
                    if ctx.debug.has_breakpoint(op.guest_pc) {
                        return BlockResult::Exit(ExitReason::Breakpoint { addr: op.guest_pc });
                    }
                    if let Err(reason) = super::arm_pauth::begin_instruction(
                        state,
                        memory,
                        raw,
                        features,
                        op.guest_pc,
                    ) {
                        return BlockResult::Exit(reason);
                    }
                }
                OpKind::ArmInstructionCommit { raw } => {
                    let ArchRegState::Aarch64(state) = &mut ctx.arch_regs else {
                        unreachable!()
                    };
                    super::arm_pauth::commit_instruction(state, raw, op.guest_pc);
                    ctx.pc = state.pc;
                    ctx.insn_count = ctx.insn_count.saturating_add(1);
                }
                _ => {
                    if let Err(error) = self.execute_op(ctx, memory, op) {
                        // Keep the faulting guest PC; no retirement occurs.
                        return BlockResult::Exit(ExitReason::MemoryFault {
                            addr: match error {
                                crate::smir::ir::memory::MemoryError::PageFault {
                                    addr, ..
                                }
                                | crate::smir::ir::memory::MemoryError::AccessViolation {
                                    addr,
                                    ..
                                }
                                | crate::smir::ir::memory::MemoryError::Alignment {
                                    addr, ..
                                }
                                | crate::smir::ir::memory::MemoryError::Mmio { addr, .. }
                                | crate::smir::ir::memory::MemoryError::OutOfBounds { addr } => {
                                    addr
                                }
                                crate::smir::ir::memory::MemoryError::ExclusiveFailed => {
                                    op.guest_pc
                                }
                            },
                            write: op.kind.writes_memory(),
                        });
                    }
                    if let Some(reason) = ctx.exit_reason.take() {
                        return BlockResult::Exit(reason);
                    }
                }
            }
        }
        let result = self.execute_terminator(ctx, memory, &block.terminator);
        if let BlockResult::Continue(next) = result {
            let ArchRegState::Aarch64(state) = &mut ctx.arch_regs else {
                unreachable!()
            };
            let next = state
                .pauth_environment()
                .unwrap()
                .controls
                .branch_address(next);
            state.pc = next;
            ctx.pc = next;
            BlockResult::Continue(next)
        } else {
            result
        }
    }
}
