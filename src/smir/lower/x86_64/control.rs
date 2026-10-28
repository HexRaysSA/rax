//! Prologue/epilogue, block, and terminator lowering

use crate::smir::lower::x86_64::*;
use std::collections::HashMap;

use crate::smir::ir::flags::{FlagSet, FlagUpdate};
use crate::smir::ir::ops::{
    OpKind, SmirOp, X86AdxKind, X86AluEncoding, X86BlsKind, X86CacheControlKind, X86CountKind,
    X86OpHint, X86RepMode, X86SsePrefix, X86StringKind, X86VecAlign, X86VecMap, X86X87ControlKind,
};
use crate::smir::ir::types::{
    Address, ArchReg, BlockId, Condition, DispSize, FenceKind, FpRoundMode, GuestAddr, MemWidth,
    OpWidth, ShiftOp, SignExtend, SrcOperand, VLaneOp, VReg, VecCmpCond, VecElementType,
    VecUnaryOp, VecWidth, X86Reg,
};
use crate::smir::ir::{CallTarget, SmirBlock, SmirFunction, Terminator, x86_native_replay_spans};

use crate::smir::lower::regalloc::{PhysReg, RegAlloc, RegLocation};
use crate::smir::lower::{
    CodeBuffer, LowerError, LowerResult, RelocKind, RelocTarget, Relocation, SmirLowerer,
    X86_GUEST_APX_ENABLED_OFFSET, X86_GUEST_CALL_FN_OFFSET, X86_GUEST_CPL_OFFSET,
    X86_GUEST_CR0_OFFSET, X86_GUEST_CR4_OFFSET, X86_GUEST_CTX_OFFSET, X86_GUEST_EXIT_PC_OFFSET,
    X86_GUEST_FS_BASE_OFFSET, X86_GUEST_GS_BASE_OFFSET, X86_GUEST_K_OFFSET,
    X86_GUEST_LOAD_FN_OFFSET, X86_GUEST_MXCSR_OFFSET, X86_GUEST_PAIR_LOAD_FN_OFFSET,
    X86_GUEST_PAIR_STORE_FN_OFFSET, X86_GUEST_RFLAGS_OFFSET, X86_GUEST_STORE_FN_OFFSET,
    X86_GUEST_TSC_AUX_OFFSET, X86_GUEST_VEC_LOAD_FN_OFFSET, X86_GUEST_VEC_STORE_FN_OFFSET,
    X86_GUEST_X87_TAG_WORD_OFFSET, X86_GUEST_XCR0_OFFSET, X86_GUEST_XGETBV1_OFFSET,
    X86_HOST_MXCSR_OFFSET, X86_STATE_PTR_AT_RBP,
};

impl X86_64Lowerer {
    /// Emit function prologue
    pub(crate) fn emit_prologue(&mut self) {
        let mut emitter = X86Emitter::new(&mut self.code);

        // PUSH RBP
        emitter.emit_push(PhysReg::Rbp);

        // MOV RBP, RSP
        emitter.emit_mov_rr(PhysReg::Rbp, PhysReg::Rsp, OpWidth::W64);

        // Save callee-saved registers
        for &reg in self.regalloc.callee_saved_used() {
            emitter.emit_push(reg);
        }

        // Allocate stack space for spills
        let frame_size = self.regalloc.frame_size();
        if frame_size > 0 {
            emitter.emit_sub_ri(PhysReg::Rsp, frame_size as i64, OpWidth::W64);
        }
    }

    /// Emit function epilogue
    pub(crate) fn emit_epilogue(&mut self) {
        self.emit_epilogue_with_ret(None);
    }

    pub(crate) fn emit_epilogue_with_ret(&mut self, ret_imm: Option<u16>) {
        // Deallocate the frame with `lea rsp, [rsp + frame]` rather than
        // `mov rsp, rbp`. The block body is guest-controlled and owns all GPRs,
        // so it can overwrite RBP (`mov rbp, imm`, `lea rbp, ...`); restoring
        // RSP from RBP would let the guest pivot the host stack and hijack the
        // `ret`. The frame-size LEA is also flag-preserving (unlike `add`), and
        // it mirrors the prologue's `lea rsp, [rsp - frame]`. The frame size is
        // not final yet, so emit a forced-disp32 placeholder and record it for
        // backpatching once lowering completes.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea_disp(PhysReg::Rsp, PhysReg::Rsp, 0, DispSize::Disp32);
        }
        // The disp32 is the final 4 bytes of the LEA just emitted.
        self.epilogue_stack_patches.push(self.code.position() - 4);

        let mut emitter = X86Emitter::new(&mut self.code);

        // NOTE: callee-saved guest registers are intentionally NOT restored
        // here. A lowered block owns all GPRs (identity-mapped guest state), and
        // the `enter_native` shim preserves the HOST's callee-saved registers.
        // Restoring them here would clobber guest writes to RBX/R12-R15 — the
        // hazard the native differential exposes.

        // POP RBP
        emitter.emit_pop(PhysReg::Rbp);

        // RET
        if let Some(imm) = ret_imm {
            if imm == 0 {
                emitter.emit_ret();
            } else {
                emitter.emit_ret_imm16(imm);
            }
        } else {
            emitter.emit_ret();
        }
    }

    /// Lower a block terminator
    pub(crate) fn lower_terminator(
        &mut self,
        source: BlockId,
        term: &Terminator,
    ) -> Result<(), LowerError> {
        match term {
            Terminator::Branch { target } => {
                if let Some(&resume_pc) = self.native_exit_edges.get(&(source, *target)) {
                    self.emit_native_exit(resume_pc);
                } else {
                    // Record jump to fix up later
                    let jump_offset = self.code.position();
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_jmp_rel32(0); // Placeholder
                    self.pending_jumps
                        .push((jump_offset + 1, *target, RelocKind::PcRel32));
                }
            }

            Terminator::CondBranch {
                cond,
                true_target,
                false_target,
            } => {
                // Determine the native condition for the taken branch. If
                // `lower_block` folded a trailing `TestCondition` (the common
                // guest-Jcc shape), branch directly off the live guest flags
                // with the guest condition — no register is touched. Otherwise
                // fall back to materializing the cond vreg and `test`ing it.
                let taken = if let Some(c) = self.pending_cond.take() {
                    X86Cond::from_condition(c)
                } else {
                    let cond_reg = self.get_reg(*cond)?;
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_test_rr(cond_reg, cond_reg, OpWidth::W64);
                    X86Cond::Ne
                };

                if let Some(&resume_pc) = self.native_exit_edges.get(&(source, *true_target)) {
                    // If the true edge exits, invert the branch to skip over the
                    // inline exit stub when the condition is false.
                    let skip_exit = self.emit_jcc_placeholder(taken.invert());
                    self.emit_native_exit(resume_pc);
                    self.patch_rel32_to_current(skip_exit)?;
                } else {
                    // Jcc<taken> true_target
                    let jnz_offset = self.code.position();
                    {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_jcc_rel32(taken, 0); // Placeholder
                    }
                    self.pending_jumps
                        .push((jnz_offset + 2, *true_target, RelocKind::PcRel32));
                }

                if let Some(&resume_pc) = self.native_exit_edges.get(&(source, *false_target)) {
                    self.emit_native_exit(resume_pc);
                } else {
                    // JMP false_target
                    let jmp_offset = self.code.position();
                    {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_jmp_rel32(0); // Placeholder
                    }
                    self.pending_jumps
                        .push((jmp_offset + 1, *false_target, RelocKind::PcRel32));
                }
            }

            Terminator::IndirectBranch { target, .. } => {
                let target_reg = self.get_reg(*target)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_jmp_reg(target_reg);
            }

            Terminator::IndirectBranchMem { addr, .. } => {
                self.emit_group5_mem(4, addr)?;
            }

            Terminator::Return { .. } => {
                self.emit_epilogue();
            }

            Terminator::Call {
                target,
                continuation,
                ..
            } if self.call_helpers => {
                // Lift-through-calls: run the callee in the interpreter, resume
                // native at `continuation`.
                let call_pc = self.jit_call_site_pc(source, *continuation)?;
                self.emit_jit_call_op(target, *continuation, call_pc)?;
            }

            Terminator::Call {
                target,
                continuation,
                ..
            } => match target {
                CallTarget::GuestAddr(addr) => {
                    let call_pos = self.code.position();
                    let next_rip = if self.pcrel_adjust {
                        self.guest_base as i64 + (call_pos + 5) as i64
                    } else {
                        self.block_guest_pcs
                            .get(continuation)
                            .copied()
                            .unwrap_or(self.guest_base + (call_pos + 5) as u64)
                            as i64
                    };
                    let rel = *addr as i64 - next_rip;
                    if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
                        return Err(LowerError::RelocationOutOfRange {
                            offset: call_pos,
                            target: *addr as usize,
                        });
                    }
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_call_rel32(rel as i32);
                }
                CallTarget::Indirect(reg) => {
                    let target_reg = self.get_reg(*reg)?;
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_call_reg(target_reg);
                }
                CallTarget::IndirectMem(addr) => {
                    self.emit_group5_mem(2, addr)?;
                }
                _ => {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("Call target {:?}", target),
                    });
                }
            },

            Terminator::TailCall { target, .. } => match target {
                CallTarget::GuestAddr(addr) => {
                    let jmp_pos = self.code.position();
                    let next_rip = if self.pcrel_adjust {
                        self.guest_base as i64 + (jmp_pos + 5) as i64
                    } else {
                        self.guest_base as i64 + (jmp_pos + 5) as i64
                    };
                    let rel = *addr as i64 - next_rip;
                    if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
                        return Err(LowerError::RelocationOutOfRange {
                            offset: jmp_pos,
                            target: *addr as usize,
                        });
                    }
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_jmp_rel32(rel as i32);
                }
                CallTarget::Indirect(reg) => {
                    let target_reg = self.get_reg(*reg)?;
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_jmp_reg(target_reg);
                }
                CallTarget::IndirectMem(addr) => {
                    self.emit_group5_mem(4, addr)?;
                }
                _ => {
                    return Err(LowerError::UnsupportedOp {
                        op: format!("TailCall target {:?}", target),
                    });
                }
            },

            Terminator::Unreachable => {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_ud2();
            }

            _ => {
                return Err(LowerError::UnsupportedOp {
                    op: format!("Terminator: {:?}", term),
                });
            }
        }

        Ok(())
    }

    pub(crate) fn lower_block(&mut self, block: &SmirBlock) -> Result<(), LowerError> {
        // Record block offset
        self.block_offsets.insert(block.id, self.code.position());
        self.block_guest_pcs.insert(block.id, block.guest_pc);

        // JIT frontier native-exit stub: return to the trampoline before
        // executing this block's ops/terminator.
        if let Some(&resume_pc) = self.native_exits.get(&block.id) {
            self.emit_native_exit(resume_pc);
            return Ok(());
        }

        // Initialize register allocator for this block
        self.regalloc.begin_block(block);
        let native_replay_spans = x86_native_replay_spans(block, &self.x86_instruction_bytes);

        // Count virtual definitions and uses once. Exact helper-backed fusion
        // validation and lowering are then O(1) per candidate; the complete
        // block pass remains O(N).
        let mut virtual_definitions = HashMap::new();
        let mut virtual_uses = HashMap::new();
        for op in &block.ops {
            for reg in op.kind.dests() {
                if matches!(reg, VReg::Virtual(_)) {
                    *virtual_definitions.entry(reg).or_insert(0usize) += 1;
                }
            }
            for reg in op.kind.source_vregs() {
                if matches!(reg, VReg::Virtual(_)) {
                    *virtual_uses.entry(reg).or_insert(0usize) += 1;
                }
            }
        }

        // Validate before peepholes consume operations so no direct-memory fold
        // can hide a guest RSP/RBP destination or address from the safety guard.
        // Exact helper-backed fusion/stack sequences are validated as units
        // because their virtual/state-backed destinations are intentionally
        // elided.
        let mut validate_idx = 0;
        while validate_idx < block.ops.len() {
            if let Some(span) = native_replay_spans.get(&validate_idx) {
                validate_idx = span.end;
                continue;
            }
            #[cfg(feature = "smir-jit")]
            {
                if self.mem_helpers {
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mmx_scalar_memory_transfer_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mmx_memory_source_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(sequence) =
                        crate::smir::lower::runtime::x86_jit_vex_fp_compare_memory_sequence(
                            block,
                            validate_idx,
                            true,
                            &self.x86_instruction_bytes,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += sequence.consumed;
                        continue;
                    }
                    if let Some(sequence) =
                        crate::smir::lower::runtime::x86_jit_vex_scalar_convert_memory_sequence(
                            block,
                            validate_idx,
                            true,
                            &self.x86_instruction_bytes,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += sequence.consumed;
                        continue;
                    }
                    if let Some(sequence) =
                        crate::smir::lower::runtime::x86_jit_vex_ne_convert_memory_sequence(
                            block,
                            validate_idx,
                            true,
                            &self.x86_instruction_bytes,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += sequence.consumed;
                        continue;
                    }
                    if let Some(sequence) =
                        crate::smir::lower::runtime::x86_jit_vex_fp16_narrow_memory_sequence(
                            block,
                            validate_idx,
                            true,
                            &self.x86_instruction_bytes,
                        )
                    {
                        validate_idx += sequence.consumed;
                        continue;
                    }
                    if let Some(sequence) =
                        crate::smir::lower::runtime::x86_jit_vex_extract_memory_sequence(
                            block,
                            validate_idx,
                            true,
                            &self.x86_instruction_bytes,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += sequence.consumed();
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_vex_scalar_move_memory_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &self.x86_instruction_bytes,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(sequence) =
                        crate::smir::lower::runtime::x86_jit_vex_movntdqa_memory_sequence(
                            block,
                            validate_idx,
                            true,
                            &self.x86_instruction_bytes,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += sequence.consumed;
                        continue;
                    }
                    if let Some(sequence) =
                        crate::smir::lower::runtime::x86_jit_vex_phminposuw_memory_sequence(
                            block,
                            validate_idx,
                            true,
                            &self.x86_instruction_bytes,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += sequence.consumed;
                        continue;
                    }
                    if let Some(sequence) =
                        crate::smir::lower::runtime::x86_jit_vex_packed_abs_memory_sequence(
                            block,
                            validate_idx,
                            true,
                            &self.x86_instruction_bytes,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += sequence.consumed;
                        continue;
                    }
                    if let Some(sequence) =
                        crate::smir::lower::runtime::x86_jit_vex_broadcast_memory_sequence(
                            block,
                            validate_idx,
                            true,
                            &self.x86_instruction_bytes,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += sequence.consumed;
                        continue;
                    }
                    if let Some(sequence) =
                        crate::smir::lower::runtime::x86_jit_vex_packed_extend_memory_sequence(
                            block,
                            validate_idx,
                            true,
                            &self.x86_instruction_bytes,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += sequence.consumed;
                        continue;
                    }
                    if let Some(sequence) =
                        crate::smir::lower::runtime::x86_jit_vex_binary_memory_sequence(
                            block,
                            validate_idx,
                            true,
                            &self.x86_instruction_bytes,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += sequence.consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_shift_rmw_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_unary_rmw_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_alu_rmw_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_cmpccxadd_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &self.x86_instruction_bytes,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_atomic_rmw_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_state_compare_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_push_memory_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_push_flags_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_cmpxchg_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_bit_offset_test_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_bit_offset_update_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_bit_update_rmw_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_alu_source_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_tbm_source_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_cmove_source_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_extend_source_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_movrs_high_byte_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_movrs_state_backed_load_sequence_len(
                            block,
                            validate_idx,
                            true,
                            self.x86_instruction_bytes
                                .get(&(block.id, block.ops[validate_idx].guest_pc)),
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_movbe_memory_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_widening_mul_source_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_mulx_source_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_bmi_source_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_bmi2_shift_source_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if self.jit_fault_deopt_guards {
                        if let Some(consumed) =
                            crate::smir::lower::runtime::x86_jit_mem_unsigned_div_source_sequence_len(
                                block,
                                validate_idx,
                                true,
                                &virtual_definitions,
                                &virtual_uses,
                            )
                        {
                            validate_idx += consumed;
                            continue;
                        }
                        if let Some(consumed) =
                            crate::smir::lower::runtime::x86_jit_mem_signed_div_source_sequence_len(
                                block,
                                validate_idx,
                                true,
                                &virtual_definitions,
                                &virtual_uses,
                            )
                        {
                            validate_idx += consumed;
                            continue;
                        }
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_bit_test_source_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_bit_scan_source_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_mem_count_source_sequence_len(
                            block,
                            validate_idx,
                            true,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if crate::smir::lower::runtime::x86_mem_crc32_pair_valid(
                        block,
                        validate_idx,
                        true,
                        &virtual_definitions,
                        &virtual_uses,
                    ) {
                        validate_idx += 2;
                        continue;
                    }
                    if let Some(consumed) = crate::smir::lower::runtime::x86_jit_pop2_sequence_len(
                        block,
                        validate_idx,
                        true,
                        &virtual_definitions,
                        &virtual_uses,
                    ) {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) = crate::smir::lower::runtime::x86_jit_push2_sequence_len(
                        block,
                        validate_idx,
                        true,
                        &virtual_definitions,
                        &virtual_uses,
                    ) {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) = crate::smir::lower::runtime::x86_jit_pop_sequence_len(
                        block,
                        validate_idx,
                        true,
                        &virtual_definitions,
                        &virtual_uses,
                    ) {
                        validate_idx += consumed;
                        continue;
                    }
                }
                if self.jit_fault_deopt_guards {
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_high_byte_unsigned_div_source_sequence_len(
                            block,
                            validate_idx,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if let Some(consumed) =
                        crate::smir::lower::runtime::x86_jit_high_byte_signed_div_source_sequence_len(
                            block,
                            validate_idx,
                            &virtual_definitions,
                            &virtual_uses,
                        )
                    {
                        validate_idx += consumed;
                        continue;
                    }
                    if crate::smir::lower::runtime::x86_jit_unsigned_div_register_shape_valid(
                        &block.ops[validate_idx],
                    ) {
                        validate_idx += 1;
                        continue;
                    }
                    if crate::smir::lower::runtime::x86_jit_signed_div_register_shape_valid(
                        &block.ops[validate_idx],
                    ) {
                        validate_idx += 1;
                        continue;
                    }
                }
            }
            let op = &block.ops[validate_idx];
            Self::ensure_native_stack_dests_safe(op, self.mem_helpers)?;
            Self::ensure_native_stack_memory_safe(op, self.mem_helpers)?;
            validate_idx += 1;
        }

        let mut end_idx = block.ops.len();

        // Fold a trailing `TestCondition` that exists only to feed this block's
        // `CondBranch` into a direct `Jcc<cond>` off live flags. The x86 lifter
        // emits, for a guest Jcc, `TestCondition { dst, cond }` as the block's
        // last op plus `CondBranch { cond: dst, .. }`. Materializing `dst` into
        // a host register would clobber guest state under the identity reg map
        // (no free scratch GPR), so skip the op and let `lower_terminator` read
        // the flags the block body's last flag-setting op (e.g. `dec`) produced.
        self.pending_cond = None;
        if let Terminator::CondBranch { cond, .. } = &block.terminator {
            if end_idx > 0 {
                if let OpKind::TestCondition {
                    dst,
                    cond: guest_cond,
                } = &block.ops[end_idx - 1].kind
                {
                    if dst == cond {
                        self.pending_cond = Some(*guest_cond);
                        end_idx -= 1;
                    }
                }
            }
        }

        // Lower each operation
        let mut idx = 0;
        while idx < end_idx {
            self.regalloc.set_current_idx(idx);
            if let Some(span) = native_replay_spans.get(&idx) {
                self.emit_native_replay_span(span)?;
                idx = span.end;
                continue;
            }
            #[cfg(feature = "smir-jit")]
            if self.emit_x86_io_if_present(block, idx)? {
                return Ok(());
            }
            #[cfg(feature = "smir-jit")]
            if self.emit_x86_enter_if_present(block, idx)? {
                idx += 1;
                continue;
            }
            #[cfg(feature = "smir-jit")]
            if self.emit_x86_leave_if_present(block, idx)? {
                idx += 1;
                continue;
            }
            #[cfg(feature = "smir-jit")]
            if matches!(block.ops[idx].kind, OpKind::X86StackFlags(..)) {
                if self.emit_x86_stack_flags(block, idx)? {
                    // POPF supplies a complete RFLAGS override to the runtime
                    // bridge, so its successful path leaves at `next_pc`.
                    return Ok(());
                }
                // PUSHF preserves flags and commits guest RSP through state, so
                // successful execution can continue inside the native region.
                idx += 1;
                continue;
            }
            if self.emit_xsetbv_if_present(block, idx)? {
                // Both success and fault paths return through an exit stub.
                // No following op or terminator in this block is reachable.
                return Ok(());
            }
            if matches!(block.ops[idx].kind, OpKind::X86WriteControl { .. }) {
                self.emit_x86_write_control(&block.ops[idx])?;
                // Control-state changes terminate native execution.
                return Ok(());
            }
            if matches!(block.ops[idx].kind, OpKind::X86DescriptorTableLoad(..)) {
                self.emit_x86_descriptor_table_load(&block.ops[idx])?;
                // Descriptor-state changes terminate native execution.
                return Ok(());
            }
            if matches!(block.ops[idx].kind, OpKind::X86Invlpg(..)) {
                self.emit_x86_invlpg(&block.ops[idx])?;
                // Translation invalidation is a serializing frontier.
                return Ok(());
            }
            if matches!(block.ops[idx].kind, OpKind::X86Invpcid(..)) {
                self.emit_x86_invpcid(&block.ops[idx])?;
                // Process-context invalidation is a serializing frontier.
                return Ok(());
            }
            if matches!(block.ops[idx].kind, OpKind::X86SystemSelectorLoad(..)) {
                self.emit_x86_system_selector_load(&block.ops[idx])?;
                // LLDT/LTR serialize; MOV Sreg, POP FS/GS, and LSS/LFS/LGS
                // still change hidden segment state. Every success and fault
                // path leaves through an exact exit stub before any later
                // guest op.
                return Ok(());
            }
            if matches!(block.ops[idx].kind, OpKind::X86LoadMxcsr { .. }) {
                self.emit_x86_load_mxcsr(&block.ops[idx])?;
                // A valid load commits MXCSR and leaves at next_pc; every
                // fault or feature rejection leaves at the original guest PC.
                // No later operation or terminator in this block is reachable.
                return Ok(());
            }
            if matches!(block.ops[idx].kind, OpKind::X86FarJump(..)) {
                if idx + 1 != block.ops.len() || !x86_far_jump_terminal_shape_valid(block) {
                    return Err(LowerError::InvalidOperand {
                        op: "X86FarJump".to_string(),
                        operand: "must be the sole owner of a matching terminal indirect branch"
                            .to_string(),
                    });
                }
                self.emit_x86_far_jump(&block.ops[idx])?;
                // The helper supplies the dynamic target and both success and
                // deoptimization paths return before the generic indirect term.
                return Ok(());
            }
            if matches!(block.ops[idx].kind, OpKind::X86FarCall(..)) {
                if idx + 1 != block.ops.len() || !x86_far_call_terminal_shape_valid(block) {
                    return Err(LowerError::InvalidOperand {
                        op: "X86FarCall".to_string(),
                        operand: "must be the sole owner of a matching terminal indirect branch"
                            .to_string(),
                    });
                }
                self.emit_x86_far_call(&block.ops[idx])?;
                // The helper owns return-frame construction and the dynamic
                // target; both success and replay paths return before the term.
                return Ok(());
            }
            if matches!(block.ops[idx].kind, OpKind::X86FarReturn(..)) {
                if idx + 1 != block.ops.len() || !x86_far_return_terminal_shape_valid(block) {
                    return Err(LowerError::InvalidOperand {
                        op: "X86FarReturn".to_string(),
                        operand: "must be the sole owner of a matching terminal indirect branch"
                            .to_string(),
                    });
                }
                self.emit_x86_far_return(&block.ops[idx])?;
                // The helper owns the return-frame reads and dynamic target;
                // both success and replay paths return before the terminator.
                return Ok(());
            }
            if matches!(block.ops[idx].kind, OpKind::X86FastSystemTransfer(..)) {
                if idx + 1 != block.ops.len()
                    || !x86_fast_system_transfer_terminal_shape_valid(block)
                {
                    return Err(LowerError::InvalidOperand {
                        op: "X86FastSystemTransfer".to_string(),
                        operand: "must be the sole owner of a matching terminal indirect branch"
                            .to_string(),
                    });
                }
                self.emit_x86_fast_system_transfer(&block.ops[idx])?;
                // The helper supplies the dynamic target and both success and
                // replay paths return before generic indirect lowering.
                return Ok(());
            }
            if matches!(&block.ops[idx].kind, OpKind::X86Msr(msr) if msr.write) {
                self.emit_x86_msr(&block.ops[idx])?;
                // Successful WRMSR changes architectural admission state and
                // both success/fault paths leave through exact exit stubs.
                return Ok(());
            }
            #[cfg(feature = "smir-jit")]
            if let Some(consumed) =
                self.try_lower_jit_ah_flags(block, idx, &virtual_definitions, &virtual_uses)?
            {
                idx += consumed;
                continue;
            }
            // The memory-fusion peepholes emit direct host-pointer accesses,
            // which are invalid under the JIT's MMU helper-call mode. In that
            // mode each Load/Store is lowered individually via the helper path
            // (see `emit_jit_mem_op`). The helper-backed scalar, vector-source,
            // XMM/MMX masked, and CRC fusions below are explicitly restricted
            // to that mode.
            if self.mem_helpers {
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_exact_vector_memory_replay(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_evex_gfni_affine_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_gfni_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_duplicate_move_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_estimate_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_fp_flag_compare_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_sqrt_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_packed_convert_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_ne_convert_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) =
                    self.try_lower_jit_vex_fp16_narrow_memory_destination(block, idx)?
                {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_round_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_scalar_convert_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_extract_memory_destination(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_scalar_move_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_fp_compare_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_fp_dot_product_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_mpsadbw_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_scalar_insert_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_alignr_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_fp_shuffle_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_immediate_blend_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_immediate_permute_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_cross_lane_128_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_variable_blend_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_variable_permute_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_lane_shuffle_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_aes_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_movntdqa_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_phminposuw_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_packed_abs_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_broadcast_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_packed_extend_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_ptest_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_vex_binary_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) =
                    self.try_lower_jit_maskmovdqu(block, idx, &virtual_definitions, &virtual_uses)?
                {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mmx_maskmovq(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mmx_scalar_memory_transfer(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mmx_memory_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mem_shift_rmw(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mem_unary_rmw(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) =
                    self.try_lower_jit_mem_alu_rmw(block, idx, &virtual_definitions, &virtual_uses)?
                {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_cmpccxadd(block, idx)? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mem_atomic_rmw(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mem_state_compare(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) =
                    self.try_lower_jit_push_memory(block, idx, &virtual_definitions, &virtual_uses)?
                {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) =
                    self.try_lower_jit_push_flags(block, idx, &virtual_definitions, &virtual_uses)?
                {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) =
                    self.try_lower_jit_cmpxchg(block, idx, &virtual_definitions, &virtual_uses)?
                {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mem_bit_offset_test(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mem_bit_offset_update(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mem_bit_update_rmw(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mem_alu_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mem_tbm_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) =
                    self.try_lower_jit_mem_cmove(block, idx, &virtual_definitions, &virtual_uses)?
                {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) =
                    self.try_lower_jit_mem_extend(block, idx, &virtual_definitions, &virtual_uses)?
                {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_movrs_high_byte(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_movrs_state_backed(block, idx)? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_movbe_memory(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mem_widening_mul_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mem_mulx_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mem_bmi_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mem_bmi2_shift_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mem_bit_test_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mem_bit_scan_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                #[cfg(feature = "smir-jit")]
                if let Some(consumed) = self.try_lower_jit_mem_count_source(
                    block,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) =
                    self.try_lower_jit_pop2(&block.ops, idx, &virtual_definitions, &virtual_uses)?
                {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) =
                    self.try_lower_jit_push2(&block.ops, idx, &virtual_definitions, &virtual_uses)?
                {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) =
                    self.try_lower_jit_pop(&block.ops, idx, &virtual_definitions, &virtual_uses)?
                {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) =
                    self.try_lower_jit_push(&block.ops, idx, &virtual_definitions, &virtual_uses)?
                {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) = self.try_lower_jit_mem_crc32c(
                    &block.ops,
                    idx,
                    &virtual_definitions,
                    &virtual_uses,
                )? {
                    idx += consumed;
                    continue;
                }
            } else {
                if let Some(consumed) = self.try_lower_mem_extend(&block.ops, idx)? {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) = self.try_lower_vmem_binop(&block.ops, idx)? {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) = self.try_lower_mem_shift(&block.ops, idx)? {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) = self.try_lower_mem_alu(&block.ops, idx)? {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) = self.try_lower_mem_imul(&block.ops, idx)? {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) = self.try_lower_mem_group3(&block.ops, idx)? {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) = self.try_lower_mem_shld(&block.ops, idx)? {
                    idx += consumed;
                    continue;
                }
                if let Some(consumed) = self.try_lower_push_pop(&block.ops, idx)? {
                    idx += consumed;
                    continue;
                }
            }
            #[cfg(feature = "smir-jit")]
            if let Some(consumed) =
                self.try_lower_jit_unsigned_div(block, idx, &virtual_definitions, &virtual_uses)?
            {
                idx += consumed;
                continue;
            }
            #[cfg(feature = "smir-jit")]
            if let Some(consumed) =
                self.try_lower_jit_signed_div(block, idx, &virtual_definitions, &virtual_uses)?
            {
                idx += consumed;
                continue;
            }
            self.lower_op(&block.ops[idx])?;
            idx += 1;
        }

        // CALL retires in its helper only after the return-address push.
        if !matches!(block.terminator, Terminator::Call { .. }) {
            self.emit_x86_retirement();
        }
        // Lower terminator
        self.lower_terminator(block.id, &block.terminator)?;

        Ok(())
    }
}
