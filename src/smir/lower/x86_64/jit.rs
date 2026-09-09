//! JIT lowering: native exits, memory-op RMW fast paths, relocation patching

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
use crate::smir::ir::{
    CallTarget, SmirBlock, SmirFunction, Terminator, X86InstructionBytes,
    x86_evex_native_replay_spans,
};

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
    X86_GUEST_ZMM_OFFSET, X86_HOST_MXCSR_OFFSET, X86_STATE_PTR_AT_RBP,
};

impl X86_64Lowerer {
    /// Mark blocks as JIT native-exit stubs (block-id ⇒ resume guest PC). Call
    /// after `new()` and before `lower_function`. Each marked block lowers to an
    /// exit stub that records `exit_pc` and returns; its ops/terminator are not
    /// emitted. Requires the block to be reachable only as an exit edge.
    pub fn set_native_exits(&mut self, exits: std::collections::HashMap<BlockId, u64>) {
        self.native_exits = exits;
    }

    /// Mark individual branch edges as JIT native-exit stubs. Call after `new()`
    /// and before `lower_function`.
    pub fn set_native_exit_edges(
        &mut self,
        exits: std::collections::HashMap<(BlockId, BlockId), u64>,
    ) {
        self.native_exit_edges = exits;
    }

    /// Enable precise JIT-only guarded exits for native instructions whose
    /// host fault conditions must be handled by the guest interpreter.
    pub fn set_jit_fault_deopt_guards(&mut self, on: bool) {
        self.jit_fault_deopt_guards = on;
    }

    pub(crate) fn emit_jcc_placeholder(&mut self, cond: X86Cond) -> usize {
        let off = self.code.position();
        let mut emitter = X86Emitter::new(&mut self.code);
        emitter.emit_jcc_rel32(cond, 0);
        off + 2
    }

    pub(crate) fn patch_rel32_to_current(&mut self, offset: usize) -> Result<(), LowerError> {
        let target = self.code.position();
        let rel = target as i64 - offset as i64 - 4;
        if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
            return Err(LowerError::RelocationOutOfRange { offset, target });
        }
        self.code.patch_i32(offset, rel as i32);
        Ok(())
    }

    pub(crate) fn emit_native_exit(&mut self, resume_pc: u64) {
        // JIT native-exit stub: record the resume guest PC into `exit_pc` and
        // return to the trampoline. The state pointer lives at
        // [rbp+X86_STATE_PTR_AT_RBP] in the enter_native frame; borrow RAX as
        // scratch via push/pop so no guest register is disturbed.
        self.code.emit_u8(0x50); // push rax
        // mov rax, [rbp+state_ptr]
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x8B);
        self.code.emit_u8(0x45);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8);
        // mov dword [rax+exit_pc], resume_pc<low32>   (C7 80 <disp32> <imm32>)
        self.code.emit_u8(0xC7);
        self.code.emit_u8(0x80);
        self.code.emit_u32(X86_GUEST_EXIT_PC_OFFSET as u32);
        self.code.emit_u32(resume_pc as u32);
        // mov dword [rax+exit_pc+4], resume_pc<high32>
        self.code.emit_u8(0xC7);
        self.code.emit_u8(0x80);
        self.code.emit_u32((X86_GUEST_EXIT_PC_OFFSET + 4) as u32);
        self.code.emit_u32((resume_pc >> 32) as u32);
        self.code.emit_u8(0x58); // pop rax
        self.emit_epilogue_with_ret(None);
    }

    /// x86 encoding (0..31) of an architectural GPR VReg, or Err for a
    /// non-arch / non-GPR operand (so the region bails to the interpreter).
    pub(crate) fn jit_arch_enc(&self, v: VReg) -> Result<u8, LowerError> {
        use crate::smir::ir::types::ArchReg;
        match v {
            VReg::Arch(ArchReg::X86(r)) => r.gpr_index().ok_or_else(|| LowerError::UnsupportedOp {
                op: "jit-mem: non-GPR operand".to_string(),
            }),
            _ => Err(LowerError::UnsupportedOp {
                op: "jit-mem: non-arch operand".to_string(),
            }),
        }
    }

    /// Lower one architectural XMM/YMM/ZMM memory transfer through the vCPU
    /// MMU. The complete vector file is published before the helper call because
    /// SysV permits the callee to clobber every vector/opmask register. A failed
    /// helper leaves the addressed ZMM slot unchanged and exits at `guest_pc`,
    /// allowing the interpreter to deliver the precise memory exception.
    pub(crate) fn emit_jit_vector_mem_op(
        &mut self,
        guest_pc: u64,
        is_load: bool,
        vector: VReg,
        addr: &Address,
        width: VecWidth,
        hint: Option<X86OpHint>,
    ) -> Result<(), LowerError> {
        let index = Self::x86_vector_state_index(vector, width).ok_or_else(|| {
            LowerError::InvalidOperand {
                op: if is_load { "VLoad" } else { "VStore" }.to_string(),
                operand: "architectural vector register class must match transfer width"
                    .to_string(),
            }
        })?;
        let size = match width {
            VecWidth::V128 => 16u32,
            VecWidth::V256 => 32,
            VecWidth::V512 => 64,
            _ => {
                return Err(LowerError::InvalidOperand {
                    op: if is_load { "VLoad" } else { "VStore" }.to_string(),
                    operand: format!("unsupported vector-memory width {width:?}"),
                });
            }
        };
        // Legacy SSE loads update only XMM[127:0]. VEX/EVEX loads clear every
        // architectural bit above the encoded vector length. The helper starts
        // from the old slot only for the legacy form, then commits atomically
        // after the complete MMU read succeeds.
        let zero_upper = is_load && !matches!(hint, Some(X86OpHint::SseMov { .. }));

        self.emit_jit_vector_mem_helper(guest_pc, is_load, index, addr, size, zero_upper, true)
    }

    /// Store the low scalar lane of an architectural XMM slot through the x86
    /// MMU helper. State-backed-only regions read the marshalled slot directly;
    /// a region that also executes native vector ops publishes/reloads the host
    /// vector file around the helper through `preserve_vector_mem_helpers`.
    pub(crate) fn emit_jit_xmm_state_store_op(
        &mut self,
        guest_pc: u64,
        vector: VReg,
        addr: &Address,
        width: MemWidth,
    ) -> Result<(), LowerError> {
        let VReg::Arch(ArchReg::X86(X86Reg::Xmm(index @ 0..=15))) = vector else {
            return Err(LowerError::InvalidOperand {
                op: "X86Sse4aMovntStore".to_string(),
                operand: "source must be an encodable architectural XMM register".to_string(),
            });
        };
        let size = match width {
            MemWidth::B4 => 4,
            MemWidth::B8 => 8,
            _ => {
                return Err(LowerError::InvalidOperand {
                    op: "X86Sse4aMovntStore".to_string(),
                    operand: "width must be 4 or 8 bytes".to_string(),
                });
            }
        };
        if !self.mem_helpers {
            return Err(LowerError::UnsupportedOp {
                op: "X86Sse4aMovntStore requires JIT memory helpers".to_string(),
            });
        }

        self.emit_jit_vector_mem_helper(
            guest_pc,
            false,
            index,
            addr,
            size,
            false,
            self.preserve_vector_mem_helpers,
        )
    }

    pub(crate) fn emit_jit_vector_mem_helper(
        &mut self,
        guest_pc: u64,
        is_load: bool,
        index: u8,
        addr: &Address,
        size: u32,
        zero_upper: bool,
        preserve_vectors: bool,
    ) -> Result<(), LowerError> {
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq; stack remains 16-byte aligned
        self.emit_spill_legacy_gprs_to_state_from_rax(8);
        self.emit_helper_call_state(PhysReg::Rax, true, preserve_vectors);
        self.emit_x86_state_address_rsi(addr)?;

        self.code.emit_u8(0x48);
        self.code.emit_u8(0x89);
        self.code.emit_u8(0xC7); // mov rdi, rax (GuestRegs state)
        self.code.emit_u8(0xBA); // mov edx, vector index
        self.code.emit_u32(u32::from(index));
        self.code.emit_u8(0xB9); // mov ecx, byte size
        self.code.emit_u32(size);
        if is_load {
            self.code.emit_u8(0x41);
            self.code.emit_u8(0xB8); // mov r8d, zero_upper
            self.code.emit_u32(u32::from(zero_upper));
        }
        self.code.emit_u8(0xFF);
        self.code.emit_u8(0x90); // call qword [rax+helper]
        self.code.emit_u32(if is_load {
            X86_GUEST_VEC_LOAD_FN_OFFSET as u32
        } else {
            X86_GUEST_VEC_STORE_FN_OFFSET as u32
        });

        self.code.emit_u8(0x48);
        self.code.emit_u8(0x8B);
        self.code.emit_u8(0x4D);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x85);
        self.code.emit_u8(0xC0); // test rax,rax
        let fault = self.emit_jcc_placeholder(X86Cond::E);

        self.emit_helper_call_state(PhysReg::Rcx, false, preserve_vectors);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq
        self.emit_flag_preserving_stack_pop8();
        self.code.emit_u8(0xE9);
        let done = self.code.position();
        self.code.emit_u32(0);

        self.patch_rel32_to_current(fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, preserve_vectors);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(guest_pc);

        self.patch_rel32_to_current(done)?;
        Ok(())
    }

    /// Fuse the exact fault-precise memory-destination unary sequence emitted
    /// by the x86 lifter. The helper-backed load and store surround a native
    /// scratch-RAX computation. Flag-writing operations preserve the incoming
    /// flags for the speculative compute and replay them only after a
    /// successful store; `NOT` is intrinsically flag-neutral and has no replay.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn try_lower_jit_mem_unary_rmw(
        &mut self,
        block: &SmirBlock,
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(consumed) = crate::smir::lower::runtime::x86_jit_mem_unary_rmw_sequence_len(
            block,
            idx,
            true,
            virtual_definitions,
            virtual_uses,
        ) else {
            return Ok(None);
        };

        let load = &block.ops[idx];
        let (addr, mem_width) = match &load.kind {
            OpKind::Load {
                addr,
                width,
                sign: SignExtend::Zero,
                ..
            } => (addr, *width),
            _ => unreachable!("validated scalar unary RMW starts with Load"),
        };
        let width = mem_width
            .to_op_width()
            .expect("validated scalar unary RMW width has an integer width");
        let tag = match &block.ops[idx + 1].kind {
            OpKind::Not { .. } => 0,
            OpKind::Neg { .. } => 1,
            OpKind::Inc { .. } => 2,
            OpKind::Dec { .. } => 3,
            _ => unreachable!("validated scalar unary RMW consumer"),
        };

        // Four 8-byte caller slots retain the original memory value, computed
        // store value, one alignment word, and complete architectural RAX.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -32);
            emitter.emit_mov_mr(PhysReg::Rsp, 24, PhysReg::Rax, OpWidth::W64);
        }
        self.emit_jit_mem_op(
            load.guest_pc,
            true,
            None,
            Some(16),
            None,
            None,
            None,
            addr,
            mem_width,
            SignExtend::Zero,
            32,
        )?;

        // Compute the value to store. NEG/INC/DEC are wrapped so a later store
        // fault observes the complete incoming flags; NOT does not alter flags.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 0, width);
        }
        if tag != 0 {
            self.code.emit_u8(0x9C); // pushfq
        }
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            match tag {
                0 => emitter.emit_not(PhysReg::Rax, width),
                1 => emitter.emit_neg(PhysReg::Rax, width),
                2 => emitter.emit_inc(PhysReg::Rax, width),
                3 => emitter.emit_dec(PhysReg::Rax, width),
                _ => unreachable!("validated scalar unary RMW tag"),
            }
        }
        if tag != 0 {
            self.code.emit_u8(0x9D); // popfq
        }
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_mr(PhysReg::Rsp, 8, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
        }

        self.emit_jit_mem_op(
            load.guest_pc,
            false,
            None,
            None,
            None,
            None,
            Some(24),
            addr,
            mem_width,
            SignExtend::Zero,
            32,
        )?;

        // A successful flagged operation replays on the original operand.
        // INC/DEC naturally retain the incoming CF; MOV/LEA cleanup is neutral.
        // The three-operation form publishes no architectural flags at all
        // (optimization proved them dead) and therefore has no replay.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            if tag != 0 && consumed == 4 {
                emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 0, width);
                match tag {
                    1 => emitter.emit_neg(PhysReg::Rax, width),
                    2 => emitter.emit_inc(PhysReg::Rax, width),
                    3 => emitter.emit_dec(PhysReg::Rax, width),
                    _ => unreachable!("validated flagged scalar unary RMW tag"),
                }
            }
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 32);
        }
        Ok(Some(consumed))
    }

    /// Merge selected incoming status bits into a native replay image at
    /// `[rsp]`, optionally clearing deterministic undefined outputs. The caller
    /// has already pushed the native RFLAGS image, so its saved incoming image
    /// is at caller-frame offset 16 + the active 8-byte stack slot = 24.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn emit_merge_jit_shift_status(&mut self, preserve_rflags: i64, clear_rflags: i64) {
        let mut emitter = X86Emitter::new(&mut self.code);
        if preserve_rflags != 0 {
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
            emitter.emit_and_ri(PhysReg::Rax, preserve_rflags, OpWidth::W64);
            emitter.emit_alu_mi_disp(
                4,
                PhysReg::Rsp,
                0,
                DispSize::Auto,
                !preserve_rflags,
                OpWidth::W64,
            );
            emitter.emit_alu_mem_disp(
                0x08,
                PhysReg::Rax,
                PhysReg::Rsp,
                0,
                DispSize::Auto,
                OpWidth::W64,
                X86AluEncoding::RmReg,
            );
        }
        if clear_rflags != 0 {
            emitter.emit_alu_mi_disp(
                4,
                PhysReg::Rsp,
                0,
                DispSize::Auto,
                !clear_rflags,
                OpWidth::W64,
            );
        }
    }

    /// Merge the deterministic count-equals-width SHL/SHR status image. The
    /// final PUSHFQ places native replay flags at [RSP], the original
    /// zero-extended memory operand at [RSP+8], and incoming flags at [RSP+24].
    /// AF is preserved, OF is cleared, and CF is reconstructed from the last
    /// original bit shifted out instead of relying on an architecturally
    /// undefined native CF result.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn emit_merge_jit_shift_boundary_cf(&mut self, kind: ShiftRegOp, width: OpWidth) {
        self.emit_merge_jit_shift_status(1 << 4, 1 << 11);

        let boundary_bit = match kind {
            ShiftRegOp::Shl => 0,
            ShiftRegOp::Shr => width.bits() - 1,
            _ => unreachable!("boundary CF reconstruction is only valid for SHL/SHR"),
        };
        let mut emitter = X86Emitter::new(&mut self.code);
        emitter.emit_alu_mi_disp(4, PhysReg::Rsp, 0, DispSize::Auto, !1, OpWidth::W64);
        emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 8, OpWidth::W64);
        if boundary_bit != 0 {
            emitter.emit_shr_ri(PhysReg::Rax, boundary_bit as u8, OpWidth::W64);
        }
        emitter.emit_and_ri(PhysReg::Rax, 1, OpWidth::W64);
        emitter.emit_alu_mem_disp(
            0x08,
            PhysReg::Rax,
            PhysReg::Rsp,
            0,
            DispSize::Auto,
            OpWidth::W64,
            X86AluEncoding::RmReg,
        );
    }

    /// Fuse an exact fault-precise memory-destination shift/rotate sequence.
    /// The speculative scratch-RAX operation is wrapped by PUSHFQ/POPFQ, so
    /// store faults retain every incoming flag; only a successful store reaches
    /// the native replay. A masked RFLAGS merge then implements the interpreter's
    /// deterministic policy for architecturally undefined status outputs.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn try_lower_jit_mem_shift_rmw(
        &mut self,
        block: &SmirBlock,
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(consumed) = crate::smir::lower::runtime::x86_jit_mem_shift_rmw_sequence_len(
            block,
            idx,
            true,
            virtual_definitions,
            virtual_uses,
        ) else {
            return Ok(None);
        };

        let load = &block.ops[idx];
        let (addr, mem_width) = match &load.kind {
            OpKind::Load {
                addr,
                width,
                sign: SignExtend::Zero,
                ..
            } => (addr, *width),
            _ => unreachable!("validated scalar shift RMW starts with Load"),
        };
        let width = mem_width
            .to_op_width()
            .expect("validated scalar shift RMW width has an integer width");
        let (kind, amount) = match &block.ops[idx + 1].kind {
            OpKind::Rol { amount, .. } => (ShiftRegOp::Rol, amount),
            OpKind::Ror { amount, .. } => (ShiftRegOp::Ror, amount),
            OpKind::Rcl { amount, .. } => (ShiftRegOp::Rcl, amount),
            OpKind::Rcr { amount, .. } => (ShiftRegOp::Rcr, amount),
            OpKind::Shl { amount, .. } => (ShiftRegOp::Shl, amount),
            OpKind::Shr { amount, .. } => (ShiftRegOp::Shr, amount),
            OpKind::Sar { amount, .. } => (ShiftRegOp::Sar, amount),
            _ => unreachable!("validated scalar shift RMW consumer"),
        };
        let raw_count = match amount {
            SrcOperand::Imm(value) => Some(*value as u8),
            SrcOperand::Reg(VReg::Arch(ArchReg::X86(X86Reg::Rcx))) => None,
            _ => unreachable!("validated scalar shift RMW count"),
        };
        let count_mask = if width == OpWidth::W64 { 0x3f } else { 0x1f };
        const X86_STATUS_RFLAGS: i64 = 0x08D5;
        const ROTATE_UNCHANGED_RFLAGS: i64 = 0x00D4;
        enum StatusMerge {
            Static {
                preserve_rflags: i64,
                clear_rflags: i64,
            },
            BoundaryCf,
            Dynamic,
        }
        let status_merge = match raw_count {
            None => StatusMerge::Dynamic,
            Some(raw_count) => {
                let count = raw_count & count_mask;
                if count == 0 {
                    StatusMerge::Static {
                        preserve_rflags: X86_STATUS_RFLAGS,
                        clear_rflags: 0,
                    }
                } else {
                    match kind {
                        ShiftRegOp::Rol | ShiftRegOp::Ror | ShiftRegOp::Rcl | ShiftRegOp::Rcr => {
                            StatusMerge::Static {
                                preserve_rflags: ROTATE_UNCHANGED_RFLAGS
                                    | if count == 1 { 0 } else { 1 << 11 },
                                clear_rflags: 0,
                            }
                        }
                        ShiftRegOp::Shl | ShiftRegOp::Shr if u32::from(count) == width.bits() => {
                            StatusMerge::BoundaryCf
                        }
                        ShiftRegOp::Shl | ShiftRegOp::Shr if u32::from(count) > width.bits() => {
                            StatusMerge::Static {
                                preserve_rflags: 1 << 4,
                                clear_rflags: 1 | (1 << 11),
                            }
                        }
                        ShiftRegOp::Shl | ShiftRegOp::Shr | ShiftRegOp::Sar => {
                            StatusMerge::Static {
                                preserve_rflags: 1 << 4,
                                clear_rflags: if count == 1 { 0 } else { 1 << 11 },
                            }
                        }
                    }
                }
            }
        };

        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -32);
            emitter.emit_mov_mr(PhysReg::Rsp, 24, PhysReg::Rax, OpWidth::W64);
            // Capture the incoming status image before either helper. RAX is
            // restored before its coherent GuestRegs snapshot is published.
            emitter.code.emit_u8(0x9C); // pushfq
            emitter.emit_pop(PhysReg::Rax);
            emitter.emit_mov_mr(PhysReg::Rsp, 16, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
        }
        self.emit_jit_mem_op(
            load.guest_pc,
            true,
            None,
            Some(16),
            None,
            None,
            None,
            addr,
            mem_width,
            SignExtend::Zero,
            32,
        )?;

        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 0, width);
        }
        self.code.emit_u8(0x9C); // pushfq
        if let Some(raw_count) = raw_count {
            self.emit_shift_reg_imm(kind, PhysReg::Rax, raw_count, width);
        } else {
            self.emit_shift_reg_cl(kind, PhysReg::Rax, width);
        }
        self.code.emit_u8(0x9D); // popfq
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_mr(PhysReg::Rsp, 8, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
        }

        self.emit_jit_mem_op(
            load.guest_pc,
            false,
            None,
            None,
            None,
            None,
            Some(24),
            addr,
            mem_width,
            SignExtend::Zero,
            32,
        )?;

        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 0, width);
        }
        if let Some(raw_count) = raw_count {
            self.emit_shift_reg_imm(kind, PhysReg::Rax, raw_count, width);
        } else {
            self.emit_shift_reg_cl(kind, PhysReg::Rax, width);
        }

        // Keep the native replay image on the stack while scratch RAX selects
        // the exact incoming-bit policy. The branch tests may change live host
        // flags, but every path edits the saved image and converges at POPFQ.
        self.code.emit_u8(0x9C); // pushfq: native replay flags
        match status_merge {
            StatusMerge::Static {
                preserve_rflags,
                clear_rflags,
            } => self.emit_merge_jit_shift_status(preserve_rflags, clear_rflags),
            StatusMerge::BoundaryCf => self.emit_merge_jit_shift_boundary_cf(kind, width),
            StatusMerge::Dynamic => {
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_mov_rr(PhysReg::Rax, PhysReg::Rcx, OpWidth::W64);
                    emitter.emit_and_ri(PhysReg::Rax, i64::from(count_mask), OpWidth::W64);
                    emitter.emit_test_rr(PhysReg::Rax, PhysReg::Rax, OpWidth::W64);
                }
                let count_zero = self.emit_jcc_placeholder(X86Cond::E);
                {
                    let mut emitter = X86Emitter::new(&mut self.code);
                    emitter.emit_cmp_ri(PhysReg::Rax, 1, OpWidth::W64);
                }
                let count_one = self.emit_jcc_placeholder(X86Cond::E);
                let subword_logical_shift = matches!(kind, ShiftRegOp::Shl | ShiftRegOp::Shr)
                    && matches!(width, OpWidth::W8 | OpWidth::W16);
                let (count_boundary, count_oversized) = if subword_logical_shift {
                    {
                        let mut emitter = X86Emitter::new(&mut self.code);
                        emitter.emit_cmp_ri(PhysReg::Rax, i64::from(width.bits()), OpWidth::W64);
                    }
                    (
                        Some(self.emit_jcc_placeholder(X86Cond::E)),
                        Some(self.emit_jcc_placeholder(X86Cond::A)),
                    )
                } else {
                    (None, None)
                };

                let (one_preserve, multi_preserve, multi_clear) = match kind {
                    ShiftRegOp::Rol | ShiftRegOp::Ror | ShiftRegOp::Rcl | ShiftRegOp::Rcr => (
                        ROTATE_UNCHANGED_RFLAGS,
                        ROTATE_UNCHANGED_RFLAGS | (1 << 11),
                        0,
                    ),
                    ShiftRegOp::Shl | ShiftRegOp::Shr | ShiftRegOp::Sar => {
                        (1 << 4, 1 << 4, 1 << 11)
                    }
                };
                self.emit_merge_jit_shift_status(multi_preserve, multi_clear);
                self.code.emit_u8(0xE9);
                let multi_done = self.code.position();
                self.code.emit_u32(0);

                self.patch_rel32_to_current(count_one)?;
                self.emit_merge_jit_shift_status(one_preserve, 0);
                self.code.emit_u8(0xE9);
                let one_done = self.code.position();
                self.code.emit_u32(0);

                self.patch_rel32_to_current(count_zero)?;
                self.emit_merge_jit_shift_status(X86_STATUS_RFLAGS, 0);
                if let (Some(count_boundary), Some(count_oversized)) =
                    (count_boundary, count_oversized)
                {
                    self.code.emit_u8(0xE9);
                    let zero_done = self.code.position();
                    self.code.emit_u32(0);

                    self.patch_rel32_to_current(count_boundary)?;
                    self.emit_merge_jit_shift_boundary_cf(kind, width);
                    self.code.emit_u8(0xE9);
                    let boundary_done = self.code.position();
                    self.code.emit_u32(0);

                    self.patch_rel32_to_current(count_oversized)?;
                    self.emit_merge_jit_shift_status(1 << 4, 1 | (1 << 11));
                    self.patch_rel32_to_current(zero_done)?;
                    self.patch_rel32_to_current(boundary_done)?;
                }
                self.patch_rel32_to_current(multi_done)?;
                self.patch_rel32_to_current(one_done)?;
            }
        }
        self.code.emit_u8(0x9D); // popfq: merged guest flags
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 32);
        }
        Ok(Some(consumed))
    }

    /// Fuse `Load virtual; CMove architectural_dst,virtual` into an
    /// unconditional fault-precise helper load followed by a native conditional
    /// move from caller-owned stack storage. The helper must run even when the
    /// condition is false. State-backed destinations seed a scratch with their
    /// complete old value before native CMOV applies its destination width.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn try_lower_jit_mem_cmove(
        &mut self,
        block: &SmirBlock,
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(consumed) = crate::smir::lower::runtime::x86_jit_mem_cmove_source_sequence_len(
            block,
            idx,
            true,
            virtual_definitions,
            virtual_uses,
        ) else {
            return Ok(None);
        };

        let load = &block.ops[idx];
        let (addr, mem_width) = match &load.kind {
            OpKind::Load {
                addr,
                width,
                sign: SignExtend::Zero,
                ..
            } => (addr, *width),
            _ => unreachable!("validated memory CMOV starts with Load"),
        };
        let (dst, cond, width) = match &block.ops[idx + 1].kind {
            OpKind::CMove {
                dst, cond, width, ..
            } => (*dst, *cond, *width),
            _ => unreachable!("validated memory CMOV consumer"),
        };
        let dst_index = self.jit_arch_enc(dst)?;
        let x86_cond = X86Cond::from_condition(cond);

        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -16);
        }
        self.emit_jit_mem_op(
            load.guest_pc,
            true,
            None,
            Some(16),
            None,
            None,
            None,
            addr,
            mem_width,
            SignExtend::Zero,
            16,
        )?;

        if dst_index <= 15 && !matches!(dst_index, 4 | 5) {
            let dst_reg = self.get_dst_reg(dst)?;
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_cmovcc_rm_disp(x86_cond, dst_reg, PhysReg::Rsp, 0, DispSize::Auto, width);
        } else {
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_push(PhysReg::Rax);
                emitter.emit_push(PhysReg::Rdx);
            }
            self.emit_load_state_ptr_rax();
            self.emit_struct_mov(
                PhysReg::Rax,
                PhysReg::Rdx.encoding(),
                i32::from(dst_index) * 8,
                false,
            );
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_cmovcc_rm_disp(
                    x86_cond,
                    PhysReg::Rdx,
                    PhysReg::Rsp,
                    16,
                    DispSize::Auto,
                    width,
                );
            }
            self.emit_store_gpr_slot_from_reg(dst_index, PhysReg::Rdx, width)?;
            if dst_index == 5 {
                let commit_width = if width == OpWidth::W16 {
                    OpWidth::W16
                } else {
                    OpWidth::W64
                };
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_mr(PhysReg::Rbp, 0, PhysReg::Rdx, commit_width);
            }
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_pop(PhysReg::Rdx);
                emitter.emit_pop(PhysReg::Rax);
            }
        }

        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
        }
        Ok(Some(consumed))
    }

    /// Fuse `Load virtual; ZeroExtend/SignExtend architectural_dst,virtual`
    /// into a fault-precise MMU helper load followed by a native extension from
    /// caller-owned stack storage. Identity-mapped destinations use their host
    /// register directly. Guest RSP/RBP and APX EGPR destinations commit only
    /// after a successful helper return through their canonical state slots.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn try_lower_jit_mem_extend(
        &mut self,
        block: &SmirBlock,
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(consumed) = crate::smir::lower::runtime::x86_jit_mem_extend_source_sequence_len(
            block,
            idx,
            true,
            virtual_definitions,
            virtual_uses,
        ) else {
            return Ok(None);
        };

        let load = &block.ops[idx];
        let (addr, mem_width, sign) = match &load.kind {
            OpKind::Load {
                addr, width, sign, ..
            } => (addr, *width, *sign),
            _ => unreachable!("validated memory extension starts with Load"),
        };
        let (dst, from_width, to_width, signed) = match &block.ops[idx + 1].kind {
            OpKind::ZeroExtend {
                dst,
                from_width,
                to_width,
                ..
            } => (*dst, *from_width, *to_width, false),
            OpKind::SignExtend {
                dst,
                from_width,
                to_width,
                ..
            } => (*dst, *from_width, *to_width, true),
            _ => unreachable!("validated memory-extension consumer"),
        };
        let dst_index = self.jit_arch_enc(dst)?;

        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -16);
        }
        self.emit_jit_mem_op(
            load.guest_pc,
            true,
            None,
            Some(16),
            None,
            None,
            None,
            addr,
            mem_width,
            sign,
            16,
        )?;

        if dst_index <= 15 && !matches!(dst_index, 4 | 5) {
            let dst_reg = self.get_dst_reg(dst)?;
            let mut emitter = X86Emitter::new(&mut self.code);
            if signed {
                emitter.emit_movsx_rm_disp(
                    dst_reg,
                    PhysReg::Rsp,
                    0,
                    DispSize::Auto,
                    from_width,
                    to_width,
                );
            } else {
                emitter.emit_movzx_rm_disp(
                    dst_reg,
                    PhysReg::Rsp,
                    0,
                    DispSize::Auto,
                    from_width,
                    to_width,
                );
            }
        } else {
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_push(PhysReg::Rax);
                emitter.emit_push(PhysReg::Rdx);
            }
            self.emit_load_state_ptr_rax();
            self.emit_struct_mov(
                PhysReg::Rax,
                PhysReg::Rdx.encoding(),
                i32::from(dst_index) * 8,
                false,
            );
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                if signed {
                    emitter.emit_movsx_rm_disp(
                        PhysReg::Rdx,
                        PhysReg::Rsp,
                        16,
                        DispSize::Auto,
                        from_width,
                        to_width,
                    );
                } else {
                    emitter.emit_movzx_rm_disp(
                        PhysReg::Rdx,
                        PhysReg::Rsp,
                        16,
                        DispSize::Auto,
                        from_width,
                        to_width,
                    );
                }
            }
            self.emit_store_gpr_slot_from_reg(dst_index, PhysReg::Rdx, to_width)?;
            if dst_index == 5 {
                let commit_width = if to_width == OpWidth::W16 {
                    OpWidth::W16
                } else {
                    OpWidth::W64
                };
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_mr(PhysReg::Rbp, 0, PhysReg::Rdx, commit_width);
            }
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_pop(PhysReg::Rdx);
                emitter.emit_pop(PhysReg::Rax);
            }
        }

        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
        }
        Ok(Some(consumed))
    }

    /// Stage any architectural x86 GPR in caller-owned host-stack space. The
    /// identity-mapped legacy registers are read directly; guest RSP/RBP and
    /// APX EGPRs are read from their canonical GuestRegs slots because they do
    /// not have a usable identity-mapped host register.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn emit_jit_stage_arch_gpr(
        &mut self,
        source: VReg,
        caller_stack_offset: i32,
    ) -> Result<(), LowerError> {
        let index = Self::x86_gpr_index(source).ok_or_else(|| LowerError::InvalidOperand {
            op: "guarded x86 DIV".to_string(),
            operand: "divisor must be an architectural x86 GPR".to_string(),
        })?;
        if index <= 15 && !matches!(index, 4 | 5) {
            let source = self.get_reg(source)?;
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_mr(PhysReg::Rsp, caller_stack_offset, source, OpWidth::W64);
            return Ok(());
        }

        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_push(PhysReg::Rax);
            emitter.emit_push(PhysReg::Rcx);
            emitter.emit_mov_rm(
                PhysReg::Rax,
                PhysReg::Rbp,
                X86_STATE_PTR_AT_RBP,
                OpWidth::W64,
            );
            emitter.emit_mov_rm(
                PhysReg::Rcx,
                PhysReg::Rax,
                i32::from(index) * 8,
                OpWidth::W64,
            );
            emitter.emit_mov_mr(
                PhysReg::Rsp,
                caller_stack_offset + 16,
                PhysReg::Rcx,
                OpWidth::W64,
            );
            emitter.emit_pop(PhysReg::Rcx);
            emitter.emit_pop(PhysReg::Rax);
        }
        Ok(())
    }

    /// Lower exact x86 `DIV r/m` through pre-fault guards. The divisor is
    /// staged in a 16-byte caller frame, while the original RFLAGS/RAX/RDX are
    /// snapshotted above it. A zero divisor or high-half overflow exits to the
    /// interpreter at the current guest PC without committing either result;
    /// only a proven-safe path executes native DIV, so host #DE is impossible.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn try_lower_jit_unsigned_div(
        &mut self,
        block: &SmirBlock,
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        if !self.jit_fault_deopt_guards {
            return Ok(None);
        }

        enum DivisorSource {
            Memory {
                addr: Address,
                mem_width: MemWidth,
                guest_pc: u64,
            },
            Register(VReg),
            LegacyHighByte(VReg),
        }

        let (source, consumer_idx, consumed) = if self.mem_helpers
            && crate::smir::lower::runtime::x86_jit_mem_unsigned_div_source_sequence_len(
                block,
                idx,
                true,
                virtual_definitions,
                virtual_uses,
            )
            .is_some()
        {
            let OpKind::Load {
                addr,
                width,
                sign: SignExtend::Zero,
                ..
            } = &block.ops[idx].kind
            else {
                unreachable!("validated unsigned memory DIV starts with Load")
            };
            (
                DivisorSource::Memory {
                    addr: addr.clone(),
                    mem_width: *width,
                    guest_pc: block.ops[idx].guest_pc,
                },
                idx + 1,
                2,
            )
        } else if crate::smir::lower::runtime::x86_jit_high_byte_unsigned_div_source_sequence_len(
            block,
            idx,
            virtual_definitions,
            virtual_uses,
        )
        .is_some()
        {
            let OpKind::Shr {
                src: parent,
                width: OpWidth::W64,
                ..
            } = &block.ops[idx].kind
            else {
                unreachable!("validated high-byte unsigned DIV starts with Shr")
            };
            (DivisorSource::LegacyHighByte(*parent), idx + 1, 2)
        } else if crate::smir::lower::runtime::x86_jit_unsigned_div_register_shape_valid(
            &block.ops[idx],
        ) {
            let OpKind::DivU {
                src2: SrcOperand::Reg(source),
                ..
            } = &block.ops[idx].kind
            else {
                unreachable!("validated register unsigned DIV")
            };
            (DivisorSource::Register(*source), idx, 1)
        } else {
            return Ok(None);
        };

        let consumer = &block.ops[consumer_idx];
        let width = match &consumer.kind {
            OpKind::DivU { width, .. } => *width,
            _ => unreachable!("validated unsigned DIV consumer"),
        };

        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -16);
        }
        match &source {
            DivisorSource::Memory {
                addr,
                mem_width,
                guest_pc,
            } => self.emit_jit_mem_op(
                *guest_pc,
                true,
                None,
                Some(16),
                None,
                None,
                None,
                addr,
                *mem_width,
                SignExtend::Zero,
                16,
            )?,
            DivisorSource::Register(source) | DivisorSource::LegacyHighByte(source) => {
                self.emit_jit_stage_arch_gpr(*source, 0)?;
            }
        }

        // Current layout after the snapshots:
        // [rsp+0]=old RDX, [rsp+8]=old RAX, [rsp+16]=old RFLAGS,
        // [rsp+24]=zero-extended/staged divisor, [rsp+32]=caller padding.
        self.code.emit_u8(0x9C); // pushfq
        self.code.emit_u8(0x50); // push rax
        self.code.emit_u8(0x52); // push rdx

        if matches!(source, DivisorSource::LegacyHighByte(_)) {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
            emitter.emit_shr_ri(PhysReg::Rax, 8, OpWidth::W64);
            emitter.emit_mov_mr(PhysReg::Rsp, 24, PhysReg::Rax, OpWidth::W64);
        }

        let mut fault_branches = Vec::with_capacity(2);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
            emitter.emit_test_rr(PhysReg::Rax, PhysReg::Rax, width);
        }
        fault_branches.push(self.emit_jcc_placeholder(X86Cond::E));

        {
            let mut emitter = X86Emitter::new(&mut self.code);
            if width == OpWidth::W8 {
                // AX is the complete 16-bit dividend; compare AH with the
                // unsigned 8-bit divisor after moving AH into DL.
                emitter.emit_mov_rm(PhysReg::Rdx, PhysReg::Rsp, 8, OpWidth::W64);
                emitter.emit_shr_ri(PhysReg::Rdx, 8, OpWidth::W64);
                emitter.emit_cmp_rr(PhysReg::Rdx, PhysReg::Rax, OpWidth::W8);
            } else {
                emitter.emit_mov_rm(PhysReg::Rdx, PhysReg::Rsp, 0, OpWidth::W64);
                emitter.emit_cmp_rr(PhysReg::Rdx, PhysReg::Rax, width);
            }
        }
        // For unsigned RDX:RAX / divisor, quotient overflow is equivalent to
        // the high half being greater than or equal to the divisor.
        fault_branches.push(self.emit_jcc_placeholder(X86Cond::Ae));

        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rdx, PhysReg::Rsp, 0, OpWidth::W64);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 8, OpWidth::W64);
            emitter.emit_group3_m_disp(6, PhysReg::Rsp, 24, DispSize::Auto, width);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
        }
        self.code.emit_u8(0x9D); // restore architecturally undefined flags deterministically
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
        }
        self.code.emit_u8(0xE9);
        let success_done = self.code.position();
        self.code.emit_u32(0);

        let fault = self.code.position();
        for branch in fault_branches {
            self.code
                .patch_i32(branch, (fault as i64 - (branch as i64 + 4)) as i32);
        }
        self.code.emit_u8(0x5A); // restore old RDX
        self.code.emit_u8(0x58); // restore old RAX
        self.code.emit_u8(0x9D); // restore old RFLAGS
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
        }
        self.emit_native_exit(consumer.guest_pc);

        let done = self.code.position();
        self.code.patch_i32(
            success_done,
            (done as i64 - (success_done as i64 + 4)) as i32,
        );
        Ok(Some(consumed))
    }

    /// Lower exact x86 `IDIV r/m` through zero-divisor and signed quotient-
    /// range guards. The guard compares the unsigned magnitude of the signed
    /// 2N-bit dividend against `|divisor| * 2^(N-1)` for a nonnegative
    /// quotient, or `|divisor| * (2^(N-1) + 1)` for a negative quotient. A
    /// value at or above the selected threshold cannot fit in the N-bit signed
    /// quotient and deoptimizes at the current guest PC before native IDIV.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn try_lower_jit_signed_div(
        &mut self,
        block: &SmirBlock,
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        if !self.jit_fault_deopt_guards {
            return Ok(None);
        }

        enum DivisorSource {
            Memory {
                addr: Address,
                mem_width: MemWidth,
                guest_pc: u64,
            },
            Register(VReg),
            LegacyHighByte(VReg),
        }

        let (source, consumer_idx, consumed) = if self.mem_helpers
            && crate::smir::lower::runtime::x86_jit_mem_signed_div_source_sequence_len(
                block,
                idx,
                true,
                virtual_definitions,
                virtual_uses,
            )
            .is_some()
        {
            let OpKind::Load {
                addr,
                width,
                sign: SignExtend::Zero,
                ..
            } = &block.ops[idx].kind
            else {
                unreachable!("validated signed memory IDIV starts with Load")
            };
            (
                DivisorSource::Memory {
                    addr: addr.clone(),
                    mem_width: *width,
                    guest_pc: block.ops[idx].guest_pc,
                },
                idx + 1,
                2,
            )
        } else if crate::smir::lower::runtime::x86_jit_high_byte_signed_div_source_sequence_len(
            block,
            idx,
            virtual_definitions,
            virtual_uses,
        )
        .is_some()
        {
            let OpKind::Shr {
                src: parent,
                width: OpWidth::W64,
                ..
            } = &block.ops[idx].kind
            else {
                unreachable!("validated high-byte signed IDIV starts with Shr")
            };
            (DivisorSource::LegacyHighByte(*parent), idx + 1, 2)
        } else if crate::smir::lower::runtime::x86_jit_signed_div_register_shape_valid(
            &block.ops[idx],
        ) {
            let OpKind::DivS {
                src2: SrcOperand::Reg(source),
                ..
            } = &block.ops[idx].kind
            else {
                unreachable!("validated register signed IDIV")
            };
            (DivisorSource::Register(*source), idx, 1)
        } else {
            return Ok(None);
        };

        let consumer = &block.ops[consumer_idx];
        let width = match &consumer.kind {
            OpKind::DivS { width, .. } => *width,
            _ => unreachable!("validated signed IDIV consumer"),
        };

        // The 48-byte caller frame remains 16-byte aligned across memory
        // helper calls. After four snapshots the layout is:
        // [rsp+0]=old RCX, [rsp+8]=old RDX, [rsp+16]=old RAX,
        // [rsp+24]=old RFLAGS, [rsp+32]=raw divisor,
        // [rsp+40]=|divisor|, [rsp+48]=|dividend| low,
        // [rsp+56]=|dividend| high, [rsp+64]=quotient-sign bits.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -48);
        }
        match &source {
            DivisorSource::Memory {
                addr,
                mem_width,
                guest_pc,
            } => self.emit_jit_mem_op(
                *guest_pc,
                true,
                None,
                Some(16),
                None,
                None,
                None,
                addr,
                *mem_width,
                SignExtend::Zero,
                48,
            )?,
            DivisorSource::Register(source) | DivisorSource::LegacyHighByte(source) => {
                self.emit_jit_stage_arch_gpr(*source, 0)?;
            }
        }

        self.code.emit_u8(0x9C); // pushfq
        self.code.emit_u8(0x50); // push rax
        self.code.emit_u8(0x52); // push rdx
        self.code.emit_u8(0x51); // push rcx

        if matches!(source, DivisorSource::LegacyHighByte(_)) {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 32, OpWidth::W64);
            emitter.emit_shr_ri(PhysReg::Rax, 8, OpWidth::W64);
            emitter.emit_mov_mr(PhysReg::Rsp, 32, PhysReg::Rax, OpWidth::W64);
        }

        let mut fault_branches = Vec::with_capacity(4);

        // Reject a zero divisor using the architected operand width.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            if matches!(width, OpWidth::W8 | OpWidth::W16) {
                emitter.emit_xor_rr(PhysReg::Rax, PhysReg::Rax, OpWidth::W32);
            }
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 32, width);
            emitter.emit_test_rr(PhysReg::Rax, PhysReg::Rax, width);
        }
        fault_branches.push(self.emit_jcc_placeholder(X86Cond::E));

        // Preserve the sign of the mathematical quotient as the sign bit of
        // (dividend high half XOR divisor) at the operand width.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            if width == OpWidth::W8 {
                emitter.emit_xor_rr(PhysReg::Rcx, PhysReg::Rcx, OpWidth::W32);
                emitter.emit_mov_rm(PhysReg::Rcx, PhysReg::Rsp, 16, OpWidth::W16);
                emitter.emit_shr_ri(PhysReg::Rcx, 8, OpWidth::W16);
            } else {
                if width == OpWidth::W16 {
                    emitter.emit_xor_rr(PhysReg::Rcx, PhysReg::Rcx, OpWidth::W32);
                }
                emitter.emit_mov_rm(PhysReg::Rcx, PhysReg::Rsp, 8, width);
            }
            if matches!(width, OpWidth::W8 | OpWidth::W16) {
                emitter.emit_xor_rr(PhysReg::Rax, PhysReg::Rax, OpWidth::W32);
            }
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 32, width);
            emitter.emit_xor_rr(PhysReg::Rcx, PhysReg::Rax, width);
            emitter.emit_mov_mr(PhysReg::Rsp, 64, PhysReg::Rcx, OpWidth::W64);
        }

        // Convert the N-bit signed divisor to an exact unsigned magnitude.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            if matches!(width, OpWidth::W8 | OpWidth::W16) {
                emitter.emit_xor_rr(PhysReg::Rax, PhysReg::Rax, OpWidth::W32);
            }
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 32, width);
            emitter.emit_test_rr(PhysReg::Rax, PhysReg::Rax, width);
        }
        let divisor_nonnegative = self.emit_jcc_placeholder(X86Cond::Ns);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_neg(PhysReg::Rax, width);
        }
        let divisor_magnitude_ready = self.code.position();
        self.code.patch_i32(
            divisor_nonnegative,
            (divisor_magnitude_ready as i64 - (divisor_nonnegative as i64 + 4)) as i32,
        );
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_mr(PhysReg::Rsp, 40, PhysReg::Rax, OpWidth::W64);
        }

        if width == OpWidth::W64 {
            // Exact unsigned magnitude of the signed 128-bit RDX:RAX value.
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 16, OpWidth::W64);
                emitter.emit_mov_rm(PhysReg::Rdx, PhysReg::Rsp, 8, OpWidth::W64);
                emitter.emit_test_rr(PhysReg::Rdx, PhysReg::Rdx, OpWidth::W64);
            }
            let dividend_nonnegative = self.emit_jcc_placeholder(X86Cond::Ns);
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_neg(PhysReg::Rax, OpWidth::W64);
                emitter.emit_adc_ri(PhysReg::Rdx, 0, OpWidth::W64);
                emitter.emit_neg(PhysReg::Rdx, OpWidth::W64);
            }
            let dividend_magnitude_ready = self.code.position();
            self.code.patch_i32(
                dividend_nonnegative,
                (dividend_magnitude_ready as i64 - (dividend_nonnegative as i64 + 4)) as i32,
            );
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_mr(PhysReg::Rsp, 48, PhysReg::Rax, OpWidth::W64);
                emitter.emit_mov_mr(PhysReg::Rsp, 56, PhysReg::Rdx, OpWidth::W64);

                // T = |d| << 63, represented as RDX:RAX.
                emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 40, OpWidth::W64);
                emitter.emit_mov_rr(PhysReg::Rdx, PhysReg::Rax, OpWidth::W64);
                emitter.emit_shl_ri(PhysReg::Rax, 63, OpWidth::W64);
                emitter.emit_shr_ri(PhysReg::Rdx, 1, OpWidth::W64);
                emitter.emit_mov_rm(PhysReg::Rcx, PhysReg::Rsp, 64, OpWidth::W64);
                emitter.emit_test_rr(PhysReg::Rcx, PhysReg::Rcx, OpWidth::W64);
            }
            let quotient_nonnegative = self.emit_jcc_placeholder(X86Cond::Ns);
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                // Negative quotients admit magnitude 2^(N-1), so their first
                // overflowing magnitude is |d| * (2^(N-1) + 1).
                emitter.emit_mov_rm(PhysReg::Rcx, PhysReg::Rsp, 40, OpWidth::W64);
                emitter.emit_add_rr(PhysReg::Rax, PhysReg::Rcx, OpWidth::W64);
                emitter.emit_adc_ri(PhysReg::Rdx, 0, OpWidth::W64);
            }
            let threshold_ready = self.code.position();
            self.code.patch_i32(
                quotient_nonnegative,
                (threshold_ready as i64 - (quotient_nonnegative as i64 + 4)) as i32,
            );

            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_rm(PhysReg::Rcx, PhysReg::Rsp, 56, OpWidth::W64);
                emitter.emit_cmp_rr(PhysReg::Rcx, PhysReg::Rdx, OpWidth::W64);
            }
            fault_branches.push(self.emit_jcc_placeholder(X86Cond::A));
            let high_below_threshold = self.emit_jcc_placeholder(X86Cond::B);
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_rm(PhysReg::Rcx, PhysReg::Rsp, 48, OpWidth::W64);
                emitter.emit_cmp_rr(PhysReg::Rcx, PhysReg::Rax, OpWidth::W64);
            }
            fault_branches.push(self.emit_jcc_placeholder(X86Cond::Ae));
            let range_guard_done = self.code.position();
            self.code.patch_i32(
                high_below_threshold,
                (range_guard_done as i64 - (high_below_threshold as i64 + 4)) as i32,
            );
        } else {
            let dividend_width = match width {
                OpWidth::W8 => OpWidth::W16,
                OpWidth::W16 => OpWidth::W32,
                OpWidth::W32 => OpWidth::W64,
                _ => unreachable!("signed division width validated above"),
            };
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                match width {
                    OpWidth::W8 => {
                        emitter.emit_xor_rr(PhysReg::Rcx, PhysReg::Rcx, OpWidth::W32);
                        emitter.emit_mov_rm(PhysReg::Rcx, PhysReg::Rsp, 16, OpWidth::W16);
                    }
                    OpWidth::W16 => {
                        emitter.emit_xor_rr(PhysReg::Rcx, PhysReg::Rcx, OpWidth::W32);
                        emitter.emit_mov_rm(PhysReg::Rcx, PhysReg::Rsp, 8, OpWidth::W16);
                        emitter.emit_shl_ri(PhysReg::Rcx, 16, OpWidth::W32);
                        emitter.emit_xor_rr(PhysReg::Rax, PhysReg::Rax, OpWidth::W32);
                        emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 16, OpWidth::W16);
                        emitter.emit_or_rr(PhysReg::Rcx, PhysReg::Rax, OpWidth::W32);
                    }
                    OpWidth::W32 => {
                        emitter.emit_mov_rm(PhysReg::Rcx, PhysReg::Rsp, 8, OpWidth::W32);
                        emitter.emit_shl_ri(PhysReg::Rcx, 32, OpWidth::W64);
                        emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 16, OpWidth::W32);
                        emitter.emit_or_rr(PhysReg::Rcx, PhysReg::Rax, OpWidth::W64);
                    }
                    _ => unreachable!("signed division width validated above"),
                }
                emitter.emit_test_rr(PhysReg::Rcx, PhysReg::Rcx, dividend_width);
            }
            let dividend_nonnegative = self.emit_jcc_placeholder(X86Cond::Ns);
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_neg(PhysReg::Rcx, dividend_width);
            }
            let dividend_magnitude_ready = self.code.position();
            self.code.patch_i32(
                dividend_nonnegative,
                (dividend_magnitude_ready as i64 - (dividend_nonnegative as i64 + 4)) as i32,
            );
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_mr(PhysReg::Rsp, 48, PhysReg::Rcx, OpWidth::W64);
                emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 40, OpWidth::W64);
                emitter.emit_shl_ri(
                    PhysReg::Rax,
                    match width {
                        OpWidth::W8 => 7,
                        OpWidth::W16 => 15,
                        OpWidth::W32 => 31,
                        _ => unreachable!("signed division width validated above"),
                    },
                    OpWidth::W64,
                );
                emitter.emit_mov_rm(PhysReg::Rcx, PhysReg::Rsp, 64, OpWidth::W64);
                emitter.emit_test_rr(PhysReg::Rcx, PhysReg::Rcx, width);
            }
            let quotient_nonnegative = self.emit_jcc_placeholder(X86Cond::Ns);
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_rm(PhysReg::Rcx, PhysReg::Rsp, 40, OpWidth::W64);
                emitter.emit_add_rr(PhysReg::Rax, PhysReg::Rcx, OpWidth::W64);
            }
            let threshold_ready = self.code.position();
            self.code.patch_i32(
                quotient_nonnegative,
                (threshold_ready as i64 - (quotient_nonnegative as i64 + 4)) as i32,
            );
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_rm(PhysReg::Rcx, PhysReg::Rsp, 48, OpWidth::W64);
                emitter.emit_cmp_rr(PhysReg::Rcx, PhysReg::Rax, OpWidth::W64);
            }
            fault_branches.push(self.emit_jcc_placeholder(X86Cond::Ae));
        }

        // Only the range-proven path restores the implicit dividend and runs
        // native /7 against the unchanged raw signed divisor.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rcx, PhysReg::Rsp, 0, OpWidth::W64);
            emitter.emit_mov_rm(PhysReg::Rdx, PhysReg::Rsp, 8, OpWidth::W64);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 16, OpWidth::W64);
            emitter.emit_group3_m_disp(7, PhysReg::Rsp, 32, DispSize::Auto, width);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 24);
        }
        self.code.emit_u8(0x9D); // restore architecturally undefined flags deterministically
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 48);
        }
        self.code.emit_u8(0xE9);
        let success_done = self.code.position();
        self.code.emit_u32(0);

        let fault = self.code.position();
        for branch in fault_branches {
            self.code
                .patch_i32(branch, (fault as i64 - (branch as i64 + 4)) as i32);
        }
        self.code.emit_u8(0x59); // restore old RCX
        self.code.emit_u8(0x5A); // restore old RDX
        self.code.emit_u8(0x58); // restore old RAX
        self.code.emit_u8(0x9D); // restore old RFLAGS
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 48);
        }
        self.emit_native_exit(consumer.guest_pc);

        let done = self.code.position();
        self.code.patch_i32(
            success_done,
            (done as i64 - (success_done as i64 + 4)) as i32,
        );
        Ok(Some(consumed))
    }

    /// Fuse the x86 lifter's exact non-locked immediate memory BTS/BTR/BTC
    /// sequence. The original and updated operands remain in caller-owned
    /// stack words across the MMU helpers. Speculative native modification is
    /// flag-neutralized; only a successful store reaches the BT replay that
    /// commits CF while retaining every other incoming status flag.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn try_lower_jit_mem_bit_update_rmw(
        &mut self,
        block: &SmirBlock,
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(consumed) = crate::smir::lower::runtime::x86_jit_mem_bit_update_rmw_sequence_len(
            block,
            idx,
            true,
            virtual_definitions,
            virtual_uses,
        ) else {
            return Ok(None);
        };

        let load = &block.ops[idx];
        let (addr, mem_width) = match &load.kind {
            OpKind::Load {
                addr,
                width,
                sign: SignExtend::Zero,
                ..
            } => (addr, *width),
            _ => unreachable!("validated memory bit update starts with Load"),
        };
        let action_index = if consumed == 4 { idx + 1 } else { idx + 3 };
        let kind = match &block.ops[action_index].kind {
            OpKind::Or { .. } => BitTestRegOp::Set,
            OpKind::And { .. } | OpKind::Not { .. } => BitTestRegOp::Reset,
            OpKind::Xor { .. } => BitTestRegOp::Complement,
            _ => unreachable!("validated immediate memory bit-update action"),
        };
        let (index, width) = match &block.ops[idx + consumed - 1].kind {
            OpKind::Bt {
                index: SrcOperand::Imm(index),
                width,
                ..
            } => (*index as u8, *width),
            _ => unreachable!("validated immediate memory bit-update replay"),
        };

        // Caller-frame layout:
        //   [rsp+0]  original zero-extended memory value
        //   [rsp+8]  updated store value
        //   [rsp+16] alignment word
        //   [rsp+24] complete architectural RAX
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -32);
            emitter.emit_mov_mr(PhysReg::Rsp, 24, PhysReg::Rax, OpWidth::W64);
        }
        self.emit_jit_mem_op(
            load.guest_pc,
            true,
            None,
            Some(16),
            None,
            None,
            None,
            addr,
            mem_width,
            SignExtend::Zero,
            32,
        )?;

        // Copy the complete staged load, then modify only the encoded operand
        // width. PUSHFQ/POPFQ prevents the speculative CF from becoming guest
        // state if the following helper-backed store faults.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 0, OpWidth::W64);
            emitter.emit_mov_mr(PhysReg::Rsp, 8, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
        }
        self.code.emit_u8(0x9C); // pushfq (incoming)
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_bit_test_mi_disp(kind, PhysReg::Rsp, 16, index, width);
        }
        self.code.emit_u8(0x9D); // popfq (incoming)

        // The store helper's 16-byte internal spill shifts caller [rsp+8] to
        // active [rsp+24]. A fault removes the entire caller frame and restarts
        // the instruction with memory, registers, and flags uncommitted.
        self.emit_jit_mem_op(
            load.guest_pc,
            false,
            None,
            None,
            None,
            None,
            Some(24),
            addr,
            mem_width,
            SignExtend::Zero,
            32,
        )?;

        // Replay non-modifying BT on the original word only after the store
        // succeeds. `finish_bmi_flags` merges native CF into incoming RFLAGS.
        self.code.emit_u8(0x9C); // pushfq (incoming)
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_bit_test_mi_disp(BitTestRegOp::Test, PhysReg::Rsp, 8, index, width);
        }
        self.finish_bmi_flags(PhysReg::Rax, Some(1 << 0));
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, 24, OpWidth::W64);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 32);
        }
        Ok(Some(consumed))
    }

    /// Fuse the x86 lifter's exact non-modifying immediate memory bit test:
    /// `Load virtual; Bt virtual,imm`. The helper stages the operand in a
    /// caller-owned word; native BT then supplies CF, which is the only status
    /// bit merged into the saved guest RFLAGS image.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn try_lower_jit_mem_bit_test_source(
        &mut self,
        block: &SmirBlock,
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(consumed) = crate::smir::lower::runtime::x86_jit_mem_bit_test_source_sequence_len(
            block,
            idx,
            true,
            virtual_definitions,
            virtual_uses,
        ) else {
            return Ok(None);
        };

        let load = &block.ops[idx];
        let (addr, mem_width) = match &load.kind {
            OpKind::Load {
                addr,
                width,
                sign: SignExtend::Zero,
                ..
            } => (addr, *width),
            _ => unreachable!("validated memory bit test starts with Load"),
        };
        let (index, width) = match block.ops[idx + 1].kind {
            OpKind::Bt {
                index: SrcOperand::Imm(index),
                width,
                ..
            } => (index as u8, width),
            _ => unreachable!("validated immediate memory bit-test consumer"),
        };

        // Keep a 16-byte aligned caller frame. The top word receives the
        // helper result, while RAX remains available as the flag-merge scratch
        // and is preserved by `finish_bmi_flags`.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_push(PhysReg::Rax);
            emitter.emit_push(PhysReg::Rax);
        }
        self.emit_jit_mem_op(
            load.guest_pc,
            true,
            None,
            Some(16),
            None,
            None,
            None,
            addr,
            mem_width,
            SignExtend::Zero,
            16,
        )?;

        self.code.emit_u8(0x9C); // pushfq (old)
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_bit_test_mi_disp(BitTestRegOp::Test, PhysReg::Rsp, 8, index, width);
        }
        self.finish_bmi_flags(PhysReg::Rax, Some(1 << 0));
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
        }
        Ok(Some(consumed))
    }

    /// Fuse the x86 lifter's exact `Load virtual; Bsf/Bsr dst,virtual` pair.
    /// The helper stages the load in caller-owned stack storage, leaving the
    /// architectural destination intact until the native scan executes. Only
    /// ZF is merged back into the pre-instruction RFLAGS image; the remaining
    /// status flags retain the emulator's deterministic undefined values.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn try_lower_jit_mem_bit_scan_source(
        &mut self,
        block: &SmirBlock,
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(consumed) = crate::smir::lower::runtime::x86_jit_mem_bit_scan_source_sequence_len(
            block,
            idx,
            true,
            virtual_definitions,
            virtual_uses,
        ) else {
            return Ok(None);
        };

        let load = &block.ops[idx];
        let (addr, mem_width) = match &load.kind {
            OpKind::Load {
                addr,
                width,
                sign: SignExtend::Zero,
                ..
            } => (addr, *width),
            _ => unreachable!("validated bit-scan memory source starts with Load"),
        };
        let (dst, width, reverse) = match block.ops[idx + 1].kind {
            OpKind::Bsf { dst, width, .. } => (dst, width, false),
            OpKind::Bsr { dst, width, .. } => (dst, width, true),
            _ => unreachable!("validated bit-scan memory-source consumer"),
        };
        let dst_reg = self.get_dst_reg(dst)?;
        Self::ensure_flag_stack_operands_safe("bit-scan memory-source", &[dst_reg])?;

        // One word receives the helper result and one preserves the complete
        // pre-instruction destination for partial-width/zero-source behavior.
        // Keeping two words also retains the helper call's stack alignment.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_push(dst_reg);
            emitter.emit_push(dst_reg);
        }
        self.emit_jit_mem_op(
            load.guest_pc,
            true,
            None,
            // The helper has pushed RAX and RFLAGS while writing the result,
            // placing the caller-owned result word at its [rsp+16].
            Some(16),
            None,
            None,
            None,
            addr,
            mem_width,
            SignExtend::Zero,
            16,
        )?;

        // After saving old RFLAGS the staged source is at [rsp+8] and the
        // complete pre-instruction destination is at [rsp+16]. For a zero
        // source the ISA leaves the result undefined; restore Rax's retained-
        // destination interpreter policy explicitly rather than depending on
        // host-microarchitecture behavior. Jcc and Mov preserve native ZF.
        self.code.emit_u8(0x9C); // pushfq (old)
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_bit_scan_rm(reverse, dst_reg, PhysReg::Rsp, 8, width);
        }
        let nonzero = self.emit_jcc_placeholder(X86Cond::Ne);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(dst_reg, PhysReg::Rsp, 16, OpWidth::W64);
        }
        self.patch_rel32_to_current(nonzero)?;
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_push(dst_reg);
        }
        self.code.emit_u8(0x9C); // pushfq (new)
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_alu_mi_disp(4, PhysReg::Rsp, 0, DispSize::Auto, 1 << 6, OpWidth::W64);
            emitter.emit_pop(dst_reg); // masked new ZF
            emitter.emit_alu_mi_disp(
                4,
                PhysReg::Rsp,
                8,
                DispSize::Auto,
                !(1i64 << 6),
                OpWidth::W64,
            );
            emitter.emit_alu_mem_disp(
                0x08,
                dst_reg,
                PhysReg::Rsp,
                8,
                DispSize::Auto,
                OpWidth::W64,
                X86AluEncoding::RmReg,
            );
            emitter.emit_pop(dst_reg); // restore scan result
        }
        self.code.emit_u8(0x9D); // popfq (merged)
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
        }
        Ok(Some(consumed))
    }

    /// Fuse the x86 lifter's exact `Load virtual; X86Count dst,virtual` pair.
    /// The MMU helper writes the zero-extended load into caller-owned stack
    /// space, leaving every architectural GPR unchanged until the count
    /// instruction executes. The 16-byte reservation retains call alignment;
    /// helper reload restores the destination's pre-instruction value before
    /// x86 16-bit partial-register semantics apply.
    #[cfg(feature = "smir-jit")]
    pub(crate) fn try_lower_jit_mem_count_source(
        &mut self,
        block: &SmirBlock,
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let Some(consumed) = crate::smir::lower::runtime::x86_jit_mem_count_source_sequence_len(
            block,
            idx,
            true,
            virtual_definitions,
            virtual_uses,
        ) else {
            return Ok(None);
        };

        let load = &block.ops[idx];
        let (addr, mem_width) = match &load.kind {
            OpKind::Load {
                addr,
                width,
                sign: SignExtend::Zero,
                ..
            } => (addr, *width),
            _ => unreachable!("validated scalar count memory source starts with Load"),
        };
        let (dst, width, kind, flags) = match block.ops[idx + 1].kind {
            OpKind::X86Count {
                dst,
                width,
                kind,
                flags,
                ..
            } => (dst, width, kind, flags),
            _ => unreachable!("validated scalar count memory-source consumer"),
        };
        let dst_reg = self.get_dst_reg(dst)?;
        Self::ensure_flag_stack_operands_safe("scalar count memory-source", &[dst_reg])?;

        // Reserve a helper-result word plus alignment padding. The fault path
        // removes both words before returning to the trampoline.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_push(dst_reg);
            emitter.emit_push(dst_reg);
        }
        self.emit_jit_mem_op(
            load.guest_pc,
            true,
            None,
            // `emit_jit_mem_op` has pushed RAX and RFLAGS while it stages the
            // return value, so the caller-owned top word is at [rsp+16].
            Some(16),
            None,
            None,
            None,
            addr,
            mem_width,
            SignExtend::Zero,
            16,
        )?;

        let requested = flags.as_set();
        if requested.is_empty() {
            self.code.emit_u8(0x9C); // pushfq: APX NF/preserved status
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_x86_count_rm(kind, dst_reg, PhysReg::Rsp, 8, width);
            }
            self.code.emit_u8(0x9D); // popfq
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
            return Ok(Some(consumed));
        }

        if kind == X86CountKind::Popcnt && requested == FlagSet::ALL_X86 {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_x86_count_rm(kind, dst_reg, PhysReg::Rsp, 0, width);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
            return Ok(Some(consumed));
        }

        // Merge only the requested, architecturally defined status bits. After
        // saving old RFLAGS the staged memory source is at [rsp+8]. The result
        // and flag-stack layout then matches `lower_x86_count` exactly.
        let rflags_mask = Self::x86_status_rflags_mask(requested);
        self.code.emit_u8(0x9C); // pushfq (old)
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_x86_count_rm(kind, dst_reg, PhysReg::Rsp, 8, width);
            emitter.emit_push(dst_reg);
        }
        self.code.emit_u8(0x9C); // pushfq (new)
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_alu_mi_disp(
                4,
                PhysReg::Rsp,
                0,
                DispSize::Auto,
                rflags_mask,
                OpWidth::W64,
            );
            emitter.emit_pop(dst_reg);
            emitter.emit_alu_mi_disp(
                4,
                PhysReg::Rsp,
                8,
                DispSize::Auto,
                !rflags_mask,
                OpWidth::W64,
            );
            emitter.emit_alu_mem_disp(
                0x08,
                dst_reg,
                PhysReg::Rsp,
                8,
                DispSize::Auto,
                OpWidth::W64,
                X86AluEncoding::RmReg,
            );
            emitter.emit_pop(dst_reg);
        }
        self.code.emit_u8(0x9D); // popfq (merged)
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
        }
        Ok(Some(consumed))
    }

    /// Emit one fault-precise APX paired-stack helper call. The helper consumes
    /// the coherent GuestRegs snapshot and performs the complete architectural
    /// POP2/PUSH2 commit; native code only restores the snapshot or exits to the
    /// interpreter at the original instruction PC.
    pub(crate) fn emit_jit_pair_op(
        &mut self,
        guest_pc: u64,
        is_load: bool,
        low: VReg,
        high: VReg,
    ) -> Result<(), LowerError> {
        let low_enc = self.jit_arch_enc(low)?;
        let high_enc = self.jit_arch_enc(high)?;
        if low_enc == 4 || high_enc == 4 || (is_load && low_enc == high_enc) {
            return Err(LowerError::InvalidOperand {
                op: if is_load { "APX POP2" } else { "APX PUSH2" }.to_string(),
                operand: "RSP operands and duplicate POP2 destinations are invalid".to_string(),
            });
        }

        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq; keep the helper call 16-byte aligned
        self.emit_spill_legacy_gprs_to_state_from_rax(8);
        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_mem_helpers);

        self.code.emit_u8(0x48);
        self.code.emit_u8(0x89);
        self.code.emit_u8(0xC7); // mov rdi,rax (GuestRegs state)
        self.code.emit_u8(0xBE); // mov esi, low register encoding
        self.code.emit_u32(u32::from(low_enc));
        self.code.emit_u8(0xBA); // mov edx, high register encoding
        self.code.emit_u32(u32::from(high_enc));
        self.code.emit_u8(0xFF);
        self.code.emit_u8(0x90); // call qword [rax+paired helper]
        self.code.emit_u32(if is_load {
            X86_GUEST_PAIR_LOAD_FN_OFFSET as u32
        } else {
            X86_GUEST_PAIR_STORE_FN_OFFSET as u32
        });

        self.code.emit_u8(0x48);
        self.code.emit_u8(0x8B);
        self.code.emit_u8(0x4D);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x85);
        self.code.emit_u8(0xC0); // test rax,rax
        let fault = self.emit_jcc_placeholder(X86Cond::E);

        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        if is_load && (low_enc == 5 || high_enc == 5) {
            self.emit_sync_saved_rbp_from_state(PhysReg::Rcx);
        }
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq
        self.emit_flag_preserving_stack_pop8();
        self.code.emit_u8(0xE9);
        let done = self.code.position();
        self.code.emit_u32(0);

        self.patch_rel32_to_current(fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(guest_pc);

        self.patch_rel32_to_current(done)?;
        Ok(())
    }

    /// Fuse the exact five-op APX PUSH2 shape emitted by the x86 lifter.
    pub(crate) fn try_lower_jit_push2(
        &mut self,
        ops: &[crate::smir::ir::ops::SmirOp],
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
        let Some(first) = ops.get(idx) else {
            return Ok(None);
        };
        let (tmp_low, src_low) = match first.kind {
            OpKind::Mov {
                dst: temporary @ VReg::Virtual(_),
                src: SrcOperand::Reg(source @ VReg::Arch(ArchReg::X86(reg))),
                width: OpWidth::W64,
            } if reg.gpr_index().is_some() && source != rsp => (temporary, source),
            _ => return Ok(None),
        };
        let second = match ops.get(idx + 1) {
            Some(op) if op.guest_pc == first.guest_pc => op,
            _ => return Ok(None),
        };
        let (tmp_high, src_high) = match second.kind {
            OpKind::Mov {
                dst: temporary @ VReg::Virtual(_),
                src: SrcOperand::Reg(source @ VReg::Arch(ArchReg::X86(reg))),
                width: OpWidth::W64,
            } if reg.gpr_index().is_some() && source != rsp => (temporary, source),
            _ => return Ok(None),
        };
        let Some(sub) = ops.get(idx + 2).filter(|op| op.guest_pc == first.guest_pc) else {
            return Ok(None);
        };
        let Some(store_low) = ops.get(idx + 3).filter(|op| op.guest_pc == first.guest_pc) else {
            return Ok(None);
        };
        let Some(store_high) = ops.get(idx + 4).filter(|op| op.guest_pc == first.guest_pc) else {
            return Ok(None);
        };
        if !matches!(
            sub.kind,
            OpKind::Sub {
                dst,
                src1,
                src2: SrcOperand::Imm(16),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            } if dst == rsp && src1 == rsp
        ) || !matches!(
            store_low.kind,
            OpKind::Store {
                src,
                addr: Address::Direct(base),
                width: MemWidth::B8,
            } if src == tmp_low && base == rsp
        ) || !matches!(
            &store_high.kind,
            OpKind::Store {
                src,
                addr,
                width: MemWidth::B8,
            } if *src == tmp_high && *addr == Address::base_off(rsp, 8)
        ) || virtual_definitions.get(&tmp_low) != Some(&1)
            || virtual_uses.get(&tmp_low) != Some(&1)
            || virtual_definitions.get(&tmp_high) != Some(&1)
            || virtual_uses.get(&tmp_high) != Some(&1)
        {
            return Ok(None);
        }

        self.emit_jit_pair_op(first.guest_pc, false, src_low, src_high)?;
        Ok(Some(5))
    }

    /// Fuse the exact five-op APX POP2 shape emitted by the x86 lifter.
    pub(crate) fn try_lower_jit_pop2(
        &mut self,
        ops: &[crate::smir::ir::ops::SmirOp],
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
        let Some(first) = ops.get(idx) else {
            return Ok(None);
        };
        let tmp_low = match first.kind {
            OpKind::Load {
                dst: temporary @ VReg::Virtual(_),
                addr: Address::Direct(base),
                width: MemWidth::B8,
                sign: SignExtend::Zero,
            } if base == rsp => temporary,
            _ => return Ok(None),
        };
        let second = match ops.get(idx + 1) {
            Some(op) if op.guest_pc == first.guest_pc => op,
            _ => return Ok(None),
        };
        let tmp_high = match &second.kind {
            OpKind::Load {
                dst: temporary @ VReg::Virtual(_),
                addr,
                width: MemWidth::B8,
                sign: SignExtend::Zero,
            } if *addr == Address::base_off(rsp, 8) => *temporary,
            _ => return Ok(None),
        };
        let Some(add) = ops.get(idx + 2).filter(|op| op.guest_pc == first.guest_pc) else {
            return Ok(None);
        };
        let Some(low_commit) = ops.get(idx + 3).filter(|op| op.guest_pc == first.guest_pc) else {
            return Ok(None);
        };
        let Some(high_commit) = ops.get(idx + 4).filter(|op| op.guest_pc == first.guest_pc) else {
            return Ok(None);
        };
        let dst_low = match low_commit.kind {
            OpKind::Mov {
                dst: destination @ VReg::Arch(ArchReg::X86(reg)),
                src: SrcOperand::Reg(source),
                width: OpWidth::W64,
            } if reg.gpr_index().is_some() && destination != rsp && source == tmp_low => {
                destination
            }
            _ => return Ok(None),
        };
        let dst_high = match high_commit.kind {
            OpKind::Mov {
                dst: destination @ VReg::Arch(ArchReg::X86(reg)),
                src: SrcOperand::Reg(source),
                width: OpWidth::W64,
            } if reg.gpr_index().is_some() && destination != rsp && source == tmp_high => {
                destination
            }
            _ => return Ok(None),
        };
        if dst_low == dst_high
            || !matches!(
                add.kind,
                OpKind::Add {
                    dst,
                    src1,
                    src2: SrcOperand::Imm(16),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                } if dst == rsp && src1 == rsp
            )
            || virtual_definitions.get(&tmp_low) != Some(&1)
            || virtual_uses.get(&tmp_low) != Some(&1)
            || virtual_definitions.get(&tmp_high) != Some(&1)
            || virtual_uses.get(&tmp_high) != Some(&1)
        {
            return Ok(None);
        }

        self.emit_jit_pair_op(first.guest_pc, true, dst_low, dst_high)?;
        Ok(Some(5))
    }

    /// Fuse the exact POP shapes emitted by the x86 lifter. The memory helper
    /// runs against the pre-increment RSP snapshot and exits before any state
    /// commit on fault. Ordinary destinations then increment RSP; POP RSP uses
    /// the loaded value directly; POP SP stages the value on the host stack so
    /// full-width increment carries are retained before the low-16-bit merge.
    pub(crate) fn try_lower_jit_pop(
        &mut self,
        ops: &[crate::smir::ir::ops::SmirOp],
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
        let load = match ops.get(idx) {
            Some(op) => op,
            None => return Ok(None),
        };
        let (popped, mem_width, delta) = match load.kind {
            OpKind::Load {
                dst,
                addr: Address::Direct(base),
                width: mem_width @ (MemWidth::B2 | MemWidth::B8),
                sign: SignExtend::Zero,
            } if base == rsp => (
                dst,
                mem_width,
                if mem_width == MemWidth::B2 { 2 } else { 8 },
            ),
            _ => return Ok(None),
        };

        if let VReg::Arch(ArchReg::X86(reg)) = popped {
            if reg.gpr_index().is_none() || popped == rsp {
                return Ok(None);
            }
            let increment = match ops.get(idx + 1) {
                Some(op) if op.guest_pc == load.guest_pc => op,
                _ => return Ok(None),
            };
            if !matches!(
                increment.kind,
                OpKind::Add {
                    dst,
                    src1,
                    src2: SrcOperand::Imm(amount),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                } if dst == rsp && src1 == rsp && amount == delta
            ) {
                return Ok(None);
            }

            self.emit_jit_mem_op(
                load.guest_pc,
                true,
                Some(popped),
                None,
                None,
                None,
                None,
                &Address::Direct(rsp),
                mem_width,
                SignExtend::Zero,
                0,
            )?;
            if reg.gpr_index() == Some(5) {
                // The helper committed GuestRegs.gpr[RBP], but hardware RBP is
                // the native frame pointer. Synchronize the prologue-saved
                // guest word, then restore any scratch-clobbered live GPRs.
                self.code.emit_u8(0x48);
                self.code.emit_u8(0x8B);
                self.code.emit_u8(0x4D);
                self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8);
                self.emit_sync_saved_rbp_from_state(PhysReg::Rcx);
                self.emit_reload_all(PhysReg::Rcx);
            }
            self.lower_state_backed_stack_gpr_alu(
                false,
                rsp,
                rsp,
                &SrcOperand::Imm(delta),
                OpWidth::W64,
                FlagUpdate::None,
            )?;
            return Ok(Some(2));
        }

        let VReg::Virtual(_) = popped else {
            return Ok(None);
        };
        if virtual_definitions.get(&popped) != Some(&1) || virtual_uses.get(&popped) != Some(&1) {
            return Ok(None);
        }

        if mem_width == MemWidth::B8 {
            let commit = match ops.get(idx + 1) {
                Some(op) if op.guest_pc == load.guest_pc => op,
                _ => return Ok(None),
            };
            if !matches!(
                commit.kind,
                OpKind::Mov {
                    dst,
                    src: SrcOperand::Reg(src),
                    width: OpWidth::W64,
                } if dst == rsp && src == popped
            ) {
                return Ok(None);
            }
            self.emit_jit_mem_op(
                load.guest_pc,
                true,
                Some(rsp),
                None,
                None,
                None,
                None,
                &Address::Direct(rsp),
                MemWidth::B8,
                SignExtend::Zero,
                0,
            )?;
            return Ok(Some(2));
        }

        let increment = match ops.get(idx + 1) {
            Some(op) if op.guest_pc == load.guest_pc => op,
            _ => return Ok(None),
        };
        let incremented = match increment.kind {
            OpKind::Add {
                dst: temporary @ VReg::Virtual(_),
                src1,
                src2: SrcOperand::Imm(2),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            } if src1 == rsp => temporary,
            _ => return Ok(None),
        };
        if virtual_definitions.get(&incremented) != Some(&1)
            || virtual_uses.get(&incremented) != Some(&1)
        {
            return Ok(None);
        }
        let increment_commit = match ops.get(idx + 2) {
            Some(op) if op.guest_pc == load.guest_pc => op,
            _ => return Ok(None),
        };
        let low_commit = match ops.get(idx + 3) {
            Some(op) if op.guest_pc == load.guest_pc => op,
            _ => return Ok(None),
        };
        if !matches!(
            increment_commit.kind,
            OpKind::Mov {
                dst,
                src: SrcOperand::Reg(src),
                width: OpWidth::W64,
            } if dst == rsp && src == incremented
        ) || !matches!(
            low_commit.kind,
            OpKind::Mov {
                dst,
                src: SrcOperand::Reg(src),
                width: OpWidth::W16,
            } if dst == rsp && src == popped
        ) {
            return Ok(None);
        }

        // Reserve 16 bytes without changing flags. The helper stores its
        // zero-extended return value at the caller-owned top slot. Its fault
        // path removes this reservation before returning to the trampoline.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -16);
        }
        self.emit_jit_mem_op(
            load.guest_pc,
            true,
            None,
            Some(16),
            None,
            None,
            None,
            &Address::Direct(rsp),
            MemWidth::B2,
            SignExtend::Zero,
            16,
        )?;
        self.lower_state_backed_stack_gpr_alu(
            false,
            rsp,
            rsp,
            &SrcOperand::Imm(2),
            OpWidth::W64,
            FlagUpdate::None,
        )?;

        // At this point GuestRegs.gpr[RSP] contains old_rsp + 2. Merge the
        // staged POP value into only its low 16 bits, preserving the carry into
        // bit 16 and every live guest register and flag.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_push(PhysReg::Rax);
            emitter.emit_push(PhysReg::Rcx);
        }
        self.emit_load_state_ptr_rax();
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rcx, PhysReg::Rsp, 16, OpWidth::W16);
            emitter.emit_mov_mr(PhysReg::Rax, 4 * 8, PhysReg::Rcx, OpWidth::W16);
            emitter.emit_pop(PhysReg::Rcx);
            emitter.emit_pop(PhysReg::Rax);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
        }
        Ok(Some(4))
    }

    /// Fuse a lifted PUSH into one fault-precise helper store followed by the
    /// state-backed RSP commit. The helper observes the old state snapshot and
    /// stores at `old_rsp - width`; only its success path performs the SUB.
    pub(crate) fn try_lower_jit_push(
        &mut self,
        ops: &[crate::smir::ir::ops::SmirOp],
        idx: usize,
        virtual_definitions: &HashMap<VReg, usize>,
        virtual_uses: &HashMap<VReg, usize>,
    ) -> Result<Option<usize>, LowerError> {
        let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
        let (sub_index, store_index, snapshot) = match ops.get(idx).map(|op| &op.kind) {
            Some(OpKind::Mov {
                dst: temporary @ VReg::Virtual(_),
                src: SrcOperand::Reg(source),
                width: OpWidth::W16 | OpWidth::W64,
            }) if *source == rsp => (idx + 1, idx + 2, Some(*temporary)),
            _ => (idx, idx + 1, None),
        };
        let sub = match ops.get(sub_index) {
            Some(op) => op,
            None => return Ok(None),
        };
        let delta = match sub.kind {
            OpKind::Sub {
                dst,
                src1,
                src2: SrcOperand::Imm(delta @ (2 | 8)),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            } if dst == rsp && src1 == rsp => delta,
            _ => return Ok(None),
        };
        let store = match ops.get(store_index) {
            Some(op) if op.guest_pc == sub.guest_pc => op,
            _ => return Ok(None),
        };
        if snapshot.is_some_and(|_| ops[idx].guest_pc != sub.guest_pc) {
            return Ok(None);
        }
        let expected_width = if delta == 2 {
            MemWidth::B2
        } else {
            MemWidth::B8
        };
        let store_source = match &store.kind {
            OpKind::Store {
                src,
                addr: Address::Direct(base),
                width,
            } if *base == rsp && *width == expected_width => *src,
            _ => return Ok(None),
        };
        let (source, consumed) = if let Some(temporary) = snapshot {
            let expected_snapshot_width = if delta == 2 {
                OpWidth::W16
            } else {
                OpWidth::W64
            };
            if store_source != temporary
                || !matches!(ops[idx].kind, OpKind::Mov { width, .. } if width == expected_snapshot_width)
                || virtual_definitions.get(&temporary) != Some(&1)
                || virtual_uses.get(&temporary) != Some(&1)
            {
                return Ok(None);
            }
            (rsp, 3)
        } else {
            let source_valid = matches!(store_source, VReg::Imm(_))
                || matches!(store_source, VReg::Arch(ArchReg::X86(reg)) if reg.gpr_index().is_some());
            if store_source == rsp || !source_valid {
                return Ok(None);
            }
            (store_source, 2)
        };

        let address = Address::BaseOffset {
            base: rsp,
            offset: -delta,
            disp_size: DispSize::Auto,
        };
        let (source_reg, source_imm) = match source {
            VReg::Imm(value) => (None, Some(value)),
            register => (Some(register), None),
        };
        self.emit_jit_mem_op(
            store.guest_pc,
            false,
            None,
            None,
            source_reg,
            source_imm,
            None,
            &address,
            expected_width,
            SignExtend::Zero,
            0,
        )?;
        self.lower_state_backed_stack_gpr_alu(
            true,
            rsp,
            rsp,
            &SrcOperand::Imm(delta),
            OpWidth::W64,
            FlagUpdate::None,
        )?;
        Ok(Some(consumed))
    }
}
