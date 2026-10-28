//! Uncategorized lowering helpers

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
    /// Create a new x86_64 lowerer
    pub fn new() -> Self {
        X86_64Lowerer {
            code: CodeBuffer::with_capacity(4096),
            regalloc: RegAlloc::new(),
            block_offsets: HashMap::new(),
            relocations: Vec::new(),
            pending_jumps: Vec::new(),
            guest_base: 0,
            pcrel_adjust: true,
            jit_fault_deopt_guards: false,
            guest_pcrel_lea_immediates: false,
            block_guest_pcs: HashMap::new(),
            x86_instruction_bytes: HashMap::new(),
            pending_cond: None,
            native_exits: std::collections::HashMap::new(),
            x86_instruction_retirement: false,
            native_exit_edges: std::collections::HashMap::new(),
            mem_helpers: false,
            preserve_vector_mem_helpers: false,
            preserve_vector_call_helpers: false,
            preserve_vector_system_helpers: false,
            avx_ymm16_vector_state: false,
            native_vector_state_active: false,
            preserve_mmx_helpers: false,
            narrow_vector_opmask_helpers: false,
            call_helpers: false,
            epilogue_stack_patches: Vec::new(),
        }
    }

    pub(crate) fn try_lower_push_pop(
        &mut self,
        ops: &[crate::smir::ir::ops::SmirOp],
        idx: usize,
    ) -> Result<Option<usize>, LowerError> {
        if idx + 1 >= ops.len() {
            return Ok(None);
        }

        match (&ops[idx].kind, &ops[idx + 1].kind) {
            (
                OpKind::Sub {
                    dst,
                    src1,
                    src2: SrcOperand::Imm(8),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
                OpKind::Store {
                    src,
                    addr: Address::Direct(addr_base),
                    width: MemWidth::B8,
                },
            ) if *dst == *src1 && self.is_rsp(*dst) && self.is_rsp(*addr_base) => {
                if let VReg::Imm(val) = src {
                    let hint = ops[idx + 1].x86_hint;
                    let mut emitter = X86Emitter::new(&mut self.code);
                    match hint {
                        Some(X86OpHint::PushImm8) => {
                            emitter.emit_push_imm8(*val as i8);
                            return Ok(Some(2));
                        }
                        Some(X86OpHint::PushImm32) => {
                            emitter.emit_push_imm32(*val as i32);
                            return Ok(Some(2));
                        }
                        _ => {}
                    }
                }

                if matches!(src, VReg::Arch(ArchReg::X86(X86Reg::Rsp))) {
                    return Ok(None);
                }
                let src_reg = self.get_reg(*src)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_push(src_reg);
                return Ok(Some(2));
            }
            (
                OpKind::Load {
                    dst,
                    addr: Address::Direct(addr_base),
                    width: MemWidth::B8,
                    sign: SignExtend::Zero,
                },
                OpKind::Add {
                    dst: add_dst,
                    src1,
                    src2: SrcOperand::Imm(8),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
            ) if *add_dst == *src1 && self.is_rsp(*add_dst) && self.is_rsp(*addr_base) => {
                if matches!(dst, VReg::Arch(ArchReg::X86(X86Reg::Rsp))) {
                    return Ok(None);
                }
                let dst_reg = self.get_dst_reg(*dst)?;
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_pop(dst_reg);
                return Ok(Some(2));
            }
            _ => {}
        }

        Ok(None)
    }

    pub(crate) fn try_lower_vmem_binop(
        &mut self,
        ops: &[crate::smir::ir::ops::SmirOp],
        idx: usize,
    ) -> Result<Option<usize>, LowerError> {
        let (tmp, addr, width) = match ops.get(idx).map(|op| &op.kind) {
            Some(OpKind::VLoad { dst, addr, width }) => (*dst, addr, *width),
            _ => return Ok(None),
        };

        if width != VecWidth::V128 {
            return Ok(None);
        }

        let op = match ops.get(idx + 1) {
            Some(op) => op,
            None => return Ok(None),
        };

        match &op.kind {
            OpKind::VAdd {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } if *src2 == tmp && *dst == *src1 => {
                if *elem != VecElementType::I32 || *lanes != 4 {
                    return Ok(None);
                }
                let dst_reg = self.get_dst_reg(*dst)?;
                if !dst_reg.is_vec() {
                    return Err(LowerError::InvalidOperand {
                        op: "VAdd".to_string(),
                        operand: "destination must be vector register".to_string(),
                    });
                }
                if let Some(enc_hint) = self.vec_hint(op.x86_hint) {
                    let enc = VecEncoding { width, ..enc_hint };
                    self.emit_vec_mem(enc, dst_reg, Some(dst_reg), addr)?;
                } else {
                    if self.vec_requires_vex(&[dst_reg]) {
                        return Ok(None);
                    }
                    let prefix = self.sse_prefix(op.x86_hint);
                    let opcode = self.sse_opcode(op.x86_hint, 0xFE);
                    self.emit_sse_mov_mem(prefix, opcode, dst_reg, addr)?;
                }
                return Ok(Some(2));
            }
            OpKind::VMul {
                dst,
                src1,
                src2,
                elem,
                lanes,
            } if *src2 == tmp && *dst == *src1 => {
                if *elem != VecElementType::I32 || *lanes != 4 {
                    return Ok(None);
                }
                let dst_reg = self.get_dst_reg(*dst)?;
                if !dst_reg.is_vec() {
                    return Err(LowerError::InvalidOperand {
                        op: "VMul".to_string(),
                        operand: "destination must be vector register".to_string(),
                    });
                }
                if let Some(enc_hint) = self.vec_hint(op.x86_hint) {
                    let enc = VecEncoding { width, ..enc_hint };
                    self.emit_vec_mem(enc, dst_reg, Some(dst_reg), addr)?;
                } else {
                    if self.vec_requires_vex(&[dst_reg]) {
                        return Ok(None);
                    }
                    self.emit_sse_op38_mem(Some(0x66), 0x40, dst_reg, addr)?;
                }
                return Ok(Some(2));
            }
            _ => {}
        }

        Ok(None)
    }

    pub(crate) fn emit_flag_preserving_stack_pop8(&mut self) {
        // lea rsp,[rsp+8]  (48 8D 64 24 08)
        self.code.emit_u8(0x48);
        self.code.emit_u8(0x8D);
        self.code.emit_u8(0x64);
        self.code.emit_u8(0x24);
        self.code.emit_u8(0x08);
    }

    /// Fix up all pending jumps
    pub(crate) fn fixup_jumps(&mut self) -> Result<(), LowerError> {
        for (offset, target, kind) in self.pending_jumps.drain(..).collect::<Vec<_>>() {
            let target_offset =
                self.block_offsets
                    .get(&target)
                    .ok_or_else(|| LowerError::UndefinedLabel {
                        label: format!("block_{}", target.0),
                    })?;

            match kind {
                RelocKind::PcRel32 => {
                    let rel = (*target_offset as i64) - (offset as i64) - 4;
                    if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
                        return Err(LowerError::RelocationOutOfRange {
                            offset,
                            target: *target_offset,
                        });
                    }
                    self.code.patch_i32(offset, rel as i32);
                }
                RelocKind::PcRel8 => {
                    let rel = (*target_offset as i64) - (offset as i64) - 1;
                    if rel < -128 || rel > 127 {
                        return Err(LowerError::RelocationOutOfRange {
                            offset,
                            target: *target_offset,
                        });
                    }
                    self.code.data[offset] = rel as i8 as u8;
                }
                _ => {}
            }
        }

        Ok(())
    }
}
