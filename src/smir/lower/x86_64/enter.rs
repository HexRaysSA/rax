//! Exact helper-backed lowering for x86 `ENTER imm16, imm8`.

use std::collections::HashMap;

use crate::smir::ir::ops::{OpKind, X86EnterOp};
use crate::smir::ir::types::{BlockId, OpWidth};
use crate::smir::ir::{SmirBlock, X86InstructionBytes};
use crate::smir::lift::x86_64::decode_prefixes;
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{LowerError, X86_GUEST_ENTER_FN_OFFSET, X86_STATE_PTR_AT_RBP};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86EnterEncoding {
    pub(crate) allocation_size: u16,
    pub(crate) nesting_level: u8,
    pub(crate) width: OpWidth,
    pub(crate) requires_apx: bool,
    pub(crate) next_pc: u64,
}

/// Recover and validate one exact long-mode ENTER source encoding and its
/// dedicated SMIR payload. Runtime is O(1); no source-derived field is trusted
/// without matching the retained instruction bytes.
pub(crate) fn x86_enter_encoding(
    block: &SmirBlock,
    op_index: usize,
    instruction_bytes: &HashMap<(BlockId, u64), X86InstructionBytes>,
) -> Option<X86EnterEncoding> {
    let op = block.ops.get(op_index)?;
    let OpKind::X86Enter(X86EnterOp {
        allocation_size,
        nesting_level,
        width,
        requires_apx,
        next_pc,
    }) = &op.kind
    else {
        return None;
    };
    if op.x86_hint.is_some() || *nesting_level >= 32 {
        return None;
    }
    let source = instruction_bytes.get(&(block.id, op.guest_pc))?;
    let bytes = source.as_slice();
    let prefix = decode_prefixes(bytes).ok()?;
    if prefix.lock || prefix.rex2_m() || bytes.get(prefix.cursor) != Some(&0xC8) {
        return None;
    }
    let expected_len = prefix.cursor.checked_add(4)?;
    if bytes.len() != expected_len || bytes.len() > 15 {
        return None;
    }
    let encoded_allocation =
        u16::from_le_bytes([bytes[prefix.cursor + 1], bytes[prefix.cursor + 2]]);
    let encoded_nesting = bytes[prefix.cursor + 3] & 0x1F;
    let encoded_width = if prefix.operand_size_override && !prefix.rex_w() {
        OpWidth::W16
    } else {
        OpWidth::W64
    };
    let encoded_apx = prefix.rex2.is_some();
    let encoded_next_pc = op.guest_pc.checked_add(bytes.len() as u64)?;
    if block.ops.iter().enumerate().any(|(index, candidate)| {
        index != op_index
            && candidate.guest_pc >= op.guest_pc
            && candidate.guest_pc < encoded_next_pc
    }) {
        return None;
    }
    (*allocation_size == encoded_allocation
        && *nesting_level == encoded_nesting
        && *width == encoded_width
        && *requires_apx == encoded_apx
        && *next_pc == encoded_next_pc)
        .then_some(X86EnterEncoding {
            allocation_size: encoded_allocation,
            nesting_level: encoded_nesting,
            width: encoded_width,
            requires_apx: encoded_apx,
            next_pc: encoded_next_pc,
        })
}

impl X86_64Lowerer {
    /// Return true after lowering one exact ENTER helper transaction.
    pub(crate) fn emit_x86_enter_if_present(
        &mut self,
        block: &SmirBlock,
        op_index: usize,
    ) -> Result<bool, LowerError> {
        if !matches!(block.ops[op_index].kind, OpKind::X86Enter(..)) {
            return Ok(false);
        }
        if !self.mem_helpers || !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "ENTER requires JIT MMU helpers and precise deoptimization guards".into(),
            });
        }
        let encoding = x86_enter_encoding(block, op_index, &self.x86_instruction_bytes)
            .ok_or_else(|| LowerError::InvalidOperand {
                op: "X86Enter".into(),
                operand: "requires exact C8 iw ib provenance and matching masked payload".into(),
            })?;

        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq; helper call remains 16-byte aligned
        self.emit_spill_legacy_gprs_to_state_from_rax(8);
        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_mem_helpers);

        // SysV arguments: RDI=state, ESI=allocation, EDX=nesting,
        // ECX=operand width in bytes, R8D=REX2/APX requirement.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_ri(
                PhysReg::Rsi,
                i64::from(encoding.allocation_size),
                OpWidth::W32,
            );
            emitter.emit_mov_ri(
                PhysReg::Rdx,
                i64::from(encoding.nesting_level),
                OpWidth::W32,
            );
            emitter.emit_mov_ri(
                PhysReg::Rcx,
                i64::from(encoding.width.bits() / 8),
                OpWidth::W32,
            );
            emitter.emit_mov_ri(
                PhysReg::R8,
                i64::from(u8::from(encoding.requires_apx)),
                OpWidth::W32,
            );
        }
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.emit_host_c_helper_call(X86_GUEST_ENTER_FN_OFFSET as u32);

        self.code.emit_bytes(&[0x48, 0x8B, 0x4D]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state]
        self.code.emit_bytes(&[0x48, 0x85, 0xC0]); // test rax,rax
        let fault = self.emit_jcc_placeholder(X86Cond::E);

        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_sync_saved_rbp_from_state(PhysReg::Rcx);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.code.emit_u8(0xE9);
        let done = self.code.position();
        self.code.emit_u32(0);

        self.patch_rel32_to_current(fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(block.ops[op_index].guest_pc);
        self.patch_rel32_to_current(done)?;
        Ok(true)
    }
}
