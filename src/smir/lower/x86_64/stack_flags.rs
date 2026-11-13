//! Exact helper-backed lowering for x86 PUSHF/PUSHFQ and POPF/POPFQ.

use std::collections::HashMap;

use crate::smir::ir::ops::{OpKind, X86StackFlagsKind, X86StackFlagsOp};
use crate::smir::ir::types::{BlockId, OpWidth};
use crate::smir::ir::{SmirBlock, X86InstructionBytes};
use crate::smir::lift::x86_64::decode_prefixes;
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{LowerError, X86_GUEST_STACK_FLAGS_FN_OFFSET, X86_STATE_PTR_AT_RBP};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86StackFlagsEncoding {
    pub(crate) kind: X86StackFlagsKind,
    pub(crate) width: OpWidth,
    pub(crate) requires_apx: bool,
    pub(crate) next_pc: u64,
}

/// Recover and validate one exact long-mode 9C/9D source encoding. Runtime is
/// O(1), and no structured payload is trusted without matching retained bytes.
pub(crate) fn x86_stack_flags_encoding(
    block: &SmirBlock,
    op_index: usize,
    instruction_bytes: &HashMap<(BlockId, u64), X86InstructionBytes>,
) -> Option<X86StackFlagsEncoding> {
    let op = block.ops.get(op_index)?;
    let OpKind::X86StackFlags(X86StackFlagsOp {
        kind,
        width,
        requires_apx,
        next_pc,
    }) = &op.kind
    else {
        return None;
    };
    if op.x86_hint.is_some() {
        return None;
    }

    let source = instruction_bytes.get(&(block.id, op.guest_pc))?;
    let bytes = source.as_slice();
    let prefix = decode_prefixes(bytes).ok()?;
    if prefix.lock || prefix.rex2_m() {
        return None;
    }
    let opcode = *bytes.get(prefix.cursor)?;
    let encoded_kind = match opcode {
        0x9C => X86StackFlagsKind::Push,
        0x9D => X86StackFlagsKind::Pop,
        _ => return None,
    };
    let expected_len = prefix.cursor.checked_add(1)?;
    if bytes.len() != expected_len || bytes.len() > 15 {
        return None;
    }
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
    (*kind == encoded_kind
        && *width == encoded_width
        && *requires_apx == encoded_apx
        && *next_pc == encoded_next_pc)
        .then_some(X86StackFlagsEncoding {
            kind: encoded_kind,
            width: encoded_width,
            requires_apx: encoded_apx,
            next_pc: encoded_next_pc,
        })
}

impl X86_64Lowerer {
    /// Lower one exact stack-flags transaction. A successful PUSHF can continue
    /// in the current region after its state-backed RSP commit; POPF must leave
    /// so the bridge can import its complete RFLAGS override. Every failure
    /// leaves at `guest_pc` for exact direct replay. The return value is true
    /// only when the successful path is terminal.
    pub(crate) fn emit_x86_stack_flags(
        &mut self,
        block: &SmirBlock,
        op_index: usize,
    ) -> Result<bool, LowerError> {
        if !self.mem_helpers || !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "PUSHF/POPF requires JIT MMU helpers and precise deoptimization guards".into(),
            });
        }
        let encoding = x86_stack_flags_encoding(block, op_index, &self.x86_instruction_bytes)
            .ok_or_else(|| LowerError::InvalidOperand {
                op: "X86StackFlags".into(),
                operand: "requires exact 9C/9D provenance and a matching structured payload".into(),
            })?;

        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // push current native guest-status RFLAGS
        self.emit_spill_legacy_gprs_to_state_from_rax(8);
        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_mem_helpers);

        // SysV arguments: RDI=state, ESI=kind, EDX=width, ECX=APX required,
        // R8=current native status/DF image saved at [RSP].
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_ri(
                PhysReg::Rsi,
                match encoding.kind {
                    X86StackFlagsKind::Push => 0,
                    X86StackFlagsKind::Pop => 1,
                },
                OpWidth::W32,
            );
            emitter.emit_mov_ri(
                PhysReg::Rdx,
                i64::from(encoding.width.bits() / 8),
                OpWidth::W32,
            );
            emitter.emit_mov_ri(
                PhysReg::Rcx,
                i64::from(u8::from(encoding.requires_apx)),
                OpWidth::W32,
            );
            emitter.emit_mov_rm(PhysReg::R8, PhysReg::Rsp, 0, OpWidth::W64);
        }
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.emit_host_c_helper_call(X86_GUEST_STACK_FLAGS_FN_OFFSET as u32);

        self.code.emit_bytes(&[0x48, 0x8B, 0x4D]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state]
        self.code.emit_bytes(&[0x48, 0x85, 0xC0]); // test rax,rax
        let fault = self.emit_jcc_placeholder(X86Cond::E);

        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // restore pre-operation native flags
        self.emit_flag_preserving_stack_pop8(); // discard saved guest RAX
        let success_done = if encoding.kind == X86StackFlagsKind::Push {
            self.code.emit_u8(0xE9);
            let branch = self.code.position();
            self.code.emit_u32(0);
            Some(branch)
        } else {
            self.emit_x86_retirement();
            self.emit_native_exit(encoding.next_pc);
            None
        };

        self.patch_rel32_to_current(fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(block.ops[op_index].guest_pc);
        if let Some(branch) = success_done {
            self.patch_rel32_to_current(branch)?;
        }
        Ok(encoding.kind == X86StackFlagsKind::Pop)
    }
}
