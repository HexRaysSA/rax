//! Exact, helper-backed scalar x86 port-I/O lowering.

use std::collections::HashMap;

use crate::smir::ir::ops::{OpKind, SmirOp};
use crate::smir::ir::types::{ArchReg, BlockId, MemWidth, OpWidth, VReg, X86Reg};
use crate::smir::ir::{SmirBlock, X86InstructionBytes};
use crate::smir::lift::x86_64::decode_prefixes;
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{LowerError, X86_GUEST_IO_FN_OFFSET, X86_STATE_PTR_AT_RBP};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum X86IoPort {
    Immediate(u16),
    Dx,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct X86IoEncoding {
    pub(crate) port: X86IoPort,
    pub(crate) size: u8,
    pub(crate) output: bool,
    pub(crate) next_pc: u64,
}

/// Recover and validate the exact source encoding for one scalar `IN`/`OUT`.
/// The source PC must own exactly one SMIR operation, preventing malformed IR
/// from hiding guards or additional effects behind a terminal external exit.
pub(crate) fn x86_io_encoding(
    block: &SmirBlock,
    op_index: usize,
    instruction_bytes: &HashMap<(BlockId, u64), X86InstructionBytes>,
) -> Option<X86IoEncoding> {
    let op = block.ops.get(op_index)?;
    if op.x86_hint.is_some()
        || block
            .ops
            .iter()
            .filter(|candidate| candidate.guest_pc == op.guest_pc)
            .count()
            != 1
    {
        return None;
    }
    let source = instruction_bytes.get(&(block.id, op.guest_pc))?;
    let bytes = source.as_slice();
    let prefix = decode_prefixes(bytes).ok()?;
    if prefix.lock || prefix.rex2.is_some() {
        return None;
    }
    let opcode = *bytes.get(prefix.cursor)?;
    let immediate = matches!(opcode, 0xE4..=0xE7);
    let expected_len = prefix.cursor.checked_add(1 + usize::from(immediate))?;
    if bytes.len() != expected_len {
        return None;
    }

    let size = match opcode {
        0xE4 | 0xE6 | 0xEC | 0xEE => 1,
        0xE5 | 0xE7 | 0xED | 0xEF => {
            // REX.W overrides a preceding 0x66. Port I/O still has no 64-bit
            // form, so the resulting architectural width is 32 bits.
            if prefix.operand_size_override && !prefix.rex_w() {
                2
            } else {
                4
            }
        }
        _ => return None,
    };
    let output = matches!(opcode, 0xE6 | 0xE7 | 0xEE | 0xEF);
    let encoded_port = if immediate {
        X86IoPort::Immediate(u16::from(bytes[prefix.cursor + 1]))
    } else {
        X86IoPort::Dx
    };
    let expected_width = match size {
        1 => MemWidth::B1,
        2 => MemWidth::B2,
        4 => MemWidth::B4,
        _ => unreachable!("validated scalar I/O width"),
    };
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rdx = VReg::Arch(ArchReg::X86(X86Reg::Rdx));
    let shape_matches = match &op.kind {
        OpKind::IoIn { dst, port, width } => {
            !output
                && *dst == rax
                && *width == expected_width
                && match (port, encoded_port) {
                    (VReg::Imm(value), X86IoPort::Immediate(encoded)) => {
                        *value == i64::from(encoded)
                    }
                    (candidate, X86IoPort::Dx) => *candidate == rdx,
                    _ => false,
                }
        }
        OpKind::IoOut { port, value, width } => {
            output
                && *value == rax
                && *width == expected_width
                && match (port, encoded_port) {
                    (VReg::Imm(value), X86IoPort::Immediate(encoded)) => {
                        *value == i64::from(encoded)
                    }
                    (candidate, X86IoPort::Dx) => *candidate == rdx,
                    _ => false,
                }
        }
        _ => false,
    };
    shape_matches.then_some(X86IoEncoding {
        port: encoded_port,
        size,
        output,
        next_pc: op.guest_pc.checked_add(bytes.len() as u64)?,
    })
}

impl X86_64Lowerer {
    /// Return true after emitting a terminal scalar-I/O helper frontier.
    pub(crate) fn emit_x86_io_if_present(
        &mut self,
        block: &SmirBlock,
        op_index: usize,
    ) -> Result<bool, LowerError> {
        if !matches!(
            block.ops[op_index].kind,
            OpKind::IoIn { .. } | OpKind::IoOut { .. }
        ) {
            return Ok(false);
        }
        self.emit_x86_io(block, op_index)?;
        Ok(true)
    }

    /// Lower one scalar port transfer into a dynamic permission helper and an
    /// exact external-exit frontier. Both paths restore all native state;
    /// helper failure replays the instruction directly at its source PC.
    fn emit_x86_io(&mut self, block: &SmirBlock, op_index: usize) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "scalar port I/O requires JIT fault-deoptimization guards".to_string(),
            });
        }
        let encoding =
            x86_io_encoding(block, op_index, &self.x86_instruction_bytes).ok_or_else(|| {
                LowerError::InvalidOperand {
                    op: "scalar port I/O".to_string(),
                    operand:
                        "requires exact E4-E7/EC-EF provenance and canonical RAX/DX SMIR shape"
                            .to_string(),
                }
            })?;

        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq; helper call remains 16-byte aligned
        self.emit_spill_legacy_gprs_to_state_from_rax(8);
        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_system_helpers);

        // SysV arguments: RDI=state, ESI=zero-extended port, EDX=size,
        // ECX=output direction. Dynamic ports read the published low DX.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            match encoding.port {
                X86IoPort::Immediate(port) => {
                    emitter.emit_mov_ri(PhysReg::Rsi, i64::from(port), OpWidth::W32);
                }
                X86IoPort::Dx => {
                    emitter.emit_mov_rm(PhysReg::Rsi, PhysReg::Rax, 2 * 8, OpWidth::W32);
                }
            }
            emitter.emit_mov_ri(PhysReg::Rdx, i64::from(encoding.size), OpWidth::W32);
            emitter.emit_mov_ri(
                PhysReg::Rcx,
                i64::from(u8::from(encoding.output)),
                OpWidth::W32,
            );
        }
        if encoding.port == X86IoPort::Dx {
            self.code.emit_bytes(&[0x81, 0xE6, 0xFF, 0xFF, 0x00, 0x00]); // and esi,0xffff
        }
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.code.emit_u8(0xFF);
        self.code.emit_u8(0x90); // call qword [rax+io_fn]
        self.code.emit_u32(X86_GUEST_IO_FN_OFFSET as u32);

        self.code.emit_bytes(&[0x48, 0x8B, 0x4D]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        self.code.emit_bytes(&[0x48, 0x85, 0xC0]); // test rax,rax
        let fault = self.emit_jcc_placeholder(X86Cond::E);

        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_x86_retirement();
        self.emit_native_exit(encoding.next_pc);

        self.patch_rel32_to_current(fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(block.ops[op_index].guest_pc);
        Ok(())
    }
}
