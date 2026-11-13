//! Calls from staged integer operands to the host C callback ABI.
//!
//! Callers stage up to six integer/pointer arguments in System V registers.
//! Unix emits its original call bytes. Windows reserves its 32-byte home area,
//! moves the first four arguments into RCX/RDX/R8/R9 and places later arguments
//! on the stack. A two-word load result uses a hidden return buffer on Windows.

use super::{X86_64Lowerer, X86Emitter};
#[cfg(windows)]
use crate::smir::ir::types::OpWidth;
use crate::smir::lower::regalloc::PhysReg;

impl X86_64Lowerer {
    pub(super) fn emit_host_c_helper_call(&mut self, offset: u32) {
        #[cfg(not(windows))]
        {
            self.code.emit_bytes(&[0xff, 0x90]);
            self.code.emit_u32(offset);
        }
        #[cfg(windows)]
        {
            X86Emitter::new(&mut self.code).emit_mov_rm(
                PhysReg::R11,
                PhysReg::Rax,
                offset as i32,
                OpWidth::W64,
            );
            self.emit_host_c_helper_reg(
                PhysReg::R11,
                offset == crate::smir::lower::X86_GUEST_LOAD_FN_OFFSET as u32,
            );
        }
    }

    pub(super) fn emit_host_c_helper_reg(&mut self, target: PhysReg, returns_pair: bool) {
        emit_host_c_call(&mut self.code, target, returns_pair);
    }
}

/// Entry RSP is 16-byte aligned. Callers preserve their live state and flags.
/// Operands are staged in RDI, RSI, RDX, RCX, R8, R9; results are normalized to
/// RAX, or RAX/RDX for a repr(C) pair of two u64 values.
pub(crate) fn emit_host_c_call(
    code: &mut crate::smir::lower::CodeBuffer,
    target: PhysReg,
    returns_pair: bool,
) {
    #[cfg(not(windows))]
    {
        let _ = returns_pair;
        X86Emitter::new(code).emit_call_reg(target);
    }
    #[cfg(windows)]
    {
        // [0,32): home area; [32,56): stack arguments; [64,80): result;
        // [96,144): six staged operands; [144,152): callback address.
        const FRAME: i64 = 160;
        const ARGUMENTS: i32 = 96;
        const TARGET: i32 = 144;
        const RESULT: i32 = 64;
        let mut emitter = X86Emitter::new(code);
        emitter.emit_sub_ri(PhysReg::Rsp, FRAME, OpWidth::W64);
        for (i, source) in [
            PhysReg::Rdi,
            PhysReg::Rsi,
            PhysReg::Rdx,
            PhysReg::Rcx,
            PhysReg::R8,
            PhysReg::R9,
        ]
        .into_iter()
        .enumerate()
        {
            emitter.emit_mov_mr(PhysReg::Rsp, ARGUMENTS + i as i32 * 8, source, OpWidth::W64);
        }
        emitter.emit_mov_mr(PhysReg::Rsp, TARGET, target, OpWidth::W64);
        if returns_pair {
            emitter.emit_lea(PhysReg::Rcx, PhysReg::Rsp, RESULT);
        }
        let shift = usize::from(returns_pair);
        for i in 0..6usize {
            let position = i + shift;
            let source = ARGUMENTS + i as i32 * 8;
            if position < 4 {
                let target = [PhysReg::Rcx, PhysReg::Rdx, PhysReg::R8, PhysReg::R9][position];
                emitter.emit_mov_rm(target, PhysReg::Rsp, source, OpWidth::W64);
            } else {
                emitter.emit_mov_rm(PhysReg::R10, PhysReg::Rsp, source, OpWidth::W64);
                emitter.emit_mov_mr(
                    PhysReg::Rsp,
                    32 + (position as i32 - 4) * 8,
                    PhysReg::R10,
                    OpWidth::W64,
                );
            }
        }
        emitter.emit_mov_rm(PhysReg::R11, PhysReg::Rsp, TARGET, OpWidth::W64);
        emitter.emit_call_reg(PhysReg::R11);
        if returns_pair {
            emitter.emit_mov_rm(PhysReg::Rax, PhysReg::Rsp, RESULT, OpWidth::W64);
            emitter.emit_mov_rm(PhysReg::Rdx, PhysReg::Rsp, RESULT + 8, OpWidth::W64);
        }
        emitter.emit_add_ri(PhysReg::Rsp, FRAME, OpWidth::W64);
    }
}

#[cfg(all(test, feature = "smir-jit", target_arch = "x86_64"))]
mod tests;
