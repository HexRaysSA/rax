//! State-backed x87 environment/control lowering.

use crate::smir::ir::ops::{OpKind, SmirOp, X86X87ControlKind, X86X87DataKind};
use crate::smir::ir::types::{DispSize, OpWidth};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{
    LowerError, X86_GUEST_CR0_OFFSET, X86_GUEST_X87_CONTROL_WORD_OFFSET,
    X86_GUEST_X87_DATA_PTR_OFFSET, X86_GUEST_X87_INSTR_PTR_OFFSET,
    X86_GUEST_X87_LAST_OPCODE_OFFSET, X86_GUEST_X87_PAYLOAD_HIGH_OFFSET,
    X86_GUEST_X87_PAYLOAD_OFFSET, X86_GUEST_X87_STATUS_WORD_OFFSET, X86_GUEST_X87_TAG_WORD_OFFSET,
    X86_STATE_PTR_AT_RBP,
};

use crate::smir::lower::x86_64::{BitTestRegOp, X86_64Lowerer, X86Cond, X86Emitter};

const CR0_EM: i64 = 1 << 2;
const CR0_NE: i64 = 1 << 5;
const CR0_TS: i64 = 1 << 3;
const FSW_ES: i64 = 1 << 7;

/// Validate every x87 operation with complete state-backed native semantics.
/// Prefix provenance is represented by a preceding APX guard, not a hint.
pub(crate) fn x86_x87_state_shape_valid(op: &SmirOp) -> bool {
    op.x86_hint.is_none() && op.kind.x86_x87_state_jit_shape_valid()
}

impl X86_64Lowerer {
    /// Deoptimize before the x87 instruction while CR0.EM or CR0.TS is set.
    /// Direct replay delivers #NM after the already-emitted encoding/APX guard
    /// and before any environment or GPR state is committed.
    fn emit_x86_x87_available_guard(
        &mut self,
        guest_pc: u64,
        waiting: bool,
    ) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "x87 control requires JIT fault-deoptimization guards".to_string(),
            });
        }

        self.code.emit_u8(0x9C); // pushfq
        self.code.emit_u8(0x50); // push rax
        self.emit_load_state_ptr_rax();
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_test_mi_disp(
                PhysReg::Rax,
                X86_GUEST_CR0_OFFSET,
                DispSize::Auto,
                CR0_EM | CR0_TS,
                OpWidth::W64,
            );
        }
        let available = self.emit_jcc_placeholder(X86Cond::E);

        self.code.emit_u8(0x58); // pop rax
        self.code.emit_u8(0x9D); // popfq
        self.emit_native_exit(guest_pc);

        self.patch_rel32_to_current(available)?;

        if waiting {
            self.emit_load_state_ptr_rax();
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_test_mi_disp(
                    PhysReg::Rax,
                    X86_GUEST_CR0_OFFSET,
                    DispSize::Auto,
                    CR0_NE,
                    OpWidth::W64,
                );
            }
            let legacy_error_mode = self.emit_jcc_placeholder(X86Cond::E);
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_test_mi_disp(
                    PhysReg::Rax,
                    X86_GUEST_X87_STATUS_WORD_OFFSET,
                    DispSize::Auto,
                    FSW_ES,
                    OpWidth::W64,
                );
            }
            let no_pending_error = self.emit_jcc_placeholder(X86Cond::E);

            self.code.emit_u8(0x58); // pop rax
            self.code.emit_u8(0x9D); // popfq
            self.emit_native_exit(guest_pc);

            self.patch_rel32_to_current(legacy_error_mode)?;
            self.patch_rel32_to_current(no_pending_error)?;
        }

        self.code.emit_u8(0x58); // pop rax
        self.code.emit_u8(0x9D); // popfq
        Ok(())
    }

    fn emit_x86_x87_tag_word(&mut self, tag_word: i64) {
        self.code.emit_u8(0x50); // push rax
        self.emit_load_state_ptr_rax();
        X86Emitter::new(&mut self.code).emit_mov_mi_disp(
            PhysReg::Rax,
            X86_GUEST_X87_TAG_WORD_OFFSET,
            DispSize::Auto,
            tag_word,
            OpWidth::W64,
        );
        self.code.emit_u8(0x58); // pop rax
    }

    fn emit_x86_x87_init(&mut self, guest_pc: u64) -> Result<(), LowerError> {
        self.emit_x86_x87_available_guard(guest_pc, false)?;
        self.code.emit_u8(0x50); // push rax
        self.emit_load_state_ptr_rax();
        let mut emitter = X86Emitter::new(&mut self.code);
        for (offset, value) in [
            (X86_GUEST_X87_CONTROL_WORD_OFFSET, 0x037F),
            (X86_GUEST_X87_STATUS_WORD_OFFSET, 0),
            (X86_GUEST_X87_TAG_WORD_OFFSET, 0xFFFF),
            (X86_GUEST_X87_DATA_PTR_OFFSET, 0),
            (X86_GUEST_X87_INSTR_PTR_OFFSET, 0),
            (X86_GUEST_X87_LAST_OPCODE_OFFSET, 0),
        ] {
            emitter.emit_mov_mi_disp(PhysReg::Rax, offset, DispSize::Auto, value, OpWidth::W64);
        }
        self.code.emit_u8(0x58); // pop rax
        Ok(())
    }

    fn emit_x86_x87_clear_exceptions(&mut self, guest_pc: u64) -> Result<(), LowerError> {
        self.emit_x86_x87_available_guard(guest_pc, false)?;
        self.code.emit_u8(0x9C); // pushfq
        self.code.emit_u8(0x50); // push rax
        self.emit_load_state_ptr_rax();
        X86Emitter::new(&mut self.code).emit_alu_mi_disp(
            4,
            PhysReg::Rax,
            X86_GUEST_X87_STATUS_WORD_OFFSET,
            DispSize::Auto,
            !0x80FF,
            OpWidth::W64,
        );
        self.code.emit_u8(0x58); // pop rax
        self.code.emit_u8(0x9D); // popfq
        Ok(())
    }

    fn emit_x86_x87_store_status_ax(&mut self, guest_pc: u64) -> Result<(), LowerError> {
        self.emit_x86_x87_available_guard(guest_pc, false)?;
        self.code.emit_u8(0x51); // push rcx
        let mut emitter = X86Emitter::new(&mut self.code);
        emitter.emit_mov_rm(
            PhysReg::Rcx,
            PhysReg::Rbp,
            X86_STATE_PTR_AT_RBP,
            OpWidth::W64,
        );
        emitter.emit_mov_rm(
            PhysReg::Rax,
            PhysReg::Rcx,
            X86_GUEST_X87_STATUS_WORD_OFFSET,
            OpWidth::W16,
        );
        self.code.emit_u8(0x59); // pop rcx
        Ok(())
    }

    /// Mark logical ST(i) empty. RAX holds the GuestRegs pointer; RCX and RDX
    /// are caller-saved scratch registers preserved by the enclosing sequence.
    fn emit_x86_x87_free_tag(&mut self, st: u8) {
        let mut emitter = X86Emitter::new(&mut self.code);
        emitter.emit_mov_rm(
            PhysReg::Rcx,
            PhysReg::Rax,
            X86_GUEST_X87_STATUS_WORD_OFFSET,
            OpWidth::W64,
        );
        emitter.emit_shr_ri(PhysReg::Rcx, 11, OpWidth::W64);
        emitter.emit_add_ri(PhysReg::Rcx, i64::from(st), OpWidth::W64);
        emitter.emit_and_ri(PhysReg::Rcx, 7, OpWidth::W64);
        emitter.emit_shl_ri(PhysReg::Rcx, 1, OpWidth::W64);
        emitter.emit_mov_ri(PhysReg::Rdx, 3, OpWidth::W64);
        emitter.emit_shl_cl(PhysReg::Rdx, OpWidth::W64);
        emitter.emit_mov_rm(
            PhysReg::Rcx,
            PhysReg::Rax,
            X86_GUEST_X87_TAG_WORD_OFFSET,
            OpWidth::W64,
        );
        emitter.emit_or_rr(PhysReg::Rcx, PhysReg::Rdx, OpWidth::W64);
        emitter.emit_mov_mr(
            PhysReg::Rax,
            X86_GUEST_X87_TAG_WORD_OFFSET,
            PhysReg::Rcx,
            OpWidth::W64,
        );
    }

    /// Rotate TOP by one. `clear_c1` selects the defined FINCSTP/FDECSTP C1=0
    /// behavior; FFREEP preserves all four architecturally undefined C bits.
    fn emit_x86_x87_rotate_top(&mut self, increment: bool, clear_c1: bool) {
        let mut emitter = X86Emitter::new(&mut self.code);
        emitter.emit_mov_rm(
            PhysReg::Rdx,
            PhysReg::Rax,
            X86_GUEST_X87_STATUS_WORD_OFFSET,
            OpWidth::W64,
        );
        emitter.emit_mov_rr(PhysReg::Rcx, PhysReg::Rdx, OpWidth::W64);
        emitter.emit_shr_ri(PhysReg::Rcx, 11, OpWidth::W64);
        if increment {
            emitter.emit_add_ri(PhysReg::Rcx, 1, OpWidth::W64);
        } else {
            emitter.emit_sub_ri(PhysReg::Rcx, 1, OpWidth::W64);
        }
        emitter.emit_and_ri(PhysReg::Rcx, 7, OpWidth::W64);
        emitter.emit_shl_ri(PhysReg::Rcx, 11, OpWidth::W64);
        let cleared = if clear_c1 { 0x3A00 } else { 0x3800 };
        emitter.emit_and_ri(PhysReg::Rdx, !cleared, OpWidth::W64);
        emitter.emit_or_rr(PhysReg::Rdx, PhysReg::Rcx, OpWidth::W64);
        emitter.emit_mov_mr(
            PhysReg::Rax,
            X86_GUEST_X87_STATUS_WORD_OFFSET,
            PhysReg::Rdx,
            OpWidth::W64,
        );
    }

    fn emit_x86_x87_record_data_op(&mut self, guest_pc: u64, fop: u16) {
        let mut emitter = X86Emitter::new(&mut self.code);
        emitter.emit_mov_ri_imm64(PhysReg::Rcx, guest_pc as i64);
        emitter.emit_mov_mr(
            PhysReg::Rax,
            X86_GUEST_X87_INSTR_PTR_OFFSET,
            PhysReg::Rcx,
            OpWidth::W64,
        );
        emitter.emit_mov_mi_disp(
            PhysReg::Rax,
            X86_GUEST_X87_LAST_OPCODE_OFFSET,
            DispSize::Auto,
            i64::from(fop & 0x07FF),
            OpWidth::W64,
        );
    }

    fn emit_x86_x87_stack_metadata(
        &mut self,
        kind: X86X87DataKind,
        st: u8,
        fop: u16,
        guest_pc: u64,
    ) -> Result<(), LowerError> {
        self.emit_x86_x87_available_guard(guest_pc, true)?;
        self.code.emit_u8(0x9C); // pushfq
        self.code.emit_u8(0x50); // push rax
        self.code.emit_u8(0x51); // push rcx
        self.code.emit_u8(0x52); // push rdx
        self.emit_load_state_ptr_rax();

        match kind {
            X86X87DataKind::Free => self.emit_x86_x87_free_tag(st),
            X86X87DataKind::FreePop => {
                self.emit_x86_x87_free_tag(st);
                self.emit_x86_x87_free_tag(0);
                self.emit_x86_x87_rotate_top(true, false);
            }
            X86X87DataKind::DecrementTop => self.emit_x86_x87_rotate_top(false, true),
            X86X87DataKind::IncrementTop => self.emit_x86_x87_rotate_top(true, true),
            _ => unreachable!("validated x87 stack metadata"),
        }
        self.emit_x86_x87_record_data_op(guest_pc, fop);

        self.code.emit_u8(0x5A); // pop rdx
        self.code.emit_u8(0x59); // pop rcx
        self.code.emit_u8(0x58); // pop rax
        self.code.emit_u8(0x9D); // popfq
        Ok(())
    }

    /// Apply FCHS/FABS to the direct engine's raw physical payload slot. Empty
    /// ST(0) deoptimizes before all state changes so direct replay can apply the
    /// masked or unmasked #IS response without duplicating exception policy in
    /// native code.
    fn emit_x86_x87_sign_operation(
        &mut self,
        kind: X86X87DataKind,
        fop: u16,
        guest_pc: u64,
    ) -> Result<(), LowerError> {
        self.emit_x86_x87_available_guard(guest_pc, true)?;
        self.code.emit_u8(0x9C); // pushfq
        self.code.emit_u8(0x50); // push rax
        self.code.emit_u8(0x51); // push rcx
        self.code.emit_u8(0x52); // push rdx
        self.emit_load_state_ptr_rax();

        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(
                PhysReg::Rcx,
                PhysReg::Rax,
                X86_GUEST_X87_STATUS_WORD_OFFSET,
                OpWidth::W64,
            );
            emitter.emit_shr_ri(PhysReg::Rcx, 11, OpWidth::W64);
            emitter.emit_and_ri(PhysReg::Rcx, 7, OpWidth::W64);
            emitter.emit_mov_rm(
                PhysReg::Rdx,
                PhysReg::Rax,
                X86_GUEST_X87_TAG_WORD_OFFSET,
                OpWidth::W64,
            );
            emitter.emit_shl_ri(PhysReg::Rcx, 1, OpWidth::W64);
            emitter.emit_shr_cl(PhysReg::Rdx, OpWidth::W64);
            emitter.emit_and_ri(PhysReg::Rdx, 3, OpWidth::W64);
            emitter.emit_cmp_ri(PhysReg::Rdx, 3, OpWidth::W64);
        }
        let nonempty = self.emit_jcc_placeholder(X86Cond::Ne);

        self.code.emit_u8(0x5A); // pop rdx
        self.code.emit_u8(0x59); // pop rcx
        self.code.emit_u8(0x58); // pop rax
        self.code.emit_u8(0x9D); // popfq
        self.emit_native_exit(guest_pc);

        self.patch_rel32_to_current(nonempty)?;
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_shr_ri(PhysReg::Rcx, 1, OpWidth::W64);
            emitter.emit_alu_mi_disp(
                4,
                PhysReg::Rax,
                X86_GUEST_X87_STATUS_WORD_OFFSET,
                DispSize::Auto,
                !0x0200,
                OpWidth::W64,
            );
            // The sign is bit 79 of the binary80 value: bit 15 of the
            // register's sign-and-exponent word.
            emitter.emit_lea_sib(
                PhysReg::Rdx,
                Some(PhysReg::Rax),
                PhysReg::Rcx,
                8,
                X86_GUEST_X87_PAYLOAD_HIGH_OFFSET,
            );
            emitter.emit_bit_test_mi_disp(
                if kind == X86X87DataKind::ChangeSign {
                    BitTestRegOp::Complement
                } else {
                    BitTestRegOp::Reset
                },
                PhysReg::Rdx,
                0,
                15,
                OpWidth::W64,
            );
        }
        self.emit_x86_x87_record_data_op(guest_pc, fop);

        self.code.emit_u8(0x5A); // pop rdx
        self.code.emit_u8(0x59); // pop rcx
        self.code.emit_u8(0x58); // pop rax
        self.code.emit_u8(0x9D); // popfq
        Ok(())
    }

    /// Register stores use the pre-pop physical source and destination. TOP is
    /// masked to 0..7, so each eight-byte access stays in the 64-byte payload.
    /// Empty sources exit before all commits for precise direct #IS handling.
    fn emit_x86_x87_store_operation(
        &mut self,
        st: u8,
        pop: bool,
        fop: u16,
        guest_pc: u64,
    ) -> Result<(), LowerError> {
        self.emit_x86_x87_available_guard(guest_pc, true)?;
        for byte in [0x9C, 0x50, 0x51, 0x52, 0x41, 0x50] {
            self.code.emit_u8(byte); // pushfq; push rax, rcx, rdx, r8
        }
        self.emit_load_state_ptr_rax();
        {
            let mut e = X86Emitter::new(&mut self.code);
            e.emit_mov_rm(
                PhysReg::Rcx,
                PhysReg::Rax,
                X86_GUEST_X87_STATUS_WORD_OFFSET,
                OpWidth::W64,
            );
            e.emit_shr_ri(PhysReg::Rcx, 11, OpWidth::W64);
            e.emit_and_ri(PhysReg::Rcx, 7, OpWidth::W64);
            e.emit_shl_ri(PhysReg::Rcx, 1, OpWidth::W64);
            e.emit_mov_rm(
                PhysReg::R8,
                PhysReg::Rax,
                X86_GUEST_X87_TAG_WORD_OFFSET,
                OpWidth::W64,
            );
            e.emit_shr_cl(PhysReg::R8, OpWidth::W64);
            e.emit_and_ri(PhysReg::R8, 3, OpWidth::W64);
            e.emit_cmp_ri(PhysReg::R8, 3, OpWidth::W64);
        }
        let nonempty = self.emit_jcc_placeholder(X86Cond::Ne);
        for byte in [0x41, 0x58, 0x5A, 0x59, 0x58, 0x9D] {
            self.code.emit_u8(byte); // pop r8, rdx, rcx, rax; popfq
        }
        self.emit_native_exit(guest_pc);
        self.patch_rel32_to_current(nonempty)?;
        {
            let mut e = X86Emitter::new(&mut self.code);
            e.emit_shr_ri(PhysReg::Rcx, 1, OpWidth::W64);
            e.emit_lea_sib(
                PhysReg::Rdx,
                Some(PhysReg::Rax),
                PhysReg::Rcx,
                8,
                X86_GUEST_X87_PAYLOAD_OFFSET,
            );
        }
        // The high words sit at a fixed distance from the significands in a
        // parallel eight-slot array: carry the source's across on the stack.
        let high_delta = X86_GUEST_X87_PAYLOAD_HIGH_OFFSET - X86_GUEST_X87_PAYLOAD_OFFSET;
        self.code.emit_u8(0xFF); // push qword [rdx + high_delta]
        self.code.emit_u8(0xB2);
        self.code.emit_i32(high_delta);
        {
            let mut e = X86Emitter::new(&mut self.code);
            e.emit_mov_rm(PhysReg::Rdx, PhysReg::Rdx, 0, OpWidth::W64);
            e.emit_add_ri(PhysReg::Rcx, i64::from(st), OpWidth::W64);
            e.emit_and_ri(PhysReg::Rcx, 7, OpWidth::W64);
            // Both copies use pre-pop TOP; R8 retains the original source tag.
            e.emit_lea_sib(
                PhysReg::Rcx,
                Some(PhysReg::Rax),
                PhysReg::Rcx,
                8,
                X86_GUEST_X87_PAYLOAD_OFFSET,
            );
            e.emit_mov_mr(PhysReg::Rcx, 0, PhysReg::Rdx, OpWidth::W64);
        }
        self.code.emit_u8(0x8F); // pop qword [rcx + high_delta]
        self.code.emit_u8(0x81);
        self.code.emit_i32(high_delta);
        {
            let mut e = X86Emitter::new(&mut self.code);
            e.emit_mov_rm(
                PhysReg::Rcx,
                PhysReg::Rax,
                X86_GUEST_X87_STATUS_WORD_OFFSET,
                OpWidth::W64,
            );
            e.emit_shr_ri(PhysReg::Rcx, 11, OpWidth::W64);
            e.emit_add_ri(PhysReg::Rcx, i64::from(st), OpWidth::W64);
            e.emit_and_ri(PhysReg::Rcx, 7, OpWidth::W64);
            e.emit_shl_ri(PhysReg::Rcx, 1, OpWidth::W64);
            e.emit_shl_cl(PhysReg::R8, OpWidth::W64);
            e.emit_mov_ri(PhysReg::Rdx, 3, OpWidth::W64);
            e.emit_shl_cl(PhysReg::Rdx, OpWidth::W64);
            e.emit_not(PhysReg::Rdx, OpWidth::W64);
            e.emit_mov_rm(
                PhysReg::Rcx,
                PhysReg::Rax,
                X86_GUEST_X87_TAG_WORD_OFFSET,
                OpWidth::W64,
            );
            e.emit_and_rr(PhysReg::Rcx, PhysReg::Rdx, OpWidth::W64);
            e.emit_or_rr(PhysReg::Rcx, PhysReg::R8, OpWidth::W64);
            e.emit_mov_mr(
                PhysReg::Rax,
                X86_GUEST_X87_TAG_WORD_OFFSET,
                PhysReg::Rcx,
                OpWidth::W64,
            );
            e.emit_alu_mi_disp(
                4,
                PhysReg::Rax,
                X86_GUEST_X87_STATUS_WORD_OFFSET,
                DispSize::Auto,
                !0x0200,
                OpWidth::W64,
            );
        }
        if pop {
            self.emit_x86_x87_free_tag(0);
            self.emit_x86_x87_rotate_top(true, true);
        }
        self.emit_x86_x87_record_data_op(guest_pc, fop);
        for byte in [0x41, 0x58, 0x5A, 0x59, 0x58, 0x9D] {
            self.code.emit_u8(byte);
        }
        Ok(())
    }

    pub(crate) fn lower_op_x87(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        match &op.kind {
            OpKind::X86X87Control { kind, .. }
                if matches!(
                    kind,
                    X86X87ControlKind::Init
                        | X86X87ControlKind::ClearExceptions
                        | X86X87ControlKind::EnterMmx
                        | X86X87ControlKind::EmptyMmx
                        | X86X87ControlKind::StoreStatusAx
                ) =>
            {
                if !x86_x87_state_shape_valid(op) {
                    return Err(LowerError::InvalidOperand {
                        op: format!("X86X87Control {kind:?}"),
                        operand: "requires an unhinted operand-free control".to_string(),
                    });
                }
                match kind {
                    X86X87ControlKind::Init => self.emit_x86_x87_init(op.guest_pc),
                    X86X87ControlKind::ClearExceptions => {
                        self.emit_x86_x87_clear_exceptions(op.guest_pc)
                    }
                    X86X87ControlKind::EnterMmx => {
                        self.emit_x86_x87_tag_word(0);
                        Ok(())
                    }
                    X86X87ControlKind::EmptyMmx => {
                        self.emit_x86_x87_tag_word(0xFFFF);
                        Ok(())
                    }
                    X86X87ControlKind::StoreStatusAx => {
                        self.emit_x86_x87_store_status_ax(op.guest_pc)
                    }
                    _ => unreachable!("filtered above"),
                }
            }
            OpKind::X86X87Data { kind, st, fop, .. } if kind.is_stack_metadata() => {
                if !x86_x87_state_shape_valid(op) {
                    return Err(LowerError::InvalidOperand {
                        op: format!("X86X87Data {kind:?}"),
                        operand: "requires an exact unhinted register encoding".to_string(),
                    });
                }
                self.emit_x86_x87_stack_metadata(*kind, *st, *fop, op.guest_pc)
            }
            OpKind::X86X87Data {
                kind: kind @ (X86X87DataKind::ChangeSign | X86X87DataKind::Absolute),
                fop,
                ..
            } => {
                if !x86_x87_state_shape_valid(op) {
                    return Err(LowerError::InvalidOperand {
                        op: format!("X86X87Data {kind:?}"),
                        operand: "requires an exact unhinted register encoding".to_string(),
                    });
                }
                self.emit_x86_x87_sign_operation(*kind, *fop, op.guest_pc)
            }
            OpKind::X86X87Data {
                kind: kind @ (X86X87DataKind::StoreRegister | X86X87DataKind::StorePopRegister),
                st,
                fop,
                ..
            } => {
                if !x86_x87_state_shape_valid(op) {
                    return Err(LowerError::InvalidOperand {
                        op: format!("X86X87Data {kind:?}"),
                        operand: "requires an exact unhinted register encoding".to_string(),
                    });
                }
                self.emit_x86_x87_store_operation(
                    *st,
                    *kind == X86X87DataKind::StorePopRegister,
                    *fop,
                    op.guest_pc,
                )
            }
            _ => self.lower_op_misc(op),
        }
    }
}
