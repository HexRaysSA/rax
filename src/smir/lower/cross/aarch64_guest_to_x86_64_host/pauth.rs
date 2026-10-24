//! SysV calls into the same full guest-state helper used by the AArch64 host.

use super::*;
use crate::smir::lower::Aarch64GuestRegs;

impl Aarch64X86_64Lowerer {
    /// Enable only with `Aarch64PauthRuntime::run` or an equivalent scoped ABI.
    pub fn set_pauth_helpers(&mut self, enabled: bool) {
        self.pauth_helpers = enabled;
    }

    pub(super) fn lower_pauth_helper(
        &mut self,
        phase: u64,
        raw: u32,
        pc: u64,
        features: u64,
    ) -> Result<(), LowerError> {
        if !self.pauth_helpers {
            return Err(LowerError::UnsupportedOp {
                op: "AArch64 PAuth scoped helper ABI is disabled".into(),
            });
        }
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(B3, STATE, Aarch64GuestRegs::PAUTH_FN_OFFSET, OpWidth::W64);
            emitter.emit_test_rr(B3, B3, OpWidth::W64);
        }
        let absent = self.emit_jcc_placeholder(X86Cond::E);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_ri(PhysReg::Rsi, phase as i64, OpWidth::W64);
            emitter.emit_mov_ri(PhysReg::Rdx, i64::from(raw), OpWidth::W64);
            emitter.emit_mov_ri(PhysReg::Rcx, pc as i64, OpWidth::W64);
            emitter.emit_mov_ri(PhysReg::R8, features as i64, OpWidth::W64);
            // SysV entry RSP is 8 mod 16; the prologue's PUSH RBP and 16-byte
            // frame make it aligned. Save the caller-saved persistent RDI and
            // add 8 bytes so CALL still observes 16-byte alignment.
            emitter.emit_push(STATE);
            emitter.emit_sub_ri(PhysReg::Rsp, 8, OpWidth::W64);
            emitter.emit_call_reg(B3);
            emitter.emit_add_ri(PhysReg::Rsp, 8, OpWidth::W64);
            emitter.emit_pop(STATE);
            emitter.emit_test_rr(ACC, ACC, OpWidth::W64);
        }
        let success = self.emit_jcc_placeholder(X86Cond::Ne);
        self.emit_epilogue(); // exact error and PC are retained by the helper
        self.patch_rel32_to_current(absent)?;
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_ri(ACC, pc as i64, OpWidth::W64);
            emitter.emit_mov_mr(STATE, A64_PC_OFFSET, ACC, OpWidth::W64);
            emitter.emit_mov_rm(
                ACC,
                STATE,
                Aarch64GuestRegs::EXIT_FLAGS_OFFSET,
                OpWidth::W64,
            );
            emitter.emit_or_ri(ACC, Aarch64GuestRegs::EXIT_VALID as i64, OpWidth::W64);
            emitter.emit_mov_mr(
                STATE,
                Aarch64GuestRegs::EXIT_FLAGS_OFFSET,
                ACC,
                OpWidth::W64,
            );
        }
        self.emit_epilogue();
        self.patch_rel32_to_current(success)
    }
}
