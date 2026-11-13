//! Optional controller-backed CR8 read through the append-only frame callback.
use super::*;
use crate::smir::lower::{X86_GUEST_CONTROL_READ_FN_OFFSET, X86_STATE_PTR_AT_RBP};
impl X86_64Lowerer {
    pub(super) fn emit_live_cr8_read(&mut self, guest_pc: u64) -> Result<(), LowerError> {
        self.code.emit_bytes(&[0x48, 0x83, 0xb8]); // cmp qword [rax+callback],0
        self.code.emit_u32(X86_GUEST_CONTROL_READ_FN_OFFSET as u32);
        self.code.emit_u8(0);
        let absent = self.emit_jcc_placeholder(X86Cond::E);
        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_system_helpers);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
        }
        self.code.emit_u8(0xfc); // SysV requires DF clear across the Rust call.
        self.emit_host_c_helper_call(X86_GUEST_CONTROL_READ_FN_OFFSET as u32);
        self.code.emit_bytes(&[0x48, 0x8b, 0x4d]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8);
        self.code.emit_bytes(&[0x48, 0x85, 0xc0]);
        let failed = self.emit_jcc_placeholder(X86Cond::E);
        self.code.emit_bytes(&[0x48, 0xff, 0xc8]); // dec rax: CR8+1 -> CR8
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_mr(
                PhysReg::Rcx,
                X86_GUEST_CR8_OFFSET,
                PhysReg::Rax,
                OpWidth::W64,
            );
        }
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0xe9);
        let done = self.code.position();
        self.code.emit_u32(0);
        self.patch_rel32_to_current(failed)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9d);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(guest_pc);
        self.patch_rel32_to_current(done)?;
        self.patch_rel32_to_current(absent)?;
        Ok(())
    }
}
