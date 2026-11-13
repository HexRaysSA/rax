//! Helper-backed original-VEX CMPccXADD lowering.

use super::*;

impl X86_64Lowerer {
    /// Lower one byte-validated original-VEX CMPccXADD transaction.
    ///
    /// The Rust helper owns both the locked write-back and the architectural
    /// old-value/flag commit. Zero means no transaction occurred and branches
    /// to exact direct replay at the source PC. Runtime is O(1) and emits O(1)
    /// host code.
    pub(crate) fn try_lower_jit_cmpccxadd(
        &mut self,
        block: &SmirBlock,
        idx: usize,
    ) -> Result<Option<usize>, LowerError> {
        let Some(sequence) = crate::smir::lower::runtime::x86_jit_cmpccxadd_sequence(
            block,
            idx,
            true,
            &self.x86_instruction_bytes,
        ) else {
            return Ok(None);
        };
        if !self.mem_helpers || !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "CMPccXADD requires JIT MMU helpers and precise deoptimization guards"
                    .to_string(),
            });
        }

        // Publish every live legacy GPR and the current materialized host-safe
        // RFLAGS image before crossing the Rust ABI. Guest RSP/RBP are already
        // authoritative in their state-backed slots.
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq; guest RAX is at [rsp+8]
        self.emit_spill_legacy_gprs_to_state_from_rax(8);
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(PhysReg::Rdx, PhysReg::Rsp, 0, OpWidth::W64);
            emitter.emit_mov_mr(
                PhysReg::Rax,
                X86_GUEST_RFLAGS_OFFSET,
                PhysReg::Rdx,
                OpWidth::W64,
            );
        }
        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_mem_helpers);
        self.emit_jit_mem_effective_address(sequence.addr, false)?;

        // SysV arguments: RDI=state, RSI=address, EDX=cmp register,
        // ECX=add register, R8D=size, R9D=condition code.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_ri(PhysReg::Rdx, i64::from(sequence.encoding.cmp), OpWidth::W32);
            emitter.emit_mov_ri(PhysReg::Rcx, i64::from(sequence.encoding.add), OpWidth::W32);
            emitter.emit_mov_ri(
                PhysReg::R8,
                i64::from(sequence.encoding.width.bytes()),
                OpWidth::W32,
            );
            emitter.emit_mov_ri(
                PhysReg::R9,
                i64::from(sequence.encoding.condition_code),
                OpWidth::W32,
            );
        }
        self.code.emit_u8(0xFC); // cld: platform ABI requires DF=0
        self.emit_host_c_helper_call(X86_GUEST_CMPCCXADD_FN_OFFSET as u32);

        self.code.emit_bytes(&[0x48, 0x8B, 0x4D]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        self.code.emit_bytes(&[0x48, 0x85, 0xC0]); // test rax,rax
        let fault = self.emit_jcc_placeholder(X86Cond::E);

        // Commit the helper's comparison flags through the saved image, then
        // reload every identity-mapped GPR from the helper's state result.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(
                PhysReg::Rdx,
                PhysReg::Rcx,
                X86_GUEST_RFLAGS_OFFSET,
                OpWidth::W64,
            );
            emitter.emit_mov_mr(PhysReg::Rsp, 0, PhysReg::Rdx, OpWidth::W64);
        }
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        if sequence.encoding.cmp == 5 {
            self.emit_sync_saved_rbp_from_state(PhysReg::Rcx);
        }
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq
        self.emit_flag_preserving_stack_pop8(); // discard saved pre-op RAX
        self.code.emit_u8(0xE9);
        let done = self.code.position();
        self.code.emit_u32(0);

        // The helper is non-committing on zero. Restore native register files
        // and the exact pre-operation flags before direct replay.
        self.patch_rel32_to_current(fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_mem_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D);
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(sequence.guest_pc);

        self.patch_rel32_to_current(done)?;
        Ok(Some(sequence.consumed))
    }
}
