//! Native-stack alias safety for guest RSP/RBP.

use super::*;

impl X86_64Lowerer {
    pub(crate) fn native_stack_dst(vreg: VReg) -> Option<X86Reg> {
        match vreg {
            VReg::Arch(ArchReg::X86(reg @ (X86Reg::Rsp | X86Reg::Rbp))) => Some(reg),
            _ => None,
        }
    }

    pub(crate) fn ensure_native_stack_dst_safe(vreg: VReg) -> Result<(), LowerError> {
        if let Some(reg) = Self::native_stack_dst(vreg) {
            return Err(LowerError::InvalidRegister(format!(
                "guest {reg:?} cannot be a native lowerer destination"
            )));
        }
        Ok(())
    }

    pub(crate) fn ensure_native_stack_dests_safe(
        op: &SmirOp,
        mem_helpers: bool,
    ) -> Result<(), LowerError> {
        // A helper-backed load delivers its result into the destination's
        // `GuestRegs` slot (and re-synchronizes the prologue-saved guest RBP
        // word), never into the host stack/frame register of the same name.
        if mem_helpers && matches!(&op.kind, OpKind::Load { .. }) {
            return Ok(());
        }
        if Self::mov_touches_state_backed_gpr(&op.kind)
            || matches!(
                &op.kind,
                OpKind::X86Opmask(opmask) if x86_opmask_native_shape_valid(opmask)
            )
            || Self::alu_touches_state_backed_stack_gpr(&op.kind)
            || x86_scalar_alu_immediate_valid(op)
            || x86_state_backed_gpr_lea_valid(op)
            || x86_state_backed_stack_group1_valid(op)
            || x86_state_backed_gpr_extend_valid(op)
            || x86_state_backed_gpr_cmove_valid(op)
            || x86_state_backed_gpr_setcc_valid(op)
            || x86_state_backed_gpr_not_valid(op)
            || x86_state_backed_gpr_neg_valid(op)
            || x86_state_backed_gpr_inc_dec_valid(op)
            || x86_state_backed_gpr_rotate_valid(op)
            || x86_state_backed_gpr_shift_valid(op)
            || x86_shift_group6_shape_valid(op)
            || x86_state_backed_gpr_carry_rotate_valid(op)
            || x86_state_backed_gpr_double_shift_valid(op)
            || x86_state_backed_gpr_count_valid(op)
            || x86_state_backed_gpr_bit_scan_valid(op)
            || x86_state_backed_gpr_bit_test_valid(op)
            || x86_state_backed_gpr_crc32_valid(op)
            || x86_state_backed_gpr_and_not_valid(op)
            || x86_state_backed_gpr_bextr_bzhi_valid(op)
            || x86_state_backed_gpr_bls_valid(op)
            || x86_state_backed_gpr_tbm_valid(op)
            || x86_state_backed_gpr_adx_valid(op)
            || x86_state_backed_gpr_pdep_pext_valid(op)
            || x86_state_backed_gpr_mulx_valid(op)
            || x86_state_multiply_valid(op)
            || x86_state_random_valid(op)
            || x86_state_backed_gpr_bswap_valid(op)
            || x86_state_backed_gpr_xchg_valid(op)
            || x86_cmpxchg_shape_valid(op)
            || x86_xadd_shape_valid(op)
            || x86_fsgsbase_shape_valid(&op.kind)
            || x86_read_control_shape_valid(&op.kind)
            || x86_rdpid_shape_valid(&op.kind)
            || x86_smsw_shape_valid(&op.kind)
            || x86_system_selector_store_shape_valid(op)
            || x86_system_selector_load_shape_valid(op)
            || x86_selector_query_shape_valid(op)
            || x86_lmsw_shape_valid(op)
            || x86_read_debug_shape_valid(&op.kind)
            || x86_write_debug_shape_valid(&op.kind)
            // Dedicated fast-system-transfer, ENTER, LEAVE, and PUSHF/POPF lowering
            // never maps architectural RSP/RBP onto host RSP/RBP. Their exact
            // shape/ownership validators run before state-backed commits in
            // `lower_block`.
            || matches!(
                op.kind,
                OpKind::X86FastSystemTransfer(..)
                    | OpKind::X86Enter(..)
                    | OpKind::X86Leave(..)
                    | OpKind::X86StackFlags(..)
            )
        {
            return Ok(());
        }
        for dst in op.kind.dests() {
            Self::ensure_native_stack_dst_safe(dst)?;
        }
        Ok(())
    }

    pub(crate) fn ensure_native_stack_memory_safe(
        op: &SmirOp,
        mem_helpers: bool,
    ) -> Result<(), LowerError> {
        if mem_helpers {
            return Ok(());
        }
        let address = match &op.kind {
            OpKind::Load { addr, .. } | OpKind::Store { addr, .. } => addr,
            _ => return Ok(()),
        };
        if let Some(reg) = address.regs().into_iter().find_map(Self::native_stack_dst) {
            return Err(LowerError::InvalidRegister(format!(
                "guest {reg:?} cannot address native memory without MMU helpers"
            )));
        }
        Ok(())
    }

    pub(crate) fn ensure_count_native_stack_safe(
        op: &'static str,
        dst_reg: PhysReg,
        src_reg: PhysReg,
    ) -> Result<(), LowerError> {
        if matches!(dst_reg, PhysReg::Rsp | PhysReg::Rbp)
            || matches!(src_reg, PhysReg::Rsp | PhysReg::Rbp)
        {
            return Err(LowerError::InvalidOperand {
                op: op.to_string(),
                operand: "RSP/RBP operands are not safe with flag-preserving count lowering"
                    .to_string(),
            });
        }

        Ok(())
    }
}
