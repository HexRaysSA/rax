//! Operation-local native-clobber predicates, after exact sequence matching.

use super::*;
use crate::smir::ir::ops::{OpKind, SmirOp, X86OpHint};
use crate::smir::ir::types::{ArchReg, VReg, X86Reg};

pub(super) fn operation_is_clobber_safe(
    op: &SmirOp,
    allow_mem: bool,
    io_ok: bool,
    enter_ok: bool,
    leave_ok: bool,
    stack_flags_ok: bool,
) -> bool {
    if crate::smir::lower::x86_64::x86_scalar_alu_immediate_candidate(op) {
        return crate::smir::lower::x86_64::x86_scalar_alu_immediate_valid(op);
    }
    // The native trampoline runs the region on the HOST stack: guest RSP is
    // never loaded into the host RSP, and the lowerer's prologue repurposes RBP
    // as the frame pointer. Validated MOV forms use GuestRegs slots and keep the
    // prologue's saved guest RBP coherent; other RSP/RBP operations would still
    // compute against host stack state and therefore remain ineligible.
    let touches_sp_bp = |v: &VReg| {
        matches!(
            v,
            VReg::Arch(ArchReg::X86(X86Reg::Rsp)) | VReg::Arch(ArchReg::X86(X86Reg::Rbp))
        )
    };

    // Fail closed outside generic whitelists and exact helper/replay shapes.
    let cldemote_ok = matches!(
        &op.kind,
        OpKind::X86CacheControl {
            addr,
            kind: crate::smir::ir::ops::X86CacheControlKind::Cldemote,
        } if x86_jit_mem_address_shape_valid(addr)
    );
    let alignment_ok = matches!(
        &op.kind,
        OpKind::X86CheckAlignment { addr, alignment }
            if matches!(alignment, 16 | 32 | 64) && x86_jit_mem_address_shape_valid(addr)
    );
    let alignment_ac_ok = crate::smir::lower::x86_64::x86_check_alignment_ac_shape_valid(op);
    let opmask_ok = matches!(
        &op.kind,
        OpKind::X86Opmask(opmask)
            if op.x86_hint.is_none()
                && crate::smir::lower::x86_64::x86_opmask_native_shape_valid(opmask)
                && opmask.memory_address().is_none_or(|addr| {
                    allow_mem && x86_jit_mem_address_shape_valid(addr)
                })
    );
    let opmask_mem_ok = opmask_ok
        && matches!(
            &op.kind,
            OpKind::X86Opmask(opmask) if opmask.reads_memory() || opmask.writes_memory()
        );
    let vector_mem_ok = allow_mem && x86_jit_vector_mem_shape_valid(&op.kind);
    let mmx_mem_ok = allow_mem && x86_jit_mmx_mem_shape_valid(op);
    let sse4a_movnt_ok = allow_mem
        && crate::smir::lower::x86_64::x86_sse4a_movnt_store_shape_valid(op)
        && matches!(
            &op.kind,
            OpKind::X86Sse4aMovntStore { addr, .. }
                if x86_jit_mem_address_shape_valid(addr)
        );
    let mxcsr_store_ok = allow_mem
        && x86_store_mxcsr_shape_valid(op)
        && matches!(
            &op.kind,
            OpKind::X86StoreMxcsr { addr, .. } if x86_jit_mem_address_shape_valid(addr)
        );
    let mxcsr_load_ok = allow_mem
        && x86_load_mxcsr_shape_valid(op)
        && matches!(
            &op.kind,
            OpKind::X86LoadMxcsr { addr, .. } if x86_jit_mem_address_shape_valid(addr)
        );
    let stack_mov_ok = x86_state_backed_stack_mov_valid(&op.kind);
    let stack_alu_ok = x86_state_backed_stack_alu_valid(&op.kind);
    // A helper-backed scalar load commits its result into the destination's
    // GuestRegs slot rather than into the host register of the same name,
    // so guest RSP/RBP are valid load destinations under memory JIT.
    let state_mem_load_ok = allow_mem
        && matches!(&op.kind, OpKind::Load { .. })
        && x86_jit_scalar_mem_shape_valid(&op.kind);
    let state_lea_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_lea_valid(op);
    let stack_group1_ok = crate::smir::lower::x86_64::x86_state_backed_stack_group1_valid(op);
    let state_extend_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_extend_valid(op);
    let state_cmove_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_cmove_valid(op);
    let state_setcc_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_setcc_valid(op);
    let state_not_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_not_valid(op);
    let state_neg_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_neg_valid(op);
    let state_inc_dec_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_inc_dec_valid(op);
    let state_rotate_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_rotate_valid(op);
    let state_shift_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_shift_valid(op);
    let shift_group6_ok = crate::smir::lower::x86_64::x86_shift_group6_shape_valid(op);
    let state_carry_rotate_ok =
        crate::smir::lower::x86_64::x86_state_backed_gpr_carry_rotate_valid(op);
    let state_double_shift_ok =
        crate::smir::lower::x86_64::x86_state_backed_gpr_double_shift_valid(op);
    let state_count_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_count_valid(op);
    let state_bit_scan_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_bit_scan_valid(op);
    let state_bit_test_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_bit_test_valid(op);
    let state_crc32_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_crc32_valid(op);
    let state_and_not_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_and_not_valid(op);
    let state_bextr_bzhi_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_bextr_bzhi_valid(op);
    let state_bls_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_bls_valid(op);
    let state_tbm_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_tbm_valid(op);
    let state_xop_ok = crate::smir::lower::x86_64::x86_xop_packed_bit_shape_valid(op);
    let state_vbit_select_ok = crate::smir::lower::x86_64::x86_vbit_select_shape_valid(op);
    let state_vcmp_ok = crate::smir::lower::x86_64::x86_state_vcmp_shape_valid(op);
    let state_adx_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_adx_valid(op);
    let state_pdep_pext_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_pdep_pext_valid(op);
    let state_mulx_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_mulx_valid(op);
    let state_multiply_ok = crate::smir::lower::x86_64::x86_state_multiply_valid(op);
    let random_ok = crate::smir::lower::x86_64::x86_random_shape_valid(op);
    let state_random_ok = crate::smir::lower::x86_64::x86_state_random_valid(op);
    let state_bswap_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_bswap_valid(op);
    let state_xchg_ok = crate::smir::lower::x86_64::x86_state_backed_gpr_xchg_valid(op);
    let xadd_ok = crate::smir::lower::x86_64::x86_xadd_shape_valid(op);
    let cmpxchg_ok = crate::smir::lower::x86_64::x86_cmpxchg_shape_valid(op);
    let fsgsbase_ok = crate::smir::lower::x86_64::x86_fsgsbase_shape_valid(&op.kind);
    let read_control_ok = x86_read_control_shape_valid(&op.kind);
    let smsw_ok = match &op.kind {
        OpKind::X86Smsw(smsw) if x86_smsw_shape_valid(&op.kind) => match &smsw.target {
            X86SmswTarget::Register { .. } => true,
            X86SmswTarget::Memory { addr } => allow_mem && x86_jit_mem_address_shape_valid(addr),
        },
        _ => false,
    };
    let selector_store_ok = match &op.kind {
        OpKind::X86SystemSelectorStore(store) if x86_system_selector_store_shape_valid(op) => {
            match &store.target {
                X86SystemSelectorTarget::Register { .. } => true,
                X86SystemSelectorTarget::Memory { addr } => {
                    allow_mem && x86_jit_mem_address_shape_valid(addr)
                }
                X86SystemSelectorTarget::Stack { .. } => allow_mem,
            }
        }
        _ => false,
    };
    let selector_load_ok = match &op.kind {
        OpKind::X86SystemSelectorLoad(load) if x86_system_selector_load_shape_valid(op) => {
            allow_mem
                && match &load.source {
                    X86SystemSelectorSource::Register { .. } => true,
                    X86SystemSelectorSource::Memory { addr, .. } => {
                        x86_jit_mem_address_shape_valid(addr)
                    }
                    X86SystemSelectorSource::Stack { .. } => true,
                    X86SystemSelectorSource::FarPointer { addr, .. } => {
                        x86_jit_mem_address_shape_valid(addr)
                    }
                }
        }
        _ => false,
    };
    let selector_verify_ok = match &op.kind {
        OpKind::X86SelectorVerify(verify) if x86_selector_verify_shape_valid(op) => {
            allow_mem
                && match &verify.source {
                    X86SelectorVerifySource::Register { .. } => true,
                    X86SelectorVerifySource::Memory { addr, .. } => {
                        x86_jit_mem_address_shape_valid(addr)
                    }
                }
        }
        _ => false,
    };
    let selector_query_ok = match &op.kind {
        OpKind::X86SelectorQuery(query) if x86_selector_query_shape_valid(op) => {
            allow_mem
                && match &query.source {
                    X86SelectorQuerySource::Register { .. } => true,
                    X86SelectorQuerySource::Memory { addr, .. } => {
                        x86_jit_mem_address_shape_valid(addr)
                    }
                }
        }
        _ => false,
    };
    let lmsw_ok = match &op.kind {
        OpKind::X86Lmsw(lmsw) if x86_lmsw_shape_valid(op) => match &lmsw.source {
            X86LmswSource::Register { .. } => true,
            X86LmswSource::Memory { addr } => allow_mem && x86_jit_mem_address_shape_valid(addr),
        },
        _ => false,
    };
    let descriptor_store_ok = match &op.kind {
        OpKind::X86DescriptorTableStore(store)
            if crate::smir::lower::x86_64::x86_descriptor_table_store_shape_valid(op) =>
        {
            allow_mem && x86_jit_mem_address_shape_valid(&store.addr)
        }
        _ => false,
    };
    let descriptor_load_ok = match &op.kind {
        OpKind::X86DescriptorTableLoad(load)
            if crate::smir::lower::x86_64::x86_descriptor_table_load_shape_valid(op) =>
        {
            allow_mem && x86_jit_mem_address_shape_valid(&load.addr)
        }
        _ => false,
    };
    let invlpg_ok = matches!(
        &op.kind,
        OpKind::X86Invlpg(invlpg)
            if x86_invlpg_shape_valid(op)
                && x86_jit_mem_address_shape_valid(&invlpg.addr)
    );
    let invpcid_ok = matches!(
        &op.kind,
        OpKind::X86Invpcid(invpcid)
            if allow_mem
                && x86_invpcid_shape_valid(op)
                && x86_jit_mem_address_shape_valid(&invpcid.addr)
    );
    let far_jump_ok = matches!(
        &op.kind,
        OpKind::X86FarJump(jump)
            if allow_mem
                && x86_far_jump_shape_valid(op)
                && x86_jit_mem_address_shape_valid(&jump.addr)
    );
    let far_call_ok = matches!(
        &op.kind,
        OpKind::X86FarCall(call)
            if allow_mem
                && x86_far_call_shape_valid(op)
                && x86_jit_mem_address_shape_valid(&call.addr)
    );
    let far_return_ok = allow_mem && x86_far_return_shape_valid(op);
    let fast_system_transfer_ok = x86_fast_system_transfer_shape_valid(op);
    let read_debug_ok = x86_read_debug_shape_valid(&op.kind);
    let rdpid_ok = x86_rdpid_shape_valid(&op.kind);
    let write_control_ok = x86_write_control_shape_valid(op);
    let write_debug_ok = x86_write_debug_shape_valid(&op.kind);
    let cli_ok = x86_cli_shape_valid(op);
    let sti_ok = x86_sti_shape_valid(op);
    let swapgs_ok = crate::smir::lower::x86_64::x86_swapgs_shape_valid(&op.kind);
    let monitor_mwait_ok = match &op.kind {
        OpKind::X86MonitorMwait(X86MonitorMwaitOp { addr, .. })
            if crate::smir::lower::x86_64::x86_monitor_mwait_shape_valid(&op.kind) =>
        {
            addr.as_ref().map_or(true, |addr| {
                allow_mem && x86_jit_mem_address_shape_valid(addr)
            })
        }
        _ => false,
    };
    let waitpkg_ok = match &op.kind {
        OpKind::X86WaitPkg(X86WaitPkgOp::Umonitor { addr, .. }) => {
            allow_mem && x86_waitpkg_shape_valid(op) && x86_jit_mem_address_shape_valid(addr)
        }
        OpKind::X86WaitPkg(X86WaitPkgOp::Umwait { .. } | X86WaitPkgOp::Tpause { .. }) => {
            x86_waitpkg_shape_valid(op)
        }
        _ => false,
    };
    let pkru_ok = crate::smir::lower::x86_64::x86_pkru_shape_valid(&op.kind);
    let stack_state_ok = stack_mov_ok
        || opmask_ok
        || stack_alu_ok
        || stack_group1_ok
        || state_mem_load_ok
        || state_lea_ok
        || state_extend_ok
        || state_cmove_ok
        || state_setcc_ok
        || state_not_ok
        || state_neg_ok
        || state_inc_dec_ok
        || state_rotate_ok
        || state_shift_ok
        || shift_group6_ok
        || state_carry_rotate_ok
        || state_double_shift_ok
        || state_count_ok
        || state_bit_scan_ok
        || state_bit_test_ok
        || state_crc32_ok
        || state_and_not_ok
        || state_bextr_bzhi_ok
        || state_bls_ok
        || state_tbm_ok
        || state_adx_ok
        || state_pdep_pext_ok
        || state_mulx_ok
        || state_multiply_ok
        || state_random_ok
        || state_bswap_ok
        || state_xchg_ok
        || xadd_ok
        || cmpxchg_ok
        || mxcsr_store_ok
        || mxcsr_load_ok
        || waitpkg_ok
        || fsgsbase_ok
        || read_control_ok
        || smsw_ok
        || selector_store_ok
        || selector_load_ok
        || selector_verify_ok
        || selector_query_ok
        || lmsw_ok
        || descriptor_store_ok
        || descriptor_load_ok
        || invlpg_ok
        || invpcid_ok
        || fast_system_transfer_ok
        || read_debug_ok
        || rdpid_ok
        || write_control_ok
        || write_debug_ok
        || enter_ok
        || leave_ok
        || stack_flags_ok;
    if (crate::smir::lower::x86_64::x86_state_backed_gpr_lea_candidate(op) && !state_lea_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_stack_group1_candidate(op)
            && !stack_group1_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_extend_candidate(op)
            && !state_extend_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_cmove_candidate(op) && !state_cmove_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_setcc_candidate(op) && !state_setcc_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_not_candidate(op) && !state_not_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_neg_candidate(op) && !state_neg_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_inc_dec_candidate(op)
            && !state_inc_dec_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_rotate_candidate(op)
            && !state_rotate_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_shift_candidate(op)
            && !state_shift_ok
            && !shift_group6_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_carry_rotate_candidate(op)
            && !state_carry_rotate_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_double_shift_candidate(op)
            && !state_double_shift_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_count_candidate(op) && !state_count_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_bit_scan_candidate(op)
            && !state_bit_scan_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_bit_test_candidate(op)
            && !state_bit_test_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_crc32_candidate(op) && !state_crc32_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_and_not_candidate(op)
            && !state_and_not_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_bextr_bzhi_candidate(op)
            && !state_bextr_bzhi_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_bls_candidate(op) && !state_bls_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_tbm_candidate(op) && !state_tbm_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_adx_candidate(op) && !state_adx_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_pdep_pext_candidate(op)
            && !state_pdep_pext_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_mulx_candidate(op) && !state_mulx_ok)
        || (crate::smir::lower::x86_64::x86_state_multiply_candidate(op) && !state_multiply_ok)
        || (crate::smir::lower::x86_64::x86_state_random_candidate(op) && !state_random_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_bswap_candidate(op) && !state_bswap_ok)
        || (crate::smir::lower::x86_64::x86_state_backed_gpr_xchg_candidate(op) && !state_xchg_ok)
    {
        return false;
    }
    let unsigned_div_ok = x86_jit_unsigned_div_register_shape_valid(op);
    let signed_div_ok = x86_jit_signed_div_register_shape_valid(op);
    let guarded_div_ok = unsigned_div_ok || signed_div_ok;
    let mem_ok = (allow_mem && x86_jit_scalar_mem_shape_valid(&op.kind))
        || cldemote_ok
        || alignment_ok
        || alignment_ac_ok
        || opmask_mem_ok
        || vector_mem_ok
        || mmx_mem_ok
        || sse4a_movnt_ok
        || mxcsr_store_ok
        || mxcsr_load_ok
        || descriptor_store_ok
        || descriptor_load_ok
        || far_jump_ok
        || far_call_ok
        || far_return_ok
        || selector_load_ok
        || selector_verify_ok
        || selector_query_ok
        || enter_ok
        || leave_ok
        || stack_flags_ok
        || matches!(
            &op.kind,
            OpKind::X86SystemSelectorStore(store)
                if selector_store_ok
                    && matches!(
                        &store.target,
                        X86SystemSelectorTarget::Memory { .. }
                            | X86SystemSelectorTarget::Stack { .. }
                    )
        );
    let scalar_ok = matches!(
        op.kind,
        OpKind::AndNot { .. }
            | OpKind::X86Bls { .. }
            | OpKind::X86Tbm { .. }
            | OpKind::X86Adx { .. }
            | OpKind::X86XTest
    ) || xadd_ok
        || cmpxchg_ok
        || guarded_div_ok
        || io_ok
        || shift_group6_ok
        || crate::smir::lower::x86_64::x86_flag_control_shape_valid(op);
    let vector_ok = if matches!(op.kind, OpKind::X86Opmask(_)) {
        opmask_ok
    } else {
        x86_native_vector_smir_op(op)
    };
    let mmx_ok = is_x86_native_mmx_op(op) || mmx_mem_ok;
    if !op.is_jit_safe()
        && !mem_ok
        && !scalar_ok
        && !state_xop_ok
        && !state_vbit_select_ok
        && !state_vcmp_ok
        && !vector_ok
        && !mmx_ok
    {
        return false;
    }
    if x86_movx_uses_ambiguous_high_byte_source(op) {
        return false;
    }
    if matches!(op.x86_hint, Some(X86OpHint::LegacyHighByteReg))
        && !x86_legacy_high_byte_movx_shape_valid(op)
    {
        return false;
    }
    if matches!(op.x86_hint, Some(X86OpHint::Mulx)) && !x86_mulx_shape_valid(op) && !state_mulx_ok {
        return false;
    }
    if matches!(
        op.kind,
        OpKind::MulU {
            dst_hi: None,
            width: crate::smir::ir::types::OpWidth::W8,
            ..
        } | OpKind::MulS {
            dst_hi: None,
            width: crate::smir::ir::types::OpWidth::W8,
            ..
        }
    ) && !x86_byte_full_mul_shape_valid(&op.kind)
        && !state_multiply_ok
    {
        return false;
    }
    if matches!(
        op.kind,
        OpKind::MulU {
            dst_hi: Some(_),
            width: crate::smir::ir::types::OpWidth::W16,
            ..
        } | OpKind::MulS {
            dst_hi: Some(_),
            width: crate::smir::ir::types::OpWidth::W16,
            ..
        }
    ) && !x86_word_full_mul_shape_valid(&op.kind, true)
        && !state_multiply_ok
    {
        return false;
    }
    if matches!(op.kind, OpKind::Bsf { .. } | OpKind::Bsr { .. })
        && !x86_bit_scan_shape_valid(&op.kind)
        && !state_bit_scan_ok
    {
        return false;
    }
    if matches!(op.kind, OpKind::Crc32C { .. })
        && !x86_crc32_shape_valid(&op.kind)
        && !state_crc32_ok
    {
        return false;
    }
    if matches!(op.kind, OpKind::X86ReadPid { .. }) && !rdpid_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86Random { .. }) && !random_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86CacheControl { .. }) && !cldemote_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86CheckAlignment { .. }) && !alignment_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86CheckAlignmentAc { .. }) && !alignment_ac_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86Opmask(_)) && !opmask_ok {
        return false;
    }
    if matches!(op.kind, OpKind::VLoad { .. } | OpKind::VStore { .. })
        && !vector_mem_ok
        && !mmx_mem_ok
    {
        return false;
    }
    if matches!(op.kind, OpKind::X86Sse4aMovntStore { .. }) && !sse4a_movnt_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86StoreMxcsr { .. }) && !mxcsr_store_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86LoadMxcsr { .. }) && !mxcsr_load_ok {
        return false;
    }
    if !x86_x87_op_shape_valid(op) {
        return false;
    }
    if matches!(op.kind, OpKind::X86XGetBv { .. }) && !x86_xgetbv_shape_valid(&op.kind) {
        return false;
    }
    if matches!(op.kind, OpKind::X86Clts) && !x86_clts_shape_valid(&op.kind) {
        return false;
    }
    if matches!(op.kind, OpKind::X86Msr(..)) && !crate::smir::lower::x86_64::x86_msr_shape_valid(op)
    {
        return false;
    }
    if matches!(op.kind, OpKind::X86ReadControl { .. }) && !read_control_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86Smsw(..)) && !smsw_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86SystemSelectorStore(..)) && !selector_store_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86SystemSelectorLoad(..)) && !selector_load_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86SelectorVerify(..)) && !selector_verify_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86SelectorQuery(..)) && !selector_query_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86Lmsw(..)) && !lmsw_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86DescriptorTableStore(..)) && !descriptor_store_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86DescriptorTableLoad(..)) && !descriptor_load_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86Invlpg(..)) && !invlpg_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86Invpcid(..)) && !invpcid_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86FarJump(..)) && !far_jump_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86FarCall(..)) && !far_call_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86FarReturn(..)) && !far_return_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86FastSystemTransfer(..)) && !fast_system_transfer_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86ReadDebug { .. }) && !read_debug_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86WriteControl { .. }) && !write_control_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86WriteDebug { .. }) && !write_debug_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86RequireApx)
        && !crate::smir::lower::x86_64::x86_require_apx_shape_valid(op)
    {
        return false;
    }
    if matches!(op.kind, OpKind::X86RequireSse4a)
        && !crate::smir::lower::x86_64::x86_require_sse4a_shape_valid(op)
    {
        return false;
    }
    if matches!(op.kind, OpKind::X86RequireTbm)
        && !crate::smir::lower::x86_64::x86_require_tbm_shape_valid(op)
    {
        return false;
    }
    if matches!(op.kind, OpKind::X86RequireXop)
        && !crate::smir::lower::x86_64::x86_require_xop_shape_valid(op)
    {
        return false;
    }
    if matches!(op.kind, OpKind::X86Tbm { .. }) && op.x86_hint.is_some() {
        return false;
    }
    if matches!(op.kind, OpKind::X86XopPackedBit { .. }) && !state_xop_ok {
        return false;
    }
    if matches!(op.kind, OpKind::VBitSelect { .. }) && !state_vbit_select_ok {
        return false;
    }
    if matches!(op.kind, OpKind::VCmp { .. })
        && matches!(op.x86_hint, Some(X86OpHint::XopVpcom))
        && !state_vcmp_ok
    {
        return false;
    }
    if matches!(op.kind, OpKind::X86Sse4aBitfield { .. })
        && !crate::smir::lower::x86_64::x86_sse4a_bitfield_shape_valid(op)
    {
        return false;
    }
    if matches!(op.kind, OpKind::X86Cli { .. }) && !cli_ok {
        return false;
    }
    if matches!(op.kind, OpKind::IoIn { .. } | OpKind::IoOut { .. }) && !io_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86Enter(..)) && !enter_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86Leave(..)) && !leave_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86StackFlags(..)) && !stack_flags_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86Sti { .. }) && !sti_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86Cpuid { .. })
        && !crate::smir::lower::x86_64::x86_cpuid_shape_valid(&op.kind)
    {
        return false;
    }
    if matches!(op.kind, OpKind::X86ReadTsc(..))
        && !crate::smir::lower::x86_64::x86_read_tsc_shape_valid(&op.kind)
    {
        return false;
    }
    if matches!(op.kind, OpKind::X86ReadPmc(..))
        && !crate::smir::lower::x86_64::x86_read_pmc_shape_valid(op)
    {
        return false;
    }
    if matches!(op.kind, OpKind::X86FsGsBase { .. }) && !fsgsbase_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86SwapGs { .. }) && !swapgs_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86MonitorMwait(..)) && !monitor_mwait_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86WaitPkg(..)) && !waitpkg_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86Pkru { .. }) && !pkru_ok {
        return false;
    }
    if let OpKind::Fence { kind } = &op.kind {
        if !matches!(
            *kind,
            crate::smir::ir::types::FenceKind::LoadLoad
                | crate::smir::ir::types::FenceKind::Full
                | crate::smir::ir::types::FenceKind::StoreStore
                | crate::smir::ir::types::FenceKind::InstructionSerialize
        ) {
            return false;
        }
    }
    if matches!(
        op.kind,
        OpKind::Bt { .. } | OpKind::Bts { .. } | OpKind::Btr { .. } | OpKind::Btc { .. }
    ) && !x86_bit_test_shape_valid(&op.kind)
        && !state_bit_test_ok
    {
        return false;
    }
    if matches!(op.kind, OpKind::Cwd { .. }) && !x86_cwd_shape_valid(&op.kind) {
        return false;
    }
    if matches!(op.kind, OpKind::Rcl { .. } | OpKind::Rcr { .. })
        && !x86_carry_rotate_shape_valid(&op.kind)
        && !state_carry_rotate_ok
    {
        return false;
    }
    if matches!(
        op.kind,
        OpKind::AndNot { .. }
            | OpKind::Bextr { .. }
            | OpKind::Bzhi { .. }
            | OpKind::X86Bls { .. }
            | OpKind::X86Tbm { .. }
            | OpKind::Pdep { .. }
            | OpKind::Pext { .. }
    ) && !x86_bmi_shape_valid(&op.kind)
        && !state_and_not_ok
        && !state_bextr_bzhi_ok
        && !state_bls_ok
        && !state_tbm_ok
        && !state_pdep_pext_ok
    {
        return false;
    }
    if matches!(op.kind, OpKind::X86Adx { .. }) && !x86_adx_shape_valid(&op.kind) && !state_adx_ok {
        return false;
    }
    if matches!(
        op.kind,
        OpKind::Clz { .. } | OpKind::Ctz { .. } | OpKind::Popcnt { .. } | OpKind::X86Count { .. }
    ) && !x86_count_shape_valid(&op.kind)
        && !state_count_ok
    {
        return false;
    }
    if matches!(op.kind, OpKind::Bswap { .. })
        && !x86_bswap_shape_valid(&op.kind)
        && !state_bswap_ok
    {
        return false;
    }
    if matches!(op.kind, OpKind::Xchg { .. }) && !x86_xchg_shape_valid(&op.kind) && !state_xchg_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86Xadd(..)) && !xadd_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86Cmpxchg(..)) && !cmpxchg_ok {
        return false;
    }
    if matches!(op.kind, OpKind::X86NddDoubleShift { .. })
        && !x86_ndd_double_shift_shape_valid(&op.kind)
        && !state_double_shift_ok
    {
        return false;
    }
    if !x86_jit_scalar_alu_immediate_valid(&op.kind) {
        return false;
    }
    // (2) no virtual-temp writes (would clobber a guest GPR).
    if op
        .kind
        .dests()
        .iter()
        .any(|d| matches!(d, VReg::Virtual(_)))
    {
        return false;
    }
    // (3) guest RSP/RBP. Validated MOV/MOVX/CMOV/SETcc/NOT/NEG/INC/DEC/
    // ROL/ROR/RCL/RCR/SHL/SHR/SAR/SHLD/SHRD (including APX NDD)/count/
    // bit-scan/bit-test/CRC32/BMI/ADX/PDEP/PEXT/MULX/BSWAP/XCHG/XADD/
    // CMPXCHG/RDPID/RDRAND/RDSEED/ADD/SUB
    // reads/writes are state-backed.
    // Other writes are not modeled and bail. A read is additionally valid
    // as an operand of a mem-JIT Load/Store (an address base/index, or a stored value): the MMU
    // helper reads the value from the GuestRegs struct — the current guest
    // RSP/RBP — not the host RSP/RBP. CLDEMOTE is also safe because
    // its architecturally ignorable hint never materializes the address;
    // X86CheckAlignment snapshots live GPRs and computes from GuestRegs.
    // Any OTHER op reading RSP/RBP would use the host frame pointer / host
    // stack (wrong) → bail.
    if !stack_state_ok && op.kind.dests().iter().any(touches_sp_bp) {
        return false;
    }
    if !mem_ok
        && !stack_state_ok
        && !guarded_div_ok
        && op.kind.source_vregs().iter().any(touches_sp_bp)
    {
        return false;
    }
    true
}
