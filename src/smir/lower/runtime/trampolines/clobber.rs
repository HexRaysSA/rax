//! trampolines::clobber tests

use super::*;
use crate::smir::ir::ops::{
    X86LmswSource, X86MonitorMwaitOp, X86SelectorQuerySource, X86SelectorVerifySource,
    X86SmswTarget, X86SystemSelectorSource, X86SystemSelectorTarget, X86WaitPkgOp,
};
use crate::smir::lower::runtime::*;
use crate::smir::lower::x86_64::{
    x86_cli_shape_valid, x86_clts_shape_valid, x86_enter_encoding, x86_far_call_shape_valid,
    x86_far_call_terminal_shape_valid, x86_far_jump_shape_valid, x86_far_jump_terminal_shape_valid,
    x86_far_return_shape_valid, x86_far_return_terminal_shape_valid,
    x86_fast_system_transfer_shape_valid, x86_fast_system_transfer_terminal_shape_valid,
    x86_invlpg_shape_valid, x86_invpcid_shape_valid, x86_io_encoding, x86_leave_encoding,
    x86_lmsw_shape_valid, x86_load_mxcsr_shape_valid, x86_rdpid_shape_valid,
    x86_read_control_shape_valid, x86_read_debug_shape_valid, x86_selector_query_shape_valid,
    x86_selector_verify_shape_valid, x86_smsw_shape_valid, x86_stack_flags_encoding,
    x86_sti_shape_valid, x86_store_mxcsr_shape_valid, x86_system_selector_load_shape_valid,
    x86_system_selector_store_shape_valid, x86_waitpkg_shape_valid, x86_write_control_shape_valid,
    x86_write_debug_shape_valid,
};

#[path = "clobber/flags.rs"]
mod flags;
#[path = "clobber/operation.rs"]
mod operation;
pub(crate) use flags::x86_native_op_would_clobber_preserved_flags;
#[path = "clobber/scalar_memory.rs"]
mod scalar_memory;
pub(crate) use scalar_memory::x86_jit_scalar_mem_shape_valid;
#[path = "clobber/xsetbv.rs"]
mod xsetbv;
use xsetbv::x86_xsetbv_reachable_prefix;
#[path = "clobber/x87.rs"]
mod x87;
use x87::x86_x87_op_shape_valid;

/// Decide whether native execution is safe under the 1:1 identity register map.
///
/// The identity map leaves every host GPR holding live guest state. A materialized
/// `VReg::Virtual` would therefore alias guest state and makes a block ineligible.
///
/// Exemptions are virtual values that the lowerer proves it never materializes:
/// a trailing `TestCondition` whose `dst` feeds the block's `CondBranch`, and
/// (when MMU helpers are enabled) single-use temporaries in exact x86 memory
/// source pairs, MMX `MASKMOVQ`, or the pre-decrement RSP snapshot in PUSH RSP.
/// The former folds to a direct `Jcc`; the memory forms fold to exact
/// helper-backed operations.
///
/// Validated RSP/RBP forms use state-backed slots rather than host stack/frame
/// registers.
pub fn is_native_clobber_safe(func: &crate::smir::ir::SmirFunction) -> bool {
    is_native_clobber_safe_excluding(func, &std::collections::HashMap::new(), false)
}
/// Like [`is_native_clobber_safe`] but skips blocks in `excluded` (block-id ⇒
/// resume PC, i.e. the native-exit stubs). Those blocks are lowered to exit
/// stubs and never execute natively, so their ops can't clobber guest state —
/// excluding them lets the JIT accept regions whose loop is clobber-safe even
/// when an exit/continuation block uses a virtual temporary.
pub fn is_native_clobber_safe_excluding(
    func: &crate::smir::ir::SmirFunction,
    excluded: &std::collections::HashMap<crate::smir::ir::types::BlockId, u64>,
    allow_mem: bool,
) -> bool {
    if allow_mem && !x86_jit_scalar_alu_function_virtuals_closed(func) {
        return false;
    }
    let flag_live_in = x86_flag_live_in(func, excluded);
    func.blocks
        .iter()
        .filter(|b| !excluded.contains_key(&b.id))
        .all(|b| {
            let flags_live_out = x86_block_flag_live_out(b, excluded, &flag_live_in);
            block_is_clobber_safe(b, &func.x86_instruction_bytes, allow_mem, flags_live_out)
        })
}
/// True if every op in `block` is safe to execute natively under the JIT:
///   (1) it is on the fail-safe register-only whitelist (`SmirOp::is_jit_safe`)
///       — so it touches no memory and is validated bit-exact vs KVM; and
///   (2) it writes only architectural registers (no virtual temp, which would
///       alias a guest GPR under the identity register map).
/// A trailing `TestCondition` feeding the block's `CondBranch`, exact
/// helper-backed scalar/CRC memory sequences, and exact POP/PUSH stack
/// temporaries are exempt because the lowerer never materializes their virtual
/// destinations.
pub(crate) fn block_is_clobber_safe(
    block: &crate::smir::ir::SmirBlock,
    x86_instruction_bytes: &std::collections::HashMap<
        (
            crate::smir::ir::types::BlockId,
            crate::smir::ir::types::GuestAddr,
        ),
        crate::smir::ir::X86InstructionBytes,
    >,
    allow_mem: bool,
    flags_live_out: crate::smir::ir::flags::FlagSet,
) -> bool {
    use crate::smir::ir::Terminator;
    use crate::smir::ir::ops::{OpKind, X86OpHint};
    use crate::smir::ir::types::{ArchReg, VReg, X86Reg};

    let xsetbv_prefix = match x86_xsetbv_reachable_prefix(block, x86_instruction_bytes) {
        Ok(prefix) => prefix,
        Err(()) => return false,
    };
    let block = xsetbv_prefix.as_ref().unwrap_or(block);
    let flags_live_out = if xsetbv_prefix.is_some() {
        crate::smir::ir::flags::FlagSet::ALL_X86
    } else {
        flags_live_out
    };

    // A native host trap cannot stand in for a guest architectural exception:
    // it would signal the emulator process rather than producing an exact
    // guest exit. Frontier blocks explicitly listed in `excluded` never reach
    // this function, so rejecting terminal traps here does not constrain the
    // existing native-exit mechanism.
    if matches!(
        block.terminator,
        Terminator::Trap { .. } | Terminator::Unreachable
    ) {
        return false;
    }

    let n = block.ops.len();
    let terminal_control_count = block
        .ops
        .iter()
        .filter(|op| {
            matches!(
                op.kind,
                OpKind::X86FarJump(..)
                    | OpKind::X86FarCall(..)
                    | OpKind::X86FarReturn(..)
                    | OpKind::X86FastSystemTransfer(..)
            )
        })
        .count();
    if terminal_control_count != 0
        && (terminal_control_count != 1
            || !(x86_far_jump_terminal_shape_valid(block)
                || x86_far_call_terminal_shape_valid(block)
                || x86_far_return_terminal_shape_valid(block)
                || x86_fast_system_transfer_terminal_shape_valid(block)))
    {
        return false;
    }
    let native_replay_spans =
        crate::smir::ir::x86_native_replay_spans(block, x86_instruction_bytes);
    // Count virtual definitions and uses once. Exact helper-sequence validation
    // then remains O(1) per candidate and the complete gate remains O(N).
    let mut virtual_definitions = std::collections::HashMap::new();
    let mut virtual_uses = std::collections::HashMap::new();
    for op in &block.ops {
        for reg in op.kind.dests() {
            if matches!(reg, VReg::Virtual(_)) {
                *virtual_definitions.entry(reg).or_insert(0usize) += 1;
            }
        }
        for reg in op.kind.source_vregs() {
            if matches!(reg, VReg::Virtual(_)) {
                *virtual_uses.entry(reg).or_insert(0usize) += 1;
            }
        }
    }

    // Generic flag-suppressed ADC/SBB lowering cannot retain a live carry and
    // is rejected by `x86_block_preserves_live_flags`. An exact helper-backed
    // memory RMW sequence is different: its compute is wrapped by PUSHFQ/POPFQ
    // and its post-store replay consumes the same incoming carry. Exempt only
    // that validated compute index from the generic clobber check.
    let mut preserved_clobber_exceptions = std::collections::HashSet::new();
    let mut scan = 0;
    while scan < n {
        if let Some(consumed) = x86_jit_mem_alu_rmw_sequence_len(
            block,
            scan,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            preserved_clobber_exceptions.insert(scan + 1);
            scan += consumed;
        } else if let Some(consumed) = x86_jit_mem_alu_source_sequence_len(
            block,
            scan,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            preserved_clobber_exceptions.insert(scan + 1);
            scan += consumed;
        } else {
            scan += 1;
        }
    }
    if !x86_block_preserves_live_flags(block, flags_live_out, &preserved_clobber_exceptions) {
        return false;
    }

    let mut i = 0;
    while i < n {
        if let Some(span) = native_replay_spans.get(&i) {
            i = span.end;
            continue;
        }
        if let Some(consumed) = x86_jit_maskmovdqu_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_xop_source_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_vbit_select_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) =
            x86_jit_mem_vpcom_sequence_len(block, i, allow_mem, &virtual_definitions, &virtual_uses)
        {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mmx_maskmovq_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mmx_scalar_memory_transfer_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mmx_memory_source_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(sequence) =
            x86_jit_aes_memory_sequence(block, i, allow_mem, &virtual_definitions, &virtual_uses)
        {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_evex_bf16_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_evex_memory_replay_sequence_len(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_evex_broadcast_logic_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_evex_broadcast_interleave_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_evex_packed_fp16_arithmetic_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_evex_packed_fp_arithmetic_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_evex_gfni_affine_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_evex_fixup_imm_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_evex_packed_funnel_shift_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_evex_packed_rotate_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_evex_packed_variable_shift_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_evex_shared_count_shift_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_evex_alignr_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_evex_vector_align_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_evex_mask_blend_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_evex_scalar_fma3_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_evex_packed_fma3_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_fma4_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_vpermil2_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_sm3_sm4_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_packed_string_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_masked_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vpclmulqdq_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_gfni_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_duplicate_move_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_estimate_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_fp_flag_compare_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_sqrt_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_packed_convert_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_ne_convert_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) =
            x86_jit_vex_fp16_narrow_memory_sequence(block, i, allow_mem, x86_instruction_bytes)
        {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_round_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_scalar_convert_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_extract_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed();
            continue;
        }
        if let Some(consumed) = x86_jit_vex_scalar_move_memory_sequence_len(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_fp_compare_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_fp_dot_product_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_mpsadbw_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_scalar_insert_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_alignr_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_fp_shuffle_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_immediate_blend_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_immediate_permute_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_cross_lane_128_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_variable_blend_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_variable_permute_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_lane_shuffle_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_movntdqa_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_phminposuw_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_packed_abs_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_broadcast_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_packed_extend_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_ptest_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(sequence) = x86_jit_vex_binary_memory_sequence(
            block,
            i,
            allow_mem,
            x86_instruction_bytes,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += sequence.consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_shift_rmw_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_unary_rmw_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_alu_rmw_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) =
            x86_jit_cmpccxadd_sequence_len(block, i, allow_mem, x86_instruction_bytes)
        {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_atomic_rmw_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_state_compare_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_push_memory_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_push_flags_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) =
            x86_jit_ah_flags_sequence_len(block, i, &virtual_definitions, &virtual_uses)
        {
            i += consumed;
            continue;
        }
        if let Some(consumed) =
            x86_jit_cmpxchg_sequence_len(block, i, allow_mem, &virtual_definitions, &virtual_uses)
        {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_bit_offset_test_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_bit_offset_update_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_bit_update_rmw_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_alu_source_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_tbm_source_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_cmove_source_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_extend_source_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_movrs_high_byte_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_movrs_state_backed_load_sequence_len(
            block,
            i,
            allow_mem,
            x86_instruction_bytes.get(&(block.id, block.ops[i].guest_pc)),
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_movbe_memory_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_widening_mul_source_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_mulx_source_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_bmi_source_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_bmi2_shift_source_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_unsigned_div_source_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_signed_div_source_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_high_byte_unsigned_div_source_sequence_len(
            block,
            i,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_high_byte_signed_div_source_sequence_len(
            block,
            i,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_bit_test_source_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_bit_scan_source_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) = x86_jit_mem_count_source_sequence_len(
            block,
            i,
            allow_mem,
            &virtual_definitions,
            &virtual_uses,
        ) {
            i += consumed;
            continue;
        }
        if let Some(consumed) =
            x86_jit_pop2_sequence_len(block, i, allow_mem, &virtual_definitions, &virtual_uses)
        {
            i += consumed;
            continue;
        }
        if x86_jit_pop2_candidate(block, i) {
            return false;
        }
        if let Some(consumed) =
            x86_jit_push2_sequence_len(block, i, allow_mem, &virtual_definitions, &virtual_uses)
        {
            i += consumed;
            continue;
        }
        if x86_jit_push2_candidate(block, i) {
            return false;
        }
        if let Some(consumed) =
            x86_jit_pop_sequence_len(block, i, allow_mem, &virtual_definitions, &virtual_uses)
        {
            i += consumed;
            continue;
        }
        if x86_jit_pop_candidate(block, i) {
            return false;
        }
        if let Some(consumed) =
            x86_jit_push_sequence_len(block, i, allow_mem, &virtual_definitions, &virtual_uses)
        {
            i += consumed;
            continue;
        }
        if x86_jit_push_candidate(block, i) {
            return false;
        }
        if x86_mem_crc32_pair_valid(block, i, allow_mem, &virtual_definitions, &virtual_uses) {
            i += 2;
            continue;
        }
        let op = &block.ops[i];
        let io_ok = x86_io_encoding(block, i, x86_instruction_bytes).is_some();
        let enter_ok = allow_mem && x86_enter_encoding(block, i, x86_instruction_bytes).is_some();
        let leave_ok = allow_mem && x86_leave_encoding(block, i, x86_instruction_bytes).is_some();
        let stack_flags_ok =
            allow_mem && x86_stack_flags_encoding(block, i, x86_instruction_bytes).is_some();
        if i + 1 == n {
            if let (Terminator::CondBranch { cond, .. }, OpKind::TestCondition { dst, .. }) =
                (&block.terminator, &op.kind)
            {
                if dst == cond {
                    i += 1;
                    continue;
                }
            }
        }
        if !operation::operation_is_clobber_safe(
            op,
            allow_mem,
            io_ok,
            enter_ok,
            leave_ok,
            stack_flags_ok,
        ) {
            return false;
        }
        i += 1;
    }
    true
}
