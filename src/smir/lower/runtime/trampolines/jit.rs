//! trampolines::jit tests

use super::*;
use crate::smir::lower::runtime::*;

/// Verify host support for scalar x86 extensions emitted directly by the
/// identity-register native JIT. Generic scalar lowerings use baseline x86-64;
/// Encoding-hinted MULX, scalar BMI/ADX operations, and native count operations
/// require additional CPUID features; CRC32C requires SSE4.2, while RDRAND and
/// RDSEED retain their independent architectural feature gates. Excluded exit
/// blocks do not execute natively and therefore do not contribute feature
/// requirements.
pub fn x86_native_scalar_features_supported_excluding(
    func: &crate::smir::ir::SmirFunction,
    excluded: &std::collections::HashMap<crate::smir::ir::types::BlockId, u64>,
) -> bool {
    let (needs_bmi2, needs_bmi1, needs_lzcnt, needs_popcnt, needs_adx) =
        x86_native_scalar_feature_requirements_excluding(func, excluded);
    let needs_sse42 = func
        .blocks
        .iter()
        .filter(|block| !excluded.contains_key(&block.id))
        .flat_map(|block| &block.ops)
        .any(|op| matches!(op.kind, crate::smir::ir::ops::OpKind::Crc32C { .. }));
    let (needs_rdrand, needs_rdseed) = func
        .blocks
        .iter()
        .filter(|block| !excluded.contains_key(&block.id))
        .flat_map(|block| &block.ops)
        .fold((false, false), |(rdrand, rdseed), op| match op.kind {
            crate::smir::ir::ops::OpKind::X86Random { seed, .. } => {
                (rdrand || !seed, rdseed || seed)
            }
            _ => (rdrand, rdseed),
        });

    #[cfg(target_arch = "x86_64")]
    {
        (!needs_bmi2 || std::is_x86_feature_detected!("bmi2"))
            && (!needs_bmi1 || std::is_x86_feature_detected!("bmi1"))
            && (!needs_lzcnt || std::is_x86_feature_detected!("lzcnt"))
            && (!needs_popcnt || std::is_x86_feature_detected!("popcnt"))
            && (!needs_adx || std::is_x86_feature_detected!("adx"))
            && (!needs_sse42 || std::is_x86_feature_detected!("sse4.2"))
            && (!needs_rdrand || std::is_x86_feature_detected!("rdrand"))
            && (!needs_rdseed || std::is_x86_feature_detected!("rdseed"))
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        !(needs_bmi2
            || needs_bmi1
            || needs_lzcnt
            || needs_popcnt
            || needs_adx
            || needs_sse42
            || needs_rdrand
            || needs_rdseed)
    }
}
pub(crate) fn x86_native_scalar_feature_requirements_excluding(
    func: &crate::smir::ir::SmirFunction,
    excluded: &std::collections::HashMap<crate::smir::ir::types::BlockId, u64>,
) -> (bool, bool, bool, bool, bool) {
    use crate::smir::ir::ops::X86OpHint;

    use crate::smir::ir::ops::{OpKind, X86CountKind};

    let mut needs_bmi2 = false;
    let mut needs_bmi1 = false;
    let mut needs_lzcnt = false;
    let mut needs_popcnt = false;
    let mut needs_adx = false;
    for op in func
        .blocks
        .iter()
        .filter(|block| !excluded.contains_key(&block.id))
        .flat_map(|block| &block.ops)
    {
        needs_bmi2 |= matches!(op.x86_hint, Some(X86OpHint::Mulx))
            || matches!(
                op.kind,
                OpKind::Bzhi { .. } | OpKind::Pdep { .. } | OpKind::Pext { .. }
            );
        needs_bmi1 |= matches!(
            op.kind,
            OpKind::Bextr { .. }
                | OpKind::X86Bls { .. }
                | OpKind::Ctz { .. }
                | OpKind::X86Count {
                    kind: X86CountKind::Tzcnt,
                    ..
                }
        );
        needs_lzcnt |= matches!(
            op.kind,
            OpKind::Clz { .. }
                | OpKind::X86Count {
                    kind: X86CountKind::Lzcnt,
                    ..
                }
        );
        needs_popcnt |= matches!(
            op.kind,
            OpKind::Popcnt { .. }
                | OpKind::X86Count {
                    kind: X86CountKind::Popcnt,
                    ..
                }
        );
        needs_adx |= matches!(op.kind, OpKind::X86Adx { .. });
    }
    (needs_bmi2, needs_bmi1, needs_lzcnt, needs_popcnt, needs_adx)
}
/// Exact register-only shapes shared by MOVMSKPS, MOVMSKPD, and PMOVMSKB.
/// RSP/RBP destinations are excluded because the x86 native trampoline owns
/// those host registers. High vector registers require EVEX, which this
/// instruction family does not define.
pub(crate) fn x86_mov_mask_shape_valid(op: &crate::smir::ir::ops::OpKind) -> bool {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, VReg, VecElementType, X86Reg};

    let OpKind::X86MovMask {
        dst,
        src,
        elem,
        lanes,
        dst_width,
    } = op
    else {
        return false;
    };
    let gpr = matches!(
        dst,
        VReg::Arch(ArchReg::X86(
            X86Reg::Rax
                | X86Reg::Rcx
                | X86Reg::Rdx
                | X86Reg::Rbx
                | X86Reg::Rsi
                | X86Reg::Rdi
                | X86Reg::R8
                | X86Reg::R9
                | X86Reg::R10
                | X86Reg::R11
                | X86Reg::R12
                | X86Reg::R13
                | X86Reg::R14
                | X86Reg::R15
        ))
    );
    let source = match (elem, lanes, src) {
        (VecElementType::I8, 16, VReg::Arch(ArchReg::X86(X86Reg::Xmm(0..=15))))
        | (VecElementType::F32, 4, VReg::Arch(ArchReg::X86(X86Reg::Xmm(0..=15))))
        | (VecElementType::F64, 2, VReg::Arch(ArchReg::X86(X86Reg::Xmm(0..=15))))
        | (VecElementType::I8, 32, VReg::Arch(ArchReg::X86(X86Reg::Ymm(0..=15))))
        | (VecElementType::F32, 8, VReg::Arch(ArchReg::X86(X86Reg::Ymm(0..=15))))
        | (VecElementType::F64, 4, VReg::Arch(ArchReg::X86(X86Reg::Ymm(0..=15)))) => true,
        _ => false,
    };
    gpr && source && matches!(dst_width, OpWidth::W32 | OpWidth::W64)
}
/// Exact register-only MOVD/MOVQ shape. The native identity bridge can expose
/// architectural GPRs other than RSP/RBP and all 32 XMM registers; encoding
/// metadata later restricts legacy/VEX forms to XMM0..15. Memory operands stay
/// expanded into explicit scalar loads/stores so their fault effects remain
/// visible to the JIT memory gate.
pub(crate) fn x86_movd_q_shape_valid(op: &crate::smir::ir::ops::OpKind) -> bool {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, VReg, X86Reg};

    let OpKind::X86MovdQ {
        dst,
        src,
        width,
        zero_upper,
    } = op
    else {
        return false;
    };
    let gpr = |reg: &VReg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some_and(|index| index <= 15 && !matches!(index, 4 | 5)));
    let xmm = |reg: &VReg| matches!(reg, VReg::Arch(ArchReg::X86(X86Reg::Xmm(0..=31))));
    let vector_dst = xmm(dst) && gpr(src);
    let gpr_dst = gpr(dst) && xmm(src);
    matches!(width, OpWidth::W32 | OpWidth::W64)
        && (vector_dst || gpr_dst)
        && (!gpr_dst || !*zero_upper)
}
/// Return `(AVX, AVX2)` requirements for an admitted MOVMSK operation.
/// Every VEX form needs AVX; only VPMOVMSKB with a 256-bit source additionally
/// needs AVX2. Legacy SSE/SSE2 forms are baseline on x86-64 hosts.
pub(crate) fn x86_mov_mask_feature_requirements(op: &crate::smir::ir::ops::SmirOp) -> (bool, bool) {
    use crate::smir::ir::ops::X86OpHint;
    use crate::smir::ir::types::VecWidth;

    if !x86_mov_mask_shape_valid(&op.kind) {
        return (false, false);
    }
    match op.x86_hint {
        Some(X86OpHint::VexOp { opcode, width, .. }) => {
            (true, opcode == 0xD7 && width == VecWidth::V256)
        }
        _ => (false, false),
    }
}
pub(crate) fn x86_flag_live_in(
    func: &crate::smir::ir::SmirFunction,
    excluded: &std::collections::HashMap<crate::smir::ir::types::BlockId, u64>,
) -> std::collections::HashMap<crate::smir::ir::types::BlockId, crate::smir::ir::flags::FlagSet> {
    use crate::smir::ir::flags::FlagSet;

    let mut live_in: std::collections::HashMap<_, _> = func
        .blocks
        .iter()
        .filter(|b| !excluded.contains_key(&b.id))
        .map(|b| (b.id, FlagSet::EMPTY))
        .collect();

    let mut changed = true;
    while changed {
        changed = false;
        for block in func
            .blocks
            .iter()
            .rev()
            .filter(|b| !excluded.contains_key(&b.id))
        {
            let mut live = x86_block_flag_live_out(block, excluded, &live_in);
            for op in block.ops.iter().rev() {
                live = x86_flags_before_op(&op.kind, live);
            }
            if live_in.get(&block.id).copied() != Some(live) {
                live_in.insert(block.id, live);
                changed = true;
            }
        }
    }

    live_in
}
pub(crate) fn x86_block_flag_live_out(
    block: &crate::smir::ir::SmirBlock,
    excluded: &std::collections::HashMap<crate::smir::ir::types::BlockId, u64>,
    live_in: &std::collections::HashMap<
        crate::smir::ir::types::BlockId,
        crate::smir::ir::flags::FlagSet,
    >,
) -> crate::smir::ir::flags::FlagSet {
    use crate::smir::ir::flags::FlagSet;

    let successors = block.terminator.successors();
    if successors.is_empty() {
        return FlagSet::ALL_X86;
    }

    let mut live = FlagSet::EMPTY;
    for succ in successors {
        live = live.union(if excluded.contains_key(&succ) {
            FlagSet::ALL_X86
        } else {
            live_in.get(&succ).copied().unwrap_or(FlagSet::ALL_X86)
        });
    }
    live
}
pub(crate) fn x86_flags_before_op(
    op: &crate::smir::ir::ops::OpKind,
    live_after: crate::smir::ir::flags::FlagSet,
) -> crate::smir::ir::flags::FlagSet {
    live_after
        .difference(x86_flag_defs(op))
        .union(x86_flag_uses(op))
}
pub(crate) fn x86_flag_uses(op: &crate::smir::ir::ops::OpKind) -> crate::smir::ir::flags::FlagSet {
    use crate::smir::ir::flags::{FlagSet, FlagState};
    use crate::smir::ir::ops::{OpKind, X86AdxKind};

    match op {
        OpKind::TestCondition { cond, .. }
        | OpKind::SetCC { cond, .. }
        | OpKind::CMove { cond, .. } => FlagState::required_flags(*cond),
        OpKind::Adc { .. } | OpKind::Sbb { .. } | OpKind::Rcl { .. } | OpKind::Rcr { .. } => {
            FlagSet::CF
        }
        OpKind::X86Adx { kind, .. } => match kind {
            X86AdxKind::Adcx => FlagSet::CF,
            X86AdxKind::Adox => FlagSet::OF,
        },
        OpKind::CmcCF => FlagSet::CF,
        _ => FlagSet::EMPTY,
    }
}
pub(crate) fn x86_flag_defs(op: &crate::smir::ir::ops::OpKind) -> crate::smir::ir::flags::FlagSet {
    use crate::smir::ir::flags::FlagSet;
    use crate::smir::ir::ops::{OpKind, X86WaitPkgOp};

    match op {
        OpKind::Add { flags, .. }
        | OpKind::Sub { flags, .. }
        | OpKind::Adc { flags, .. }
        | OpKind::Sbb { flags, .. }
        | OpKind::Neg { flags, .. }
        | OpKind::Inc { flags, .. }
        | OpKind::Dec { flags, .. }
        | OpKind::MulU { flags, .. }
        | OpKind::MulS { flags, .. }
        | OpKind::And { flags, .. }
        | OpKind::Or { flags, .. }
        | OpKind::Xor { flags, .. }
        | OpKind::AndNot { flags, .. }
        | OpKind::Shl { flags, .. }
        | OpKind::Shr { flags, .. }
        | OpKind::Sar { flags, .. }
        | OpKind::Shld { flags, .. }
        | OpKind::Shrd { flags, .. }
        | OpKind::X86NddDoubleShift { flags, .. }
        | OpKind::Rol { flags, .. }
        | OpKind::Ror { flags, .. }
        | OpKind::Rcl { flags, .. }
        | OpKind::Rcr { flags, .. }
        | OpKind::Bsf { flags, .. }
        | OpKind::Bsr { flags, .. }
        | OpKind::Bextr { flags, .. }
        | OpKind::Bzhi { flags, .. }
        | OpKind::X86Bls { flags, .. }
        | OpKind::X86Tbm { flags, .. }
        | OpKind::X86Adx { flags, .. }
        | OpKind::X86Count { flags, .. } => flags.as_set(),
        OpKind::Cmp { .. }
        | OpKind::Test { .. }
        | OpKind::AtomicCmpXadd { .. }
        | OpKind::X86XTest => FlagSet::ALL_X86,
        OpKind::X86Random { .. } => FlagSet::ALL_X86,
        OpKind::X86WaitPkg(X86WaitPkgOp::Umwait { .. } | X86WaitPkgOp::Tpause { .. }) => {
            FlagSet::ALL_X86
        }
        OpKind::Bt { .. }
        | OpKind::Bts { .. }
        | OpKind::Btr { .. }
        | OpKind::Btc { .. }
        | OpKind::SetCF { .. }
        | OpKind::CmcCF => FlagSet::CF,
        _ => FlagSet::EMPTY,
    }
}
pub(crate) fn x86_block_preserves_live_flags(
    block: &crate::smir::ir::SmirBlock,
    mut live: crate::smir::ir::flags::FlagSet,
    preserved_clobber_exceptions: &std::collections::HashSet<usize>,
) -> bool {
    use crate::smir::ir::flags::{FlagSet, FlagUpdate};
    use crate::smir::ir::ops::{OpKind, X86AdxKind};

    for (index, op) in block.ops.iter().enumerate().rev() {
        if let OpKind::X86Adx {
            kind,
            flags: FlagUpdate::None,
            ..
        } = &op.kind
        {
            let native_output = match kind {
                X86AdxKind::Adcx => FlagSet::CF,
                X86AdxKind::Adox => FlagSet::OF,
            };
            if !crate::smir::lower::x86_64::x86_state_backed_gpr_adx_valid(op)
                && !live.intersection(native_output).is_empty()
            {
                return false;
            }
        }
        if !preserved_clobber_exceptions.contains(&index)
            && x86_native_op_would_clobber_preserved_flags(&op.kind)
            && !crate::smir::lower::x86_64::x86_state_backed_gpr_double_shift_valid(op)
            && !crate::smir::lower::x86_64::x86_scalar_alu_immediate_valid(op)
            && !live.is_empty()
        {
            return false;
        }
        live = x86_flags_before_op(&op.kind, live);
    }
    true
}
pub(crate) fn x86_xgetbv_shape_valid(op: &crate::smir::ir::ops::OpKind) -> bool {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, VReg, X86Reg};

    matches!(
        op,
        OpKind::X86XGetBv {
            dst_low: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
            dst_high: VReg::Arch(ArchReg::X86(X86Reg::Rdx)),
            selector: VReg::Arch(ArchReg::X86(X86Reg::Rcx)),
        }
    )
}
pub(crate) fn x86_crc32_shape_valid(op: &crate::smir::ir::ops::OpKind) -> bool {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::OpWidth;

    matches!(
        op,
        OpKind::Crc32C {
            dst,
            crc,
            data,
            data_width: OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
        } if dst == crc && x86_native_identity_gpr(dst) && x86_native_identity_gpr(data)
    )
}
pub(crate) fn x86_flagged_unary_shape(
    kind: &crate::smir::ir::ops::OpKind,
) -> Option<(
    u8,
    crate::smir::ir::types::VReg,
    crate::smir::ir::types::VReg,
    crate::smir::ir::types::OpWidth,
    crate::smir::ir::flags::FlagUpdate,
)> {
    use crate::smir::ir::ops::OpKind;

    match kind {
        OpKind::Neg {
            dst,
            src,
            width,
            flags,
        } => Some((0, *dst, *src, *width, *flags)),
        OpKind::Inc {
            dst,
            src,
            width,
            flags,
        } => Some((1, *dst, *src, *width, *flags)),
        OpKind::Dec {
            dst,
            src,
            width,
            flags,
        } => Some((2, *dst, *src, *width, *flags)),
        _ => None,
    }
}
/// Validate the exact fault-precise scalar memory-destination unary sequence
/// emitted by the x86 lifter. `NEG`/`INC`/`DEC` use `Load old; unary result`
/// without flags; `Store result`; then a full-flag replay into a dead virtual.
/// Flag-neutral `NOT` reuses the load virtual in place and needs no replay.
pub(crate) fn x86_jit_mem_unary_rmw_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{OpWidth, SignExtend, VReg};

    if !allow_mem {
        return None;
    }
    let load = block.ops.get(index)?;
    let (old, addr, mem_width) = match &load.kind {
        OpKind::Load {
            dst: old @ VReg::Virtual(_),
            addr,
            width,
            sign: SignExtend::Zero,
        } => (*old, addr, *width),
        _ => return None,
    };
    let width = mem_width.to_op_width()?;
    if !matches!(
        width,
        OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64
    ) || !x86_jit_mem_address_shape_valid(addr)
    {
        return None;
    }

    let compute = block.ops.get(index + 1)?;
    let store = block.ops.get(index + 2)?;
    if compute.guest_pc != load.guest_pc || store.guest_pc != load.guest_pc {
        return None;
    }

    if let Some((compute_tag, result, compute_old, compute_width, compute_flags)) =
        x86_flagged_unary_shape(&compute.kind)
    {
        if !matches!(result, VReg::Virtual(_))
            || compute_old != old
            || compute_width != width
            || compute_flags != FlagUpdate::None
            || !matches!(
                &store.kind,
                OpKind::Store {
                    src,
                    addr: store_addr,
                    width: store_width,
                } if *src == result && *store_addr == *addr && *store_width == mem_width
            )
            || virtual_definitions.get(&old) != Some(&1)
            || virtual_definitions.get(&result) != Some(&1)
            || virtual_uses.get(&result) != Some(&1)
        {
            return None;
        }

        // Optimization can prove the architectural flags dead and delete the
        // post-store replay; the remaining three-operation form publishes no
        // flags and consumes the loaded value exactly once.
        if virtual_uses.get(&old) == Some(&1) {
            return Some(3);
        }

        let replay = block.ops.get(index + 3)?;
        let (replay_tag, flags_result, replay_old, replay_width, replay_flags) =
            x86_flagged_unary_shape(&replay.kind)?;
        if replay.guest_pc != load.guest_pc
            || !matches!(flags_result, VReg::Virtual(_))
            || compute_tag != replay_tag
            || replay_old != old
            || replay_width != width
            || replay_flags != FlagUpdate::All
            || virtual_uses.get(&old) != Some(&2)
            || virtual_definitions.get(&flags_result) != Some(&1)
            || virtual_uses.contains_key(&flags_result)
        {
            return None;
        }
        return Some(4);
    }

    if !matches!(
        &compute.kind,
        OpKind::Not {
            dst,
            src,
            width: not_width,
        } if *dst == old && *src == old && *not_width == width
    ) || !matches!(
        &store.kind,
        OpKind::Store {
            src,
            addr: store_addr,
            width: store_width,
        } if *src == old && *store_addr == *addr && *store_width == mem_width
    ) || virtual_definitions.get(&old) != Some(&2)
        || virtual_uses.get(&old) != Some(&2)
    {
        return None;
    }

    Some(3)
}
pub(crate) fn x86_shift_rmw_shape(
    kind: &crate::smir::ir::ops::OpKind,
) -> Option<(
    u8,
    crate::smir::ir::types::VReg,
    crate::smir::ir::types::VReg,
    crate::smir::ir::types::SrcOperand,
    crate::smir::ir::types::OpWidth,
    crate::smir::ir::flags::FlagUpdate,
)> {
    use crate::smir::ir::ops::OpKind;

    match kind {
        OpKind::Rol {
            dst,
            src,
            amount,
            width,
            flags,
        } => Some((0, *dst, *src, amount.clone(), *width, *flags)),
        OpKind::Ror {
            dst,
            src,
            amount,
            width,
            flags,
        } => Some((1, *dst, *src, amount.clone(), *width, *flags)),
        OpKind::Rcl {
            dst,
            src,
            amount,
            width,
            flags,
        } => Some((2, *dst, *src, amount.clone(), *width, *flags)),
        OpKind::Rcr {
            dst,
            src,
            amount,
            width,
            flags,
        } => Some((3, *dst, *src, amount.clone(), *width, *flags)),
        OpKind::Shl {
            dst,
            src,
            amount,
            width,
            flags,
        } => Some((4, *dst, *src, amount.clone(), *width, *flags)),
        OpKind::Shr {
            dst,
            src,
            amount,
            width,
            flags,
        } => Some((5, *dst, *src, amount.clone(), *width, *flags)),
        OpKind::Sar {
            dst,
            src,
            amount,
            width,
            flags,
        } => Some((7, *dst, *src, amount.clone(), *width, *flags)),
        _ => None,
    }
}
/// Validate the exact four-op fault-precise memory-destination shift/rotate
/// sequence emitted by the x86 lifter. Immediate counts are normalized exactly
/// as x86 does. ROL/ROR/RCL/RCR accept every immediate/CL count because native
/// value/CF behavior follows the operand or through-carry period while the saved
/// RFLAGS merge classifies zero/one/multi using the raw masked count. SAR also
/// accepts every count because repeated sign fill keeps its result and CF
/// representable. Subword SHL/SHR counts are also representable: equality
/// derives CF from the staged original operand, while oversized counts clear
/// Rax's deterministic CF/OF outputs after replay.
pub(crate) fn x86_jit_mem_shift_rmw_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::flags::{FlagSet, FlagUpdate};
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{OpWidth, SignExtend, SrcOperand, VReg};

    if !allow_mem {
        return None;
    }
    let load = block.ops.get(index)?;
    let (old, addr, mem_width) = match &load.kind {
        OpKind::Load {
            dst: old @ VReg::Virtual(_),
            addr,
            width,
            sign: SignExtend::Zero,
        } => (*old, addr, *width),
        _ => return None,
    };
    let width = mem_width.to_op_width()?;
    if !matches!(
        width,
        OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64
    ) || !x86_jit_mem_address_shape_valid(addr)
    {
        return None;
    }

    let compute = block.ops.get(index + 1)?;
    let store = block.ops.get(index + 2)?;
    let replay = block.ops.get(index + 3)?;
    if [compute, store, replay]
        .into_iter()
        .any(|op| op.guest_pc != load.guest_pc)
    {
        return None;
    }
    if matches!(
        compute.x86_hint,
        Some(crate::smir::ir::ops::X86OpHint::ShiftGroup6)
    ) || matches!(
        replay.x86_hint,
        Some(crate::smir::ir::ops::X86OpHint::ShiftGroup6)
    ) {
        return None;
    }
    let (compute_tag, result, compute_old, amount, compute_width, compute_flags) =
        x86_shift_rmw_shape(&compute.kind)?;
    let (replay_tag, flags_result, replay_old, replay_amount, replay_width, replay_flags) =
        x86_shift_rmw_shape(&replay.kind)?;
    let count_valid = match &amount {
        SrcOperand::Imm(value) if (0..=i64::from(u8::MAX)).contains(value) => true,
        SrcOperand::Reg(VReg::Arch(crate::smir::ir::types::ArchReg::X86(
            crate::smir::ir::types::X86Reg::Rcx,
        ))) => true,
        _ => false,
    };
    let rotate_flags = FlagSet::CF.union(FlagSet::OF);
    let replay_flags_valid = if compute_tag <= 3 {
        matches!(replay_flags, FlagUpdate::Specific(set) if set == rotate_flags)
    } else {
        replay_flags == FlagUpdate::All
    };
    if !matches!(result, VReg::Virtual(_))
        || !matches!(flags_result, VReg::Virtual(_))
        || compute_tag != replay_tag
        || compute_old != old
        || replay_old != old
        || amount != replay_amount
        || compute_width != width
        || replay_width != width
        || compute_flags != FlagUpdate::None
        || !replay_flags_valid
        || !count_valid
        || !matches!(
            &store.kind,
            OpKind::Store {
                src,
                addr: store_addr,
                width: store_width,
            } if *src == result && *store_addr == *addr && *store_width == mem_width
        )
        || virtual_definitions.get(&old) != Some(&1)
        || virtual_uses.get(&old) != Some(&2)
        || virtual_definitions.get(&result) != Some(&1)
        || virtual_uses.get(&result) != Some(&1)
        || virtual_definitions.get(&flags_result) != Some(&1)
        || virtual_uses.contains_key(&flags_result)
    {
        return None;
    }

    Some(4)
}
/// Validate the exact memory-source conditional-move pair emitted by the x86
/// lifter: `Load virtual; CMove architectural_dst,virtual`. The architectural
/// memory read is unconditional even when the condition is false, so native
/// lowering always calls the MMU helper before a flag-neutral CMOV from staged
/// caller storage. RSP/RBP and APX EGPR destinations commit through GuestRegs.
pub(crate) fn x86_jit_mem_cmove_source_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, SignExtend, VReg};

    if !allow_mem {
        return None;
    }
    let load = block.ops.get(index)?;
    let (temporary, addr, mem_width) = match &load.kind {
        OpKind::Load {
            dst: temporary @ VReg::Virtual(_),
            addr,
            width,
            sign: SignExtend::Zero,
        } => (*temporary, addr, *width),
        _ => return None,
    };
    let width = mem_width.to_op_width()?;
    if !matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
        || !x86_jit_mem_address_shape_valid(addr)
        || load.x86_hint.is_some()
        || virtual_definitions.get(&temporary) != Some(&1)
        || virtual_uses.get(&temporary) != Some(&1)
    {
        return None;
    }

    let consumer = block.ops.get(index + 1)?;
    if consumer.guest_pc != load.guest_pc || consumer.x86_hint.is_some() {
        return None;
    }
    matches!(
        &consumer.kind,
        OpKind::CMove {
            dst: VReg::Arch(ArchReg::X86(dst)),
            src,
            width: consumer_width,
            ..
        } if dst.gpr_index().is_some() && *src == temporary && *consumer_width == width
    )
    .then_some(2)
}
/// Validate an exact scalar memory-extension pair emitted by the x86 lifter:
/// `Load virtual; ZeroExtend/SignExtend architectural_dst,virtual`. The MMU
/// helper stages the scalar in caller-owned stack space, and the lowerer then
/// performs the extension without ever assigning the SSA temporary to an
/// identity-mapped guest register. All architectural GPR destinations are
/// representable: RSP/RBP and APX EGPRs commit through their GuestRegs slots.
pub(crate) fn x86_jit_mem_extend_source_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, SignExtend, VReg};

    if !allow_mem {
        return None;
    }
    let load = block.ops.get(index)?;
    let (temporary, addr, mem_width, load_sign) = match &load.kind {
        OpKind::Load {
            dst: temporary @ VReg::Virtual(_),
            addr,
            width,
            sign,
        } => (*temporary, addr, *width, *sign),
        _ => return None,
    };
    let from_width = mem_width.to_op_width()?;
    if !matches!(from_width, OpWidth::W8 | OpWidth::W16 | OpWidth::W32)
        || !x86_jit_mem_address_shape_valid(addr)
        || load.x86_hint.is_some()
        || virtual_definitions.get(&temporary) != Some(&1)
        || virtual_uses.get(&temporary) != Some(&1)
    {
        return None;
    }

    let consumer = block.ops.get(index + 1)?;
    if consumer.guest_pc != load.guest_pc || consumer.x86_hint.is_some() {
        return None;
    }
    let (dst, src, op_from_width, to_width, expected_sign) = match &consumer.kind {
        OpKind::ZeroExtend {
            dst,
            src,
            from_width,
            to_width,
        } => (dst, src, from_width, to_width, SignExtend::Zero),
        OpKind::SignExtend {
            dst,
            src,
            from_width,
            to_width,
        } => (dst, src, from_width, to_width, SignExtend::Sign),
        _ => return None,
    };
    let destination_is_gpr =
        matches!(dst, VReg::Arch(ArchReg::X86(reg)) if reg.gpr_index().is_some());
    let strictly_widens = matches!(
        (from_width, to_width),
        (OpWidth::W8, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
            | (OpWidth::W16, OpWidth::W32 | OpWidth::W64)
            | (OpWidth::W32, OpWidth::W64)
    );

    (*src == temporary
        && *op_from_width == from_width
        && load_sign == expected_sign
        && destination_is_gpr
        && strictly_widens)
        .then_some(2)
}
pub(crate) fn x86_jit_div_consumer_valid(
    op: &crate::smir::ir::ops::SmirOp,
    source: crate::smir::ir::types::VReg,
    width: crate::smir::ir::types::OpWidth,
    allow_no_flags: bool,
    signed: bool,
) -> bool {
    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, SrcOperand, VReg, X86Reg};

    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rdx = VReg::Arch(ArchReg::X86(X86Reg::Rdx));
    let exact_shape = match &op.kind {
        OpKind::DivU {
            quot,
            rem,
            src1,
            src2: SrcOperand::Reg(divisor),
            width: op_width,
            flags,
        } if !signed => {
            *quot == rax
                && *rem == (width != OpWidth::W8).then_some(rdx)
                && *src1 == rax
                && *divisor == source
                && *op_width == width
                && (*flags == FlagUpdate::All || (allow_no_flags && *flags == FlagUpdate::None))
        }
        OpKind::DivS {
            quot,
            rem,
            src1,
            src2: SrcOperand::Reg(divisor),
            width: op_width,
            flags,
        } if signed => {
            *quot == rax
                && *rem == (width != OpWidth::W8).then_some(rdx)
                && *src1 == rax
                && *divisor == source
                && *op_width == width
                && (*flags == FlagUpdate::All || (allow_no_flags && *flags == FlagUpdate::None))
        }
        _ => false,
    };
    matches!(
        width,
        OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64
    ) && op.x86_hint.is_none()
        && exact_shape
}
/// Validate a register-source x86 `DIV r/m` shape. Guarded JIT lowering stages
/// the divisor before checking zero/quotient-overflow conditions, so every GPR
/// encoding (legacy, RSP/RBP, and APX EGPR) is representable without exposing
/// the host stack/frame registers.
pub(crate) fn x86_jit_unsigned_div_register_shape_valid(op: &crate::smir::ir::ops::SmirOp) -> bool {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, SrcOperand, VReg};

    let (source, width) = match &op.kind {
        OpKind::DivU {
            src2: SrcOperand::Reg(source @ VReg::Arch(ArchReg::X86(reg))),
            width,
            ..
        } if reg.gpr_index().is_some() => (*source, *width),
        _ => return false,
    };
    x86_jit_div_consumer_valid(op, source, width, true, false)
}
/// Validate a register-source x86 `IDIV r/m` shape. Signed division uses the
/// same staged-source and precise-deoptimization contract as unsigned DIV,
/// with an exact signed quotient-range guard before native execution.
pub(crate) fn x86_jit_signed_div_register_shape_valid(op: &crate::smir::ir::ops::SmirOp) -> bool {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, SrcOperand, VReg};

    let (source, width) = match &op.kind {
        OpKind::DivS {
            src2: SrcOperand::Reg(source @ VReg::Arch(ArchReg::X86(reg))),
            width,
            ..
        } if reg.gpr_index().is_some() => (*source, *width),
        _ => return false,
    };
    x86_jit_div_consumer_valid(op, source, width, true, true)
}
/// Validate `Load virtual; DivU RDX:RAX,RAX,virtual` from the x86 lifter. The
/// helper load must be exact SSA and fault before the guarded native divide can
/// commit either implicit destination.
pub(crate) fn x86_jit_mem_unsigned_div_source_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{OpWidth, SignExtend, VReg};

    if !allow_mem {
        return None;
    }
    let load = block.ops.get(index)?;
    let (temporary, addr, width) = match &load.kind {
        OpKind::Load {
            dst: temporary @ VReg::Virtual(_),
            addr,
            width,
            sign: SignExtend::Zero,
        } => (*temporary, addr, width.to_op_width()?),
        _ => return None,
    };
    if !matches!(
        width,
        OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64
    ) || !x86_jit_mem_address_shape_valid(addr)
        || virtual_definitions.get(&temporary) != Some(&1)
        || virtual_uses.get(&temporary) != Some(&1)
    {
        return None;
    }

    let consumer = block.ops.get(index + 1)?;
    (consumer.guest_pc == load.guest_pc
        && x86_jit_div_consumer_valid(consumer, temporary, width, true, false))
    .then_some(2)
}
/// Validate `Load virtual; DivS RDX:RAX,RAX,virtual` from the x86 lifter.
/// Exact SSA ownership keeps the helper-loaded signed divisor out of the
/// identity register map until guarded IDIV consumes it.
pub(crate) fn x86_jit_mem_signed_div_source_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{OpWidth, SignExtend, VReg};

    if !allow_mem {
        return None;
    }
    let load = block.ops.get(index)?;
    let (temporary, addr, width) = match &load.kind {
        OpKind::Load {
            dst: temporary @ VReg::Virtual(_),
            addr,
            width,
            sign: SignExtend::Zero,
        } => (*temporary, addr, width.to_op_width()?),
        _ => return None,
    };
    if !matches!(
        width,
        OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64
    ) || !x86_jit_mem_address_shape_valid(addr)
        || virtual_definitions.get(&temporary) != Some(&1)
        || virtual_uses.get(&temporary) != Some(&1)
    {
        return None;
    }

    let consumer = block.ops.get(index + 1)?;
    (consumer.guest_pc == load.guest_pc
        && x86_jit_div_consumer_valid(consumer, temporary, width, true, true))
    .then_some(2)
}
/// Validate the legacy high-byte divisor extraction emitted for AH/CH/DH/BH:
/// `Shr virtual,parent,8,NF; DivU AX,AX,virtual`. The lowering stages the parent
/// and extracts the byte after saving RFLAGS, then guards the native DIV.
pub(crate) fn x86_jit_high_byte_unsigned_div_source_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, SrcOperand, VReg};

    let extract = block.ops.get(index)?;
    let temporary = match &extract.kind {
        OpKind::Shr {
            dst: temporary @ VReg::Virtual(_),
            src: VReg::Arch(ArchReg::X86(reg)),
            amount: SrcOperand::Imm(8),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        } if reg.gpr_index().is_some_and(|index| index <= 3) => *temporary,
        _ => return None,
    };
    if virtual_definitions.get(&temporary) != Some(&1) || virtual_uses.get(&temporary) != Some(&1) {
        return None;
    }

    let consumer = block.ops.get(index + 1)?;
    (consumer.guest_pc == extract.guest_pc
        && x86_jit_div_consumer_valid(consumer, temporary, OpWidth::W8, false, false))
    .then_some(2)
}
/// Validate the legacy AH/CH/DH/BH extraction immediately consumed by IDIV.
/// APX NF cannot encode a legacy high byte, so this exact shape requires the
/// architectural `FlagUpdate::All` division form.
pub(crate) fn x86_jit_high_byte_signed_div_source_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, SrcOperand, VReg};

    let extract = block.ops.get(index)?;
    let temporary = match &extract.kind {
        OpKind::Shr {
            dst: temporary @ VReg::Virtual(_),
            src: VReg::Arch(ArchReg::X86(reg)),
            amount: SrcOperand::Imm(8),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        } if reg.gpr_index().is_some_and(|index| index <= 3) => *temporary,
        _ => return None,
    };
    if virtual_definitions.get(&temporary) != Some(&1) || virtual_uses.get(&temporary) != Some(&1) {
        return None;
    }

    let consumer = block.ops.get(index + 1)?;
    (consumer.guest_pc == extract.guest_pc
        && x86_jit_div_consumer_valid(consumer, temporary, OpWidth::W8, false, true))
    .then_some(2)
}
/// Validate the exact two-op scalar count memory-source shape emitted by the
/// x86 lifter: `Load virtual; X86Count architectural_dst,virtual`. The helper-
/// backed lowerer stages the loaded value on its own stack, so the SSA virtual
/// must have exactly one definition and one use and never enters the identity
/// register map.
pub(crate) fn x86_jit_mem_count_source_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::flags::FlagSet;
    use crate::smir::ir::ops::{OpKind, X86CountKind};
    use crate::smir::ir::types::{OpWidth, SignExtend, VReg};

    if !allow_mem {
        return None;
    }
    let load = block.ops.get(index)?;
    let (temporary, addr, mem_width) = match &load.kind {
        OpKind::Load {
            dst: temporary @ VReg::Virtual(_),
            addr,
            width,
            sign: SignExtend::Zero,
        } => (*temporary, addr, *width),
        _ => return None,
    };
    let width = mem_width.to_op_width()?;
    if !matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
        || !x86_jit_mem_address_shape_valid(addr)
        || virtual_definitions.get(&temporary) != Some(&1)
        || virtual_uses.get(&temporary) != Some(&1)
    {
        return None;
    }

    let consumer = block.ops.get(index + 1)?;
    let OpKind::X86Count {
        dst,
        src,
        width: count_width,
        kind,
        flags,
    } = &consumer.kind
    else {
        return None;
    };
    let defined = match kind {
        X86CountKind::Popcnt => FlagSet::ALL_X86,
        X86CountKind::Tzcnt | X86CountKind::Lzcnt => FlagSet::CF.union(FlagSet::ZF),
    };
    (consumer.guest_pc == load.guest_pc
        && *src == temporary
        && *count_width == width
        && x86_native_identity_gpr(dst)
        && flags.as_set().difference(defined).is_empty())
    .then_some(2)
}
/// Validate the exact two-op bit-scan memory-source shape emitted by the x86
/// lifter: `Load virtual; Bsf/Bsr architectural_dst,virtual`. The helper-backed
/// lowerer consumes the load from caller-owned stack storage, so the virtual
/// must remain a single-definition/single-use value and the scan must request
/// only its architecturally defined ZF update.
pub(crate) fn x86_jit_mem_bit_scan_source_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::flags::{FlagSet, FlagUpdate};
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{OpWidth, SignExtend, VReg};

    if !allow_mem {
        return None;
    }
    let load = block.ops.get(index)?;
    let (temporary, addr, mem_width) = match &load.kind {
        OpKind::Load {
            dst: temporary @ VReg::Virtual(_),
            addr,
            width,
            sign: SignExtend::Zero,
        } => (*temporary, addr, *width),
        _ => return None,
    };
    let width = mem_width.to_op_width()?;
    if !matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
        || !x86_jit_mem_address_shape_valid(addr)
        || virtual_definitions.get(&temporary) != Some(&1)
        || virtual_uses.get(&temporary) != Some(&1)
    {
        return None;
    }

    let consumer = block.ops.get(index + 1)?;
    let (dst, src, scan_width, flags) = match &consumer.kind {
        OpKind::Bsf {
            dst,
            src,
            width,
            flags,
        }
        | OpKind::Bsr {
            dst,
            src,
            width,
            flags,
        } => (dst, src, width, flags),
        _ => return None,
    };
    (consumer.guest_pc == load.guest_pc
        && *src == temporary
        && *scan_width == width
        && x86_native_identity_gpr(dst)
        && *flags == FlagUpdate::Specific(FlagSet::ZF))
    .then_some(2)
}
/// Validate the exact non-modifying immediate memory bit-test shape emitted by
/// the x86 lifter: `Load virtual; Bt virtual,imm`. Register-index memory forms
/// first perform signed bit-string address adjustment and therefore remain a
/// distinct lowering problem. The loaded virtual must have one definition and
/// one use and the already-normalized immediate must select a bit in the
/// loaded operand.
pub(crate) fn x86_jit_mem_bit_test_source_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{OpWidth, SignExtend, SrcOperand, VReg};

    if !allow_mem {
        return None;
    }
    let load = block.ops.get(index)?;
    let (temporary, addr, mem_width) = match &load.kind {
        OpKind::Load {
            dst: temporary @ VReg::Virtual(_),
            addr,
            width,
            sign: SignExtend::Zero,
        } => (*temporary, addr, *width),
        _ => return None,
    };
    let width = mem_width.to_op_width()?;
    if !matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
        || !x86_jit_mem_address_shape_valid(addr)
        || virtual_definitions.get(&temporary) != Some(&1)
        || virtual_uses.get(&temporary) != Some(&1)
    {
        return None;
    }

    let consumer = block.ops.get(index + 1)?;
    let OpKind::Bt {
        src,
        index: SrcOperand::Imm(bit),
        width: bit_width,
    } = &consumer.kind
    else {
        return None;
    };
    (consumer.guest_pc == load.guest_pc
        && *src == temporary
        && *bit_width == width
        && (0..i64::from(width.bits())).contains(bit))
    .then_some(2)
}
/// Validate the exact fault-precise immediate memory bit-update sequence
/// emitted by the x86 lifter:
///
/// `Load old; Mov mask,1; Shl mask,imm; [Not mask]; Or/And/Xor new,old,mask;
/// Store new; Bt old,imm`. O2 may fold the W64 mask construction into an
/// immediate `Or`/`And`/`Xor`, which is accepted only when its mask exactly
/// corresponds to the final `Bt` index.
///
/// The optional `Not` and following `And` identify BTR; `Or` identifies BTS
/// and `Xor` identifies BTC. Register-index bit-string forms perform signed
/// address adjustment before this sequence and are intentionally excluded.
/// Every temporary must have the exact SSA definition/use counts implied by
/// the lifter so the native lowerer can eliminate the complete sequence.
pub(crate) fn x86_jit_mem_bit_update_rmw_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{OpWidth, SignExtend, SrcOperand, VReg};

    if !allow_mem {
        return None;
    }
    let load = block.ops.get(index)?;
    let (old, addr, mem_width) = match &load.kind {
        OpKind::Load {
            dst: old @ VReg::Virtual(_),
            addr,
            width,
            sign: SignExtend::Zero,
        } => (*old, addr, *width),
        _ => return None,
    };
    let width = mem_width.to_op_width()?;
    if !matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
        || !x86_jit_mem_address_shape_valid(addr)
    {
        return None;
    }

    // O2 constant-folds the W64 mask producer into the update. Match that
    // exact four-op form before checking the unfused lifter sequence below.
    if width == OpWidth::W64 {
        let compute = block.ops.get(index + 1)?;
        let folded = match &compute.kind {
            OpKind::Or {
                dst,
                src1,
                src2: SrcOperand::Imm(mask),
                width,
                flags,
            } => Some((0u8, *dst, *src1, *mask, *width, *flags)),
            OpKind::And {
                dst,
                src1,
                src2: SrcOperand::Imm(mask),
                width,
                flags,
            } => Some((1u8, *dst, *src1, *mask, *width, *flags)),
            OpKind::Xor {
                dst,
                src1,
                src2: SrcOperand::Imm(mask),
                width,
                flags,
            } => Some((2u8, *dst, *src1, *mask, *width, *flags)),
            _ => None,
        };
        if let Some((action, result, compute_old, mask, compute_width, compute_flags)) = folded {
            let VReg::Virtual(_) = result else {
                return None;
            };
            let store = block.ops.get(index + 2)?;
            let replay = block.ops.get(index + 3)?;
            let bit = match &replay.kind {
                OpKind::Bt {
                    src,
                    index: SrcOperand::Imm(bit),
                    width: replay_width,
                } if *src == old
                    && *replay_width == width
                    && (0..i64::from(width.bits())).contains(bit) =>
                {
                    *bit
                }
                _ => return None,
            };
            let bit_mask = 1u64 << (bit as u32);
            let expected_mask = match action {
                0 | 2 => bit_mask as i64,
                1 => (!bit_mask) as i64,
                _ => unreachable!(),
            };
            return (compute_old == old
                && mask == expected_mask
                && compute_width == width
                && compute_flags == FlagUpdate::None
                && block.ops[index..index + 4]
                    .iter()
                    .all(|op| op.guest_pc == load.guest_pc)
                && matches!(
                    &store.kind,
                    OpKind::Store {
                        src,
                        addr: store_addr,
                        width: store_width,
                    } if *src == result && *store_addr == *addr && *store_width == mem_width
                )
                && virtual_definitions.get(&old) == Some(&1)
                && virtual_uses.get(&old) == Some(&2)
                && virtual_definitions.get(&result) == Some(&1)
                && virtual_uses.get(&result) == Some(&1))
            .then_some(4);
        }
    }

    let mask = match &block.ops.get(index + 1)?.kind {
        OpKind::Mov {
            dst: mask @ VReg::Virtual(_),
            src: SrcOperand::Imm(1),
            width: mov_width,
        } if *mov_width == width => *mask,
        _ => return None,
    };
    let bit = match &block.ops.get(index + 2)?.kind {
        OpKind::Shl {
            dst,
            src,
            amount: SrcOperand::Imm(bit),
            width: shift_width,
            flags: FlagUpdate::None,
        } if *dst == mask
            && *src == mask
            && *shift_width == width
            && (0..i64::from(width.bits())).contains(bit) =>
        {
            *bit
        }
        _ => return None,
    };

    // (action tag, compute index, sequence length, exact mask def/use count)
    let (action, compute_index, consumed, mask_count) = match &block.ops.get(index + 3)?.kind {
        OpKind::Or { .. } => (0u8, index + 3, 6usize, 2usize),
        OpKind::Xor { .. } => (2u8, index + 3, 6usize, 2usize),
        OpKind::Not {
            dst,
            src,
            width: not_width,
        } if *dst == mask && *src == mask && *not_width == width => {
            (1u8, index + 4, 7usize, 3usize)
        }
        _ => return None,
    };

    let compute = block.ops.get(compute_index)?;
    let (result, compute_old, compute_mask, compute_width, compute_flags) = match &compute.kind {
        OpKind::Or {
            dst,
            src1,
            src2,
            width,
            flags,
        } if action == 0 => (*dst, *src1, src2, *width, *flags),
        OpKind::And {
            dst,
            src1,
            src2,
            width,
            flags,
        } if action == 1 => (*dst, *src1, src2, *width, *flags),
        OpKind::Xor {
            dst,
            src1,
            src2,
            width,
            flags,
        } if action == 2 => (*dst, *src1, src2, *width, *flags),
        _ => return None,
    };
    let VReg::Virtual(_) = result else {
        return None;
    };
    if compute_old != old
        || !matches!(compute_mask, SrcOperand::Reg(reg) if *reg == mask)
        || compute_width != width
        || compute_flags != FlagUpdate::None
    {
        return None;
    }

    let store = block.ops.get(compute_index + 1)?;
    let replay = block.ops.get(compute_index + 2)?;
    if block.ops[index..index + consumed]
        .iter()
        .any(|op| op.guest_pc != load.guest_pc)
        || !matches!(
            &store.kind,
            OpKind::Store {
                src,
                addr: store_addr,
                width: store_width,
            } if *src == result && *store_addr == *addr && *store_width == mem_width
        )
        || !matches!(
            &replay.kind,
            OpKind::Bt {
                src,
                index: SrcOperand::Imm(replay_bit),
                width: replay_width,
            } if *src == old && *replay_bit == bit && *replay_width == width
        )
        || virtual_definitions.get(&old) != Some(&1)
        || virtual_uses.get(&old) != Some(&2)
        || virtual_definitions.get(&mask) != Some(&mask_count)
        || virtual_uses.get(&mask) != Some(&mask_count)
        || virtual_definitions.get(&result) != Some(&1)
        || virtual_uses.get(&result) != Some(&1)
    {
        return None;
    }

    Some(consumed)
}
/// Validate the exact five-op APX PUSH2 shape emitted by the x86 lifter. Both
/// source snapshots are single-definition/single-use virtuals; native lowering
/// replaces the complete sequence with one paired helper call.
pub(crate) fn x86_jit_push2_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{Address, ArchReg, MemWidth, OpWidth, SrcOperand, VReg, X86Reg};

    if !allow_mem {
        return None;
    }
    let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
    let first = block.ops.get(index)?;
    let (tmp_low, src_low) = match first.kind {
        OpKind::Mov {
            dst: temporary @ VReg::Virtual(_),
            src: SrcOperand::Reg(source @ VReg::Arch(ArchReg::X86(reg))),
            width: OpWidth::W64,
        } if reg.gpr_index().is_some() && source != rsp => (temporary, source),
        _ => return None,
    };
    let second = block.ops.get(index + 1)?;
    let (tmp_high, src_high) = match second.kind {
        OpKind::Mov {
            dst: temporary @ VReg::Virtual(_),
            src: SrcOperand::Reg(source @ VReg::Arch(ArchReg::X86(reg))),
            width: OpWidth::W64,
        } if reg.gpr_index().is_some() && source != rsp => (temporary, source),
        _ => return None,
    };
    let sub = block.ops.get(index + 2)?;
    let store_low = block.ops.get(index + 3)?;
    let store_high = block.ops.get(index + 4)?;
    if [second, sub, store_low, store_high]
        .iter()
        .any(|op| op.guest_pc != first.guest_pc)
        || !matches!(
            sub.kind,
            OpKind::Sub {
                dst,
                src1,
                src2: SrcOperand::Imm(16),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            } if dst == rsp && src1 == rsp
        )
        || !matches!(
            store_low.kind,
            OpKind::Store {
                src,
                addr: Address::Direct(base),
                width: MemWidth::B8,
            } if src == tmp_low && base == rsp
        )
        || !matches!(
            &store_high.kind,
            OpKind::Store {
                src,
                addr,
                width: MemWidth::B8,
            } if *src == tmp_high && *addr == Address::base_off(rsp, 8)
        )
        || virtual_definitions.get(&tmp_low) != Some(&1)
        || virtual_uses.get(&tmp_low) != Some(&1)
        || virtual_definitions.get(&tmp_high) != Some(&1)
        || virtual_uses.get(&tmp_high) != Some(&1)
    {
        return None;
    }

    let _ = (src_low, src_high);
    Some(5)
}
/// Identify a PUSH2-like same-instruction sequence that failed exact
/// validation. This prevents its virtual snapshots and two stores from being
/// admitted independently.
pub(crate) fn x86_jit_push2_candidate(block: &crate::smir::ir::SmirBlock, index: usize) -> bool {
    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, SrcOperand, VReg, X86Reg};

    let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
    let Some(first) = block.ops.get(index) else {
        return false;
    };
    matches!(
        first.kind,
        OpKind::Mov {
            dst: VReg::Virtual(_),
            width: OpWidth::W64,
            ..
        }
    ) && matches!(
        block.ops.get(index + 1),
        Some(second) if second.guest_pc == first.guest_pc
            && matches!(second.kind, OpKind::Mov { dst: VReg::Virtual(_), width: OpWidth::W64, .. })
    ) && matches!(
        block.ops.get(index + 2),
        Some(sub) if sub.guest_pc == first.guest_pc
            && matches!(
                sub.kind,
                OpKind::Sub {
                    dst,
                    src1,
                    src2: SrcOperand::Imm(16),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                } if dst == rsp && src1 == rsp
            )
    )
}
/// Validate the exact five-op APX POP2 shape emitted by the x86 lifter. The
/// V-register destination consumes `[RSP]`; the distinct ModRM B-register
/// destination consumes `[RSP+8]`.
pub(crate) fn x86_jit_pop2_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{
        Address, ArchReg, MemWidth, OpWidth, SignExtend, SrcOperand, VReg, X86Reg,
    };

    if !allow_mem {
        return None;
    }
    let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
    let first = block.ops.get(index)?;
    let tmp_low = match first.kind {
        OpKind::Load {
            dst: temporary @ VReg::Virtual(_),
            addr: Address::Direct(base),
            width: MemWidth::B8,
            sign: SignExtend::Zero,
        } if base == rsp => temporary,
        _ => return None,
    };
    let second = block.ops.get(index + 1)?;
    let tmp_high = match &second.kind {
        OpKind::Load {
            dst: temporary @ VReg::Virtual(_),
            addr,
            width: MemWidth::B8,
            sign: SignExtend::Zero,
        } if *addr == Address::base_off(rsp, 8) => *temporary,
        _ => return None,
    };
    let add = block.ops.get(index + 2)?;
    let low_commit = block.ops.get(index + 3)?;
    let high_commit = block.ops.get(index + 4)?;
    let dst_low = match low_commit.kind {
        OpKind::Mov {
            dst: destination @ VReg::Arch(ArchReg::X86(reg)),
            src: SrcOperand::Reg(source),
            width: OpWidth::W64,
        } if reg.gpr_index().is_some() && destination != rsp && source == tmp_low => destination,
        _ => return None,
    };
    let dst_high = match high_commit.kind {
        OpKind::Mov {
            dst: destination @ VReg::Arch(ArchReg::X86(reg)),
            src: SrcOperand::Reg(source),
            width: OpWidth::W64,
        } if reg.gpr_index().is_some() && destination != rsp && source == tmp_high => destination,
        _ => return None,
    };
    if dst_low == dst_high
        || [second, add, low_commit, high_commit]
            .iter()
            .any(|op| op.guest_pc != first.guest_pc)
        || !matches!(
            add.kind,
            OpKind::Add {
                dst,
                src1,
                src2: SrcOperand::Imm(16),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            } if dst == rsp && src1 == rsp
        )
        || virtual_definitions.get(&tmp_low) != Some(&1)
        || virtual_uses.get(&tmp_low) != Some(&1)
        || virtual_definitions.get(&tmp_high) != Some(&1)
        || virtual_uses.get(&tmp_high) != Some(&1)
    {
        return None;
    }
    Some(5)
}
/// Identify a POP2-like paired-load prefix that failed exact validation.
pub(crate) fn x86_jit_pop2_candidate(block: &crate::smir::ir::SmirBlock, index: usize) -> bool {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{Address, ArchReg, MemWidth, SignExtend, VReg, X86Reg};

    let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
    let Some(first) = block.ops.get(index) else {
        return false;
    };
    matches!(
        first.kind,
        OpKind::Load {
            dst: VReg::Virtual(_),
            addr: Address::Direct(base),
            width: MemWidth::B8,
            sign: SignExtend::Zero,
        } if base == rsp
    ) && matches!(
        block.ops.get(index + 1),
        Some(second) if second.guest_pc == first.guest_pc
            && matches!(
                &second.kind,
                OpKind::Load {
                    dst: VReg::Virtual(_),
                    addr,
                    width: MemWidth::B8,
                    sign: SignExtend::Zero,
                } if *addr == Address::base_off(rsp, 8)
            )
    )
}
/// Validate the exact POP shapes emitted by the x86 lifter. Ordinary POP uses
/// a helper load followed by a state-backed RSP increment. POP RSP commits the
/// loaded value without exposing the increment, while POP SP first computes
/// the full-width increment and then replaces only its low 16 bits.
pub(crate) fn x86_jit_pop_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{
        Address, ArchReg, MemWidth, OpWidth, SignExtend, SrcOperand, VReg, X86Reg,
    };

    if !allow_mem {
        return None;
    }
    let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
    let load = block.ops.get(index)?;
    let (popped, mem_width, delta) = match load.kind {
        OpKind::Load {
            dst,
            addr: Address::Direct(base),
            width: mem_width @ (MemWidth::B2 | MemWidth::B8),
            sign: SignExtend::Zero,
        } if base == rsp => (
            dst,
            mem_width,
            if mem_width == MemWidth::B2 { 2 } else { 8 },
        ),
        _ => return None,
    };
    let same_pc = |offset: usize| {
        block
            .ops
            .get(index + offset)
            .is_some_and(|op| op.guest_pc == load.guest_pc)
    };

    if matches!(popped, VReg::Arch(ArchReg::X86(reg)) if reg.gpr_index().is_some()) && popped != rsp
    {
        let increment = block.ops.get(index + 1)?;
        if increment.guest_pc == load.guest_pc
            && matches!(
                increment.kind,
                OpKind::Add {
                    dst,
                    src1,
                    src2: SrcOperand::Imm(amount),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                } if dst == rsp && src1 == rsp && amount == delta
            )
        {
            return Some(2);
        }
        return None;
    }

    let VReg::Virtual(_) = popped else {
        return None;
    };
    if virtual_definitions.get(&popped) != Some(&1) || virtual_uses.get(&popped) != Some(&1) {
        return None;
    }

    if mem_width == MemWidth::B8 {
        let commit = block.ops.get(index + 1)?;
        return (same_pc(1)
            && matches!(
                commit.kind,
                OpKind::Mov {
                    dst,
                    src: SrcOperand::Reg(src),
                    width: OpWidth::W64,
                } if dst == rsp && src == popped
            ))
        .then_some(2);
    }

    let increment = block.ops.get(index + 1)?;
    let incremented = match increment.kind {
        OpKind::Add {
            dst: temporary @ VReg::Virtual(_),
            src1,
            src2: SrcOperand::Imm(2),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        } if src1 == rsp && increment.guest_pc == load.guest_pc => temporary,
        _ => return None,
    };
    if virtual_definitions.get(&incremented) != Some(&1)
        || virtual_uses.get(&incremented) != Some(&1)
        || !same_pc(2)
        || !same_pc(3)
    {
        return None;
    }
    let increment_commit = &block.ops[index + 2];
    let low_commit = &block.ops[index + 3];
    (matches!(
        increment_commit.kind,
        OpKind::Mov {
            dst,
            src: SrcOperand::Reg(src),
            width: OpWidth::W64,
        } if dst == rsp && src == incremented
    ) && matches!(
        low_commit.kind,
        OpKind::Mov {
            dst,
            src: SrcOperand::Reg(src),
            width: OpWidth::W16,
        } if dst == rsp && src == popped
    ))
    .then_some(4)
}
/// Identify a POP-like same-instruction sequence that failed exact validation.
/// Without this fail-closed check, its individual helper load and stack-state
/// operations could be admitted independently with different alias ordering.
pub(crate) fn x86_jit_pop_candidate(block: &crate::smir::ir::SmirBlock, index: usize) -> bool {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{Address, ArchReg, MemWidth, SignExtend, VReg, X86Reg};

    let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
    let Some(load) = block.ops.get(index) else {
        return false;
    };
    if !matches!(
        load.kind,
        OpKind::Load {
            addr: Address::Direct(base),
            width: MemWidth::B2 | MemWidth::B8,
            sign: SignExtend::Zero,
            ..
        } if base == rsp
    ) {
        return false;
    }
    matches!(
        block.ops.get(index + 1),
        Some(next) if next.guest_pc == load.guest_pc
            && match &next.kind {
                OpKind::Add { src1, .. } => *src1 == rsp,
                OpKind::Mov { dst, .. } => *dst == rsp,
                _ => false,
            }
    )
}
/// Validate the exact PUSH shapes emitted by the x86 lifter. Lowering performs
/// the helper-backed store against `old_rsp - width` before committing RSP, so
/// a fault restarts with the architectural stack pointer unchanged. PUSH RSP
/// has an additional single-use virtual snapshot of the pre-decrement source.
pub(crate) fn x86_jit_push_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{Address, ArchReg, MemWidth, OpWidth, SrcOperand, VReg, X86Reg};

    if !allow_mem {
        return None;
    }
    let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
    let (sub_index, store_index, snapshot) = match block.ops.get(index).map(|op| &op.kind) {
        Some(OpKind::Mov {
            dst: temporary @ VReg::Virtual(_),
            src: SrcOperand::Reg(source),
            width: OpWidth::W16 | OpWidth::W64,
        }) if *source == rsp => (index + 1, index + 2, Some(*temporary)),
        _ => (index, index + 1, None),
    };
    let sub = block.ops.get(sub_index)?;
    let delta = match sub.kind {
        OpKind::Sub {
            dst,
            src1,
            src2: SrcOperand::Imm(delta @ (2 | 8)),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        } if dst == rsp && src1 == rsp => delta,
        _ => return None,
    };
    let store = block.ops.get(store_index)?;
    if sub.guest_pc != store.guest_pc
        || snapshot.is_some_and(|_| block.ops[index].guest_pc != sub.guest_pc)
    {
        return None;
    }
    let source_valid = |source: VReg| {
        matches!(source, VReg::Imm(_))
            || matches!(source, VReg::Arch(ArchReg::X86(reg)) if reg.gpr_index().is_some())
    };
    let expected_width = if delta == 2 {
        MemWidth::B2
    } else {
        MemWidth::B8
    };
    let store_source = match &store.kind {
        OpKind::Store {
            src,
            addr: Address::Direct(base),
            width,
        } if *base == rsp && *width == expected_width => *src,
        _ => return None,
    };

    match snapshot {
        Some(temporary) => {
            let expected_snapshot_width = if delta == 2 {
                OpWidth::W16
            } else {
                OpWidth::W64
            };
            if store_source != temporary
                || !matches!(block.ops[index].kind, OpKind::Mov { width, .. } if width == expected_snapshot_width)
                || virtual_definitions.get(&temporary) != Some(&1)
                || virtual_uses.get(&temporary) != Some(&1)
            {
                return None;
            }
            Some(3)
        }
        None => {
            if store_source == rsp || !source_valid(store_source) {
                return None;
            }
            Some(2)
        }
    }
}
pub(crate) fn x86_jit_push_candidate(block: &crate::smir::ir::SmirBlock, index: usize) -> bool {
    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{Address, ArchReg, MemWidth, OpWidth, SrcOperand, VReg, X86Reg};

    let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
    let Some(sub) = block.ops.get(index) else {
        return false;
    };
    let delta = match sub.kind {
        OpKind::Sub {
            dst,
            src1,
            src2: SrcOperand::Imm(delta @ (2 | 8)),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        } if dst == rsp && src1 == rsp => delta,
        _ => return false,
    };
    matches!(
        block.ops.get(index + 1),
        Some(crate::smir::ir::ops::SmirOp {
            guest_pc,
            kind: OpKind::Store {
                addr: Address::Direct(base),
                width,
                ..
            },
            ..
        }) if *guest_pc == sub.guest_pc
            && *base == rsp
            && *width == if delta == 2 { MemWidth::B2 } else { MemWidth::B8 }
    )
}
pub(crate) fn x86_bit_scan_shape_valid(op: &crate::smir::ir::ops::OpKind) -> bool {
    use crate::smir::ir::flags::{FlagSet, FlagUpdate};
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, VReg, X86Reg};

    let native_gpr = |reg: &VReg| {
        matches!(
            reg,
            VReg::Arch(ArchReg::X86(
                X86Reg::Rax
                    | X86Reg::Rcx
                    | X86Reg::Rdx
                    | X86Reg::Rbx
                    | X86Reg::Rsi
                    | X86Reg::Rdi
                    | X86Reg::R8
                    | X86Reg::R9
                    | X86Reg::R10
                    | X86Reg::R11
                    | X86Reg::R12
                    | X86Reg::R13
                    | X86Reg::R14
                    | X86Reg::R15
            ))
        )
    };

    matches!(
        op,
        OpKind::Bsf {
            dst,
            src,
            width: OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
            flags: FlagUpdate::None | FlagUpdate::Specific(FlagSet::ZF),
        } | OpKind::Bsr {
            dst,
            src,
            width: OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
            flags: FlagUpdate::None | FlagUpdate::Specific(FlagSet::ZF),
        } if native_gpr(dst) && native_gpr(src)
    )
}
pub(crate) fn x86_bit_test_shape_valid(op: &crate::smir::ir::ops::OpKind) -> bool {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, SrcOperand, VReg, X86Reg};

    let native_gpr = |reg: &VReg| {
        matches!(
            reg,
            VReg::Arch(ArchReg::X86(
                X86Reg::Rax
                    | X86Reg::Rcx
                    | X86Reg::Rdx
                    | X86Reg::Rbx
                    | X86Reg::Rsi
                    | X86Reg::Rdi
                    | X86Reg::R8
                    | X86Reg::R9
                    | X86Reg::R10
                    | X86Reg::R11
                    | X86Reg::R12
                    | X86Reg::R13
                    | X86Reg::R14
                    | X86Reg::R15
            ))
        )
    };
    let index_valid = |index: &SrcOperand| {
        matches!(index, SrcOperand::Imm(_) | SrcOperand::Imm64(_))
            || matches!(index, SrcOperand::Reg(reg) if native_gpr(reg))
    };
    let width_valid = |width: &OpWidth| matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64);

    match op {
        OpKind::Bt { src, index, width } => {
            native_gpr(src) && index_valid(index) && width_valid(width)
        }
        OpKind::Bts {
            dst,
            src,
            index,
            width,
        }
        | OpKind::Btr {
            dst,
            src,
            index,
            width,
        }
        | OpKind::Btc {
            dst,
            src,
            index,
            width,
        } => dst == src && native_gpr(dst) && index_valid(index) && width_valid(width),
        _ => false,
    }
}
pub(crate) fn x86_bmi_shape_valid(op: &crate::smir::ir::ops::OpKind) -> bool {
    use crate::smir::ir::flags::{FlagSet, FlagUpdate};
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, SrcOperand, VReg, X86Reg};

    let native_gpr = |reg: &VReg| {
        matches!(
            reg,
            VReg::Arch(ArchReg::X86(
                X86Reg::Rax
                    | X86Reg::Rcx
                    | X86Reg::Rdx
                    | X86Reg::Rbx
                    | X86Reg::Rsi
                    | X86Reg::Rdi
                    | X86Reg::R8
                    | X86Reg::R9
                    | X86Reg::R10
                    | X86Reg::R11
                    | X86Reg::R12
                    | X86Reg::R13
                    | X86Reg::R14
                    | X86Reg::R15
            ))
        )
    };
    let andn_flags = FlagSet::CF
        .union(FlagSet::ZF)
        .union(FlagSet::SF)
        .union(FlagSet::OF);
    let bextr_flags = FlagSet::CF.union(FlagSet::ZF).union(FlagSet::OF);
    let bzhi_flags = FlagSet::CF
        .union(FlagSet::ZF)
        .union(FlagSet::SF)
        .union(FlagSet::OF);

    match op {
        OpKind::AndNot {
            dst,
            src1,
            src2: SrcOperand::Reg(src2),
            width: OpWidth::W32 | OpWidth::W64,
            flags,
        } => {
            native_gpr(dst)
                && native_gpr(src1)
                && native_gpr(src2)
                && (*flags == FlagUpdate::None || *flags == FlagUpdate::Specific(andn_flags))
        }
        OpKind::Bextr {
            dst,
            src,
            control,
            width: OpWidth::W32 | OpWidth::W64,
            flags,
        } => {
            native_gpr(dst)
                && native_gpr(src)
                && (native_gpr(control) || matches!(control, VReg::Imm(_)))
                && (*flags == FlagUpdate::None || *flags == FlagUpdate::Specific(bextr_flags))
        }
        OpKind::Bzhi {
            dst,
            src,
            index,
            width: OpWidth::W32 | OpWidth::W64,
            flags,
        } => {
            native_gpr(dst)
                && native_gpr(src)
                && native_gpr(index)
                && (*flags == FlagUpdate::None || *flags == FlagUpdate::Specific(bzhi_flags))
        }
        OpKind::X86Bls {
            dst,
            src,
            width: OpWidth::W32 | OpWidth::W64,
            flags,
            ..
        } => {
            native_gpr(dst)
                && native_gpr(src)
                && (*flags == FlagUpdate::None || *flags == FlagUpdate::Specific(andn_flags))
        }
        OpKind::X86Tbm {
            dst,
            src,
            width: OpWidth::W32 | OpWidth::W64,
            flags,
            ..
        } => {
            native_gpr(dst)
                && native_gpr(src)
                && (*flags == FlagUpdate::None || *flags == FlagUpdate::Specific(andn_flags))
        }
        OpKind::Pdep {
            dst,
            src,
            mask,
            width: OpWidth::W32 | OpWidth::W64,
        }
        | OpKind::Pext {
            dst,
            src,
            mask,
            width: OpWidth::W32 | OpWidth::W64,
        } => native_gpr(dst) && native_gpr(src) && native_gpr(mask),
        _ => false,
    }
}
pub(crate) fn x86_adx_shape_valid(op: &crate::smir::ir::ops::OpKind) -> bool {
    use crate::smir::ir::flags::{FlagSet, FlagUpdate};
    use crate::smir::ir::ops::{OpKind, X86AdxKind};
    use crate::smir::ir::types::{ArchReg, OpWidth, VReg, X86Reg};

    let native_gpr = |reg: &VReg| {
        matches!(
            reg,
            VReg::Arch(ArchReg::X86(
                X86Reg::Rax
                    | X86Reg::Rcx
                    | X86Reg::Rdx
                    | X86Reg::Rbx
                    | X86Reg::Rsi
                    | X86Reg::Rdi
                    | X86Reg::R8
                    | X86Reg::R9
                    | X86Reg::R10
                    | X86Reg::R11
                    | X86Reg::R12
                    | X86Reg::R13
                    | X86Reg::R14
                    | X86Reg::R15
            ))
        )
    };

    let OpKind::X86Adx {
        dst,
        src1,
        src2,
        width: OpWidth::W32 | OpWidth::W64,
        kind,
        flags,
    } = op
    else {
        return false;
    };
    let output = match kind {
        X86AdxKind::Adcx => FlagSet::CF,
        X86AdxKind::Adox => FlagSet::OF,
    };

    native_gpr(dst)
        && native_gpr(src1)
        && native_gpr(src2)
        && (*flags == FlagUpdate::None || *flags == FlagUpdate::Specific(output))
}
pub(crate) fn x86_count_shape_valid(op: &crate::smir::ir::ops::OpKind) -> bool {
    use crate::smir::ir::flags::FlagSet;
    use crate::smir::ir::ops::{OpKind, X86CountKind};
    use crate::smir::ir::types::{ArchReg, OpWidth, VReg, X86Reg};

    let native_gpr = |reg: &VReg| {
        matches!(
            reg,
            VReg::Arch(ArchReg::X86(
                X86Reg::Rax
                    | X86Reg::Rcx
                    | X86Reg::Rdx
                    | X86Reg::Rbx
                    | X86Reg::Rsi
                    | X86Reg::Rdi
                    | X86Reg::R8
                    | X86Reg::R9
                    | X86Reg::R10
                    | X86Reg::R11
                    | X86Reg::R12
                    | X86Reg::R13
                    | X86Reg::R14
                    | X86Reg::R15
            ))
        )
    };

    let (dst, src, width, flags_valid) = match op {
        OpKind::Clz { dst, src, width }
        | OpKind::Ctz { dst, src, width }
        | OpKind::Popcnt { dst, src, width } => (dst, src, width, true),
        OpKind::X86Count {
            dst,
            src,
            width,
            kind,
            flags,
        } => {
            let architecturally_defined = match kind {
                X86CountKind::Popcnt => FlagSet::ALL_X86,
                X86CountKind::Tzcnt | X86CountKind::Lzcnt => FlagSet::CF.union(FlagSet::ZF),
            };
            (
                dst,
                src,
                width,
                flags
                    .as_set()
                    .difference(architecturally_defined)
                    .is_empty(),
            )
        }
        _ => return false,
    };

    matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
        && native_gpr(dst)
        && native_gpr(src)
        && flags_valid
}
pub(crate) fn x86_word_full_mul_shape_valid(
    op: &crate::smir::ir::ops::OpKind,
    allow_flag_updates: bool,
) -> bool {
    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, SrcOperand, VReg, X86Reg};

    matches!(
        op,
        OpKind::MulU {
            dst_lo: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
            dst_hi: Some(VReg::Arch(ArchReg::X86(X86Reg::Rdx))),
            src1: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
            src2: SrcOperand::Reg(src2),
            width: OpWidth::W16,
            flags,
        }
            | OpKind::MulS {
                dst_lo: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
                dst_hi: Some(VReg::Arch(ArchReg::X86(X86Reg::Rdx))),
                src1: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
                src2: SrcOperand::Reg(src2),
                width: OpWidth::W16,
                flags,
            } if x86_aarch64_legacy_gpr(src2)
                && matches!(flags, FlagUpdate::None | FlagUpdate::All)
                && (allow_flag_updates || *flags == FlagUpdate::None)
    )
}
pub(crate) fn x86_byte_full_mul_shape_valid(op: &crate::smir::ir::ops::OpKind) -> bool {
    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, SrcOperand, VReg, X86Reg};

    matches!(
        op,
        OpKind::MulU {
            dst_lo: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
            dst_hi: None,
            src1: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
            src2: SrcOperand::Reg(src2),
            width: OpWidth::W8,
            flags: FlagUpdate::None | FlagUpdate::All,
        }
            | OpKind::MulS {
                dst_lo: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
                dst_hi: None,
                src1: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
                src2: SrcOperand::Reg(src2),
                width: OpWidth::W8,
                flags: FlagUpdate::None | FlagUpdate::All,
            } if x86_native_identity_gpr(src2)
    )
}
pub(crate) fn x86_movx_uses_ambiguous_high_byte_source(op: &crate::smir::ir::ops::SmirOp) -> bool {
    use crate::smir::ir::ops::{OpKind, X86OpHint};
    use crate::smir::ir::types::{ArchReg, OpWidth, VReg, X86Reg};

    if matches!(
        op.x86_hint,
        Some(X86OpHint::RexByteReg | X86OpHint::LegacyHighByteReg)
    ) {
        return false;
    }

    matches!(
        &op.kind,
        OpKind::ZeroExtend {
            src: VReg::Arch(ArchReg::X86(
                X86Reg::Rsp | X86Reg::Rbp | X86Reg::Rsi | X86Reg::Rdi
            )),
            from_width: OpWidth::W8,
            ..
        } | OpKind::SignExtend {
            src: VReg::Arch(ArchReg::X86(
                X86Reg::Rsp | X86Reg::Rbp | X86Reg::Rsi | X86Reg::Rdi
            )),
            from_width: OpWidth::W8,
            ..
        }
    )
}
pub(crate) fn x86_legacy_high_byte_movx_shape_valid(op: &crate::smir::ir::ops::SmirOp) -> bool {
    use crate::smir::ir::ops::{OpKind, X86OpHint};
    use crate::smir::ir::types::{ArchReg, OpWidth, VReg, X86Reg};

    let parent = |reg: &VReg| {
        matches!(
            reg,
            VReg::Arch(ArchReg::X86(
                X86Reg::Rax | X86Reg::Rcx | X86Reg::Rdx | X86Reg::Rbx
            ))
        )
    };
    let destination = |reg: &VReg| {
        matches!(
            reg,
            VReg::Arch(ArchReg::X86(
                X86Reg::Rax
                    | X86Reg::Rcx
                    | X86Reg::Rdx
                    | X86Reg::Rbx
                    | X86Reg::Rsp
                    | X86Reg::Rbp
                    | X86Reg::Rsi
                    | X86Reg::Rdi
            ))
        )
    };

    matches!(op.x86_hint, Some(X86OpHint::LegacyHighByteReg))
        && matches!(
            &op.kind,
            OpKind::ZeroExtend {
                dst,
                src,
                from_width: OpWidth::W8,
                to_width: OpWidth::W16 | OpWidth::W32,
            } | OpKind::SignExtend {
                dst,
                src,
                from_width: OpWidth::W8,
                to_width: OpWidth::W16 | OpWidth::W32,
            } if parent(src) && destination(dst)
        )
}
pub(crate) fn x86_ndd_double_shift_shape_valid(op: &crate::smir::ir::ops::OpKind) -> bool {
    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, SrcOperand, VReg, X86Reg};
    let OpKind::X86NddDoubleShift {
        dst,
        base,
        fill,
        amount,
        width,
        flags,
        ..
    } = op
    else {
        return false;
    };
    let native_gpr = |reg: &VReg| {
        matches!(
            reg,
            VReg::Arch(ArchReg::X86(
                X86Reg::Rax
                    | X86Reg::Rcx
                    | X86Reg::Rdx
                    | X86Reg::Rbx
                    | X86Reg::Rsi
                    | X86Reg::Rdi
                    | X86Reg::R8
                    | X86Reg::R9
                    | X86Reg::R10
                    | X86Reg::R11
                    | X86Reg::R12
                    | X86Reg::R13
                    | X86Reg::R14
                    | X86Reg::R15
            ))
        )
    };
    native_gpr(dst)
        && native_gpr(base)
        && native_gpr(fill)
        && matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
        && matches!(flags, FlagUpdate::None | FlagUpdate::All)
        && matches!(
            amount,
            SrcOperand::Imm(_) | SrcOperand::Reg(VReg::Arch(ArchReg::X86(X86Reg::Rcx)))
        )
}
