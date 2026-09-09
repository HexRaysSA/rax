//! Exact scalar ALU memory-source and read-modify-write admission shapes.

use super::*;
use crate::smir::lower::x86_64::{
    x86_scalar_alu_immediate_candidate, x86_scalar_alu_immediate_shape,
};

pub(crate) fn x86_jit_mem_address_shape_valid(addr: &crate::smir::ir::types::Address) -> bool {
    addr.is_x86_state_backed_shape()
}
pub(crate) fn x86_binary_alu_shape(
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
        OpKind::Add {
            dst,
            src1,
            src2,
            width,
            flags,
        } => Some((0, *dst, *src1, src2.clone(), *width, *flags)),
        OpKind::Or {
            dst,
            src1,
            src2,
            width,
            flags,
        } => Some((1, *dst, *src1, src2.clone(), *width, *flags)),
        OpKind::Adc {
            dst,
            src1,
            src2,
            width,
            flags,
        } => Some((2, *dst, *src1, src2.clone(), *width, *flags)),
        OpKind::Sbb {
            dst,
            src1,
            src2,
            width,
            flags,
        } => Some((3, *dst, *src1, src2.clone(), *width, *flags)),
        OpKind::And {
            dst,
            src1,
            src2,
            width,
            flags,
        } => Some((4, *dst, *src1, src2.clone(), *width, *flags)),
        OpKind::Sub {
            dst,
            src1,
            src2,
            width,
            flags,
        } => Some((5, *dst, *src1, src2.clone(), *width, *flags)),
        OpKind::Xor {
            dst,
            src1,
            src2,
            width,
            flags,
        } => Some((6, *dst, *src1, src2.clone(), *width, *flags)),
        _ => None,
    }
}
/// Validate the exact fault-precise scalar memory-destination sequence emitted
/// by the x86 lifter: `Load old; ALU result,old,source` without flags; `Store
/// result`; then the same ALU into a dead virtual with full flag updates. The
/// post-store replay is architecturally significant: a failing store must leave
/// the incoming flags unchanged.
pub(crate) fn x86_jit_mem_alu_rmw_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, SignExtend, SrcOperand, VReg};

    if let Some(folded) = x86_jit_mem_alu_folded_rmw_sequence(
        block,
        index,
        allow_mem,
        virtual_definitions,
        virtual_uses,
    ) {
        return Some(folded.consumed);
    }
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
    if [compute, store]
        .into_iter()
        .any(|op| op.guest_pc != load.guest_pc)
    {
        return None;
    }
    let (compute_tag, result, compute_old, source, compute_width, compute_flags) =
        x86_binary_alu_shape(&compute.kind)?;
    let VReg::Virtual(_) = result else {
        return None;
    };
    let source_valid = match &source {
        SrcOperand::Reg(VReg::Arch(ArchReg::X86(reg))) => reg.gpr_index().is_some(),
        SrcOperand::Imm(_) => true,
        SrcOperand::Imm64(_) => width == OpWidth::W64,
        _ => false,
    };
    if compute_old != old
        || compute_width != width
        || compute_flags != FlagUpdate::None
        || !source_valid
        || (x86_scalar_alu_immediate_candidate(compute)
            && x86_scalar_alu_immediate_shape(compute).is_none())
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
    // post-store replay. The remaining three-operation form publishes no flags
    // at all, so the loaded value is consumed exactly once and the fused
    // lowering simply omits the replay.
    if virtual_uses.get(&old) == Some(&1) {
        return Some(3);
    }

    let replay = block.ops.get(index + 3)?;
    if replay.guest_pc != load.guest_pc {
        return None;
    }
    let (replay_tag, flags_result, replay_old, replay_source, replay_width, replay_flags) =
        x86_binary_alu_shape(&replay.kind)?;
    let VReg::Virtual(_) = flags_result else {
        return None;
    };
    if compute_tag != replay_tag
        || replay_old != old
        || !(source == replay_source
            || (width == OpWidth::W64
                && source
                    .as_imm()
                    .zip(replay_source.as_imm())
                    .is_some_and(|(left, right)| left == right)))
        || replay_width != width
        || replay_flags != FlagUpdate::All
        || (x86_scalar_alu_immediate_candidate(replay)
            && x86_scalar_alu_immediate_shape(replay).is_none())
        || virtual_uses.get(&old) != Some(&2)
        || virtual_definitions.get(&flags_result) != Some(&1)
        || virtual_uses.contains_key(&flags_result)
    {
        return None;
    }

    Some(4)
}
/// Validate an exact scalar memory-source pair emitted by the x86 lifter:
/// `Load virtual; ALU/CMP/TEST ... virtual`. The load result must be an SSA
/// single-definition/single-use value, and every architectural operand must be
/// representable by the native identity bridge. Native lowering replaces the
/// pair with one fault-precise MMU helper load and a stack-backed scalar source,
/// so the virtual never aliases a live guest GPR. This also admits the exact
/// destructive two-operand `IMUL dst,virtual` and hinted
/// `IMUL dst,virtual,immediate` shapes.
pub(crate) fn x86_jit_mem_alu_source_sequence_len(
    block: &crate::smir::ir::SmirBlock,
    index: usize,
    allow_mem: bool,
    virtual_definitions: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
    virtual_uses: &std::collections::HashMap<crate::smir::ir::types::VReg, usize>,
) -> Option<usize> {
    use crate::smir::ir::flags::FlagUpdate;
    use crate::smir::ir::ops::{OpKind, X86OpHint};
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
    if !matches!(
        width,
        OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64
    ) || !x86_jit_mem_address_shape_valid(addr)
        || virtual_definitions.get(&temporary) != Some(&1)
    {
        return None;
    }

    let consumer = block.ops.get(index + 1)?;
    if consumer.guest_pc != load.guest_pc {
        return None;
    }
    if x86_jit_mem_alu_folded_source_valid(consumer, temporary, width, virtual_uses) {
        return Some(2);
    }
    if virtual_uses.get(&temporary) != Some(&1) {
        return None;
    }
    if x86_scalar_alu_immediate_candidate(consumer) {
        let shape = x86_scalar_alu_immediate_shape(consumer)?;
        let gpr = |reg| matches!(reg, VReg::Arch(crate::smir::ir::types::ArchReg::X86(reg)) if reg.gpr_index().is_some());
        return (width == OpWidth::W64 && shape.src1 == temporary && shape.dst.is_none_or(gpr))
            .then_some(2);
    }
    let identity = |reg: &VReg| x86_native_identity_gpr(reg);
    let imm_valid = |value: i64| width != OpWidth::W64 || i32::try_from(value).is_ok();
    let imul_imm_valid = |value: i64, hint: Option<X86OpHint>| match hint {
        Some(X86OpHint::ImulImm8) => i8::try_from(value).is_ok(),
        Some(X86OpHint::ImulImm32) => match width {
            OpWidth::W16 => i16::try_from(value).is_ok(),
            OpWidth::W32 | OpWidth::W64 => i32::try_from(value).is_ok(),
            _ => false,
        },
        _ => false,
    };
    let binary_shape =
        |dst: &VReg, src1: &VReg, src2: &SrcOperand, op_width: OpWidth, flags: FlagUpdate| {
            op_width == width
                && identity(dst)
                && matches!(flags, FlagUpdate::None | FlagUpdate::All)
                && match (src1, src2) {
                    (lhs, SrcOperand::Reg(rhs)) if *rhs == temporary => identity(lhs),
                    (lhs, SrcOperand::Reg(rhs)) if *lhs == temporary => identity(rhs),
                    (lhs, SrcOperand::Imm(value)) if *lhs == temporary => imm_valid(*value),
                    _ => false,
                }
        };

    let valid = match &consumer.kind {
        OpKind::Add {
            dst,
            src1,
            src2,
            width,
            flags,
        }
        | OpKind::Sub {
            dst,
            src1,
            src2,
            width,
            flags,
        }
        | OpKind::Adc {
            dst,
            src1,
            src2,
            width,
            flags,
        }
        | OpKind::Sbb {
            dst,
            src1,
            src2,
            width,
            flags,
        }
        | OpKind::And {
            dst,
            src1,
            src2,
            width,
            flags,
        }
        | OpKind::Or {
            dst,
            src1,
            src2,
            width,
            flags,
        }
        | OpKind::Xor {
            dst,
            src1,
            src2,
            width,
            flags,
        } => binary_shape(dst, src1, src2, *width, *flags),
        OpKind::Cmp {
            src1,
            src2,
            width: op_width,
        }
        | OpKind::Test {
            src1,
            src2,
            width: op_width,
        } if *op_width == width => match (src1, src2) {
            (lhs, SrcOperand::Reg(rhs)) if *lhs == temporary => identity(rhs),
            (lhs, SrcOperand::Reg(rhs)) if *rhs == temporary => identity(lhs),
            (lhs, SrcOperand::Imm(value)) if *lhs == temporary => imm_valid(*value),
            _ => false,
        },
        OpKind::MulS {
            dst_lo,
            dst_hi: None,
            src1,
            src2: SrcOperand::Reg(source),
            width: op_width,
            flags,
        } => {
            *op_width == width
                && matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
                && dst_lo == src1
                && *source == temporary
                && identity(dst_lo)
                && matches!(flags, FlagUpdate::None | FlagUpdate::All)
                && consumer.x86_hint.is_none()
        }
        OpKind::MulS {
            dst_lo,
            dst_hi: None,
            src1,
            src2: SrcOperand::Imm(value),
            width: op_width,
            flags,
        } => {
            *op_width == width
                && matches!(width, OpWidth::W16 | OpWidth::W32 | OpWidth::W64)
                && *src1 == temporary
                && identity(dst_lo)
                && matches!(flags, FlagUpdate::None | FlagUpdate::All)
                && imul_imm_valid(*value, consumer.x86_hint)
        }
        _ => false,
    };

    valid.then_some(2)
}
