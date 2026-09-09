//! Scalar identity-register and state-backed ALU admission shapes.

use super::*;

pub(crate) fn x86_native_identity_gpr(reg: &crate::smir::ir::types::VReg) -> bool {
    use crate::smir::ir::types::{ArchReg, VReg};

    matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.gpr_index().is_some_and(|index| index <= 15 && !matches!(index, 4 | 5)))
}
/// Architectural encoding of an identity-mapped GPR, if `reg` is one.
pub(crate) fn x86_native_identity_gpr_index(reg: &crate::smir::ir::types::VReg) -> Option<u8> {
    use crate::smir::ir::types::{ArchReg, VReg};

    match reg {
        VReg::Arch(ArchReg::X86(x86)) => x86
            .gpr_index()
            .filter(|index| *index <= 15 && !matches!(index, 4 | 5)),
        _ => None,
    }
}
pub(crate) fn x86_state_backed_stack_mov_valid(op: &crate::smir::ir::ops::OpKind) -> bool {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, SrcOperand, VReg};

    let gpr_index = |reg: &VReg| match reg {
        VReg::Arch(ArchReg::X86(x86)) => x86.gpr_index(),
        _ => None,
    };
    let is_stack = |reg: &VReg| gpr_index(reg).is_some_and(|index| matches!(index, 4 | 5));

    matches!(
        op,
        OpKind::Mov {
            dst,
            src: SrcOperand::Reg(src),
            width: OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
        } if gpr_index(dst).is_some()
            && gpr_index(src).is_some()
            && (is_stack(dst) || is_stack(src))
    ) || matches!(
        op,
        OpKind::Mov {
            dst,
            src: SrcOperand::Imm(_) | SrcOperand::Imm64(_),
            width: OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64,
        } if is_stack(dst)
    )
}
pub(crate) fn x86_state_backed_stack_alu_valid(op: &crate::smir::ir::ops::OpKind) -> bool {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{ArchReg, OpWidth, SrcOperand, VReg};

    let gpr_index = |reg: &VReg| match reg {
        VReg::Arch(ArchReg::X86(x86)) => x86.gpr_index(),
        _ => None,
    };
    let is_stack = |reg: &VReg| gpr_index(reg).is_some_and(|index| matches!(index, 4 | 5));
    let valid = |dst: &VReg, src1: &VReg, src2: &SrcOperand, width: &OpWidth| {
        matches!(
            width,
            OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64
        ) && gpr_index(dst).is_some()
            && gpr_index(src1).is_some()
            && match src2 {
                SrcOperand::Reg(src2) => gpr_index(src2).is_some(),
                SrcOperand::Imm(value) => *width != OpWidth::W64 || i32::try_from(*value).is_ok(),
                _ => false,
            }
            && (is_stack(dst)
                || is_stack(src1)
                || matches!(src2, SrcOperand::Reg(src2) if is_stack(src2)))
    };

    match op {
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
        } => {
            valid(dst, src1, src2, width)
                && matches!(
                    flags,
                    crate::smir::ir::flags::FlagUpdate::None
                        | crate::smir::ir::flags::FlagUpdate::All
                )
        }
        _ => false,
    }
}

/// Whether the native scalar path supports the immediate representation.
/// W64 Group 1/TEST use either an exact sign-extended immediate or a saved
/// full-width register source. Imm64 remains unsupported at narrower widths.
pub(crate) fn x86_jit_scalar_alu_immediate_valid(op: &crate::smir::ir::ops::OpKind) -> bool {
    use crate::smir::ir::ops::OpKind;
    use crate::smir::ir::types::{OpWidth, SrcOperand};

    let valid = |source: &SrcOperand, width: OpWidth| match source {
        SrcOperand::Imm(_) => true,
        SrcOperand::Imm64(_) => width == OpWidth::W64,
        _ => true,
    };

    match op {
        OpKind::Add { src2, width, .. }
        | OpKind::Sub { src2, width, .. }
        | OpKind::Adc { src2, width, .. }
        | OpKind::Sbb { src2, width, .. }
        | OpKind::And { src2, width, .. }
        | OpKind::Or { src2, width, .. }
        | OpKind::Xor { src2, width, .. }
        | OpKind::Cmp { src2, width, .. }
        | OpKind::Test { src2, width, .. } => valid(src2, *width),
        _ => true,
    }
}
