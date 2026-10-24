//! Structural validation for precise AArch64 instruction spans.

use super::{
    SmirBlock, Terminator,
    ops::OpKind,
    types::{ArchReg, ArmReg, VReg},
};
use crate::isa::arm::aarch64::pauth_instruction::PauthInstruction;

/// Validate before interpretation/lowering, so a malformed span cannot execute
/// a prefix before being rejected. Runs in O(n) time and O(1) auxiliary space.
pub(crate) fn validate_aarch64_instructions(block: &SmirBlock) -> Result<(), &'static str> {
    let mut span = None;
    let mut body_count = 0;
    for (index, op) in block.ops.iter().enumerate() {
        match op.kind {
            OpKind::ArmInstructionBegin { raw, .. } if span.is_none() => {
                span = Some((op.guest_pc, raw));
                body_count = 0;
            }
            OpKind::ArmInstructionCommit { raw } if span == Some((op.guest_pc, raw)) => {
                if let Some(instruction) = PauthInstruction::decode(raw) {
                    if body_count != 1 {
                        return Err("AArch64 PAuth instruction framing");
                    }
                    if instruction.is_control_flow()
                        && (index + 1 != block.ops.len()
                            || !matches!(
                                block.terminator,
                                Terminator::IndirectBranch {
                                    target: VReg::Arch(ArchReg::Arm(ArmReg::Pc)),
                                    ..
                                }
                            ))
                    {
                        return Err("AArch64 PAuth control-flow framing");
                    }
                }
                span = None;
            }
            OpKind::ArmInstructionBegin { .. } | OpKind::ArmInstructionCommit { .. } => {
                return Err("AArch64 instruction framing");
            }
            OpKind::ArmPauth(operation)
                if span == Some((op.guest_pc, operation.raw)) && operation.valid() =>
            {
                body_count += 1;
            }
            OpKind::ArmPauth(..) => return Err("AArch64 PAuth instruction framing"),
            _ if span.is_some_and(|(pc, raw)| {
                pc == op.guest_pc && PauthInstruction::decode(raw).is_none()
            }) =>
            {
                body_count += 1;
            }
            _ => return Err("AArch64 unframed operation"),
        }
    }
    if span.is_some() {
        Err("AArch64 instruction framing")
    } else {
        Ok(())
    }
}
