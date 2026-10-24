//! Feature-bound PAuth lifting and precise AArch64 instruction framing.

use super::*;
use crate::smir::ir::ops::ArmPauthOp;

impl Aarch64Lifter {
    pub(super) fn lift_pauth(
        &self,
        operation: ArmPauthOp,
        pc: u64,
        ctx: &mut LiftContext,
    ) -> (Vec<SmirOp>, ControlFlow) {
        let flow = if operation.instruction.is_control_flow() {
            // Authentication and ERET state restoration establish the target.
            // Generic Call/Return terminators would apply a second, different
            // transfer and could overwrite an aliased authenticated target.
            ControlFlow::IndirectBranch {
                target: VReg::Arch(ArchReg::Arm(ArmReg::Pc)),
            }
        } else {
            ControlFlow::NextInsn
        };
        (
            vec![SmirOp::new(
                ctx.next_op_id(),
                pc,
                OpKind::ArmPauth(operation),
            )],
            flow,
        )
    }

    pub(super) fn frame_instruction(
        &self,
        raw: u32,
        pc: u64,
        features: u64,
        ops: &mut Vec<SmirOp>,
        flow: &ControlFlow,
        ctx: &mut LiftContext,
    ) {
        ops.insert(
            0,
            SmirOp::new(
                ctx.next_op_id(),
                pc,
                OpKind::ArmInstructionBegin { raw, features },
            ),
        );
        if matches!(
            flow,
            ControlFlow::Trap {
                kind: TrapKind::Undefined
            }
        ) {
            ops.push(SmirOp::new(
                ctx.next_op_id(),
                pc,
                OpKind::Undefined { opcode: raw },
            ));
        }
        ops.push(SmirOp::new(
            ctx.next_op_id(),
            pc,
            OpKind::ArmInstructionCommit { raw },
        ));
    }
}
