//! Structured state-backed AArch64 operation output.

use crate::smir::ir::ops::{ArmPauthOp, OpKind};
use serde_json::{Value, json};

pub(super) fn operation_json(operation: &OpKind) -> Value {
    match operation {
        OpKind::ArmInstructionBegin { raw, features } => json!({
            "opcode": "arm_instruction_begin", "raw": raw, "features": features,
        }),
        OpKind::ArmInstructionCommit { raw } => json!({
            "opcode": "arm_instruction_commit", "raw": raw,
        }),
        OpKind::ArmPauth(ArmPauthOp { raw, instruction }) => json!({
            "opcode": "arm_pauth", "raw": raw,
            "instruction": format!("{instruction:?}"),
        }),
        _ => json!({ "opcode": "invalid_arm_pauth" }),
    }
}
