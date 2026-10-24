//! ARM control-flow summaries, including authenticated transfer metadata.

use super::{direct_label_cf, fallthrough_json, hex_u64, label_operand};
use crate::isa::arm::decoder::Mnemonic;
use serde_json::{Value, json};

pub(super) fn arm_control_flow(insn: &crate::isa::arm::DecodedInsn, pc: u64) -> Value {
    match insn.mnemonic {
        Mnemonic::B => direct_label_cf("branch", insn, pc, insn.size),
        Mnemonic::BL => direct_label_cf("call", insn, pc, insn.size),
        Mnemonic::BCC | Mnemonic::CBZ | Mnemonic::CBNZ | Mnemonic::TBZ | Mnemonic::TBNZ => {
            let target = insn
                .operands
                .iter()
                .find_map(label_operand)
                .map(|offset| (pc as i64).wrapping_add(offset) as u64);
            json!({
                "kind": "cond_branch",
                "target": target.map(hex_u64),
                "fallthrough": hex_u64(pc + insn.size as u64),
                "condition": insn.cond.map(|cond| format!("{cond:?}")),
            })
        }
        Mnemonic::BRAA | Mnemonic::BRAB | Mnemonic::BRAAZ | Mnemonic::BRABZ => {
            json!({"kind": "indirect_branch", "authenticated": true})
        }
        Mnemonic::BLRAA | Mnemonic::BLRAB | Mnemonic::BLRAAZ | Mnemonic::BLRABZ => {
            json!({"kind": "indirect_call", "authenticated": true})
        }
        Mnemonic::RETAA | Mnemonic::RETAB => {
            json!({"kind": "return", "authenticated": true})
        }
        Mnemonic::ERETAA | Mnemonic::ERETAB => {
            json!({"kind": "exception_return", "authenticated": true})
        }
        Mnemonic::BX | Mnemonic::BR => json!({"kind": "indirect_branch"}),
        Mnemonic::BLX | Mnemonic::BLR => json!({"kind": "indirect_call"}),
        Mnemonic::RET => json!({"kind": "return"}),
        Mnemonic::SVC => json!({"kind": "syscall"}),
        Mnemonic::BRK => json!({"kind": "trap", "trap": "breakpoint"}),
        Mnemonic::HLT => json!({"kind": "trap", "trap": "halt"}),
        Mnemonic::UDF | Mnemonic::UNDEFINED => json!({"kind": "trap", "trap": "undefined"}),
        _ => fallthrough_json(pc + insn.size as u64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::arm::decoder::aarch64::Aarch64Decoder;

    #[test]
    fn authenticated_transfers_are_not_reported_as_fallthrough() {
        for (word, kind) in [
            (0xd71f_081f, "indirect_branch"),
            (0xd61f_081f, "indirect_branch"),
            (0xd73f_081f, "indirect_call"),
            (0xd63f_081f, "indirect_call"),
            (0xd65f_0bff, "return"),
            (0xd69f_0bff, "exception_return"),
        ] {
            let decoded = Aarch64Decoder::decode(word).unwrap();
            let summary = arm_control_flow(&decoded, 0x1000);
            assert_eq!(summary["kind"], kind);
            assert_eq!(summary["authenticated"], true);
        }
    }
}
