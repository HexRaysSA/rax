//! Typed descriptor coherence with the public shared decoder, including reserved slots.

use super::*;
use crate::isa::arm::aarch64::pauth_instruction::PauthInstruction;
use crate::isa::arm::decoder::{Mnemonic, aarch64::Aarch64Decoder};

fn check(raw: u32) {
    let decoded = Aarch64Decoder::decode(raw).unwrap();
    let descriptor = PauthInstruction::decode(raw);
    let supported = matches!(
        decoded.mnemonic,
        Mnemonic::PACIA
            | Mnemonic::PACIB
            | Mnemonic::PACDA
            | Mnemonic::PACDB
            | Mnemonic::AUTIA
            | Mnemonic::AUTIB
            | Mnemonic::AUTDA
            | Mnemonic::AUTDB
            | Mnemonic::PACIZA
            | Mnemonic::PACIZB
            | Mnemonic::PACDZA
            | Mnemonic::PACDZB
            | Mnemonic::AUTIZA
            | Mnemonic::AUTIZB
            | Mnemonic::AUTDZA
            | Mnemonic::AUTDZB
            | Mnemonic::XPACI
            | Mnemonic::XPACD
            | Mnemonic::PACGA
            | Mnemonic::BRAA
            | Mnemonic::BRAB
            | Mnemonic::BLRAA
            | Mnemonic::BLRAB
            | Mnemonic::BRAAZ
            | Mnemonic::BRABZ
            | Mnemonic::BLRAAZ
            | Mnemonic::BLRABZ
            | Mnemonic::RETAA
            | Mnemonic::RETAB
            | Mnemonic::ERETAA
            | Mnemonic::ERETAB
            | Mnemonic::LDRAA
            | Mnemonic::LDRAB
            | Mnemonic::PACIA1716
            | Mnemonic::PACIB1716
            | Mnemonic::AUTIA1716
            | Mnemonic::AUTIB1716
            | Mnemonic::PACIAZ
            | Mnemonic::PACIBZ
            | Mnemonic::PACIASP
            | Mnemonic::PACIBSP
            | Mnemonic::AUTIAZ
            | Mnemonic::AUTIBZ
            | Mnemonic::AUTIASP
            | Mnemonic::AUTIBSP
            | Mnemonic::XPACLRI
    );
    assert_eq!(
        descriptor.is_some(),
        supported,
        "{raw:#010x}: {:?}",
        decoded.mnemonic
    );
    if let Some(instruction) = descriptor {
        assert!(instruction.valid_operands(), "{raw:#010x}");
    }
}

#[test]
fn pauth_descriptors_cover_every_register_slot_and_reserved_modifier() {
    let mut cases = 0usize;
    for rd in 0..32 {
        for rn in 0..32 {
            for opcode in 0..32 {
                check(0xdac1_0000 | (opcode << 10) | (rn << 5) | rd);
                cases += 1;
            }
            for rm in 0..32 {
                check(0x9ac0_3000 | (rm << 16) | (rn << 5) | rd);
                cases += 1;
            }
            for opc in [0, 1, 2, 4, 8, 9] {
                for op3 in [2, 3] {
                    check(0xd61f_0000 | (opc << 21) | (op3 << 10) | (rn << 5) | rd);
                    cases += 1;
                }
            }
            for immediate in [0, 1, 511, 512, 1023] {
                for writeback in 0..2 {
                    for key_b in 0..2 {
                        check(
                            0xf820_0400
                                | (key_b << 23)
                                | ((immediate >> 9) << 22)
                                | ((immediate & 511) << 12)
                                | (writeback << 11)
                                | (rn << 5)
                                | rd,
                        );
                        cases += 1;
                    }
                }
            }
        }
    }
    for immediate in 0..128 {
        for rt in 0..32 {
            check(0xd503_2000 | (immediate << 5) | rt);
            cases += 1;
        }
    }
    assert_eq!(cases, 102400);
}
