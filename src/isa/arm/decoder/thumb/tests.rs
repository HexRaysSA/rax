//! Thumb decoder tests: T16 and T32 encodings.

use super::*;

#[test]
fn test_is_32bit() {
    // 16-bit instructions
    assert!(!ThumbDecoder::is_32bit_instruction(0x4600)); // MOV r0, r0
    assert!(!ThumbDecoder::is_32bit_instruction(0xB500)); // PUSH {LR}

    // 32-bit instructions
    assert!(ThumbDecoder::is_32bit_instruction(0xF000)); // 0b11110...
    assert!(ThumbDecoder::is_32bit_instruction(0xE800)); // 0b11101...
    assert!(ThumbDecoder::is_32bit_instruction(0xF800)); // 0b11111...
}

#[test]
fn test_16bit_nop() {
    // NOP: bf00
    let insn = ThumbDecoder::decode_16bit(0xbf00).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::NOP);
    assert_eq!(insn.size, 2);
}

#[test]
fn test_16bit_mov_imm() {
    // MOVS R0, #0x42: 2042
    let insn = ThumbDecoder::decode_16bit(0x2042).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::MOVS);
    assert!(insn.sets_flags);
}

#[test]
fn test_16bit_add_reg() {
    // ADDS R0, R1, R2: 1888
    let insn = ThumbDecoder::decode_16bit(0x1888).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::ADDS);
}

#[test]
fn test_16bit_ldr_imm() {
    // LDR R0, [R1, #0]: 6808
    let insn = ThumbDecoder::decode_16bit(0x6808).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::LDR);
}

#[test]
fn test_16bit_push() {
    // PUSH {R4, LR}: b510
    let insn = ThumbDecoder::decode_16bit(0xb510).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::PUSH);
}

#[test]
fn test_16bit_pop() {
    // POP {R4, PC}: bd10
    let insn = ThumbDecoder::decode_16bit(0xbd10).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::POP);
}

#[test]
fn test_16bit_bx_lr() {
    // BX LR: 4770
    let insn = ThumbDecoder::decode_16bit(0x4770).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::BX);
}

#[test]
fn test_16bit_b() {
    // B #0x10: e004
    let insn = ThumbDecoder::decode_16bit(0xe004).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::B);
}

#[test]
fn test_16bit_beq() {
    // BEQ #0x10: d004
    let insn = ThumbDecoder::decode_16bit(0xd004).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::BCC);
    assert_eq!(insn.cond, Some(Condition::EQ));
}

#[test]
fn test_16bit_cbz_cbnz_decode_displacements_as_branch_labels() {
    for (raw, mnemonic, rn, offset) in [
        (0xb108, Mnemonic::CBZ, 0, 2),
        (0xb90f, Mnemonic::CBNZ, 7, 2),
        (0xb3f8, Mnemonic::CBZ, 0, 126),
        (0xbbff, Mnemonic::CBNZ, 7, 126),
    ] {
        let insn = ThumbDecoder::decode_16bit(raw).unwrap();
        assert_eq!(insn.mnemonic, mnemonic);
        assert_eq!(insn.size, 2);
        assert!(matches!(
            insn.operands.as_slice(),
            [Operand::Reg(reg), Operand::Label(actual)]
                if reg.num == rn && *actual == offset
        ));
    }
}

#[test]
fn test_16bit_cmp_imm() {
    // CMP R0, #0: 2800
    let insn = ThumbDecoder::decode_16bit(0x2800).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::CMP);
}

#[test]
fn test_16bit_lsl() {
    // LSLS R0, R1, #4: 0108
    let insn = ThumbDecoder::decode_16bit(0x0108).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::LSLS);
}

#[test]
fn test_16bit_svc() {
    // SVC #0: df00
    let insn = ThumbDecoder::decode_16bit(0xdf00).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::SVC);
}

#[test]
fn test_32bit_bl() {
    // BL #0x100: f000 f880
    let raw = 0xf000_f880u32;
    let insn = ThumbDecoder::decode_32bit(raw).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::BL);
    assert_eq!(insn.size, 4);
}

#[test]
fn test_32bit_mov_imm() {
    // MOV.W R0, #1: f04f 0001
    let raw = 0xf04f_0001u32;
    let insn = ThumbDecoder::decode_32bit(raw).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::MOV);
}

#[test]
fn test_32bit_add_imm() {
    // ADD.W R0, R1, #1: f101 0001
    let raw = 0xf101_0001u32;
    let insn = ThumbDecoder::decode_32bit(raw).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::ADD);
}

#[test]
fn test_32bit_ldr_imm() {
    // LDR.W R0, [R1]: f8d1 0000
    let raw = 0xf8d1_0000u32;
    let insn = ThumbDecoder::decode_32bit(raw).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::LDR);
}

#[test]
fn test_32bit_literal_loads_decode_full_positive_and_negative_imm12() {
    for (raw, mnemonic, rt, offset) in [
        (0xf8df_0123, Mnemonic::LDR, 0, 0x123),
        (0xf85f_1123, Mnemonic::LDR, 1, -0x123),
        (0xf89f_2234, Mnemonic::LDRB, 2, 0x234),
        (0xf81f_3234, Mnemonic::LDRB, 3, -0x234),
        (0xf8bf_4456, Mnemonic::LDRH, 4, 0x456),
        (0xf83f_5456, Mnemonic::LDRH, 5, -0x456),
        (0xf99f_6678, Mnemonic::LDRSB, 6, 0x678),
        (0xf91f_7678, Mnemonic::LDRSB, 7, -0x678),
        (0xf9bf_889a, Mnemonic::LDRSH, 8, 0x89a),
        (0xf93f_989a, Mnemonic::LDRSH, 9, -0x89a),
        (0xf8df_afff, Mnemonic::LDR, 10, 0xfff),
        (0xf85f_bfff, Mnemonic::LDR, 11, -0xfff),
    ] {
        let insn = ThumbDecoder::decode_32bit(raw).unwrap();
        assert_eq!(insn.mnemonic, mnemonic, "{raw:#010x}");
        assert!(
            matches!(
                insn.operands.as_slice(),
                [Operand::Reg(reg), Operand::Mem(MemOperand {
                    base,
                    offset: MemOffset::Imm(actual),
                    mode: AddressingMode::Offset,
                })] if reg.num == rt && base.num == 15 && *actual == offset
            ),
            "{raw:#010x}: {insn:?}"
        );
    }
}

#[test]
fn test_32bit_push_multiple() {
    // PUSH.W {R4-R11, LR}: e92d 4ff0
    let raw = 0xe92d_4ff0u32;
    let insn = ThumbDecoder::decode_32bit(raw).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::PUSH);
}

#[test]
fn test_32bit_register_extends_preserve_exact_operation() {
    let cases = [
        (0xfa4f_f283, Mnemonic::SXTB, 2, 3),
        (0xfa0f_f485, Mnemonic::SXTH, 4, 5),
        (0xfa5f_f687, Mnemonic::UXTB, 6, 7),
        (0xfa1f_f889, Mnemonic::UXTH, 8, 9),
    ];

    for (raw, mnemonic, rd, rm) in cases {
        let insn = ThumbDecoder::decode_32bit(raw).unwrap();
        assert_eq!(insn.mnemonic, mnemonic);
        assert_eq!(insn.size, 4);
        assert_eq!(
            insn.operands,
            vec![
                Operand::Reg(Register::arm32(rd)),
                Operand::Reg(Register::arm32(rm))
            ]
        );
    }
}
