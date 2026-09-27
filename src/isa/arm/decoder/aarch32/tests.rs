//! A32 decoder unit tests.

use super::*;

fn decode_bytes(bytes: &[u8; 4]) -> Result<DecodedInsn, DecodeError> {
    let raw = u32::from_le_bytes(*bytes);
    Aarch32Decoder::decode(raw)
}

#[test]
fn test_nop() {
    // NOP: e320f000
    let insn = decode_bytes(&[0x00, 0xf0, 0x20, 0xe3]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::NOP);
}

#[test]
fn test_mov_imm() {
    // MOV R0, #1: e3a00001
    let insn = decode_bytes(&[0x01, 0x00, 0xa0, 0xe3]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::MOV);
}

#[test]
fn test_mov_reg() {
    // MOV R0, R1: e1a00001
    let insn = decode_bytes(&[0x01, 0x00, 0xa0, 0xe1]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::MOV);
}

#[test]
fn test_add_reg() {
    // ADD R0, R1, R2: e0810002
    let insn = decode_bytes(&[0x02, 0x00, 0x81, 0xe0]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::ADD);
}

#[test]
fn test_add_imm() {
    // ADD R0, R1, #0x10: e2810010
    let insn = decode_bytes(&[0x10, 0x00, 0x81, 0xe2]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::ADD);
}

#[test]
fn test_sub_reg() {
    // SUB R0, R1, R2: e0410002
    let insn = decode_bytes(&[0x02, 0x00, 0x41, 0xe0]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::SUB);
}

#[test]
fn test_cmp_reg() {
    // CMP R0, R1: e1500001
    let insn = decode_bytes(&[0x01, 0x00, 0x50, 0xe1]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::CMP);
}

#[test]
fn test_and_reg() {
    // AND R0, R1, R2: e0010002
    let insn = decode_bytes(&[0x02, 0x00, 0x01, 0xe0]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::AND);
}

#[test]
fn test_orr_reg() {
    // ORR R0, R1, R2: e1810002
    let insn = decode_bytes(&[0x02, 0x00, 0x81, 0xe1]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::ORR);
}

#[test]
fn test_b() {
    // B #0x100: ea00003e
    let insn = decode_bytes(&[0x3e, 0x00, 0x00, 0xea]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::B);
}

#[test]
fn test_bl() {
    // BL #0x100: eb00003e
    let insn = decode_bytes(&[0x3e, 0x00, 0x00, 0xeb]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::BL);
}

#[test]
fn test_bx() {
    // BX LR: e12fff1e
    let insn = decode_bytes(&[0x1e, 0xff, 0x2f, 0xe1]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::BX);
}

#[test]
fn test_ldr_imm() {
    // LDR R0, [R1]: e5910000
    let insn = decode_bytes(&[0x00, 0x00, 0x91, 0xe5]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::LDR);
}

#[test]
fn extra_literal_imm8_high_nibble_does_not_alias_exclusive_decode() {
    for (raw, mnemonic, rt, offset) in [
        (0xe1df_0fbf_u32, Mnemonic::LDRH, 0, 0xff),
        (0xe15f_1fbf, Mnemonic::LDRH, 1, -0xff),
        (0xe1df_2fdf, Mnemonic::LDRSB, 2, 0xff),
        (0xe15f_3fdf, Mnemonic::LDRSB, 3, -0xff),
        (0xe1df_4fff, Mnemonic::LDRSH, 4, 0xff),
        (0xe15f_5fff, Mnemonic::LDRSH, 5, -0xff),
    ] {
        let insn = Aarch32Decoder::decode(raw).unwrap();
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
fn exclusive_family_still_requires_and_accepts_fixed_1001_nibble() {
    for (op, mnemonic) in [
        (0_u32, Mnemonic::STXR),
        (1, Mnemonic::LDXR),
        (2, Mnemonic::STXP),
        (3, Mnemonic::LDXP),
        (4, Mnemonic::STXRB),
        (5, Mnemonic::LDXRB),
        (6, Mnemonic::STXRH),
        (7, Mnemonic::LDXRH),
    ] {
        let raw = 0xe180_0f90 | (op << 20);
        assert_eq!(Aarch32Decoder::decode(raw).unwrap().mnemonic, mnemonic);
    }
}

#[test]
fn test_str_imm() {
    // STR R0, [R1]: e5810000
    let insn = decode_bytes(&[0x00, 0x00, 0x81, 0xe5]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::STR);
}

#[test]
fn test_ldrb() {
    // LDRB R0, [R1]: e5d10000
    let insn = decode_bytes(&[0x00, 0x00, 0xd1, 0xe5]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::LDRB);
}

#[test]
fn test_push() {
    // PUSH {LR}: e52de004 (STMDB SP!, {LR})
    let insn = decode_bytes(&[0x00, 0x40, 0x2d, 0xe9]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::PUSH);
}

#[test]
fn test_pop() {
    // POP {PC}: e8bd8000 (LDMIA SP!, {PC})
    let insn = decode_bytes(&[0x00, 0x80, 0xbd, 0xe8]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::POP);
}

#[test]
fn test_mul() {
    // MUL R0, R1, R2: e0000291
    let insn = decode_bytes(&[0x91, 0x02, 0x00, 0xe0]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::MUL);
}

#[test]
fn test_svc() {
    // SVC #0: ef000000
    let insn = decode_bytes(&[0x00, 0x00, 0x00, 0xef]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::SVC);
}

#[test]
fn test_conditional() {
    // MOVEQ R0, #1: 03a00001
    let insn = decode_bytes(&[0x01, 0x00, 0xa0, 0x03]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::MOV);
    assert_eq!(insn.cond, Some(Condition::EQ));
}

#[test]
fn test_shifted_reg() {
    // ADD R0, R1, R2, LSL #4: e0810102
    let insn = decode_bytes(&[0x02, 0x01, 0x81, 0xe0]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::ADD);
    assert_eq!(insn.operands.len(), 3);
}

#[test]
fn data_processing_register_shift_decodes_rs_for_every_opcode_and_shift() {
    for opcode in 0_u32..16 {
        let writes_result = !matches!(opcode, 8..=11);
        let uses_rn = !matches!(opcode, 13 | 15);
        let s_values: &[u32] = if writes_result { &[0, 1] } else { &[1] };
        for &s in s_values {
            for shift_bits in 0_u32..4 {
                let rn = if uses_rn { 1 } else { 0 };
                let rd = if writes_result { 2 } else { 0 };
                let raw = 0xe000_0000
                    | (opcode << 21)
                    | (s << 20)
                    | (rn << 16)
                    | (rd << 12)
                    | (3 << 8)
                    | (shift_bits << 5)
                    | (1 << 4)
                    | 4;
                let insn = Aarch32Decoder::decode(raw).unwrap();
                assert_eq!(insn.sets_flags, s != 0, "raw={raw:#010x}");
                assert_eq!(
                    insn.operands.len(),
                    usize::from(writes_result) + usize::from(uses_rn) + 1
                );
                assert!(
                    matches!(
                        insn.operands.last(),
                        Some(Operand::ShiftedReg(ShiftedRegister {
                            reg: Register { num: 4, .. },
                            shift_type,
                            amount: ShiftAmount::Register(Register { num: 3, .. }),
                        })) if *shift_type == ShiftType::from_bits(shift_bits as u8)
                    ),
                    "raw={raw:#010x}: {insn:?}"
                );
            }
        }
    }
}

#[test]
fn test_mvn() {
    // MVN R0, R1: e1e00001
    let insn = decode_bytes(&[0x01, 0x00, 0xe0, 0xe1]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::MVN);
}

#[test]
fn test_clz() {
    // CLZ R0, R1: e16f0f11
    let insn = decode_bytes(&[0x11, 0x0f, 0x6f, 0xe1]).unwrap();
    assert_eq!(insn.mnemonic, Mnemonic::CLZ);
}

#[test]
fn test_integer_divide_operands() {
    let udiv = decode_bytes(&[0x11, 0xfa, 0x30, 0xe7]).unwrap();
    assert_eq!(udiv.mnemonic, Mnemonic::UDIV);
    assert_eq!(
        udiv.operands,
        vec![
            Operand::Reg(Register::raw(0, false, false)),
            Operand::Reg(Register::raw(1, false, false)),
            Operand::Reg(Register::raw(10, false, false)),
        ]
    );

    let sdiv = decode_bytes(&[0x14, 0xfb, 0x13, 0xe7]).unwrap();
    assert_eq!(sdiv.mnemonic, Mnemonic::SDIV);
    assert_eq!(
        sdiv.operands,
        vec![
            Operand::Reg(Register::raw(3, false, false)),
            Operand::Reg(Register::raw(4, false, false)),
            Operand::Reg(Register::raw(11, false, false)),
        ]
    );
}
