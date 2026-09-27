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

/// The miscellaneous space (op1 = 10xx0, bit 7 clear) holds BKPT, BXJ,
/// ERET, HVC, and SMC; the rest of it is UNDEFINED, never the
/// TST/TEQ/CMP/CMN it would alias with S = 0 (`llvm-mc -triple=armv7a
/// -mattr=+virtualization,+trustzone`).
#[test]
fn miscellaneous_space_is_not_data_processing() {
    for (raw, mnemonic) in [
        (0xe121_2374, Mnemonic::BKPT),
        (0xe12f_ff23, Mnemonic::BX), // bxj r3
        (0xe160_006e, Mnemonic::ERET),
        (0xe141_2374, Mnemonic::HVC),
        (0xe160_0075, Mnemonic::SMC),
        (0xe100_0010, Mnemonic::UNKNOWN), // op 00, op2 001
        (0xe120_0070, Mnemonic::BKPT),
        (0xe160_0070, Mnemonic::SMC),
        (0xe120_0020, Mnemonic::BX),             // bxj r0
        (0xe160_0050, Mnemonic::A32_SAT_ADDSUB), // qdsub
    ] {
        let insn = Aarch32Decoder::decode(raw).unwrap();
        assert_eq!(insn.mnemonic, mnemonic, "{raw:#010x}");
    }
    // bxj r3 is bx r3.
    let bxj = Aarch32Decoder::decode(0xe12f_ff23).unwrap();
    assert_eq!(
        bxj.operands,
        Aarch32Decoder::decode(0xe12f_ff13).unwrap().operands
    );
}

/// The bit-field encodings need their op2 (bits 7:5); 11111/111 is UDF.
#[test]
fn bit_field_encodings_check_op2_and_udf_is_undefined() {
    for (raw, mnemonic) in [
        (0xe7fa_bcfd, Mnemonic::UDF), // udf #0xabcd
        (0xe7f0_00f0, Mnemonic::UDF),
        (0xe7e2_00d2, Mnemonic::UBFX),
        (0xe7a2_00d2, Mnemonic::SBFX),
        (0xe7c3_0092, Mnemonic::BFI),
        (0xe7c3_009f, Mnemonic::BFC),
        (0xe7e2_00f2, Mnemonic::UNKNOWN), // 11110 with op2 111
        (0xe7a2_0092, Mnemonic::UNKNOWN), // SBFX's op1 with op2 x00
        (0xe7c3_00d2, Mnemonic::UNKNOWN), // BFI's op1 with op2 x10
    ] {
        let insn = Aarch32Decoder::decode(raw).unwrap();
        assert_eq!(insn.mnemonic, mnemonic, "{raw:#010x}");
    }
}

/// The synchronization space's bits 9:8: ARMv7's exclusives (11), ARMv8's
/// acquire/release exclusives (10) and non-exclusive LDA/STL (00), and 01
/// UNDEFINED (`llvm-mc -triple=armv8a`).
#[test]
fn load_acquire_and_store_release_forms() {
    for (raw, mnemonic) in [
        (0xe191_0c9f, Mnemonic::LDAR),
        (0xe1d3_2c9f, Mnemonic::LDARB),
        (0xe1f5_4c9f, Mnemonic::LDARH),
        (0xe181_fc90, Mnemonic::STLR),
        (0xe1c3_fc92, Mnemonic::STLRB),
        (0xe1e5_fc94, Mnemonic::STLRH),
        (0xe191_0e9f, Mnemonic::LDAXR),
        (0xe1d3_2e9f, Mnemonic::LDAXRB),
        (0xe1f5_4e9f, Mnemonic::LDAXRH),
        (0xe1b8_6e9f, Mnemonic::LDAXP),
        (0xe181_9e90, Mnemonic::STLXR),
        (0xe1c3_9e92, Mnemonic::STLXRB),
        (0xe1e5_9e94, Mnemonic::STLXRH),
        (0xe1a8_9e96, Mnemonic::STLXP),
        (0xe191_0f9f, Mnemonic::LDXR),
        (0xe181_2f90, Mnemonic::STXR),
        (0xe191_0d9f, Mnemonic::UNKNOWN), // bits 9:8 = 01
        (0xe1b8_6c9f, Mnemonic::UNKNOWN), // no doubleword LDA
    ] {
        let insn = Aarch32Decoder::decode(raw).unwrap();
        assert_eq!(insn.mnemonic, mnemonic, "{raw:#010x}");
    }
}
