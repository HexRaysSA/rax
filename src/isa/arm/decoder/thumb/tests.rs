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

/// T32 coprocessor, floating-point, and Advanced SIMD encodings and the A32
/// ones LLVM 23.1.1 assembles for the same instructions
/// (`llvm-mc -triple=thumbv8a` and `-triple=armv8a`).
const T32_A32_PAIRS: [(u32, u32, Mnemonic); 14] = [
    (0xee1d_0f70, 0xee1d_0f70, Mnemonic::MRC), // mrc p15, 0, r0, c13, c0, 3
    (0xec51_0f1e, 0xec51_0f1e, Mnemonic::MRRC), // mrrc p15, 1, r0, r1, c14
    (0xeef1_0a10, 0xeef1_0a10, Mnemonic::VMRS), // vmrs r0, fpscr
    (0xeee1_1a10, 0xeee1_1a10, Mnemonic::VMSR), // vmsr fpscr, r1
    (0xef01_0d02, 0xf201_0d02, Mnemonic::VADD), // vadd.f32 d0, d1, d2
    (0xef01_0602, 0xf201_0602, Mnemonic::VMAX), // vmax.s8 d0, d1, d2
    (0xff01_0602, 0xf301_0602, Mnemonic::VMAX), // vmax.u8 d0, d1, d2
    (0xf920_070f, 0xf420_070f, Mnemonic::VLD1), // vld1.8 {d0}, [r0]
    (0xf902_178d, 0xf402_178d, Mnemonic::VST1), // vst1.32 {d1}, [r2]!
    (0xed9f_0b02, 0xed9f_0b02, Mnemonic::VLDR), // vldr d0, [pc, #8]
    (0xed03_1a01, 0xed03_1a01, Mnemonic::VSTR), // vstr s2, [r3, #-4]
    (0xed2d_8b04, 0xed2d_8b04, Mnemonic::VPUSH), // vpush {d8, d9}
    (0xec51_0b13, 0xec51_0b13, Mnemonic::VMOV), // vmov r0, r1, d3
    (0xfe00_0a81, 0xfe00_0a81, Mnemonic::VSELEQ), // vseleq.f32 s0, s1, s2
];

#[test]
fn t32_coprocessor_space_maps_to_its_a32_encoding() {
    for (t32, a32, _) in T32_A32_PAIRS {
        assert_eq!(ThumbDecoder::a32_equivalent(t32), Some(a32), "{t32:#010x}");
    }
    // Outside the space: an exclusive load, a barrier, a data-processing
    // instruction, and a load of a single register.
    for raw in [0xe851_0f01, 0xf3bf_8f5b, 0xea4f_0001, 0xf8d1_0004] {
        assert_eq!(ThumbDecoder::a32_equivalent(raw), None, "{raw:#010x}");
    }
}

#[test]
fn t32_coprocessor_space_decodes_as_its_a32_equivalent() {
    for (t32, a32, mnemonic) in T32_A32_PAIRS {
        let insn = ThumbDecoder::decode_32bit(t32).unwrap();
        let arm = Aarch32Decoder::decode(a32).unwrap();
        assert_eq!(insn.mnemonic, mnemonic, "{t32:#010x}");
        assert_eq!(insn.operands, arm.operands, "{t32:#010x}");
        assert_eq!(insn.sets_flags, arm.sets_flags, "{t32:#010x}");
        assert_eq!(
            (insn.raw, insn.size, insn.state, insn.cond),
            (t32, 4, ExecutionState::Thumb2, None),
            "{t32:#010x}"
        );
    }
}

#[test]
fn t32_exclusives_table_branches_and_acquire_release_decode() {
    // Encodings from LLVM 23.1.1 (llvm-mc -triple=thumbv8a).
    for (raw, mnemonic) in [
        (0xe851_0f01, Mnemonic::LDXR),    // ldrex r0, [r1, #4]
        (0xe841_0201, Mnemonic::STXR),    // strex r2, r0, [r1, #4]
        (0xe8d1_0f4f, Mnemonic::LDXRB),   // ldrexb r0, [r1]
        (0xe8c1_0f43, Mnemonic::STXRB),   // strexb r3, r0, [r1]
        (0xe8d1_0f5f, Mnemonic::LDXRH),   // ldrexh r0, [r1]
        (0xe8c1_0f53, Mnemonic::STXRH),   // strexh r3, r0, [r1]
        (0xe8d1_257f, Mnemonic::LDXP),    // ldrexd r2, r5, [r1]
        (0xe8c1_2574, Mnemonic::STXP),    // strexd r4, r2, r5, [r1]
        (0xe8df_f000, Mnemonic::TBB),     // tbb [pc, r0]
        (0xe8d1_f012, Mnemonic::TBH),     // tbh [r1, r2, lsl #1]
        (0xe8d1_0faf, Mnemonic::LDAR),    // lda r0, [r1]
        (0xe8d1_0f8f, Mnemonic::LDARB),   // ldab r0, [r1]
        (0xe8d1_0f9f, Mnemonic::LDARH),   // ldah r0, [r1]
        (0xe8c1_0faf, Mnemonic::STLR),    // stl r0, [r1]
        (0xe8c1_0f8f, Mnemonic::STLRB),   // stlb r0, [r1]
        (0xe8c1_0f9f, Mnemonic::STLRH),   // stlh r0, [r1]
        (0xe8d1_0fef, Mnemonic::LDAXR),   // ldaex r0, [r1]
        (0xe8c1_0fe2, Mnemonic::STLXR),   // stlex r2, r0, [r1]
        (0xe8d1_23ff, Mnemonic::LDAXP),   // ldaexd r2, r3, [r1]
        (0xe8c1_23f4, Mnemonic::STLXP),   // stlexd r4, r2, r3, [r1]
        (0xe8d1_0f2f, Mnemonic::UNKNOWN), // op3 = 0b0010: unallocated
    ] {
        let insn = ThumbDecoder::decode_32bit(raw).unwrap();
        assert_eq!(insn.mnemonic, mnemonic, "{raw:#010x}");
        assert_eq!((insn.size, insn.state), (4, ExecutionState::Thumb2));
    }
    // The rest of the group is LDRD and STRD.
    let ldrd = ThumbDecoder::decode_32bit(0xe9d2_0102).unwrap(); // ldrd r0, r1, [r2, #8]
    assert_eq!(ldrd.mnemonic, Mnemonic::LDP);
}

#[test]
fn t32_misc_control_decodes_hints_barriers_and_status_moves() {
    // Encodings from LLVM 23.1.1 (llvm-mc -triple=thumbv8a), and the
    // ARM ARM's SB (T1) and CPSIE.W (T2).
    for (raw, mnemonic) in [
        (0xf3bf_8f5b, Mnemonic::DMB), // dmb ish
        (0xf3bf_8f4f, Mnemonic::DSB), // dsb sy
        (0xf3bf_8f6f, Mnemonic::ISB), // isb sy
        (0xf3bf_8f2f, Mnemonic::CLREX),
        (0xf3bf_8f70, Mnemonic::SB),
        (0xf3af_8000, Mnemonic::NOP),     // nop.w
        (0xf3af_8001, Mnemonic::YIELD),   // yield.w
        (0xf3af_8002, Mnemonic::WFE),     // wfe.w
        (0xf3af_8003, Mnemonic::WFI),     // wfi.w
        (0xf3af_8004, Mnemonic::SEV),     // sev.w
        (0xf3af_8005, Mnemonic::SEVL),    // sevl.w
        (0xf3af_8014, Mnemonic::HINT),    // csdb
        (0xf3af_80f5, Mnemonic::HINT),    // dbg #5
        (0xf3af_8440, Mnemonic::CPS),     // cpsie.w i
        (0xf3ef_8000, Mnemonic::MRS),     // mrs r0, apsr
        (0xf380_8800, Mnemonic::MSR),     // msr apsr_nzcvq, r0
        (0xf381_8400, Mnemonic::MSR),     // msr apsr_g, r1
        (0xf7f0_a000, Mnemonic::UDF),     // udf.w #0
        (0xf3ef_8020, Mnemonic::UNKNOWN), // banked MRS
        (0xf3c3_8f00, Mnemonic::BX),      // bxj r3
    ] {
        let insn = ThumbDecoder::decode_32bit(raw).unwrap();
        assert_eq!(insn.mnemonic, mnemonic, "{raw:#010x}");
    }
    let dmb = ThumbDecoder::decode_32bit(0xf3bf_8f5b).unwrap();
    assert_eq!(
        dmb.operands,
        vec![Operand::Barrier(BarrierOption::from_bits(0xb))]
    );
}

#[test]
fn t32_push_and_pop_are_stmdb_and_ldmia_of_sp_with_writeback() {
    // Encodings from LLVM 23.1.1 (llvm-mc -triple=thumbv8a).
    for (raw, mnemonic) in [
        (0xe92d_4010, Mnemonic::PUSH),  // push.w {r4, lr}
        (0xe8ad_0030, Mnemonic::STMIA), // stm.w sp!, {r4, r5}
        (0xe8bd_8010, Mnemonic::POP),   // pop.w {r4, pc}
        (0xe93d_0030, Mnemonic::LDMDB), // ldmdb sp!, {r4, r5}
        (0xe92d_0030, Mnemonic::PUSH),  // stmdb sp!, {r4, r5}
        (0xe90d_0030, Mnemonic::STMDB), // stmdb sp, {r4, r5}
    ] {
        let insn = ThumbDecoder::decode_32bit(raw).unwrap();
        assert_eq!(insn.mnemonic, mnemonic, "{raw:#010x}");
    }
}

#[test]
fn t16_cps_decodes_and_setend_does_not() {
    // Encodings from LLVM 23.1.1 (llvm-mc -triple=thumbv7a).
    for (raw, mnemonic) in [
        (0xb662, Mnemonic::CPS),     // cpsie i
        (0xb673, Mnemonic::CPS),     // cpsid if
        (0xb677, Mnemonic::CPS),     // cpsid aif
        (0xb658, Mnemonic::UNKNOWN), // setend be
    ] {
        let insn = ThumbDecoder::decode_16bit(raw).unwrap();
        assert_eq!((insn.mnemonic, insn.size), (mnemonic, 2), "{raw:#06x}");
    }
    // BXJ r3 is BX r3.
    let bxj = ThumbDecoder::decode_32bit(0xf3c3_8f00).unwrap();
    assert_eq!(bxj.operands, vec![Operand::Reg(Register::arm32(3))]);
}
