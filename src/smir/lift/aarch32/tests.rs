//! A32 lifter unit tests.

use super::*;
use crate::smir::ir::flags::FlagSet;

fn lift(raw: u32) -> LiftResult {
    let mut lifter = Aarch32Lifter::new();
    let mut ctx = LiftContext::new(SourceArch::Aarch32);
    lifter
        .lift_insn(0x1000, &raw.to_le_bytes(), &mut ctx)
        .unwrap()
}

#[test]
fn lifts_a32_scalar_integer_matrix() {
    let cases = [
        (0xe081_0002, "add"),
        (0xe054_3385, "subs-shifted"),
        (0xe2a7_60ff, "adc-immediate"),
        (0xe0c9_800a, "sbc"),
        (0xe26c_b007, "rsb"),
        (0xe002_14e3, "and-ror"),
        (0xe385_4102, "orr-immediate"),
        (0xe027_6008, "eor"),
        (0xe1ca_900b, "bic"),
        (0xe1a0_0241, "mov-asr"),
        (0xe1e0_2003, "mvn"),
        (0xe004_0695, "mul"),
        (0xe027_a998, "mla"),
        (0xe06b_109c, "mls"),
        (0xe16f_2f13, "clz"),
        (0xe6bf_4f35, "rev"),
        (0xe6bf_6fb7, "rev16"),
        (0xe6ff_8f39, "rbit"),
        (0xe7cb_021f, "bfc"),
        (0xe7cf_1412, "bfi"),
        (0xe7e6_3654, "ubfx"),
        (0xe7a7_5856, "sbfx"),
        (0xe730_fa11, "udiv"),
        (0xe713_fb14, "sdiv"),
        (0xe30b_aeef, "movw"),
        (0xe34c_aafe, "movt"),
    ];
    for (raw, label) in cases {
        let result = lift(raw);
        assert!(
            !result.ops.is_empty(),
            "{label} must produce a concrete SMIR operation"
        );
        assert!(matches!(result.control_flow, ControlFlow::Fallthrough));
    }
}

fn encode_dp_register_shift(
    opcode: u8,
    set_flags: bool,
    rd: u8,
    rn: u8,
    rm: u8,
    rs: u8,
    shift: u8,
) -> u32 {
    0xe000_0000
        | (u32::from(opcode) << 21)
        | (u32::from(set_flags) << 20)
        | (u32::from(rn) << 16)
        | (u32::from(rd) << 12)
        | (u32::from(rs) << 8)
        | (u32::from(shift) << 5)
        | (1 << 4)
        | u32::from(rm)
}

#[test]
fn lifts_complete_a32_data_processing_register_shift_opcode_space() {
    let nzc = FlagSet::SF.union(FlagSet::ZF).union(FlagSet::CF);
    for opcode in 0_u8..16 {
        let kind = ArmDpRegShiftKind::from_opcode(opcode).unwrap();
        let rd = if kind.writes_result() { 2 } else { 0 };
        let rn = if kind.uses_rn() { 1 } else { 0 };
        let flag_modes: &[bool] = if kind.writes_result() {
            &[false, true]
        } else {
            &[true]
        };
        for &set_flags in flag_modes {
            for (shift_bits, expected_shift) in [
                (0_u8, ShiftOp::Lsl),
                (1, ShiftOp::Lsr),
                (2, ShiftOp::Asr),
                (3, ShiftOp::Ror),
            ] {
                let raw = encode_dp_register_shift(opcode, set_flags, rd, rn, 4, 3, shift_bits);
                let result = lift(raw);
                assert_eq!(result.ops.len(), 1, "raw={raw:#010x}");
                assert!(
                    matches!(
                        result.ops[0].kind,
                        OpKind::ArmDpRegShift {
                            kind: actual_kind,
                            dst,
                            rn: actual_rn,
                            rm,
                            rs,
                            shift,
                            flags,
                        } if actual_kind == kind
                            && dst == kind.writes_result().then(|| Aarch32Lifter::reg(2))
                            && actual_rn == kind.uses_rn().then(|| Aarch32Lifter::reg(1))
                            && rm == Aarch32Lifter::reg(4)
                            && rs == Aarch32Lifter::reg(3)
                            && shift == expected_shift
                            && flags == if set_flags {
                                FlagUpdate::Specific(if kind.is_logical() { nzc } else { FlagSet::NZCV })
                            } else {
                                FlagUpdate::None
                            }
                    ),
                    "raw={raw:#010x}: {:?}",
                    result.ops[0].kind
                );
            }
        }
    }
}

#[test]
fn a32_data_processing_register_shift_rejects_pc_and_noncanonical_fixed_fields() {
    let cases = [
        encode_dp_register_shift(4, false, 15, 1, 2, 3, 0),
        encode_dp_register_shift(4, false, 0, 15, 2, 3, 0),
        encode_dp_register_shift(4, false, 0, 1, 15, 3, 0),
        encode_dp_register_shift(4, false, 0, 1, 2, 15, 0),
        encode_dp_register_shift(8, true, 1, 1, 2, 3, 0),
        encode_dp_register_shift(13, false, 1, 1, 2, 3, 0),
    ];
    for raw in cases {
        let mut lifter = Aarch32Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch32);
        assert!(
            matches!(
                lifter.lift_insn(0x1000, &raw.to_le_bytes(), &mut ctx),
                Err(LiftError::Unsupported { .. })
            ),
            "raw={raw:#010x}"
        );
    }
}

#[test]
fn a32_register_shift_recognition_does_not_steal_miscellaneous_encodings() {
    for raw in [
        0xe16f_2f13_u32, // CLZ r2,r3
        0xe12f_ff1e,     // BX lr
        0xe12f_ff3e,     // BLX lr
    ] {
        let result = lift(raw);
        assert!(
            result
                .ops
                .iter()
                .all(|op| !matches!(op.kind, OpKind::ArmDpRegShift { .. })),
            "raw={raw:#010x}"
        );
    }
}

#[test]
fn lifts_a32_scalar_memory_width_sign_and_store_matrix() {
    let cases = [
        (0xe591_0004, MemWidth::B4, SignExtend::Zero, true), // ldr r0,[r1,#4]
        (0xe5d3_2002, MemWidth::B1, SignExtend::Zero, true), // ldrb r2,[r3,#2]
        (0xe1d5_40b2, MemWidth::B2, SignExtend::Zero, true), // ldrh r4,[r5,#2]
        (0xe1d7_60d1, MemWidth::B1, SignExtend::Sign, true), // ldrsb r6,[r7,#1]
        (0xe1d9_80f2, MemWidth::B2, SignExtend::Sign, true), // ldrsh r8,[r9,#2]
        (0xe58b_0004, MemWidth::B4, SignExtend::Zero, false), // str r0,[r11,#4]
        (0xe5ca_2001, MemWidth::B1, SignExtend::Zero, false), // strb r2,[r10,#1]
        (0xe1cc_40b2, MemWidth::B2, SignExtend::Zero, false), // strh r4,[r12,#2]
    ];

    for (raw, width, sign, is_load) in cases {
        let result = lift(raw);
        assert_eq!(result.ops.len(), 1, "{raw:#010x}");
        match &result.ops[0].kind {
            OpKind::Load {
                width: actual_width,
                sign: actual_sign,
                ..
            } if is_load => {
                assert_eq!(*actual_width, width, "{raw:#010x}");
                assert_eq!(*actual_sign, sign, "{raw:#010x}");
            }
            OpKind::Store {
                width: actual_width,
                ..
            } if !is_load => assert_eq!(*actual_width, width, "{raw:#010x}"),
            other => panic!("unexpected memory lift for {raw:#010x}: {other:?}"),
        }
    }
}

#[test]
fn memory_writeback_follows_access_and_register_offsets_fail_closed() {
    let pre = lift(0xe5b1_0004); // ldr r0,[r1,#4]!
    assert!(matches!(
        pre.ops.as_slice(),
        [
            SmirOp {
                kind: OpKind::Load {
                    addr: Address::BaseOffset { offset: 4, .. },
                    ..
                },
                ..
            },
            SmirOp {
                kind: OpKind::Add {
                    dst,
                    src1,
                    src2: SrcOperand::Imm(4),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                },
                ..
            }
        ] if dst == src1 && *dst == Aarch32Lifter::reg(1)
    ));

    let post_sub = lift(0xe611_0002); // ldr r0,[r1],-r2
    assert!(matches!(
        post_sub.ops.as_slice(),
        [
            SmirOp {
                kind: OpKind::Load {
                    addr: Address::Direct(base),
                    ..
                },
                ..
            },
            SmirOp {
                kind: OpKind::Sub {
                    dst,
                    src1,
                    src2: SrcOperand::Reg(index),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                },
                ..
            }
        ] if *base == Aarch32Lifter::reg(1)
            && dst == src1
            && *dst == Aarch32Lifter::reg(1)
            && *index == Aarch32Lifter::reg(2)
    ));

    let scaled = lift(0xe791_0102); // ldr r0,[r1,r2,lsl #2]
    assert!(matches!(
        &scaled.ops[0].kind,
        OpKind::Load {
            addr: Address::BaseIndexScale {
                base: Some(base),
                index,
                scale: 4,
                ..
            },
            ..
        } if *base == Aarch32Lifter::reg(1) && *index == Aarch32Lifter::reg(2)
    ));

    for raw in [
        0xe711_0002u32, // ldr r0,[r1,-r2] needs a non-clobbering address temp
        0xe7b1_0122,    // ldr r0,[r1,r2,lsr #2]! needs an address temp
        0xe5b1_1004,    // ldr r1,[r1,#4]! has constrained alias semantics
    ] {
        let mut lifter = Aarch32Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch32);
        assert!(
            matches!(
                lifter.lift_insn(0x1000, &raw.to_le_bytes(), &mut ctx),
                Err(LiftError::Unsupported { .. })
            ),
            "{raw:#010x}"
        );
    }
}

#[test]
fn lifts_a32_literal_load_width_sign_add_subtract_and_wrap_matrix() {
    for (raw, dst, address, width, sign) in [
        (0xe59f_0004, 0, 0x100c, MemWidth::B4, SignExtend::Zero),
        (0xe51f_1004, 1, 0x1004, MemWidth::B4, SignExtend::Zero),
        (0xe5df_2003, 2, 0x100b, MemWidth::B1, SignExtend::Zero),
        (0xe55f_3003, 3, 0x1005, MemWidth::B1, SignExtend::Zero),
        (0xe1df_40b2, 4, 0x100a, MemWidth::B2, SignExtend::Zero),
        (0xe15f_50d1, 5, 0x1007, MemWidth::B1, SignExtend::Sign),
        (0xe1df_60f2, 6, 0x100a, MemWidth::B2, SignExtend::Sign),
        (0xe59f_7fff, 7, 0x2007, MemWidth::B4, SignExtend::Zero),
        (0xe51f_8fff, 8, 0x0009, MemWidth::B4, SignExtend::Zero),
        (0xe1df_9fbf, 9, 0x1107, MemWidth::B2, SignExtend::Zero),
        (0xe15f_afbf, 10, 0x0f09, MemWidth::B2, SignExtend::Zero),
        (0xe1df_bfdf, 11, 0x1107, MemWidth::B1, SignExtend::Sign),
        (0xe15f_cfdf, 12, 0x0f09, MemWidth::B1, SignExtend::Sign),
        (0xe1df_dfff, 13, 0x1107, MemWidth::B2, SignExtend::Sign),
        (0xe15f_efff, 14, 0x0f09, MemWidth::B2, SignExtend::Sign),
    ] {
        let result = lift(raw);
        assert!(
            matches!(
                result.ops.as_slice(),
                [SmirOp {
                    kind: OpKind::Load {
                        dst: actual_dst,
                        addr: Address::Absolute(actual_address),
                        width: actual_width,
                        sign: actual_sign,
                    },
                    ..
                }] if *actual_dst == Aarch32Lifter::reg(dst)
                    && *actual_address == address
                    && *actual_width == width
                    && *actual_sign == sign
            ),
            "{raw:#010x}: {result:?}"
        );
        assert!(matches!(result.control_flow, ControlFlow::Fallthrough));
    }

    let mut lifter = Aarch32Lifter::new();
    let mut ctx = LiftContext::new(SourceArch::Aarch32);
    for (pc, raw, expected) in [
        (0xffff_fffc, 0xe59f_0004u32, 8),
        (0xffff_fffc, 0xe51f_0008u32, 0xffff_fffc),
    ] {
        let result = lifter.lift_insn(pc, &raw.to_le_bytes(), &mut ctx).unwrap();
        assert!(matches!(
            result.ops.as_slice(),
            [SmirOp {
                kind: OpKind::Load {
                    addr: Address::Absolute(address),
                    ..
                },
                ..
            }] if *address == expected
        ));
    }

    for raw in [
        0x059f_0004u32, // predicated literal load needs conditional commit
        0xe59f_f004,    // load-to-PC is control flow
        0xe58f_0004,    // PC-relative store is outside the literal-load subset
        0xe5bf_0004,    // writeback from PC is invalid for this subset
        0xe79f_0001,    // register-offset PC base is not a literal form
    ] {
        assert!(
            matches!(
                lifter.lift_insn(0x1000, &raw.to_le_bytes(), &mut ctx),
                Err(LiftError::Unsupported { .. })
            ),
            "{raw:#010x}"
        );
    }
    assert!(matches!(
        lifter.lift_insn(
            u64::from(u32::MAX) + 1,
            &0xe59f_0004u32.to_le_bytes(),
            &mut ctx,
        ),
        Err(LiftError::Unsupported { .. })
    ));
}

#[test]
fn lifts_a32_multiple_transfers_in_register_and_address_order() {
    fn offset(op: &SmirOp) -> i64 {
        let addr = match &op.kind {
            OpKind::Load { addr, .. } | OpKind::Store { addr, .. } => addr,
            other => panic!("expected transfer, got {other:?}"),
        };
        match addr {
            Address::Direct(_) => 0,
            Address::BaseOffset { offset, .. } => *offset,
            other => panic!("unexpected multiple-transfer address {other:?}"),
        }
    }

    for (raw, expected_offsets, label) in [
        (0xe8aa_0005, [0, 4], "stmia r10!,{r0,r2}"),
        (0xe9aa_0005, [4, 8], "stmib r10!,{r0,r2}"),
        (0xe82a_0005, [-4, 0], "stmda r10!,{r0,r2}"),
        (0xe92a_0005, [-8, -4], "stmdb r10!,{r0,r2}"),
    ] {
        let result = lift(raw);
        assert_eq!(result.ops.len(), 3, "{label}");
        assert_eq!(offset(&result.ops[0]), expected_offsets[0], "{label}");
        assert_eq!(offset(&result.ops[1]), expected_offsets[1], "{label}");
        assert!(matches!(
            &result.ops[0].kind,
            OpKind::Store { src, .. } if *src == Aarch32Lifter::reg(0)
        ));
        assert!(matches!(
            &result.ops[1].kind,
            OpKind::Store { src, .. } if *src == Aarch32Lifter::reg(2)
        ));
    }

    let load = lift(0xe8ba_002a); // ldmia r10!,{r1,r3,r5}
    assert_eq!(load.ops.len(), 4);
    assert_eq!(
        load.ops[..3].iter().map(offset).collect::<Vec<_>>(),
        vec![0, 4, 8]
    );
    assert!(matches!(
        &load.ops[3].kind,
        OpKind::Add {
            dst,
            src1,
            src2: SrcOperand::Imm(12),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        } if dst == src1 && *dst == Aarch32Lifter::reg(10)
    ));

    let push = lift(0xe92d_4011); // push {r0,r4,lr}
    assert_eq!(
        push.ops[..3].iter().map(offset).collect::<Vec<_>>(),
        vec![-12, -8, -4]
    );
    assert!(matches!(
        &push.ops[3].kind,
        OpKind::Sub {
            dst,
            src1,
            src2: SrcOperand::Imm(12),
            ..
        } if dst == src1 && *dst == Aarch32Lifter::reg(13)
    ));
}

#[test]
fn a32_multiple_transfers_reject_hidden_and_constrained_forms() {
    for raw in [
        0xe8bd_8001u32, // pop {r0,pc}: interworking control flow
        0xe8fd_0003,    // ldmia sp!,{r0,r1}^: user-bank transfer
        0xe8b1_0000,    // ldmia r1!,{}: architecturally constrained empty list
        0xe8b1_0002,    // ldmia r1!,{r1}: load/base alias
        0xe8a1_0002,    // stmia r1!,{r1}: store/writeback alias
        0xe8bf_0001,    // ldmia pc!,{r0}: pipeline PC base
    ] {
        let mut lifter = Aarch32Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch32);
        assert!(
            matches!(
                lifter.lift_insn(0x1000, &raw.to_le_bytes(), &mut ctx),
                Err(LiftError::Unsupported { .. })
            ),
            "{raw:#010x}"
        );
    }
}

#[test]
fn lifts_a32_double_transfers_with_pair_atomicity_and_writeback() {
    let load = lift(0xe1c2_00d8); // ldrd r0,r1,[r2,#8]
    assert!(matches!(
        load.ops.as_slice(),
        [SmirOp {
            kind: OpKind::LoadPair {
                dst1,
                dst2,
                addr: Address::BaseOffset {
                    base,
                    offset: 8,
                    ..
                },
                width: MemWidth::B4,
            },
            ..
        }] if *dst1 == Aarch32Lifter::reg(0)
            && *dst2 == Aarch32Lifter::reg(1)
            && *base == Aarch32Lifter::reg(2)
    ));

    let store = lift(0xe1e4_20f8); // strd r2,r3,[r4,#8]!
    assert!(matches!(
        store.ops.as_slice(),
        [
            SmirOp {
                kind: OpKind::StorePair {
                    src1,
                    src2,
                    addr: Address::BaseOffset { offset: 8, .. },
                    width: MemWidth::B4,
                },
                ..
            },
            SmirOp {
                kind: OpKind::Add {
                    dst,
                    src1: base,
                    src2: SrcOperand::Imm(8),
                    width: OpWidth::W32,
                    flags: FlagUpdate::None,
                },
                ..
            }
        ] if *src1 == Aarch32Lifter::reg(2)
            && *src2 == Aarch32Lifter::reg(3)
            && dst == base
            && *dst == Aarch32Lifter::reg(4)
    ));
}

#[test]
fn a32_double_transfers_reject_odd_pc_and_writeback_alias_pairs() {
    for raw in [
        0xe1c2_10d8u32, // ldrd odd r1 pair
        0xe1c2_e0d8,    // ldrd r14,r15 pair
        0xe1e0_00d8,    // ldrd r0,r1,[r0,#8]!: base aliases pair
        0xe1ef_20f8,    // strd r2,r3,[pc,#8]!: pipeline PC base
    ] {
        let mut lifter = Aarch32Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch32);
        assert!(
            matches!(
                lifter.lift_insn(0x1000, &raw.to_le_bytes(), &mut ctx),
                Err(LiftError::Unsupported { .. })
            ),
            "{raw:#010x}"
        );
    }
}

#[test]
fn uses_a32_pc_plus_eight_for_direct_branches() {
    let result = lift(0xea00_0002); // B +8; architectural target = 0x1010.
    assert!(matches!(
        result.control_flow,
        ControlFlow::Branch { target: 0x1010 }
    ));
    assert_eq!(result.branch_targets, vec![0x1010]);
}

#[test]
fn lifts_a32_bx_for_every_non_pc_register_and_block_terminator() {
    for rm in 0_u32..15 {
        let result = lift(0xe12f_ff10 | rm);
        assert!(result.ops.is_empty());
        assert!(result.branch_targets.is_empty());
        assert!(matches!(
            result.control_flow,
            ControlFlow::IndirectBranch { target }
                if target == Aarch32Lifter::reg(rm as u8)
        ));
    }
    let mut lifter = Aarch32Lifter::new();
    let mut reject_ctx = LiftContext::new(SourceArch::Aarch32);
    assert!(matches!(
        lifter.lift_insn(0x1000, &0xe12f_ff1fu32.to_le_bytes(), &mut reject_ctx),
        Err(LiftError::Unsupported { .. })
    ));

    struct Memory([u8; 4]);
    impl MemoryReader for Memory {
        fn read(
            &self,
            addr: GuestAddr,
            size: usize,
        ) -> Result<Vec<u8>, crate::smir::ir::memory::MemoryError> {
            if addr != 0x1000 || size != 4 {
                return Err(crate::smir::ir::memory::MemoryError::OutOfBounds { addr });
            }
            Ok(self.0.to_vec())
        }
    }

    let mut lifter = Aarch32Lifter::new();
    let mut ctx = LiftContext::new(SourceArch::Aarch32);
    let block = lifter
        .lift_block(0x1000, &Memory(0xe12f_ff1eu32.to_le_bytes()), &mut ctx)
        .unwrap();
    assert!(block.ops.is_empty());
    assert!(matches!(
        block.terminator,
        Terminator::IndirectBranch {
            target: VReg::Arch(ArchReg::Arm(ArmReg::X(14))),
            ref possible_targets,
        } if possible_targets.is_empty()
    ));
}

#[test]
fn lifts_a32_blx_immediate_and_every_register_with_old_lr_snapshot() {
    for (raw, target) in [(0xfa00_0000_u32, 0x1008), (0xfb00_0000, 0x100a)] {
        let result = lift(raw);
        assert_eq!(result.branch_targets, vec![target]);
        assert!(matches!(
            result.control_flow,
            ControlFlow::Call {
                target: CallTarget::GuestAddrInterworking {
                    addr,
                    thumb: true,
                }
            } if addr == target
        ));
        assert!(matches!(
            result.ops.as_slice(),
            [SmirOp {
                kind: OpKind::Mov {
                    dst: VReg::Arch(ArchReg::Arm(ArmReg::X(14))),
                    src: SrcOperand::Imm(0x1004),
                    width: OpWidth::W32,
                },
                ..
            }]
        ));
    }

    for rm in 0_u32..15 {
        let result = lift(0xe12f_ff30 | rm);
        assert!(result.branch_targets.is_empty());
        match (rm, result.ops.as_slice(), result.control_flow) {
            (
                14,
                [
                    SmirOp {
                        kind:
                            OpKind::Mov {
                                dst: snapshot,
                                src: SrcOperand::Reg(source),
                                width: OpWidth::W32,
                            },
                        ..
                    },
                    SmirOp {
                        kind:
                            OpKind::Mov {
                                dst: link,
                                src: SrcOperand::Imm(0x1004),
                                width: OpWidth::W32,
                            },
                        ..
                    },
                ],
                ControlFlow::Call {
                    target: CallTarget::IndirectInterworking(target),
                },
            ) => {
                assert!(matches!(snapshot, VReg::Virtual(_)));
                assert_eq!(*source, Aarch32Lifter::reg(14));
                assert_eq!(*link, Aarch32Lifter::reg(14));
                assert_eq!(target, *snapshot);
            }
            (
                _,
                [
                    SmirOp {
                        kind:
                            OpKind::Mov {
                                dst,
                                src: SrcOperand::Imm(0x1004),
                                width: OpWidth::W32,
                            },
                        ..
                    },
                ],
                ControlFlow::Call {
                    target: CallTarget::IndirectInterworking(target),
                },
            ) => {
                assert_eq!(*dst, Aarch32Lifter::reg(14));
                assert_eq!(target, Aarch32Lifter::reg(rm as u8));
            }
            other => panic!("unexpected BLX r{rm} lift: {other:?}"),
        }
    }

    let mut lifter = Aarch32Lifter::new();
    let mut ctx = LiftContext::new(SourceArch::Aarch32);
    assert!(matches!(
        lifter.lift_insn(0x1000, &0xe12f_ff3fu32.to_le_bytes(), &mut ctx),
        Err(LiftError::Unsupported { .. })
    ));
}

#[test]
fn a32_branch_and_link_pc_arithmetic_wraps_modulo_2_pow_32() {
    let mut lifter = Aarch32Lifter::new();
    let mut ctx = LiftContext::new(SourceArch::Aarch32);

    let branch = lifter
        .lift_insn(0xffff_fffc, &0xea00_0000u32.to_le_bytes(), &mut ctx)
        .unwrap(); // B +0: 0xffff_fffc + 8 wraps to 4.
    assert!(matches!(
        branch.control_flow,
        ControlFlow::Branch { target: 4 }
    ));

    let cond = lifter
        .lift_insn(0xffff_fffc, &0x0a00_0000u32.to_le_bytes(), &mut ctx)
        .unwrap(); // BEQ +0; fallthrough wraps to 0.
    assert!(matches!(
        cond.control_flow,
        ControlFlow::CondBranch {
            target: 4,
            fallthrough: 0,
            ..
        }
    ));

    let call = lifter
        .lift_insn(0xffff_fffc, &0xeb00_0000u32.to_le_bytes(), &mut ctx)
        .unwrap(); // BL +0; target 4, link 0.
    assert!(matches!(
        call.control_flow,
        ControlFlow::Call {
            target: CallTarget::GuestAddr(4)
        }
    ));
    assert!(matches!(
        call.ops.as_slice(),
        [SmirOp {
            kind: OpKind::Mov {
                dst: VReg::Arch(ArchReg::Arm(ArmReg::X(14))),
                src: SrcOperand::Imm(0),
                width: OpWidth::W32,
            },
            ..
        }]
    ));

    let exchange = lifter
        .lift_insn(0xffff_fffc, &0xfb00_0000u32.to_le_bytes(), &mut ctx)
        .unwrap(); // BLX +2; target 6, ARM link 0.
    assert!(matches!(
        exchange.control_flow,
        ControlFlow::Call {
            target: CallTarget::GuestAddrInterworking {
                addr: 6,
                thumb: true,
            }
        }
    ));
    assert!(matches!(
        exchange.ops.as_slice(),
        [SmirOp {
            kind: OpKind::Mov {
                src: SrcOperand::Imm(0),
                ..
            },
            ..
        }]
    ));

    assert!(matches!(
        lifter.lift_insn(
            u64::from(u32::MAX) + 1,
            &0xea00_0000u32.to_le_bytes(),
            &mut ctx,
        ),
        Err(LiftError::Unsupported { .. })
    ));
}

#[test]
fn lifts_every_a32_branch_condition_with_pc_plus_eight_and_fallthrough() {
    let conditions = [
        Condition::Eq,
        Condition::Ne,
        Condition::Uge,
        Condition::Ult,
        Condition::Negative,
        Condition::Positive,
        Condition::Overflow,
        Condition::NoOverflow,
        Condition::Ugt,
        Condition::Ule,
        Condition::Sge,
        Condition::Slt,
        Condition::Sgt,
        Condition::Sle,
    ];

    for (bits, expected) in conditions.into_iter().enumerate() {
        let raw = ((bits as u32) << 28) | 0x0a00_0002;
        let result = lift(raw);
        assert!(matches!(
            result.control_flow,
            ControlFlow::CondBranch {
                cond,
                target: 0x1010,
                fallthrough: 0x1004,
            } if cond == expected
        ));
        assert_eq!(result.branch_targets, vec![0x1010, 0x1004]);
    }
}

#[test]
fn a32_block_materializes_only_a_foldable_branch_condition() {
    struct Memory([u8; 4]);

    impl MemoryReader for Memory {
        fn read(
            &self,
            addr: GuestAddr,
            size: usize,
        ) -> Result<Vec<u8>, crate::smir::ir::memory::MemoryError> {
            if addr != 0x1000 || size != 4 {
                return Err(crate::smir::ir::memory::MemoryError::OutOfBounds { addr });
            }
            Ok(self.0.to_vec())
        }
    }

    let memory = Memory(0x1a00_0000u32.to_le_bytes()); // BNE +0.
    let mut lifter = Aarch32Lifter::new();
    let mut ctx = LiftContext::new(SourceArch::Aarch32);
    let block = lifter.lift_block(0x1000, &memory, &mut ctx).unwrap();
    let taken = ctx.get_or_create_block(0x1008);
    let not_taken = ctx.get_or_create_block(0x1004);

    assert!(matches!(
        block.ops.as_slice(),
        [SmirOp {
            guest_pc: 0x1000,
            kind: OpKind::TestCondition {
                dst,
                cond: Condition::Ne,
            },
            ..
        }] if matches!(dst, VReg::Virtual(_))
    ));
    assert!(matches!(
        block.terminator,
        Terminator::CondBranch {
            cond: VReg::Virtual(_),
            true_target,
            false_target,
        } if true_target == taken && false_target == not_taken
    ));
}

#[test]
fn rejects_predication_pc_and_special_shifter_state() {
    let raws: [u32; 8] = [
        0x1081_0002, // ADDNE r0,r1,r2
        0xe081_000f, // ADD r0,r1,pc
        0xe1a0_0061, // RRX r0,r1
        0xe1a0_0021, // LSR r0,r1,#32 (encoded amount zero)
        0xe7e6_365f, // UBFX r3,pc,#12,#7
        0xe037_a998, // MLAS r7,r8,r9,r10
        0xe7c3_1412, // BFI r1,r2,#8 with msb below lsb
        0xe7ff_0851, // UBFX r0,r1,#16,#32 exceeds register width
    ];
    for raw in raws {
        let mut lifter = Aarch32Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch32);
        assert!(matches!(
            lifter.lift_insn(0x1000, &raw.to_le_bytes(), &mut ctx),
            Err(LiftError::Unsupported { .. })
        ));
    }
}

#[test]
fn incomplete_input_is_reported_without_decoder_access() {
    let mut lifter = Aarch32Lifter::new();
    let mut ctx = LiftContext::new(SourceArch::Aarch32);
    assert!(matches!(
        lifter.lift_insn(0x1000, &[0, 1, 2], &mut ctx),
        Err(LiftError::Incomplete {
            have: 3,
            need: 4,
            ..
        })
    ));
}

/// BKPT, UDF, ERET, HVC, and SMC are exceptions the lifter does not model:
/// they are rejected, not lifted as the TEQ and UBFX they decoded as before
/// the decoder checked the miscellaneous space and the media op2 field.
/// BXJ (a trivial Jazelle implementation's BX) lifts as BX.
#[test]
fn a32_exception_generating_instructions_are_not_lifted() {
    for raw in [
        0xe121_2374_u32,
        0xe7f0_00f0,
        0xe160_006e,
        0xe141_2374,
        0xe160_0075,
    ] {
        let mut lifter = Aarch32Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch32);
        let result = lifter.lift_insn(0x1000, &raw.to_le_bytes(), &mut ctx);
        assert!(
            matches!(result, Err(LiftError::Unsupported { .. })),
            "{raw:#010x}: {result:?}"
        );
    }
    assert!(matches!(
        lift(0xe12f_ff23).control_flow,
        ControlFlow::IndirectBranch { target } if target == Aarch32Lifter::reg(3)
    ));
}

/// ARMv8's LDA/STL and LDAEX/STLEX, which the decoder now recognizes, stay
/// rejected: the lifter models no acquire/release ordering or exclusive
/// monitor.
#[test]
fn a32_acquire_release_accesses_are_not_lifted() {
    for raw in [
        0xe191_0c9f_u32,
        0xe181_fc90,
        0xe191_0e9f,
        0xe181_9e90,
        0xe1b8_6e9f,
    ] {
        let mut lifter = Aarch32Lifter::new();
        let mut ctx = LiftContext::new(SourceArch::Aarch32);
        let result = lifter.lift_insn(0x1000, &raw.to_le_bytes(), &mut ctx);
        assert!(
            matches!(result, Err(LiftError::Unsupported { .. })),
            "{raw:#010x}: {result:?}"
        );
    }
}
