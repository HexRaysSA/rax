//! Thumb lifter tests: T16 and T32 lifting, lengths, and fail-closed forms.

use super::*;
use crate::smir::ir::types::ShiftOp;

fn lift(bytes: &[u8]) -> LiftResult {
    let mut lifter = ThumbLifter::new();
    let mut ctx = LiftContext::new(SourceArch::Thumb);
    lifter.lift_insn(0x1000, bytes, &mut ctx).unwrap()
}

#[test]
fn lifts_mixed_t16_t32_scalar_matrix_with_exact_lengths() {
    let cases: &[(&[u8], usize, &str)] = &[
        (&[0x88, 0x18], 2, "adds-t16"),
        (&[0x63, 0x1f], 2, "subs-t16"),
        (&[0x75, 0x41], 2, "adcs-t16"),
        (&[0x87, 0x41], 2, "sbcs-t16"),
        (&[0x80, 0x29], 2, "cmp-t16"),
        (&[0xda, 0x42], 2, "cmn-t16"),
        (&[0x6c, 0x42], 2, "neg-t16"),
        (&[0xc8, 0x44], 2, "add-high-t16"),
        (&[0xda, 0x46], 2, "mov-high-t16"),
        (&[0x08, 0xba], 2, "rev-t16"),
        (&[0x01, 0xeb, 0xc2, 0x00], 4, "add-shift-t32"),
        (&[0x0c, 0xea, 0x70, 0x1b], 4, "and-ror-t32"),
        (&[0x09, 0xfb, 0x0a, 0xf8], 4, "mul-t32"),
        (&[0x04, 0xfb, 0x05, 0x63], 4, "mla-t32"),
        (&[0xa2, 0xfb, 0x03, 0x01], 4, "umull-t32"),
        (&[0xb9, 0xfb, 0xfa, 0xf8], 4, "udiv-t32"),
        (&[0xb2, 0xfa, 0x82, 0xf1], 4, "clz-t32"),
        (&[0x6a, 0xf3, 0x0f, 0x29], 4, "bfi-t32"),
        (&[0xcc, 0xf3, 0x06, 0x3b], 4, "ubfx-t32"),
        (&[0x4f, 0xfa, 0x83, 0xf2], 4, "sxtb-t32"),
        (&[0xcc, 0xf6, 0xfe, 0x27], 4, "movt-t32"),
    ];
    for (bytes, expected_len, label) in cases {
        let mut lifter = ThumbLifter::new();
        let mut ctx = LiftContext::new(SourceArch::Thumb);
        let result = lifter
            .lift_insn(0x1000, bytes, &mut ctx)
            .unwrap_or_else(|error| panic!("{label}: {error:?}"));
        assert_eq!(result.bytes_consumed, *expected_len, "{label}");
        assert!(!result.ops.is_empty(), "{label}");
        assert!(matches!(result.control_flow, ControlFlow::Fallthrough));
    }
}

#[test]
fn lifts_t16_scalar_memory_width_sign_and_address_matrix() {
    let cases: &[(&[u8], MemWidth, SignExtend, bool)] = &[
        (&[0x88, 0x50], MemWidth::B4, SignExtend::Zero, false), // str r0,[r1,r2]
        (&[0x88, 0x52], MemWidth::B2, SignExtend::Zero, false), // strh r0,[r1,r2]
        (&[0x88, 0x54], MemWidth::B1, SignExtend::Zero, false), // strb r0,[r1,r2]
        (&[0x88, 0x56], MemWidth::B1, SignExtend::Sign, true),  // ldrsb r0,[r1,r2]
        (&[0x88, 0x58], MemWidth::B4, SignExtend::Zero, true),  // ldr r0,[r1,r2]
        (&[0x88, 0x5a], MemWidth::B2, SignExtend::Zero, true),  // ldrh r0,[r1,r2]
        (&[0x88, 0x5c], MemWidth::B1, SignExtend::Zero, true),  // ldrb r0,[r1,r2]
        (&[0x88, 0x5e], MemWidth::B2, SignExtend::Sign, true),  // ldrsh r0,[r1,r2]
        (&[0x48, 0x68], MemWidth::B4, SignExtend::Zero, true),  // ldr r0,[r1,#4]
        (&[0x88, 0x78], MemWidth::B1, SignExtend::Zero, true),  // ldrb r0,[r1,#2]
        (&[0x48, 0x88], MemWidth::B2, SignExtend::Zero, true),  // ldrh r0,[r1,#2]
        (&[0x01, 0x98], MemWidth::B4, SignExtend::Zero, true),  // ldr r0,[sp,#4]
    ];

    for (bytes, width, sign, is_load) in cases {
        let result = lift(bytes);
        assert_eq!(result.bytes_consumed, 2);
        assert_eq!(result.ops.len(), 1);
        match &result.ops[0].kind {
            OpKind::Load {
                width: actual_width,
                sign: actual_sign,
                ..
            } if *is_load => {
                assert_eq!(actual_width, width, "{bytes:02x?}");
                assert_eq!(actual_sign, sign, "{bytes:02x?}");
            }
            OpKind::Store {
                width: actual_width,
                ..
            } if !*is_load => assert_eq!(actual_width, width, "{bytes:02x?}"),
            other => panic!("unexpected T16 memory lift {bytes:02x?}: {other:?}"),
        }
    }
}

#[test]
fn lifts_t32_memory_writeback_after_access_and_scaled_offsets() {
    let cases: &[(&[u8], MemWidth, SignExtend, bool, usize)] = &[
        (
            &[0x51, 0xf8, 0x04, 0x0f],
            MemWidth::B4,
            SignExtend::Zero,
            true,
            2,
        ), // ldr r0,[r1,#4]!
        (
            &[0x43, 0xf8, 0x08, 0x29],
            MemWidth::B4,
            SignExtend::Zero,
            false,
            2,
        ), // str r2,[r3],#-8
        (
            &[0x95, 0xf9, 0x07, 0x40],
            MemWidth::B1,
            SignExtend::Sign,
            true,
            1,
        ), // ldrsb.w r4,[r5,#7]
        (
            &[0x37, 0xf9, 0x00, 0x60],
            MemWidth::B2,
            SignExtend::Sign,
            true,
            1,
        ), // ldrsh.w r6,[r7,r0]
        (
            &[0x8d, 0xf8, 0x0c, 0x80],
            MemWidth::B1,
            SignExtend::Zero,
            false,
            1,
        ), // strb.w r8,[sp,#12]
        (
            &[0x2a, 0xf8, 0x04, 0x9d],
            MemWidth::B2,
            SignExtend::Zero,
            false,
            2,
        ), // strh r9,[r10,#-4]!
    ];

    for (bytes, width, sign, is_load, op_count) in cases {
        let result = lift(bytes);
        assert_eq!(result.bytes_consumed, 4, "{bytes:02x?}");
        assert_eq!(result.ops.len(), *op_count, "{bytes:02x?}");
        match &result.ops[0].kind {
            OpKind::Load {
                width: actual_width,
                sign: actual_sign,
                ..
            } if *is_load => {
                assert_eq!(actual_width, width, "{bytes:02x?}");
                assert_eq!(actual_sign, sign, "{bytes:02x?}");
            }
            OpKind::Store {
                width: actual_width,
                ..
            } if !*is_load => assert_eq!(actual_width, width, "{bytes:02x?}"),
            other => panic!("unexpected T32 memory lift {bytes:02x?}: {other:?}"),
        }
        if result.ops.len() == 2 {
            assert!(
                matches!(
                    result.ops[1].kind,
                    OpKind::Add {
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                        ..
                    } | OpKind::Sub {
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                        ..
                    }
                ),
                "writeback follows access for {bytes:02x?}"
            );
        }
    }
}

#[test]
fn lifts_t16_t32_multiple_transfers_with_ordered_writeback() {
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

    let push = lift(&[0x31, 0xb5]); // push {r0,r4,r5,lr}
    assert_eq!(push.bytes_consumed, 2);
    assert_eq!(
        push.ops[..4].iter().map(offset).collect::<Vec<_>>(),
        vec![-16, -12, -8, -4]
    );
    assert!(matches!(
        &push.ops[4].kind,
        OpKind::Sub {
            dst,
            src1,
            src2: SrcOperand::Imm(16),
            ..
        } if dst == src1 && *dst == ThumbLifter::reg(13)
    ));

    let ldm = lift(&[0x07, 0xcf]); // ldmia r7!,{r0-r2}
    assert_eq!(ldm.bytes_consumed, 2);
    assert_eq!(
        ldm.ops[..3].iter().map(offset).collect::<Vec<_>>(),
        vec![0, 4, 8]
    );
    assert!(matches!(
        &ldm.ops[3].kind,
        OpKind::Add {
            dst,
            src1,
            src2: SrcOperand::Imm(12),
            ..
        } if dst == src1 && *dst == ThumbLifter::reg(7)
    ));

    let push_w = lift(&[0x2d, 0xe9, 0x00, 0x4f]); // push.w {r8-r11,lr}
    assert_eq!(push_w.bytes_consumed, 4);
    assert_eq!(push_w.ops.len(), 6);
    assert_eq!(
        push_w.ops[..5].iter().map(offset).collect::<Vec<_>>(),
        vec![-20, -16, -12, -8, -4]
    );

    let stmdb_w = lift(&[0x2a, 0xe9, 0x05, 0x01]); // stmdb r10!,{r0,r2,r8}
    assert_eq!(stmdb_w.bytes_consumed, 4);
    assert_eq!(
        stmdb_w.ops[..3].iter().map(offset).collect::<Vec<_>>(),
        vec![-12, -8, -4]
    );
}

#[test]
fn thumb_multiple_transfers_reject_pc_empty_and_base_aliases() {
    let cases: &[&[u8]] = &[
        &[0x01, 0xbd],             // pop {r0,pc}: interworking control flow
        &[0x00, 0xb4],             // push {}: constrained empty list
        &[0x02, 0xc9],             // ldmia r1!,{r1}: load/base alias
        &[0x02, 0xc1],             // stmia r1!,{r1}: store/writeback alias
        &[0xbd, 0xe8, 0x00, 0x80], // pop.w {pc}
    ];
    for bytes in cases {
        let mut lifter = ThumbLifter::new();
        let mut ctx = LiftContext::new(SourceArch::Thumb);
        assert!(
            matches!(
                lifter.lift_insn(0x1000, bytes, &mut ctx),
                Err(LiftError::Unsupported { .. })
            ),
            "{bytes:02x?}"
        );
    }
}

#[test]
fn lifts_t32_double_transfers_with_pair_atomicity_and_writeback() {
    let load = lift(&[0xd2, 0xe9, 0x02, 0x01]); // ldrd r0,r1,[r2,#8]
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
        }] if *dst1 == ThumbLifter::reg(0)
            && *dst2 == ThumbLifter::reg(1)
            && *base == ThumbLifter::reg(2)
    ));

    let store = lift(&[0xe4, 0xe9, 0x02, 0x23]); // strd r2,r3,[r4,#8]!
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
                    ..
                },
                ..
            }
        ] if *src1 == ThumbLifter::reg(2)
            && *src2 == ThumbLifter::reg(3)
            && dst == base
            && *dst == ThumbLifter::reg(4)
    ));
}

#[test]
fn thumb_double_transfers_reject_nonadjacent_pc_and_writeback_alias_pairs() {
    let cases: &[&[u8]] = &[
        &[0xd2, 0xe9, 0x02, 0x12], // ldrd r1,r2,[r2,#8]: odd first register
        &[0xd2, 0xe9, 0x02, 0x02], // ldrd r0,r2,[r2,#8]: nonadjacent pair
        &[0xd2, 0xe9, 0x02, 0xef], // ldrd r14,pc,[r2,#8]
        &[0xf0, 0xe9, 0x02, 0x01], // ldrd r0,r1,[r0,#8]!: base alias
    ];
    for bytes in cases {
        let mut lifter = ThumbLifter::new();
        let mut ctx = LiftContext::new(SourceArch::Thumb);
        assert!(
            matches!(
                lifter.lift_insn(0x1000, bytes, &mut ctx),
                Err(LiftError::Unsupported { .. })
            ),
            "{bytes:02x?}"
        );
    }
}

#[test]
fn uses_thumb_pc_plus_four_and_sets_thumb_link_bit() {
    let branch = lift(&[0x04, 0xe0]); // B +8; target = 0x100c.
    assert!(matches!(
        branch.control_flow,
        ControlFlow::Branch { target: 0x100c }
    ));

    let t16_cond = lift(&[0x01, 0xd0]); // BEQ +2.
    assert!(matches!(
        t16_cond.control_flow,
        ControlFlow::CondBranch {
            cond: Condition::Eq,
            target: 0x1006,
            fallthrough: 0x1002,
        }
    ));
    assert_eq!(t16_cond.branch_targets, vec![0x1006, 0x1002]);

    let t32_cond = lift(&[0x40, 0xf0, 0x02, 0x80]); // BNE.W +4.
    assert_eq!(t32_cond.bytes_consumed, 4);
    assert!(matches!(
        t32_cond.control_flow,
        ControlFlow::CondBranch {
            cond: Condition::Ne,
            target: 0x1008,
            fallthrough: 0x1004,
        }
    ));
    assert_eq!(t32_cond.branch_targets, vec![0x1008, 0x1004]);

    let call = lift(&[0x00, 0xf0, 0x00, 0xf8]); // BL +0.
    assert!(matches!(
        call.control_flow,
        ControlFlow::Call {
            target: CallTarget::GuestAddr(0x1004)
        }
    ));
    assert!(matches!(
        call.ops.as_slice(),
        [SmirOp {
            kind: OpKind::Mov {
                dst: VReg::Arch(ArchReg::Arm(ArmReg::X(14))),
                src: SrcOperand::Imm(0x1005),
                width: OpWidth::W32,
            },
            ..
        }]
    ));
}

#[test]
fn lifts_t16_cbz_cbnz_for_every_low_register_and_max_forward_offset() {
    for rn in 0_u16..8 {
        for (base, zero) in [(0xb100_u16, true), (0xb900_u16, false)] {
            let raw = base | (1 << 3) | rn; // forward offset = 2.
            let result = lift(&raw.to_le_bytes());
            let reg = ThumbLifter::reg(rn as u8);
            assert_eq!(result.bytes_consumed, 2);
            assert!(result.ops.is_empty());
            assert!(matches!(
                result.control_flow,
                ControlFlow::CondBranchReg {
                    cond,
                    taken,
                    not_taken,
                } if cond == reg
                    && if zero {
                        taken == 0x1002 && not_taken == 0x1006
                    } else {
                        taken == 0x1006 && not_taken == 0x1002
                    }
            ));
        }
    }

    for (raw, zero) in [(0xb3f8_u16, true), (0xbbf8_u16, false)] {
        let result = lift(&raw.to_le_bytes()); // r0, forward offset = 126.
        assert!(matches!(
            result.control_flow,
            ControlFlow::CondBranchReg {
                taken,
                not_taken,
                ..
            } if if zero {
                taken == 0x1002 && not_taken == 0x1082
            } else {
                taken == 0x1082 && not_taken == 0x1002
            }
        ));
    }
}

#[test]
fn lifts_t16_bx_for_every_non_pc_register_and_block_terminator() {
    for rm in 0_u16..15 {
        let result = lift(&(0x4700 | (rm << 3)).to_le_bytes());
        assert!(result.ops.is_empty());
        assert!(result.branch_targets.is_empty());
        assert!(matches!(
            result.control_flow,
            ControlFlow::IndirectBranch { target }
                if target == ThumbLifter::reg(rm as u8)
        ));
    }
    let mut lifter = ThumbLifter::new();
    let mut reject_ctx = LiftContext::new(SourceArch::Thumb);
    assert!(matches!(
        lifter.lift_insn(0x1000, &[0x78, 0x47], &mut reject_ctx),
        Err(LiftError::Unsupported { .. })
    ));

    struct Memory([u8; 2]);
    impl MemoryReader for Memory {
        fn read(
            &self,
            addr: GuestAddr,
            size: usize,
        ) -> Result<Vec<u8>, crate::smir::ir::memory::MemoryError> {
            if addr != 0x1000 || size != 2 {
                return Err(crate::smir::ir::memory::MemoryError::OutOfBounds { addr });
            }
            Ok(self.0.to_vec())
        }
    }

    let mut lifter = ThumbLifter::new();
    let mut ctx = LiftContext::new(SourceArch::Thumb);
    let block = lifter
        .lift_block(0x1000, &Memory([0x70, 0x47]), &mut ctx)
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
fn lifts_thumb_blx_immediate_and_every_register_with_old_lr_snapshot() {
    let direct = lift(&[0x00, 0xf0, 0x00, 0xe8]); // BLX +0: Thumb -> ARM.
    assert_eq!(direct.bytes_consumed, 4);
    assert_eq!(direct.branch_targets, vec![0x1004]);
    assert!(matches!(
        direct.control_flow,
        ControlFlow::Call {
            target: CallTarget::GuestAddrInterworking {
                addr: 0x1004,
                thumb: false,
            }
        }
    ));
    assert!(matches!(
        direct.ops.as_slice(),
        [SmirOp {
            kind: OpKind::Mov {
                dst: VReg::Arch(ArchReg::Arm(ArmReg::X(14))),
                src: SrcOperand::Imm(0x1005),
                width: OpWidth::W32,
            },
            ..
        }]
    ));

    let mut unaligned_lifter = ThumbLifter::new();
    let mut unaligned_ctx = LiftContext::new(SourceArch::Thumb);
    let unaligned = unaligned_lifter
        .lift_insn(0x1002, &[0x00, 0xf0, 0x00, 0xe8], &mut unaligned_ctx)
        .unwrap();
    assert!(matches!(
        unaligned.control_flow,
        ControlFlow::Call {
            target: CallTarget::GuestAddrInterworking {
                addr: 0x1004,
                thumb: false,
            }
        }
    ));

    for rm in 0_u16..15 {
        let result = lift(&(0x4780 | (rm << 3)).to_le_bytes());
        assert_eq!(result.bytes_consumed, 2);
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
                                src: SrcOperand::Imm(0x1003),
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
                assert_eq!(*source, ThumbLifter::reg(14));
                assert_eq!(*link, ThumbLifter::reg(14));
                assert_eq!(target, *snapshot);
            }
            (
                _,
                [
                    SmirOp {
                        kind:
                            OpKind::Mov {
                                dst,
                                src: SrcOperand::Imm(0x1003),
                                width: OpWidth::W32,
                            },
                        ..
                    },
                ],
                ControlFlow::Call {
                    target: CallTarget::IndirectInterworking(target),
                },
            ) => {
                assert_eq!(*dst, ThumbLifter::reg(14));
                assert_eq!(target, ThumbLifter::reg(rm as u8));
            }
            other => panic!("unexpected BLX r{rm} lift: {other:?}"),
        }
    }

    let mut lifter = ThumbLifter::new();
    let mut ctx = LiftContext::new(SourceArch::Thumb);
    assert!(matches!(
        lifter.lift_insn(0x1000, &[0xf8, 0x47], &mut ctx),
        Err(LiftError::Unsupported { .. })
    ));
}

#[test]
fn thumb_control_flow_pc_arithmetic_wraps_modulo_2_pow_32() {
    let mut lifter = ThumbLifter::new();
    let mut ctx = LiftContext::new(SourceArch::Thumb);

    let branch = lifter
        .lift_insn(0xffff_fffe, &[0x00, 0xe0], &mut ctx)
        .unwrap(); // B +0: PC + 4 wraps to 2.
    assert!(matches!(
        branch.control_flow,
        ControlFlow::Branch { target: 2 }
    ));

    let cond = lifter
        .lift_insn(0xffff_fffe, &[0x00, 0xd0], &mut ctx)
        .unwrap(); // BEQ +0; fallthrough wraps to 0.
    assert!(matches!(
        cond.control_flow,
        ControlFlow::CondBranch {
            target: 2,
            fallthrough: 0,
            ..
        }
    ));

    let cbz = lifter
        .lift_insn(0xffff_fffe, &[0x00, 0xb1], &mut ctx)
        .unwrap();
    assert!(matches!(
        cbz.control_flow,
        ControlFlow::CondBranchReg {
            taken: 0,
            not_taken: 2,
            ..
        }
    ));

    let call = lifter
        .lift_insn(0xffff_fffc, &[0x00, 0xf0, 0x00, 0xf8], &mut ctx)
        .unwrap(); // BL +0; target 0, Thumb link 1.
    assert!(matches!(
        call.control_flow,
        ControlFlow::Call {
            target: CallTarget::GuestAddr(0)
        }
    ));
    assert!(matches!(
        call.ops.as_slice(),
        [SmirOp {
            kind: OpKind::Mov {
                src: SrcOperand::Imm(1),
                ..
            },
            ..
        }]
    ));

    let exchange = lifter
        .lift_insn(0xffff_fffe, &[0x00, 0xf0, 0x00, 0xe8], &mut ctx)
        .unwrap(); // BLX +0; aligned PC base wraps to 0, Thumb link wraps to 3.
    assert!(matches!(
        exchange.control_flow,
        ControlFlow::Call {
            target: CallTarget::GuestAddrInterworking {
                addr: 0,
                thumb: false,
            }
        }
    ));
    assert!(matches!(
        exchange.ops.as_slice(),
        [SmirOp {
            kind: OpKind::Mov {
                src: SrcOperand::Imm(3),
                ..
            },
            ..
        }]
    ));

    assert!(matches!(
        lifter.lift_insn(u64::from(u32::MAX) + 1, &[0x00, 0xe0], &mut ctx),
        Err(LiftError::Unsupported { .. })
    ));
}

#[test]
fn lifts_every_t16_branch_condition_with_exact_fallthrough() {
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
        let raw = 0xd001u16 | ((bits as u16) << 8);
        let result = lift(&raw.to_le_bytes());
        assert!(matches!(
            result.control_flow,
            ControlFlow::CondBranch {
                cond,
                target: 0x1006,
                fallthrough: 0x1002,
            } if cond == expected
        ));
        assert_eq!(result.branch_targets, vec![0x1006, 0x1002]);
    }
}

#[test]
fn lifts_t16_selective_flag_move_logic_multiply_and_immediate_shift_matrix() {
    let nz = ThumbLifter::t16_partial_nz_flags();
    let nzc = ThumbLifter::partial_nzc_flags();

    assert!(matches!(
        lift(&[0x00, 0x20]).ops.as_slice(),
        [
            SmirOp {
                kind: OpKind::Mov {
                    dst,
                    src: SrcOperand::Imm(0),
                    width: OpWidth::W32,
                },
                ..
            },
            SmirOp {
                kind: OpKind::And {
                    dst: flags_dst,
                    src1,
                    src2: SrcOperand::Imm(-1),
                    width: OpWidth::W32,
                    flags,
                },
                ..
            }
        ] if *dst == ThumbLifter::reg(0)
            && *flags_dst == *dst
            && *src1 == *dst
            && *flags == nz
    ));
    assert!(matches!(
        lift(&[0x08, 0x00]).ops.as_slice(),
        [SmirOp {
            kind: OpKind::And {
                dst,
                src1,
                src2: SrcOperand::Imm(-1),
                width: OpWidth::W32,
                flags,
            },
            ..
        }] if *dst == ThumbLifter::reg(0)
            && *src1 == ThumbLifter::reg(1)
            && *flags == nz
    ));

    for (bytes, expected) in [
        ([0x08, 0x40], "and"),
        ([0x48, 0x40], "xor"),
        ([0x08, 0x43], "or"),
        ([0x88, 0x43], "and-not"),
    ] {
        let result = lift(&bytes);
        let matched = match (&result.ops[0].kind, expected) {
            (OpKind::And { flags, .. }, "and")
            | (OpKind::Xor { flags, .. }, "xor")
            | (OpKind::Or { flags, .. }, "or")
            | (OpKind::AndNot { flags, .. }, "and-not") => *flags == nz,
            _ => false,
        };
        assert!(matched, "{bytes:02x?}: {result:?}");
    }

    assert!(matches!(
        lift(&[0xc8, 0x43]).ops.as_slice(),
        [SmirOp {
            kind: OpKind::AndNot {
                dst,
                src1: VReg::Imm(-1),
                flags,
                ..
            },
            ..
        }] if *dst == ThumbLifter::reg(0) && *flags == nz
    ));
    assert!(matches!(
        lift(&[0x08, 0x42]).ops.as_slice(),
        [SmirOp {
            kind: OpKind::And {
                dst: VReg::Virtual(_),
                flags,
                ..
            },
            ..
        }] if *flags == nz
    ));
    assert!(matches!(
        lift(&[0x48, 0x43]).ops.as_slice(),
        [SmirOp {
            kind: OpKind::MulU {
                dst_lo,
                dst_hi: None,
                width: OpWidth::W32,
                flags,
                ..
            },
            ..
        }] if *dst_lo == ThumbLifter::reg(0) && *flags == nz
    ));

    for (bytes, expected_amount, expected) in [
        ([0x48, 0x00], 1, "lsl"),
        ([0xc8, 0x0f], 31, "lsr"),
        ([0x08, 0x08], 32, "lsr"),
        ([0xc8, 0x17], 31, "asr"),
        ([0x08, 0x10], 32, "asr"),
    ] {
        let result = lift(&bytes);
        let matched = match (&result.ops[0].kind, expected) {
            (
                OpKind::Shl {
                    amount: SrcOperand::Imm(amount),
                    flags,
                    ..
                },
                "lsl",
            )
            | (
                OpKind::Shr {
                    amount: SrcOperand::Imm(amount),
                    flags,
                    ..
                },
                "lsr",
            )
            | (
                OpKind::Sar {
                    amount: SrcOperand::Imm(amount),
                    flags,
                    ..
                },
                "asr",
            ) => *amount == expected_amount && *flags == nzc,
            _ => false,
        };
        assert!(matched, "{bytes:02x?}: {result:?}");
    }
}

#[test]
fn lifts_all_t16_register_shift_encodings_with_exact_low_byte_contract() {
    let nzc = ThumbLifter::partial_nzc_flags();
    for (op, expected_shift) in [
        (0b0010_u16, ShiftOp::Lsl),
        (0b0011, ShiftOp::Lsr),
        (0b0100, ShiftOp::Asr),
        (0b0111, ShiftOp::Ror),
    ] {
        for rdn in 0_u8..8 {
            for rs in 0_u8..8 {
                let raw = 0x4000_u16 | (op << 6) | (u16::from(rs) << 3) | u16::from(rdn);
                let result = lift(&raw.to_le_bytes());
                assert_eq!(result.bytes_consumed, 2, "raw={raw:#06x}");
                assert!(
                    matches!(
                        result.ops.as_slice(),
                        [SmirOp {
                            kind: OpKind::ArmRegShift {
                                dst,
                                src,
                                amount: SrcOperand::Reg(amount),
                                shift,
                                width: OpWidth::W32,
                                flags,
                            },
                            ..
                        }] if *dst == ThumbLifter::reg(rdn)
                            && *src == ThumbLifter::reg(rdn)
                            && *amount == ThumbLifter::reg(rs)
                            && *shift == expected_shift
                            && *flags == nzc
                    ),
                    "raw={raw:#06x}: {result:?}"
                );
            }
        }
    }
}

#[test]
fn lifts_all_t32_register_shift_encodings_with_independent_registers_and_flags() {
    let nzc = ThumbLifter::partial_nzc_flags();
    for (kind, expected_shift) in [
        (0_u16, ShiftOp::Lsl),
        (1, ShiftOp::Lsr),
        (2, ShiftOp::Asr),
        (3, ShiftOp::Ror),
    ] {
        for setflags in [false, true] {
            let op1 = (kind << 1) | u16::from(setflags);
            for rd in 0_u8..16 {
                for rn in 0_u8..16 {
                    for rs in 0_u8..16 {
                        let hw1 = 0xfa00_u16 | (op1 << 4) | u16::from(rn);
                        let hw2 = 0xf000_u16 | (u16::from(rd) << 8) | u16::from(rs);
                        let [a, b] = hw1.to_le_bytes();
                        let [c, d] = hw2.to_le_bytes();
                        let bytes = [a, b, c, d];
                        let mut lifter = ThumbLifter::new();
                        let mut ctx = LiftContext::new(SourceArch::Thumb);
                        let lifted = lifter.lift_insn(0x1000, &bytes, &mut ctx);

                        if rd == 15 || rn == 15 || rs == 15 {
                            assert!(
                                matches!(lifted, Err(LiftError::Unsupported { .. })),
                                "PC-bearing T32 shift escaped: {bytes:02x?} {lifted:?}"
                            );
                            continue;
                        }

                        let result = lifted.unwrap_or_else(|error| {
                            panic!("T32 shift {bytes:02x?} failed: {error}")
                        });
                        let expected_flags = if setflags { nzc } else { FlagUpdate::None };
                        assert_eq!(result.bytes_consumed, 4, "raw={bytes:02x?}");
                        assert!(
                            matches!(
                                result.ops.as_slice(),
                                [SmirOp {
                                    kind: OpKind::ArmRegShift {
                                        dst,
                                        src,
                                        amount: SrcOperand::Reg(amount),
                                        shift,
                                        width: OpWidth::W32,
                                        flags,
                                    },
                                    ..
                                }] if *dst == ThumbLifter::reg(rd)
                                    && *src == ThumbLifter::reg(rn)
                                    && *amount == ThumbLifter::reg(rs)
                                    && *shift == expected_shift
                                    && *flags == expected_flags
                            ),
                            "raw={bytes:02x?}: {result:?}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn rejects_it_pc_memory_aliases_and_unmodeled_shifter_contracts() {
    let cases: &[&[u8]] = &[
        &[0x08, 0xbf],             // IT EQ
        &[0x78, 0x46],             // MOV r0,pc
        &[0x51, 0xf8, 0x04, 0x1f], // LDR r1,[r1,#4]! aliases writeback
        &[0x4f, 0xea, 0x31, 0x00], // RRX r0,r1
        &[0x4f, 0xfa, 0x93, 0xf2], // SXTB.W r2,r3,ROR #8
    ];
    for bytes in cases {
        let mut lifter = ThumbLifter::new();
        let mut ctx = LiftContext::new(SourceArch::Thumb);
        assert!(matches!(
            lifter.lift_insn(0x1000, bytes, &mut ctx),
            Err(LiftError::Unsupported { .. })
        ));
    }
}

#[test]
fn lifts_t16_t32_literal_load_alignment_width_sign_add_subtract_and_wrap_matrix() {
    let t16 = lift(&[0x00, 0x48]);
    assert!(matches!(
        t16.ops.as_slice(),
        [SmirOp {
            kind: OpKind::Load {
                dst,
                addr: Address::Absolute(0x1004),
                width: MemWidth::B4,
                sign: SignExtend::Zero,
            },
            ..
        }] if *dst == ThumbLifter::reg(0)
    ));
    assert!(matches!(
        lift(&[0xff, 0x48]).ops.as_slice(),
        [SmirOp {
            kind: OpKind::Load {
                addr: Address::Absolute(0x1400),
                ..
            },
            ..
        }]
    ));

    let cases: &[(&[u8], u8, u64, MemWidth, SignExtend)] = &[
        (
            &[0xdf, 0xf8, 0x23, 0x01],
            0,
            0x1127,
            MemWidth::B4,
            SignExtend::Zero,
        ),
        (
            &[0x5f, 0xf8, 0x23, 0x11],
            1,
            0x0ee1,
            MemWidth::B4,
            SignExtend::Zero,
        ),
        (
            &[0x9f, 0xf8, 0x34, 0x22],
            2,
            0x1238,
            MemWidth::B1,
            SignExtend::Zero,
        ),
        (
            &[0x1f, 0xf8, 0x34, 0x32],
            3,
            0x0dd0,
            MemWidth::B1,
            SignExtend::Zero,
        ),
        (
            &[0xbf, 0xf8, 0x56, 0x44],
            4,
            0x145a,
            MemWidth::B2,
            SignExtend::Zero,
        ),
        (
            &[0x1f, 0xf9, 0x56, 0x54],
            5,
            0x0bae,
            MemWidth::B1,
            SignExtend::Sign,
        ),
        (
            &[0xbf, 0xf9, 0x78, 0x66],
            6,
            0x167c,
            MemWidth::B2,
            SignExtend::Sign,
        ),
        (
            &[0x3f, 0xf9, 0x78, 0x76],
            7,
            0x098c,
            MemWidth::B2,
            SignExtend::Sign,
        ),
        (
            &[0xdf, 0xf8, 0xff, 0x8f],
            8,
            0x2003,
            MemWidth::B4,
            SignExtend::Zero,
        ),
        (
            &[0x5f, 0xf8, 0xff, 0x9f],
            9,
            0x0005,
            MemWidth::B4,
            SignExtend::Zero,
        ),
    ];
    for (bytes, dst, address, width, sign) in cases {
        let result = lift(bytes);
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
                }] if *actual_dst == ThumbLifter::reg(*dst)
                    && *actual_address == *address
                    && *actual_width == *width
                    && *actual_sign == *sign
            ),
            "{bytes:02x?}: {result:?}"
        );
    }

    let mut lifter = ThumbLifter::new();
    let mut ctx = LiftContext::new(SourceArch::Thumb);
    for (pc, bytes, expected) in [
        (0x1002, &[0x00, 0x48][..], 0x1004),
        (0xffff_fffe, &[0x01, 0x48][..], 4),
        (0xffff_fffe, &[0xdf, 0xf8, 0x04, 0x00][..], 4),
        (0xffff_fffe, &[0x5f, 0xf8, 0x04, 0x00][..], 0xffff_fffc),
    ] {
        let result = lifter.lift_insn(pc, bytes, &mut ctx).unwrap();
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

    for bytes in [
        &[0xdf, 0xf8, 0x00, 0xf0][..], // literal load to PC is control flow
        &[0xcf, 0xf8, 0x00, 0x00][..], // PC-relative store is not admitted
    ] {
        assert!(
            matches!(
                lifter.lift_insn(0x1000, bytes, &mut ctx),
                Err(LiftError::Unsupported { .. })
            ),
            "{bytes:02x?}"
        );
    }
    assert!(matches!(
        lifter.lift_insn(u64::from(u32::MAX) + 1, &[0x00, 0x48], &mut ctx,),
        Err(LiftError::Unsupported { .. })
    ));
}

#[test]
fn reports_t16_and_t32_incomplete_input_exactly() {
    let mut lifter = ThumbLifter::new();
    let mut ctx = LiftContext::new(SourceArch::Thumb);
    assert!(matches!(
        lifter.lift_insn(0x1000, &[0], &mut ctx),
        Err(LiftError::Incomplete {
            have: 1,
            need: 2,
            ..
        })
    ));
    assert!(matches!(
        lifter.lift_insn(0x1000, &[0x01, 0xeb, 0xc2], &mut ctx),
        Err(LiftError::Incomplete {
            have: 3,
            need: 4,
            ..
        })
    ));
}

#[test]
fn block_lifting_advances_over_mixed_t16_t32_widths() {
    struct Memory {
        base: GuestAddr,
        bytes: Vec<u8>,
    }

    impl MemoryReader for Memory {
        fn read(
            &self,
            addr: GuestAddr,
            size: usize,
        ) -> Result<Vec<u8>, crate::smir::ir::memory::MemoryError> {
            let offset = (addr - self.base) as usize;
            if offset + size > self.bytes.len() {
                return Err(crate::smir::ir::memory::MemoryError::OutOfBounds { addr });
            }
            Ok(self.bytes[offset..offset + size].to_vec())
        }
    }

    let memory = Memory {
        base: 0x1000,
        bytes: vec![
            0x88, 0x18, // ADDS r0,r1,r2 (T16)
            0x01, 0xeb, 0xc2, 0x00, // ADD.W r0,r1,r2,LSL #3 (T32)
            0x00, 0xe0, // B +0 (T16), target 0x100a
        ],
    };
    let mut lifter = ThumbLifter::new();
    let mut ctx = LiftContext::new(SourceArch::Thumb);
    let block = lifter.lift_block(0x1000, &memory, &mut ctx).unwrap();

    assert_eq!(block.ops.len(), 2);
    assert_eq!(block.ops[0].guest_pc, 0x1000);
    assert_eq!(block.ops[1].guest_pc, 0x1002);
    assert!(matches!(
        block.terminator,
        Terminator::Branch { target } if target == ctx.get_or_create_block(0x100a)
    ));
}

#[test]
fn thumb_block_materializes_only_a_foldable_branch_condition() {
    struct Memory {
        base: GuestAddr,
        bytes: Vec<u8>,
    }

    impl MemoryReader for Memory {
        fn read(
            &self,
            addr: GuestAddr,
            size: usize,
        ) -> Result<Vec<u8>, crate::smir::ir::memory::MemoryError> {
            let offset = (addr - self.base) as usize;
            if offset + size > self.bytes.len() {
                return Err(crate::smir::ir::memory::MemoryError::OutOfBounds { addr });
            }
            Ok(self.bytes[offset..offset + size].to_vec())
        }
    }

    let memory = Memory {
        base: 0x1000,
        bytes: vec![0x01, 0xd1], // BNE +2.
    };
    let mut lifter = ThumbLifter::new();
    let mut ctx = LiftContext::new(SourceArch::Thumb);
    let block = lifter.lift_block(0x1000, &memory, &mut ctx).unwrap();
    let taken = ctx.get_or_create_block(0x1006);
    let not_taken = ctx.get_or_create_block(0x1002);

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
fn thumb_block_keeps_cbz_as_a_register_condition_without_flag_materialization() {
    struct Memory([u8; 2]);

    impl MemoryReader for Memory {
        fn read(
            &self,
            addr: GuestAddr,
            size: usize,
        ) -> Result<Vec<u8>, crate::smir::ir::memory::MemoryError> {
            if addr != 0x1000 || size != 2 {
                return Err(crate::smir::ir::memory::MemoryError::OutOfBounds { addr });
            }
            Ok(self.0.to_vec())
        }
    }

    let mut lifter = ThumbLifter::new();
    let mut ctx = LiftContext::new(SourceArch::Thumb);
    let block = lifter
        .lift_block(0x1000, &Memory([0x08, 0xb1]), &mut ctx)
        .unwrap(); // CBZ r0,+2.
    let nonzero = ctx.get_or_create_block(0x1002);
    let zero = ctx.get_or_create_block(0x1006);

    assert!(block.ops.is_empty());
    assert!(matches!(
        block.terminator,
        Terminator::CondBranch {
            cond: VReg::Arch(ArchReg::Arm(ArmReg::X(0))),
            true_target,
            false_target,
        } if true_target == nonzero && false_target == zero
    ));
}

#[test]
fn lifts_t16_adr_as_the_word_aligned_pc_plus_its_offset() {
    // ADR r1, #24 (LLVM 23.1.1: a106) at 0x1002: Align(0x1006, 4) + 24.
    let mut lifter = ThumbLifter::new();
    let mut ctx = LiftContext::new(SourceArch::Thumb);
    let result = lifter.lift_insn(0x1002, &[0x06, 0xa1], &mut ctx).unwrap();
    assert_eq!(result.bytes_consumed, 2);
    assert!(matches!(result.control_flow, ControlFlow::Fallthrough));
    match result.ops.as_slice() {
        [op] => assert!(
            matches!(
                op.kind,
                OpKind::Mov {
                    dst,
                    src: SrcOperand::Imm(0x101c),
                    width: OpWidth::W32,
                } if dst == ThumbLifter::reg(1)
            ),
            "{:?}",
            op.kind
        ),
        ops => panic!("unexpected ADR lift: {ops:?}"),
    }
}
