//! jit_gate_tests::aarch64 tests

use super::*;
use crate::smir::lower::runtime::*;

#[test]
fn aarch64_guest_state_layout_matches_native_exit_offsets() {
    assert_eq!(
        std::mem::offset_of!(Aarch64GuestRegs, pc),
        Aarch64GuestRegs::PC_OFFSET as usize
    );
    assert_eq!(
        std::mem::offset_of!(Aarch64GuestRegs, vec_store_fn),
        Aarch64GuestRegs::VEC_STORE_FN_OFFSET as usize
    );
    assert_eq!(
        std::mem::offset_of!(Aarch64GuestRegs, exit_flags),
        Aarch64GuestRegs::EXIT_FLAGS_OFFSET as usize
    );
    assert_eq!(
        std::mem::offset_of!(Aarch64GuestRegs, x86_apx_enabled),
        Aarch64GuestRegs::X86_APX_ENABLED_OFFSET as usize
    );
    assert_eq!(
        std::mem::offset_of!(Aarch64GuestRegs, x86_tbm_enabled),
        Aarch64GuestRegs::X86_TBM_ENABLED_OFFSET as usize
    );
    assert_eq!(
        std::mem::offset_of!(Aarch64GuestRegs, x86_tbm_mode_valid),
        Aarch64GuestRegs::X86_TBM_MODE_VALID_OFFSET as usize
    );
    assert_eq!(Aarch64GuestRegs::EXIT_FLAGS_OFFSET, 864);
    assert_eq!(Aarch64GuestRegs::X86_APX_ENABLED_OFFSET, 872);
    assert_eq!(Aarch64GuestRegs::X86_TBM_ENABLED_OFFSET, 880);
    assert_eq!(Aarch64GuestRegs::X86_TBM_MODE_VALID_OFFSET, 888);
    assert_eq!(std::mem::offset_of!(Aarch64GuestRegs, pauth_context), 896);
    assert_eq!(std::mem::offset_of!(Aarch64GuestRegs, pauth_fn), 904);
    assert_eq!(Aarch64GuestRegs::PAUTH_CONTEXT_OFFSET, 896);
    assert_eq!(Aarch64GuestRegs::PAUTH_FN_OFFSET, 904);
    assert_eq!(std::mem::size_of::<Aarch64GuestRegs>(), 912);
    assert_eq!(Aarch64GuestRegs::EXIT_VALID, 1);
    assert_eq!(Aarch64GuestRegs::EXIT_AARCH32_T, 2);
    assert_eq!(Aarch64GuestRegs::EXIT_AARCH32_T_VALID, 4);
}
#[test]
fn aarch32_aarch64_gate_accepts_closed_direct_cfg_and_exact_folded_condition() {
    let mut branch = FunctionBuilder::new(FunctionId(0), 0x1000);
    let exit = branch.create_block(0x2000);
    branch.set_terminator(Terminator::Branch { target: exit });
    branch.switch_to_block(exit);
    branch.set_terminator(Terminator::Return { values: Vec::new() });
    assert!(is_aarch32_aarch64_native_clobber_safe_excluding(
        &branch.finish(),
        &std::collections::HashMap::new(),
    ));

    let cond = VReg::Virtual(VirtualId(7));
    let function = aarch32_cond_cfg(cond, cond, Condition::Ne, None);
    assert!(is_aarch32_aarch64_native_clobber_safe_excluding(
        &function,
        &std::collections::HashMap::new(),
    ));

    let excluded = std::collections::HashMap::from([
        (function.blocks[1].id, function.blocks[1].guest_pc),
        (function.blocks[2].id, function.blocks[2].guest_pc),
    ]);
    assert!(is_aarch32_aarch64_native_clobber_safe_excluding(
        &function, &excluded,
    ));

    let mut zero_test = FunctionBuilder::new(FunctionId(0), 0x1000);
    let nonzero = zero_test.create_block(0x1002);
    let zero = zero_test.create_block(0x1006);
    zero_test.set_terminator(Terminator::CondBranch {
        cond: arm_x(7),
        true_target: nonzero,
        false_target: zero,
    });
    zero_test.switch_to_block(nonzero);
    zero_test.set_terminator(Terminator::Return { values: Vec::new() });
    zero_test.switch_to_block(zero);
    zero_test.set_terminator(Terminator::Return { values: Vec::new() });
    assert!(is_aarch32_aarch64_native_clobber_safe_excluding(
        &zero_test.finish(),
        &std::collections::HashMap::new(),
    ));

    for link_pc in [0x1004, 0x1005] {
        let call = aarch32_call_cfg(
            CallTarget::GuestAddr(0x2000),
            arm_x(14),
            link_pc,
            OpWidth::W32,
            Vec::new(),
            0x1004,
        );
        assert!(is_aarch32_aarch64_native_clobber_safe_excluding(
            &call,
            &std::collections::HashMap::new(),
        ));
    }

    for (target, link_pc) in [
        (
            CallTarget::GuestAddrInterworking {
                addr: 0x2002,
                thumb: true,
            },
            0x1004,
        ),
        (
            CallTarget::GuestAddrInterworking {
                addr: 0x2000,
                thumb: false,
            },
            0x1005,
        ),
        (CallTarget::IndirectInterworking(arm_x(0)), 0x1004),
        (CallTarget::IndirectInterworking(arm_x(13)), 0x1005),
    ] {
        assert!(is_aarch32_aarch64_native_clobber_safe_excluding(
            &aarch32_call_cfg(target, arm_x(14), link_pc, OpWidth::W32, Vec::new(), 0x1004,),
            &std::collections::HashMap::new(),
        ));
    }
    let snapshot = VReg::Virtual(VirtualId(11));
    assert!(is_aarch32_aarch64_native_clobber_safe_excluding(
        &aarch32_blx_lr_cfg(snapshot, arm_x(14), snapshot, 0x1004, Vec::new()),
        &std::collections::HashMap::new(),
    ));

    for target in [arm_x(0), arm_x(7), arm_x(14)] {
        let indirect = aarch32_indirect_cfg(target, Vec::new());
        assert!(is_aarch32_aarch64_native_clobber_safe_excluding(
            &indirect,
            &std::collections::HashMap::new(),
        ));
    }
}
#[test]
fn aarch32_aarch64_gate_rejects_malformed_or_stateful_cfg_shapes() {
    let cond = VReg::Virtual(VirtualId(7));
    let other = VReg::Virtual(VirtualId(8));
    for function in [
        aarch32_cond_cfg(other, cond, Condition::Eq, None),
        aarch32_cond_cfg(cond, arm_x(0), Condition::Eq, None),
        aarch32_cond_cfg(cond, cond, Condition::Parity, None),
        aarch32_cond_cfg(cond, cond, Condition::NoParity, None),
        aarch32_cond_cfg(cond, cond, Condition::Eq, Some(OpKind::Nop)),
    ] {
        assert!(!is_aarch32_aarch64_native_clobber_safe_excluding(
            &function,
            &std::collections::HashMap::new(),
        ));
    }

    let malformed_calls = [
        aarch32_call_cfg(
            CallTarget::GuestAddr(0x2000),
            arm_x(14),
            0x1006,
            OpWidth::W32,
            Vec::new(),
            0x1004,
        ),
        aarch32_call_cfg(
            CallTarget::GuestAddr(0x2000),
            arm_x(13),
            0x1004,
            OpWidth::W32,
            Vec::new(),
            0x1004,
        ),
        aarch32_call_cfg(
            CallTarget::GuestAddr(0x2000),
            arm_x(14),
            0x1004,
            OpWidth::W64,
            Vec::new(),
            0x1004,
        ),
        aarch32_call_cfg(
            CallTarget::GuestAddr(0x2000),
            arm_x(14),
            0x1004,
            OpWidth::W32,
            vec![arm_x(0)],
            0x1004,
        ),
        aarch32_call_cfg(
            CallTarget::GuestAddr(0x2001),
            arm_x(14),
            0x1004,
            OpWidth::W32,
            Vec::new(),
            0x1004,
        ),
        aarch32_call_cfg(
            CallTarget::GuestAddr(u64::from(u32::MAX) + 1),
            arm_x(14),
            0x1004,
            OpWidth::W32,
            Vec::new(),
            0x1004,
        ),
        aarch32_call_cfg(
            CallTarget::Direct(FunctionId(9)),
            arm_x(14),
            0x1004,
            OpWidth::W32,
            Vec::new(),
            0x1004,
        ),
    ];
    for call in malformed_calls {
        assert!(!is_aarch32_aarch64_native_clobber_safe_excluding(
            &call,
            &std::collections::HashMap::new(),
        ));
    }

    let malformed_interworking_calls = [
        aarch32_call_cfg(
            CallTarget::GuestAddrInterworking {
                addr: 0x2001,
                thumb: true,
            },
            arm_x(14),
            0x1004,
            OpWidth::W32,
            Vec::new(),
            0x1004,
        ),
        aarch32_call_cfg(
            CallTarget::GuestAddrInterworking {
                addr: 0x2002,
                thumb: false,
            },
            arm_x(14),
            0x1005,
            OpWidth::W32,
            Vec::new(),
            0x1004,
        ),
        aarch32_call_cfg(
            CallTarget::GuestAddrInterworking {
                addr: 0x2000,
                thumb: true,
            },
            arm_x(14),
            0x1005,
            OpWidth::W32,
            Vec::new(),
            0x1004,
        ),
        aarch32_call_cfg(
            CallTarget::IndirectInterworking(arm_x(14)),
            arm_x(14),
            0x1004,
            OpWidth::W32,
            Vec::new(),
            0x1004,
        ),
        aarch32_call_cfg(
            CallTarget::IndirectInterworking(arm_x(15)),
            arm_x(14),
            0x1004,
            OpWidth::W32,
            Vec::new(),
            0x1004,
        ),
    ];
    for call in malformed_interworking_calls {
        assert!(!is_aarch32_aarch64_native_clobber_safe_excluding(
            &call,
            &std::collections::HashMap::new(),
        ));
    }

    let snapshot = VReg::Virtual(VirtualId(11));
    for call in [
        aarch32_blx_lr_cfg(snapshot, arm_x(13), snapshot, 0x1004, Vec::new()),
        aarch32_blx_lr_cfg(
            snapshot,
            arm_x(14),
            VReg::Virtual(VirtualId(12)),
            0x1004,
            Vec::new(),
        ),
        aarch32_blx_lr_cfg(snapshot, arm_x(14), snapshot, 0x1006, Vec::new()),
        aarch32_blx_lr_cfg(snapshot, arm_x(14), snapshot, 0x1004, vec![arm_x(0)]),
    ] {
        assert!(!is_aarch32_aarch64_native_clobber_safe_excluding(
            &call,
            &std::collections::HashMap::new(),
        ));
    }

    for indirect in [
        aarch32_indirect_cfg(arm_x(15), Vec::new()),
        aarch32_indirect_cfg(VReg::Virtual(VirtualId(9)), Vec::new()),
        aarch32_indirect_cfg(arm_x(0), vec![BlockId(1)]),
    ] {
        assert!(!is_aarch32_aarch64_native_clobber_safe_excluding(
            &indirect,
            &std::collections::HashMap::new(),
        ));
    }

    let mut missing_test = FunctionBuilder::new(FunctionId(0), 0x1000);
    let true_target = missing_test.create_block(0x2000);
    let false_target = missing_test.create_block(0x1004);
    missing_test.set_terminator(Terminator::CondBranch {
        cond,
        true_target,
        false_target,
    });
    missing_test.switch_to_block(true_target);
    missing_test.set_terminator(Terminator::Return { values: Vec::new() });
    missing_test.switch_to_block(false_target);
    missing_test.set_terminator(Terminator::Return { values: Vec::new() });
    assert!(!is_aarch32_aarch64_native_clobber_safe_excluding(
        &missing_test.finish(),
        &std::collections::HashMap::new(),
    ));

    let mut missing_target = FunctionBuilder::new(FunctionId(0), 0x1000);
    missing_target.set_terminator(Terminator::Branch {
        target: BlockId(u32::MAX),
    });
    assert!(!is_aarch32_aarch64_native_clobber_safe_excluding(
        &missing_target.finish(),
        &std::collections::HashMap::new(),
    ));

    let mut nonempty_return = FunctionBuilder::new(FunctionId(0), 0x1000);
    nonempty_return.set_terminator(Terminator::Return {
        values: vec![arm_x(0)],
    });
    assert!(!is_aarch32_aarch64_native_clobber_safe_excluding(
        &nonempty_return.finish(),
        &std::collections::HashMap::new(),
    ));

    let mut structural = aarch32_cond_cfg(cond, cond, Condition::Eq, None);
    let predecessor = structural.blocks[1].id;
    structural.blocks[0].phis.push(PhiNode {
        dst: cond,
        sources: vec![(predecessor, arm_x(0))],
    });
    assert!(!is_aarch32_aarch64_native_clobber_safe_excluding(
        &structural,
        &std::collections::HashMap::new(),
    ));
    structural.blocks[0].phis.clear();
    structural.locals.push(LocalSlot {
        id: LocalId(0),
        size: 4,
        align: 4,
    });
    assert!(!is_aarch32_aarch64_native_clobber_safe_excluding(
        &structural,
        &std::collections::HashMap::new(),
    ));
    structural.locals.clear();
    structural.blocks.push(structural.blocks[0].clone());
    assert!(!is_aarch32_aarch64_native_clobber_safe_excluding(
        &structural,
        &std::collections::HashMap::new(),
    ));

    let function = aarch32_cond_cfg(cond, cond, Condition::Eq, None);
    let nonexistent_exit = std::collections::HashMap::from([(BlockId(u32::MAX), 0x3000)]);
    assert!(!is_aarch32_aarch64_native_clobber_safe_excluding(
        &function,
        &nonexistent_exit,
    ));
    let mut missing_entry = function;
    missing_entry.entry = BlockId(u32::MAX);
    assert!(!is_aarch32_aarch64_native_clobber_safe_excluding(
        &missing_entry,
        &std::collections::HashMap::new(),
    ));
}
#[test]
fn aarch32_aarch64_gate_accepts_scalar_w32_matrix_and_rejects_hidden_state() {
    assert!(aarch32_gate(vec![
        OpKind::Mov {
            dst: arm_x(0),
            src: SrcOperand::Imm(0x1234),
            width: OpWidth::W32,
        },
        OpKind::Add {
            dst: arm_x(1),
            src1: arm_x(2),
            src2: SrcOperand::Shifted {
                reg: arm_x(3),
                shift: ShiftOp::Lsl,
                amount: 7,
            },
            width: OpWidth::W32,
            flags: FlagUpdate::All,
        },
        OpKind::Sub {
            dst: VReg::Virtual(VirtualId(0)),
            src1: arm_x(4),
            src2: SrcOperand::Reg(arm_x(5)),
            width: OpWidth::W32,
            flags: FlagUpdate::All,
        },
        OpKind::MulAdd {
            dst: arm_x(6),
            acc: arm_x(7),
            src1: arm_x(8),
            src2: arm_x(9),
            width: OpWidth::W32,
        },
        OpKind::Clz {
            dst: arm_x(10),
            src: arm_x(11),
            width: OpWidth::W32,
        },
        OpKind::Bswap {
            dst: arm_x(12),
            src: arm_x(14),
            width: OpWidth::W32,
        },
        OpKind::Neg {
            dst: arm_x(4),
            src: arm_x(5),
            width: OpWidth::W32,
            flags: FlagUpdate::All,
        },
        OpKind::SignExtend {
            dst: arm_x(0),
            src: arm_x(1),
            from_width: OpWidth::W8,
            to_width: OpWidth::W32,
        },
        OpKind::ZeroExtend {
            dst: arm_x(2),
            src: arm_x(3),
            from_width: OpWidth::W16,
            to_width: OpWidth::W32,
        },
    ]));

    for rejected in [
        OpKind::Mov {
            dst: arm_x(15),
            src: SrcOperand::Reg(arm_x(0)),
            width: OpWidth::W32,
        },
        OpKind::Mov {
            dst: arm_x(0),
            src: SrcOperand::Reg(arm_x(15)),
            width: OpWidth::W32,
        },
        OpKind::Mov {
            dst: arm_x(0),
            src: SrcOperand::Reg(arm_x(1)),
            width: OpWidth::W64,
        },
        OpKind::Mov {
            dst: VReg::Virtual(VirtualId(0)),
            src: SrcOperand::Reg(arm_x(1)),
            width: OpWidth::W32,
        },
        OpKind::And {
            dst: arm_x(0),
            src1: arm_x(1),
            src2: SrcOperand::Reg(arm_x(2)),
            width: OpWidth::W32,
            flags: FlagUpdate::All,
        },
        OpKind::Mov {
            dst: arm_x(0),
            src: SrcOperand::Shifted {
                reg: arm_x(1),
                shift: ShiftOp::Rrx,
                amount: 0,
            },
            width: OpWidth::W32,
        },
        OpKind::SignExtend {
            dst: arm_x(0),
            src: arm_x(1),
            from_width: OpWidth::W32,
            to_width: OpWidth::W64,
        },
        OpKind::Adc {
            dst: arm_x(0),
            src1: arm_x(1),
            src2: SrcOperand::Shifted {
                reg: arm_x(2),
                shift: ShiftOp::Lsl,
                amount: 0,
            },
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
    ] {
        assert!(!aarch32_gate(vec![rejected.clone()]), "{rejected:?}");
    }
}
#[test]
fn aarch32_aarch64_gate_admits_selective_nzcv_and_independent_register_shifts() {
    let nz = FlagUpdate::Specific(FlagSet::SF.union(FlagSet::ZF));
    let nzc = FlagUpdate::Specific(FlagSet::SF.union(FlagSet::ZF).union(FlagSet::CF));
    let mut accepted = Vec::new();
    for kind in 0..4 {
        accepted.push(match kind {
            0 => OpKind::And {
                dst: arm_x(0),
                src1: arm_x(0),
                src2: SrcOperand::Imm(-1),
                width: OpWidth::W32,
                flags: nz,
            },
            1 => OpKind::Or {
                dst: arm_x(1),
                src1: arm_x(1),
                src2: SrcOperand::Reg(arm_x(2)),
                width: OpWidth::W32,
                flags: nz,
            },
            2 => OpKind::Xor {
                dst: VReg::Virtual(VirtualId(9)),
                src1: arm_x(3),
                src2: SrcOperand::Reg(arm_x(4)),
                width: OpWidth::W32,
                flags: nz,
            },
            _ => OpKind::AndNot {
                dst: arm_x(5),
                src1: VReg::Imm(-1),
                src2: SrcOperand::Reg(arm_x(6)),
                width: OpWidth::W32,
                flags: nz,
            },
        });
    }
    accepted.extend([
        OpKind::MulU {
            dst_lo: arm_x(7),
            dst_hi: None,
            src1: arm_x(7),
            src2: SrcOperand::Reg(arm_x(0)),
            width: OpWidth::W32,
            flags: nz,
        },
        OpKind::Shl {
            dst: arm_x(8),
            src: arm_x(9),
            amount: SrcOperand::Imm(1),
            width: OpWidth::W32,
            flags: nzc,
        },
        OpKind::Shr {
            dst: arm_x(10),
            src: arm_x(11),
            amount: SrcOperand::Imm(32),
            width: OpWidth::W32,
            flags: nzc,
        },
        OpKind::Sar {
            dst: arm_x(12),
            src: arm_x(13),
            amount: SrcOperand::Imm(32),
            width: OpWidth::W32,
            flags: nzc,
        },
    ]);
    for shift in [ShiftOp::Lsl, ShiftOp::Lsr, ShiftOp::Asr, ShiftOp::Ror] {
        accepted.push(OpKind::ArmRegShift {
            dst: arm_x(0),
            src: arm_x(0),
            amount: if shift == ShiftOp::Ror {
                SrcOperand::Imm(0x120)
            } else {
                SrcOperand::Reg(arm_x(1))
            },
            shift,
            width: OpWidth::W32,
            flags: nzc,
        });
    }
    accepted.push(OpKind::ArmRegShift {
        dst: arm_x(2),
        src: arm_x(4),
        amount: SrcOperand::Reg(arm_x(3)),
        shift: ShiftOp::Lsl,
        width: OpWidth::W32,
        flags: FlagUpdate::None,
    });
    assert!(aarch32_gate(accepted));

    let bad_nz = FlagUpdate::Specific(FlagSet::ZF);
    for rejected in [
        OpKind::And {
            dst: arm_x(0),
            src1: VReg::Imm(-1),
            src2: SrcOperand::Reg(arm_x(2)),
            width: OpWidth::W32,
            flags: nz,
        },
        OpKind::And {
            dst: arm_x(0),
            src1: arm_x(1),
            src2: SrcOperand::Reg(arm_x(2)),
            width: OpWidth::W32,
            flags: bad_nz,
        },
        OpKind::MulU {
            dst_lo: arm_x(0),
            dst_hi: Some(arm_x(1)),
            src1: arm_x(2),
            src2: SrcOperand::Reg(arm_x(3)),
            width: OpWidth::W32,
            flags: nz,
        },
        OpKind::Shl {
            dst: arm_x(0),
            src: arm_x(1),
            amount: SrcOperand::Imm(0),
            width: OpWidth::W32,
            flags: nzc,
        },
        OpKind::Shr {
            dst: arm_x(0),
            src: arm_x(1),
            amount: SrcOperand::Imm(33),
            width: OpWidth::W32,
            flags: nzc,
        },
        OpKind::Ror {
            dst: arm_x(0),
            src: arm_x(1),
            amount: SrcOperand::Imm(1),
            width: OpWidth::W32,
            flags: nzc,
        },
        OpKind::ArmRegShift {
            dst: arm_x(0),
            src: arm_x(0),
            amount: SrcOperand::Reg(arm_x(2)),
            shift: ShiftOp::Rrx,
            width: OpWidth::W32,
            flags: nzc,
        },
        OpKind::ArmRegShift {
            dst: arm_x(0),
            src: arm_x(15),
            amount: SrcOperand::Reg(arm_x(2)),
            shift: ShiftOp::Lsl,
            width: OpWidth::W32,
            flags: nzc,
        },
        OpKind::ArmRegShift {
            dst: arm_x(15),
            src: arm_x(0),
            amount: SrcOperand::Reg(arm_x(2)),
            shift: ShiftOp::Lsl,
            width: OpWidth::W32,
            flags: nzc,
        },
        OpKind::ArmRegShift {
            dst: arm_x(0),
            src: arm_x(0),
            amount: SrcOperand::Shifted {
                reg: arm_x(2),
                shift: ShiftOp::Lsl,
                amount: 1,
            },
            shift: ShiftOp::Lsr,
            width: OpWidth::W32,
            flags: nzc,
        },
        OpKind::ArmRegShift {
            dst: arm_x(0),
            src: arm_x(0),
            amount: SrcOperand::Reg(arm_x(15)),
            shift: ShiftOp::Asr,
            width: OpWidth::W32,
            flags: nzc,
        },
        OpKind::ArmRegShift {
            dst: arm_x(0),
            src: arm_x(0),
            amount: SrcOperand::Imm(1),
            shift: ShiftOp::Ror,
            width: OpWidth::W64,
            flags: nzc,
        },
        OpKind::ArmRegShift {
            dst: arm_x(0),
            src: arm_x(0),
            amount: SrcOperand::Imm(1),
            shift: ShiftOp::Ror,
            width: OpWidth::W32,
            flags: bad_nz,
        },
    ] {
        assert!(!aarch32_gate(vec![rejected.clone()]), "{rejected:?}");
    }
}
#[test]
fn aarch32_aarch64_gate_exactly_validates_data_processing_register_shifts() {
    let nzc = FlagSet::SF.union(FlagSet::ZF).union(FlagSet::CF);
    let mut accepted = Vec::new();
    for opcode in 0_u8..16 {
        let kind = ArmDpRegShiftKind::from_opcode(opcode).unwrap();
        for shift in [ShiftOp::Lsl, ShiftOp::Lsr, ShiftOp::Asr, ShiftOp::Ror] {
            for flags in [
                FlagUpdate::None,
                FlagUpdate::Specific(if kind.is_logical() {
                    nzc
                } else {
                    FlagSet::NZCV
                }),
            ] {
                accepted.push(OpKind::ArmDpRegShift {
                    kind,
                    dst: kind.writes_result().then(|| arm_x(14)),
                    rn: kind.uses_rn().then(|| arm_x(13)),
                    rm: arm_x(12),
                    rs: arm_x(11),
                    shift,
                    flags,
                });
            }
        }
    }
    assert!(aarch32_gate(accepted));

    let valid_add = || OpKind::ArmDpRegShift {
        kind: ArmDpRegShiftKind::Add,
        dst: Some(arm_x(0)),
        rn: Some(arm_x(1)),
        rm: arm_x(2),
        rs: arm_x(3),
        shift: ShiftOp::Lsl,
        flags: FlagUpdate::Specific(FlagSet::NZCV),
    };
    let mut rejected = Vec::new();
    for mutate in 0..10 {
        let mut op = valid_add();
        let OpKind::ArmDpRegShift {
            dst,
            rn,
            rm,
            rs,
            shift,
            flags,
            ..
        } = &mut op
        else {
            unreachable!()
        };
        match mutate {
            0 => *dst = None,
            1 => *dst = Some(arm_x(15)),
            2 => *rn = None,
            3 => *rn = Some(arm_x(15)),
            4 => *rm = arm_x(15),
            5 => *rs = arm_x(15),
            6 => *shift = ShiftOp::Rrx,
            7 => *flags = FlagUpdate::Specific(nzc),
            8 => *flags = FlagUpdate::All,
            9 => *dst = Some(VReg::virt(0)),
            _ => unreachable!(),
        }
        rejected.push(op);
    }
    rejected.extend([
        OpKind::ArmDpRegShift {
            kind: ArmDpRegShiftKind::Tst,
            dst: Some(arm_x(15)),
            rn: Some(arm_x(1)),
            rm: arm_x(2),
            rs: arm_x(3),
            shift: ShiftOp::Lsr,
            flags: FlagUpdate::Specific(nzc),
        },
        OpKind::ArmDpRegShift {
            kind: ArmDpRegShiftKind::Mov,
            dst: Some(arm_x(0)),
            rn: Some(arm_x(15)),
            rm: arm_x(2),
            rs: arm_x(3),
            shift: ShiftOp::Ror,
            flags: FlagUpdate::Specific(nzc),
        },
        OpKind::ArmDpRegShift {
            kind: ArmDpRegShiftKind::And,
            dst: Some(arm_x(0)),
            rn: Some(arm_x(1)),
            rm: arm_x(2),
            rs: arm_x(3),
            shift: ShiftOp::Asr,
            flags: FlagUpdate::Specific(FlagSet::NZCV),
        },
    ]);
    for op in rejected {
        assert!(!aarch32_gate(vec![op.clone()]), "{op:?}");
    }
}
#[test]
fn aarch32_aarch64_gate_admits_only_bounded_scalar_memory_shapes() {
    let valid = vec![
        OpKind::Load {
            dst: arm_x(12),
            addr: Address::Absolute(0xffff_fffc),
            width: MemWidth::B2,
            sign: SignExtend::Sign,
        },
        OpKind::Load {
            dst: arm_x(0),
            addr: Address::BaseOffset {
                base: arm_x(13),
                offset: -4,
                disp_size: DispSize::Auto,
            },
            width: MemWidth::B4,
            sign: SignExtend::Zero,
        },
        OpKind::Load {
            dst: arm_x(1),
            addr: Address::BaseIndexScale {
                base: Some(arm_x(2)),
                index: arm_x(3),
                scale: 4,
                disp: 0,
                disp_size: DispSize::Auto,
            },
            width: MemWidth::B1,
            sign: SignExtend::Sign,
        },
        OpKind::Store {
            src: arm_x(14),
            addr: Address::Direct(arm_x(4)),
            width: MemWidth::B2,
        },
        OpKind::LoadPair {
            dst1: arm_x(5),
            dst2: arm_x(6),
            addr: Address::BaseOffset {
                base: arm_x(7),
                offset: -8,
                disp_size: DispSize::Auto,
            },
            width: MemWidth::B4,
        },
        OpKind::StorePair {
            src1: arm_x(8),
            src2: arm_x(9),
            addr: Address::Direct(arm_x(10)),
            width: MemWidth::B4,
        },
    ];
    assert!(!aarch32_gate_with_mem(valid.clone(), false));
    assert!(aarch32_gate_with_mem(valid, true));

    for invalid in [
        OpKind::Load {
            dst: arm_x(15),
            addr: Address::Direct(arm_x(1)),
            width: MemWidth::B4,
            sign: SignExtend::Zero,
        },
        OpKind::Load {
            dst: arm_x(0),
            addr: Address::Direct(arm_x(15)),
            width: MemWidth::B1,
            sign: SignExtend::Zero,
        },
        OpKind::Load {
            dst: arm_x(0),
            addr: Address::Direct(arm_x(1)),
            width: MemWidth::B4,
            sign: SignExtend::Sign,
        },
        OpKind::Load {
            dst: arm_x(0),
            addr: Address::Absolute(u64::from(u32::MAX) + 1),
            width: MemWidth::B4,
            sign: SignExtend::Zero,
        },
        OpKind::Store {
            src: arm_x(0),
            addr: Address::Absolute(0x1000),
            width: MemWidth::B4,
        },
        OpKind::Store {
            src: arm_x(0),
            addr: Address::Direct(arm_x(1)),
            width: MemWidth::B8,
        },
        OpKind::LoadPair {
            dst1: arm_x(0),
            dst2: arm_x(0),
            addr: Address::Direct(arm_x(1)),
            width: MemWidth::B4,
        },
        OpKind::LoadPair {
            dst1: arm_x(0),
            dst2: arm_x(15),
            addr: Address::Direct(arm_x(1)),
            width: MemWidth::B4,
        },
        OpKind::StorePair {
            src1: arm_x(0),
            src2: arm_x(1),
            addr: Address::Direct(arm_x(2)),
            width: MemWidth::B8,
        },
    ] {
        assert!(
            !aarch32_gate_with_mem(vec![invalid.clone()], true),
            "{invalid:?}"
        );
    }
}
#[test]
fn x86_aarch64_nzcv_bridge_is_exhaustive_and_preserves_unrepresented_rflags() {
    const CF: u64 = 1 << 0;
    const PF: u64 = 1 << 2;
    const AF: u64 = 1 << 4;
    const ZF: u64 = 1 << 6;
    const SF: u64 = 1 << 7;
    const IF: u64 = 1 << 9;
    const OF: u64 = 1 << 11;
    const STATUS4: u64 = CF | ZF | SF | OF;
    let preserved = PF | AF | IF | (1 << 1) | (1 << 21);

    for bits in 0_u64..16 {
        let rflags = preserved
            | ((bits & 0b0001 != 0) as u64 * CF)
            | ((bits & 0b0010 != 0) as u64 * ZF)
            | ((bits & 0b0100 != 0) as u64 * SF)
            | ((bits & 0b1000 != 0) as u64 * OF);
        let nzcv = x86_rflags_to_aarch64_nzcv(rflags);
        assert_eq!(
            (nzcv >> 28) & 0xf,
            (bits & 0b0100) << 1
                | (bits & 0b0010) << 1
                | (bits & 0b0001) << 1
                | (bits & 0b1000) >> 3
        );

        let prior = preserved | STATUS4;
        let merged = merge_aarch64_nzcv_into_x86_rflags(prior, nzcv | u64::MAX.wrapping_shl(32));
        assert_eq!(
            merged & STATUS4,
            rflags & STATUS4,
            "status pattern {bits:#06b}"
        );
        assert_eq!(
            merged & !STATUS4,
            prior & !STATUS4,
            "preserved pattern {bits:#06b}"
        );
    }
}
#[test]
fn x86_aarch64_gate_accepts_representable_bls_adx_bit_tests_and_nf_alu() {
    let bls_flags = FlagSet::CF
        .union(FlagSet::ZF)
        .union(FlagSet::SF)
        .union(FlagSet::OF);
    assert!(x86_aarch64_gate(vec![
        OpKind::X86Bls {
            dst: x86(X86Reg::Rax),
            src: x86(X86Reg::Rcx),
            width: OpWidth::W64,
            kind: X86BlsKind::Blsi,
            flags: FlagUpdate::Specific(bls_flags),
        },
        OpKind::X86Adx {
            dst: x86(X86Reg::Rdx),
            src1: x86(X86Reg::Rdx),
            src2: x86(X86Reg::Rbx),
            width: OpWidth::W64,
            kind: X86AdxKind::Adcx,
            flags: FlagUpdate::Specific(FlagSet::CF),
        },
        OpKind::Add {
            dst: x86(X86Reg::Rsp),
            src1: x86(X86Reg::Rsp),
            src2: SrcOperand::Imm(16),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        },
        OpKind::Add {
            dst: x86(X86Reg::Rax),
            src1: x86(X86Reg::Rax),
            src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
            width: OpWidth::W16,
            flags: FlagUpdate::None,
        },
        OpKind::Sub {
            dst: x86(X86Reg::Rdx),
            src1: x86(X86Reg::Rdx),
            src2: SrcOperand::Reg(x86(X86Reg::Rbx)),
            width: OpWidth::W8,
            flags: FlagUpdate::None,
        },
        OpKind::Adc {
            dst: x86(X86Reg::R8),
            src1: x86(X86Reg::R8),
            src2: SrcOperand::Reg(x86(X86Reg::R9)),
            width: OpWidth::W16,
            flags: FlagUpdate::None,
        },
        OpKind::Sbb {
            dst: x86(X86Reg::R9),
            src1: x86(X86Reg::R9),
            src2: SrcOperand::Reg(x86(X86Reg::R10)),
            width: OpWidth::W8,
            flags: FlagUpdate::None,
        },
        OpKind::Neg {
            dst: x86(X86Reg::R10),
            src: x86(X86Reg::R10),
            width: OpWidth::W8,
            flags: FlagUpdate::None,
        },
        OpKind::Inc {
            dst: x86(X86Reg::R11),
            src: x86(X86Reg::R11),
            width: OpWidth::W16,
            flags: FlagUpdate::None,
        },
        OpKind::Dec {
            dst: x86(X86Reg::R12),
            src: x86(X86Reg::R12),
            width: OpWidth::W8,
            flags: FlagUpdate::None,
        },
        OpKind::And {
            dst: x86(X86Reg::R13),
            src1: x86(X86Reg::R13),
            src2: SrcOperand::Reg(x86(X86Reg::R14)),
            width: OpWidth::W16,
            flags: FlagUpdate::None,
        },
        OpKind::Or {
            dst: x86(X86Reg::R14),
            src1: x86(X86Reg::R14),
            src2: SrcOperand::Reg(x86(X86Reg::R15)),
            width: OpWidth::W8,
            flags: FlagUpdate::None,
        },
        OpKind::Xor {
            dst: x86(X86Reg::R15),
            src1: x86(X86Reg::R15),
            src2: SrcOperand::Reg(x86(X86Reg::Rax)),
            width: OpWidth::W16,
            flags: FlagUpdate::None,
        },
        OpKind::Mov {
            dst: x86(X86Reg::Rax),
            src: SrcOperand::Reg(x86(X86Reg::Rcx)),
            width: OpWidth::W16,
        },
        OpKind::SetCC {
            dst: x86(X86Reg::Rdx),
            cond: crate::smir::ir::types::Condition::Eq,
            width: OpWidth::W8,
        },
        OpKind::CMove {
            dst: x86(X86Reg::Rsi),
            src: x86(X86Reg::Rdi),
            cond: crate::smir::ir::types::Condition::Eq,
            width: OpWidth::W16,
        },
        OpKind::Not {
            dst: x86(X86Reg::Rbx),
            src: x86(X86Reg::Rbx),
            width: OpWidth::W8,
        },
        OpKind::Xchg {
            reg1: x86(X86Reg::Rsi),
            reg2: x86(X86Reg::Rdi),
            width: OpWidth::W8,
        },
        OpKind::Xchg {
            reg1: x86(X86Reg::Rsi),
            reg2: x86(X86Reg::Rdi),
            width: OpWidth::W16,
        },
        OpKind::Bt {
            src: x86(X86Reg::R8),
            index: SrcOperand::Reg(x86(X86Reg::R9)),
            width: OpWidth::W16,
        },
        OpKind::Bts {
            dst: x86(X86Reg::R10),
            src: x86(X86Reg::R10),
            index: SrcOperand::Imm(15),
            width: OpWidth::W16,
        },
        OpKind::Btc {
            dst: x86(X86Reg::R11),
            src: x86(X86Reg::R11),
            index: SrcOperand::Imm64(63),
            width: OpWidth::W64,
        },
        OpKind::SetCF { value: true },
        OpKind::CmcCF,
    ]));
}
#[test]
fn x86_aarch64_gate_accepts_every_identity_mapped_low_byte_xchg_pair() {
    let registers = [
        X86Reg::Rax,
        X86Reg::Rcx,
        X86Reg::Rdx,
        X86Reg::Rbx,
        X86Reg::Rsi,
        X86Reg::Rdi,
        X86Reg::R8,
        X86Reg::R9,
        X86Reg::R10,
        X86Reg::R11,
        X86Reg::R12,
        X86Reg::R13,
        X86Reg::R14,
        X86Reg::R15,
    ];
    let mut pairs = 0usize;
    for reg1 in registers {
        for reg2 in registers {
            assert!(x86_aarch64_gate(vec![OpKind::Xchg {
                reg1: x86(reg1),
                reg2: x86(reg2),
                width: OpWidth::W8,
            }]));
            pairs += 1;
        }
    }
    assert_eq!(pairs, 14 * 14);

    // Guest RSP/RBP and APX EGPRs have no AArch64 runtime identity mapping.
    for reg in [X86Reg::Rsp, X86Reg::Rbp, X86Reg::R16, X86Reg::R31] {
        assert!(!x86_aarch64_gate(vec![OpKind::Xchg {
            reg1: x86(X86Reg::Rax),
            reg2: x86(reg),
            width: OpWidth::W8,
        }]));
    }
}
#[test]
fn x86_aarch64_gate_accepts_no_flag_sbb_complete_width_matrix() {
    for width in [OpWidth::W8, OpWidth::W16, OpWidth::W32, OpWidth::W64] {
        for src2 in [SrcOperand::Reg(x86(X86Reg::Rcx)), SrcOperand::Imm64(-1)] {
            assert!(
                x86_aarch64_gate(vec![OpKind::Sbb {
                    dst: x86(X86Reg::Rax),
                    src1: x86(X86Reg::Rax),
                    src2,
                    width,
                    flags: FlagUpdate::None,
                }]),
                "no-flag SBB {width:?} must be eligible"
            );
        }
    }
}
#[test]
fn x86_aarch64_gate_accepts_subword_shift_rotate_matrix() {
    for width in [OpWidth::W8, OpWidth::W16] {
        for amount in [SrcOperand::Imm(3), SrcOperand::Reg(x86(X86Reg::Rcx))] {
            for op in [
                OpKind::Shl {
                    dst: x86(X86Reg::Rax),
                    src: x86(X86Reg::Rax),
                    amount: amount.clone(),
                    width,
                    flags: FlagUpdate::None,
                },
                OpKind::Shr {
                    dst: x86(X86Reg::Rax),
                    src: x86(X86Reg::Rax),
                    amount: amount.clone(),
                    width,
                    flags: FlagUpdate::None,
                },
                OpKind::Sar {
                    dst: x86(X86Reg::Rax),
                    src: x86(X86Reg::Rax),
                    amount: amount.clone(),
                    width,
                    flags: FlagUpdate::None,
                },
                OpKind::Rol {
                    dst: x86(X86Reg::Rax),
                    src: x86(X86Reg::Rax),
                    amount: amount.clone(),
                    width,
                    flags: FlagUpdate::None,
                },
                OpKind::Ror {
                    dst: x86(X86Reg::Rax),
                    src: x86(X86Reg::Rax),
                    amount: amount.clone(),
                    width,
                    flags: FlagUpdate::None,
                },
            ] {
                assert!(
                    x86_aarch64_gate(vec![op]),
                    "subword shift/rotate {width:?} amount {amount:?} must be eligible"
                );
            }
        }
    }

    let rotate_flags = FlagUpdate::Specific(FlagSet::CF.union(FlagSet::OF));
    for width in [OpWidth::W8, OpWidth::W16] {
        for op in [
            OpKind::Rol {
                dst: x86(X86Reg::Rax),
                src: x86(X86Reg::Rax),
                amount: SrcOperand::Imm(1),
                width,
                flags: rotate_flags,
            },
            OpKind::Ror {
                dst: x86(X86Reg::Rax),
                src: x86(X86Reg::Rax),
                amount: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width,
                flags: rotate_flags,
            },
        ] {
            assert!(
                x86_aarch64_gate(vec![op]),
                "flag-setting subword rotate {width:?} must be eligible"
            );
        }
    }
}
#[test]
fn x86_aarch64_gate_accepts_subword_carry_rotate_partial_writes() {
    let flags = FlagUpdate::Specific(FlagSet::CF.union(FlagSet::OF));
    for width in [OpWidth::W8, OpWidth::W16] {
        for right in [false, true] {
            let op = if right {
                OpKind::Rcr {
                    dst: x86(X86Reg::Rax),
                    src: x86(X86Reg::Rax),
                    amount: SrcOperand::Imm(1),
                    width,
                    flags,
                }
            } else {
                OpKind::Rcl {
                    dst: x86(X86Reg::Rax),
                    src: x86(X86Reg::Rax),
                    amount: SrcOperand::Imm(1),
                    width,
                    flags,
                }
            };
            assert!(
                x86_aarch64_gate(vec![op]),
                "{} {width:?} must be eligible",
                if right { "RCR" } else { "RCL" }
            );
        }
    }
}
#[test]
fn x86_aarch64_gate_accepts_apx_ndd_double_shift_width_direction_and_count_matrix() {
    for width in [OpWidth::W16, OpWidth::W32, OpWidth::W64] {
        for left in [false, true] {
            for amount in [SrcOperand::Imm(4), SrcOperand::Reg(x86(X86Reg::Rcx))] {
                assert!(
                    x86_aarch64_gate(vec![OpKind::X86NddDoubleShift {
                        dst: x86(X86Reg::Rbx),
                        base: x86(X86Reg::Rax),
                        fill: x86(X86Reg::Rbx),
                        amount: amount.clone(),
                        width,
                        left,
                        flags: FlagUpdate::None,
                    }]),
                    "APX NF NDD double shift {width:?} left={left} amount={amount:?}"
                );
            }
        }
    }

    assert!(!x86_aarch64_scalar_shape_valid(
        &OpKind::X86NddDoubleShift {
            dst: x86(X86Reg::Rbx),
            base: x86(X86Reg::Rax),
            fill: x86(X86Reg::Rdx),
            amount: SrcOperand::Reg(x86(X86Reg::Rcx)),
            width: OpWidth::W16,
            left: true,
            flags: FlagUpdate::All,
        }
    ));
    for (amount, expected) in [(16, true), (17, false), (31, false), (32, true)] {
        assert_eq!(
            x86_aarch64_scalar_shape_valid(&OpKind::X86NddDoubleShift {
                dst: x86(X86Reg::Rbx),
                base: x86(X86Reg::Rax),
                fill: x86(X86Reg::Rdx),
                amount: SrcOperand::Imm(amount),
                width: OpWidth::W16,
                left: false,
                flags: FlagUpdate::All,
            }),
            expected,
            "W16 flag-setting APX NDD immediate count {amount}"
        );
    }
}
#[test]
fn x86_aarch64_gate_accepts_w16_destructive_double_shift_partial_writes() {
    for left in [false, true] {
        for amount in [SrcOperand::Imm(4), SrcOperand::Reg(x86(X86Reg::Rcx))] {
            let op = if left {
                OpKind::Shld {
                    dst: x86(X86Reg::Rax),
                    src: x86(X86Reg::Rbx),
                    amount,
                    width: OpWidth::W16,
                    flags: FlagUpdate::None,
                }
            } else {
                OpKind::Shrd {
                    dst: x86(X86Reg::Rax),
                    src: x86(X86Reg::Rbx),
                    amount,
                    width: OpWidth::W16,
                    flags: FlagUpdate::None,
                }
            };
            assert!(
                x86_aarch64_gate(vec![op]),
                "APX NF destructive W16 double shift left={left}"
            );
        }
    }

    for (amount, expected) in [(16, true), (17, false), (31, false), (32, true)] {
        assert_eq!(
            x86_aarch64_scalar_shape_valid(&OpKind::Shld {
                dst: x86(X86Reg::Rax),
                src: x86(X86Reg::Rbx),
                amount: SrcOperand::Imm(amount),
                width: OpWidth::W16,
                flags: FlagUpdate::All,
            }),
            expected,
            "W16 flag-setting SHLD immediate count {amount}"
        );
    }
    assert!(!x86_aarch64_scalar_shape_valid(&OpKind::Shrd {
        dst: x86(X86Reg::Rax),
        src: x86(X86Reg::Rbx),
        amount: SrcOperand::Reg(x86(X86Reg::Rcx)),
        width: OpWidth::W16,
        flags: FlagUpdate::All,
    }));
}
#[test]
fn x86_aarch64_gate_accepts_w16_scan_and_unary_count_partial_writes() {
    let rax = x86(X86Reg::Rax);
    let rbx = x86(X86Reg::Rbx);
    let zf_only = FlagUpdate::Specific(FlagSet::ZF);
    for op in [
        OpKind::Bsf {
            dst: rax,
            src: rbx,
            width: OpWidth::W16,
            flags: zf_only,
        },
        OpKind::Bsr {
            dst: rax,
            src: rax,
            width: OpWidth::W16,
            flags: zf_only,
        },
        OpKind::Clz {
            dst: rax,
            src: rbx,
            width: OpWidth::W16,
        },
        OpKind::Ctz {
            dst: rax,
            src: rax,
            width: OpWidth::W16,
        },
        OpKind::Popcnt {
            dst: rax,
            src: rbx,
            width: OpWidth::W16,
        },
    ] {
        assert!(x86_aarch64_gate(vec![op.clone()]), "supported {op:?}");
    }

    for op in [
        OpKind::Bsf {
            dst: rax,
            src: rbx,
            width: OpWidth::W16,
            flags: FlagUpdate::All,
        },
        OpKind::Bsr {
            dst: rax,
            src: rbx,
            width: OpWidth::W8,
            flags: zf_only,
        },
        OpKind::Popcnt {
            dst: rax,
            src: rbx,
            width: OpWidth::W8,
        },
    ] {
        assert!(!x86_aarch64_gate(vec![op.clone()]), "unsupported {op:?}");
    }
}
#[test]
fn x86_aarch64_gate_accepts_crc32c_widths_and_rejects_malformed_shapes() {
    let rax = x86(X86Reg::Rax);
    let rbx = x86(X86Reg::Rbx);
    for width in [OpWidth::W8, OpWidth::W16, OpWidth::W32, OpWidth::W64] {
        assert!(x86_aarch64_gate(vec![OpKind::Crc32C {
            dst: rax,
            crc: rax,
            data: rbx,
            data_width: width,
        }]));
        assert!(x86_aarch64_gate(vec![OpKind::Crc32C {
            dst: rax,
            crc: rax,
            data: rax,
            data_width: width,
        }]));
    }

    for op in [
        OpKind::Crc32C {
            dst: rax,
            crc: rbx,
            data: rbx,
            data_width: OpWidth::W32,
        },
        OpKind::Crc32C {
            dst: rax,
            crc: rax,
            data: VReg::virt(0),
            data_width: OpWidth::W8,
        },
        OpKind::Crc32C {
            dst: rax,
            crc: rax,
            data: rbx,
            data_width: OpWidth::W128,
        },
    ] {
        assert!(!x86_aarch64_gate(vec![op.clone()]), "malformed {op:?}");
    }
}
#[test]
fn x86_aarch64_gate_accepts_x86_count_full_and_w16_contracts() {
    let rax = x86(X86Reg::Rax);
    let rbx = x86(X86Reg::Rbx);
    for kind in [
        X86CountKind::Popcnt,
        X86CountKind::Tzcnt,
        X86CountKind::Lzcnt,
    ] {
        for width in [OpWidth::W16, OpWidth::W32, OpWidth::W64] {
            assert!(
                x86_aarch64_gate(vec![OpKind::X86Count {
                    dst: rax,
                    src: rbx,
                    width,
                    kind,
                    flags: FlagUpdate::None,
                }]),
                "APX NF {kind:?} {width:?}"
            );
        }
    }

    let count_flags = FlagUpdate::Specific(FlagSet::CF.union(FlagSet::ZF));
    for kind in [X86CountKind::Tzcnt, X86CountKind::Lzcnt] {
        assert!(x86_aarch64_gate(vec![OpKind::X86Count {
            dst: rax,
            src: rbx,
            width: OpWidth::W16,
            kind,
            flags: count_flags,
        }]));
    }

    let popcnt_all = OpKind::X86Count {
        dst: rax,
        src: rbx,
        width: OpWidth::W16,
        kind: X86CountKind::Popcnt,
        flags: FlagUpdate::All,
    };
    assert!(x86_aarch64_scalar_shape_valid(&popcnt_all));
    assert!(
        !x86_aarch64_gate(vec![popcnt_all]),
        "terminal POPCNT has live PF/AF outputs unavailable in NZCV"
    );

    for op in [
        OpKind::X86Count {
            dst: rax,
            src: rbx,
            width: OpWidth::W8,
            kind: X86CountKind::Popcnt,
            flags: FlagUpdate::None,
        },
        OpKind::X86Count {
            dst: rax,
            src: rbx,
            width: OpWidth::W64,
            kind: X86CountKind::Tzcnt,
            flags: FlagUpdate::All,
        },
    ] {
        assert!(!x86_aarch64_gate(vec![op.clone()]), "unsupported {op:?}");
    }
}
#[test]
fn x86_aarch64_gate_accepts_only_architectural_w16_extend_partial_writes() {
    let rax = x86(X86Reg::Rax);
    let rbx = x86(X86Reg::Rbx);
    for op in [
        OpKind::ZeroExtend {
            dst: rax,
            src: rbx,
            from_width: OpWidth::W8,
            to_width: OpWidth::W16,
        },
        OpKind::SignExtend {
            dst: rax,
            src: rax,
            from_width: OpWidth::W8,
            to_width: OpWidth::W16,
        },
    ] {
        assert!(
            x86_aarch64_gate(vec![op.clone()]),
            "architectural W16 extension must JIT: {op:?}"
        );
    }

    for op in [
        OpKind::ZeroExtend {
            dst: rax,
            src: rbx,
            from_width: OpWidth::W16,
            to_width: OpWidth::W16,
        },
        OpKind::SignExtend {
            dst: rax,
            src: rbx,
            from_width: OpWidth::W8,
            to_width: OpWidth::W8,
        },
        OpKind::ZeroExtend {
            dst: x86(X86Reg::R16),
            src: rbx,
            from_width: OpWidth::W8,
            to_width: OpWidth::W16,
        },
        OpKind::SignExtend {
            dst: rax,
            src: VReg::Virtual(VirtualId(9)),
            from_width: OpWidth::W8,
            to_width: OpWidth::W16,
        },
    ] {
        assert!(
            !x86_aarch64_gate(vec![op.clone()]),
            "non-architectural W16 extension must deopt: {op:?}"
        );
    }
}
#[test]
fn x86_aarch64_gate_rejects_unrepresentable_flags_registers_and_shapes() {
    let full_flag_add = OpKind::Add {
        dst: x86(X86Reg::Rax),
        src1: x86(X86Reg::Rax),
        src2: SrcOperand::Imm(1),
        width: OpWidth::W64,
        flags: FlagUpdate::All,
    };
    assert!(!x86_aarch64_gate(vec![full_flag_add]));

    // Flag-setting SBB defines PF/AF, which cannot cross the NZCV bridge.
    assert!(!x86_aarch64_gate(vec![OpKind::Sbb {
        dst: x86(X86Reg::Rax),
        src1: x86(X86Reg::Rax),
        src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
        width: OpWidth::W64,
        flags: FlagUpdate::All,
    }]));

    assert!(!x86_aarch64_gate(vec![OpKind::SetCC {
        dst: x86(X86Reg::Rax),
        cond: crate::smir::ir::types::Condition::Parity,
        width: OpWidth::W8,
    }]));
    assert!(!x86_aarch64_gate(vec![OpKind::SetCC {
        dst: x86(X86Reg::Rax),
        cond: crate::smir::ir::types::Condition::Ult,
        width: OpWidth::W8,
    }]));

    assert!(!x86_aarch64_gate(vec![OpKind::Mov {
        dst: x86(X86Reg::R18),
        src: SrcOperand::Reg(x86(X86Reg::Rax)),
        width: OpWidth::W64,
    }]));
    assert!(!x86_aarch64_gate(vec![OpKind::Mov {
        dst: VReg::virt(0),
        src: SrcOperand::Reg(x86(X86Reg::Rax)),
        width: OpWidth::W64,
    }]));

    // Other unmerged subword destination families remain fail-closed.
    assert!(!x86_aarch64_gate(vec![OpKind::AndNot {
        dst: x86(X86Reg::Rax),
        src1: x86(X86Reg::Rax),
        src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
        width: OpWidth::W16,
        flags: FlagUpdate::None,
    }]));
    assert!(!x86_aarch64_gate(vec![OpKind::SetCC {
        dst: x86(X86Reg::Rax),
        cond: crate::smir::ir::types::Condition::Eq,
        width: OpWidth::W16,
    }]));
    assert!(!x86_aarch64_gate(vec![OpKind::Bts {
        dst: x86(X86Reg::Rax),
        src: x86(X86Reg::Rax),
        index: SrcOperand::Imm(7),
        width: OpWidth::W8,
    }]));
    assert!(!x86_aarch64_gate(vec![OpKind::Btr {
        dst: x86(X86Reg::Rax),
        src: x86(X86Reg::Rcx),
        index: SrcOperand::Imm(0),
        width: OpWidth::W64,
    }]));
    assert!(!x86_aarch64_gate(vec![OpKind::Bt {
        src: x86(X86Reg::Rax),
        index: SrcOperand::Reg(VReg::virt(2)),
        width: OpWidth::W64,
    }]));
}
#[test]
fn x86_aarch64_gate_validates_terminator_register_operands() {
    let mut cond = FunctionBuilder::new(FunctionId(0), 0x1000);
    let cond_true = cond.create_block(0x1010);
    let cond_false = cond.create_block(0x1020);
    cond.set_terminator(Terminator::CondBranch {
        cond: x86(X86Reg::R18),
        true_target: cond_true,
        false_target: cond_false,
    });
    cond.switch_to_block(cond_true);
    cond.set_terminator(Terminator::Return { values: vec![] });
    cond.switch_to_block(cond_false);
    cond.set_terminator(Terminator::Return { values: vec![] });
    assert!(!is_x86_aarch64_native_clobber_safe_excluding(
        &cond.finish(),
        &std::collections::HashMap::new()
    ));

    let mut switch = FunctionBuilder::new(FunctionId(1), 0x2000);
    let case = switch.create_block(0x2010);
    let default = switch.create_block(0x2020);
    switch.set_terminator(Terminator::Switch {
        index: VReg::virt(7),
        targets: vec![case],
        default,
    });
    switch.switch_to_block(case);
    switch.set_terminator(Terminator::Return { values: vec![] });
    switch.switch_to_block(default);
    switch.set_terminator(Terminator::Return { values: vec![] });
    assert!(!is_x86_aarch64_native_clobber_safe_excluding(
        &switch.finish(),
        &std::collections::HashMap::new()
    ));

    let mut legacy = FunctionBuilder::new(FunctionId(2), 0x3000);
    let legacy_true = legacy.create_block(0x3010);
    let legacy_false = legacy.create_block(0x3020);
    legacy.set_terminator(Terminator::CondBranch {
        cond: x86(X86Reg::Rcx),
        true_target: legacy_true,
        false_target: legacy_false,
    });
    legacy.switch_to_block(legacy_true);
    legacy.set_terminator(Terminator::Return { values: vec![] });
    legacy.switch_to_block(legacy_false);
    legacy.set_terminator(Terminator::Return { values: vec![] });
    assert!(is_x86_aarch64_native_clobber_safe_excluding(
        &legacy.finish(),
        &std::collections::HashMap::new()
    ));
}
#[test]
fn x86_aarch64_gate_accepts_sub64_multiply_contracts_and_partial_writes() {
    let rax = x86(X86Reg::Rax);
    let rbx = x86(X86Reg::Rbx);
    let rdx = x86(X86Reg::Rdx);
    for src2 in [SrcOperand::Reg(rbx), SrcOperand::Imm(0x1234)] {
        assert!(
            x86_aarch64_gate(vec![OpKind::MulS {
                dst_lo: rbx,
                dst_hi: None,
                src1: rax,
                src2,
                width: OpWidth::W16,
                flags: FlagUpdate::None,
            }]),
            "APX NF W16 single-result signed multiply"
        );
    }

    let flag_setting = OpKind::MulS {
        dst_lo: rbx,
        dst_hi: None,
        src1: rax,
        src2: SrcOperand::Imm(2),
        width: OpWidth::W16,
        flags: FlagUpdate::All,
    };
    assert!(x86_aarch64_scalar_shape_valid(&flag_setting));
    assert!(x86_aarch64_block_flags_are_representable(
        &{
            let mut builder = FunctionBuilder::new(FunctionId(7), 0x7000);
            builder.push_op(0x7000, flag_setting.clone());
            builder.set_terminator(Terminator::Return { values: vec![] });
            builder.finish().blocks.remove(0)
        },
        FlagSet::EMPTY,
    ));
    assert!(
        !x86_aarch64_gate(vec![flag_setting]),
        "terminal flag-setting IMUL defines unavailable live PF/AF"
    );

    for op in [
        OpKind::MulU {
            dst_lo: rax,
            dst_hi: Some(rdx),
            src1: rax,
            src2: SrcOperand::Reg(rbx),
            width: OpWidth::W16,
            flags: FlagUpdate::None,
        },
        OpKind::MulS {
            dst_lo: rax,
            dst_hi: Some(rdx),
            src1: rax,
            src2: SrcOperand::Reg(rdx),
            width: OpWidth::W16,
            flags: FlagUpdate::None,
        },
        OpKind::MulU {
            dst_lo: rbx,
            dst_hi: Some(rbx),
            src1: rdx,
            src2: SrcOperand::Reg(rax),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
        OpKind::MulU {
            dst_lo: rbx,
            dst_hi: Some(rbx),
            src1: rdx,
            src2: SrcOperand::Reg(rax),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        },
    ] {
        assert!(x86_aarch64_gate(vec![op.clone()]), "supported {op:?}");
    }

    for op in [
        OpKind::MulS {
            dst_lo: rax,
            dst_hi: None,
            src1: rax,
            src2: SrcOperand::Reg(rbx),
            width: OpWidth::W8,
            flags: FlagUpdate::None,
        },
        OpKind::MulU {
            dst_lo: rax,
            dst_hi: None,
            src1: rax,
            src2: SrcOperand::Reg(rbx),
            width: OpWidth::W16,
            flags: FlagUpdate::None,
        },
    ] {
        assert!(!x86_aarch64_scalar_shape_valid(&op), "unsupported {op:?}");
    }

    for op in [
        OpKind::MulS {
            dst_lo: rbx,
            dst_hi: Some(rdx),
            src1: rax,
            src2: SrcOperand::Reg(rbx),
            width: OpWidth::W16,
            flags: FlagUpdate::None,
        },
        OpKind::MulU {
            dst_lo: rax,
            dst_hi: Some(rdx),
            src1: rax,
            src2: SrcOperand::Imm(3),
            width: OpWidth::W16,
            flags: FlagUpdate::None,
        },
        OpKind::MulU {
            dst_lo: rax,
            dst_hi: Some(rdx),
            src1: rax,
            src2: SrcOperand::Reg(rbx),
            width: OpWidth::W16,
            flags: FlagUpdate::All,
        },
    ] {
        assert!(
            x86_aarch64_scalar_shape_valid(&op),
            "lowerer-capable but non-architectural shape {op:?}"
        );
        assert!(!x86_aarch64_gate(vec![op.clone()]), "rejected {op:?}");
    }
}
#[test]
fn aarch64_clobber_gate_rejects_fp_mixed_with_mem_helpers() {
    let fp_add = OpKind::FAdd {
        dst: arm_v(0),
        src1: arm_v(1),
        src2: arm_v(2),
        precision: FpPrecision::F64,
    };
    let load = OpKind::Load {
        dst: arm_x(0),
        addr: Address::Direct(arm_x(1)),
        width: MemWidth::B8,
        sign: SignExtend::Zero,
    };

    assert!(
        aarch64_gate(vec![fp_add.clone()], true),
        "pure FP blocks may use the FP trampoline"
    );
    assert!(
        aarch64_gate(vec![load.clone()], true),
        "integer memory-helper blocks stay eligible when memory JIT is enabled"
    );
    assert!(
        !aarch64_gate(vec![load.clone()], false),
        "memory ops still require the memory-helper gate"
    );
    assert!(
        !aarch64_gate(vec![fp_add, load], true),
        "helper-call regions must not run with live guest SIMD state"
    );
}
