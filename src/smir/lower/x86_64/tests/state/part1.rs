//! state part 1 tests

use super::*;
use crate::smir::lower::x86_64::test_support::host_c_helper_reference;
use crate::smir::lower::x86_64::tests::*;
use crate::smir::lower::x86_64::*;

#[test]
fn rejects_non_state_backed_guest_stack_frame_address_destinations() {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rbp = VReg::Arch(ArchReg::X86(X86Reg::Rbp));

    let err = lower_single_op_err(OpKind::Lea {
        dst: rbp,
        addr: Address::Direct(rax),
    });
    assert!(
        matches!(err, LowerError::InvalidRegister(ref reg) if reg.contains("Rbp")),
        "LEA RBP,[RAX] must remain outside the state-backed path, got {err:?}"
    );
}
#[test]
fn lower_state_backed_gpr_extensions_emit_state_commits_and_reject_malformed_shapes() {
    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    let rsp = lower_single_op(OpKind::ZeroExtend {
        dst: x86(X86Reg::Rsp),
        src: x86(X86Reg::Rbx),
        from_width: OpWidth::W8,
        to_width: OpWidth::W16,
    });
    assert!(
        rsp.windows(5)
            .any(|bytes| bytes == [0x66, 0x0F, 0xB6, 0x50, 0x18]),
        "MOVZX SP,BL must read the RBX snapshot: {rsp:02X?}"
    );
    assert!(
        rsp.windows(4)
            .any(|bytes| bytes == [0x66, 0x89, 0x50, 0x20]),
        "MOVZX SP,BL must partially commit GuestRegs.gpr[4]: {rsp:02X?}"
    );

    let r16 = lower_single_op(OpKind::SignExtend {
        dst: x86(X86Reg::R16),
        src: x86(X86Reg::Rbp),
        from_width: OpWidth::W16,
        to_width: OpWidth::W64,
    });
    assert!(
        r16.windows(7)
            .any(|bytes| bytes == [0x48, 0x89, 0x90, 0x80, 0x00, 0x00, 0x00]),
        "MOVSX R16,BP must commit GuestRegs.gpr[16]: {r16:02X?}"
    );

    let same_width = lower_single_op(OpKind::SignExtend {
        dst: x86(X86Reg::R16),
        src: x86(X86Reg::Rbx),
        from_width: OpWidth::W16,
        to_width: OpWidth::W16,
    });
    assert!(
        same_width
            .windows(4)
            .any(|bytes| bytes == [0x66, 0x8B, 0x50, 0x18]),
        "same-width MOVSX R16W,BX must use a documented word copy: {same_width:02X?}"
    );
    assert!(
        !same_width
            .windows(3)
            .any(|bytes| bytes == [0x66, 0x0F, 0xBF]),
        "same-width state lowering must not depend on 66 0F BF: {same_width:02X?}"
    );

    for malformed in [OpKind::ZeroExtend {
        dst: x86(X86Reg::Rax),
        src: x86(X86Reg::Rsp),
        from_width: OpWidth::W8,
        to_width: OpWidth::W64,
    }] {
        assert!(
            matches!(
                lower_single_op_err(malformed),
                LowerError::InvalidOperand { .. }
            ),
            "malformed state-backed extension must fail lowering"
        );
    }
}
#[test]
fn lower_state_backed_gpr_cmov_emits_snapshot_cmov_and_rejects_malformed_shapes() {
    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    let rsp = lower_single_op(OpKind::CMove {
        dst: x86(X86Reg::Rsp),
        src: x86(X86Reg::Rbx),
        cond: Condition::Ne,
        width: OpWidth::W16,
    });
    for (name, expected) in [
        (
            "complete RSP destination seed",
            &[0x48, 0x8B, 0x50, 0x20][..],
        ),
        ("RBX source snapshot", &[0x66, 0x8B, 0x78, 0x18][..]),
        ("native CMOVNE DX,DI", &[0x66, 0x0F, 0x45, 0xD7][..]),
        ("partial RSP slot commit", &[0x66, 0x89, 0x50, 0x20][..]),
    ] {
        assert!(
            rsp.windows(expected.len()).any(|window| window == expected),
            "CMOVNE SP,BX missing {name} {expected:02X?}: {rsp:02X?}"
        );
    }

    let r16 = lower_single_op(OpKind::CMove {
        dst: x86(X86Reg::R16),
        src: x86(X86Reg::Rbp),
        cond: Condition::Negative,
        width: OpWidth::W64,
    });
    assert!(
        r16.windows(7)
            .any(|bytes| bytes == [0x48, 0x89, 0x90, 0x80, 0x00, 0x00, 0x00]),
        "CMOVS R16,RBP must commit GuestRegs.gpr[16]: {r16:02X?}"
    );

    for malformed in [
        OpKind::CMove {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rbx),
            cond: Condition::Ne,
            width: OpWidth::W8,
        },
        OpKind::CMove {
            dst: x86(X86Reg::Rax),
            src: x86(X86Reg::R16),
            cond: Condition::Always,
            width: OpWidth::W64,
        },
    ] {
        assert!(
            matches!(
                lower_single_op_err(malformed),
                LowerError::InvalidOperand { .. }
            ),
            "malformed state-backed CMOVcc must fail lowering"
        );
    }

    let hinted = OpKind::CMove {
        dst: x86(X86Reg::Rax),
        src: x86(X86Reg::R16),
        cond: Condition::Ne,
        width: OpWidth::W64,
    };
    assert!(matches!(
        lower_single_hinted_op_err(hinted, X86OpHint::Mulx),
        LowerError::InvalidOperand { .. }
    ));
}
#[test]
fn lower_state_backed_gpr_setcc_emits_state_commits_and_rejects_malformed_shapes() {
    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    let rsp = lower_single_op(OpKind::SetCC {
        dst: x86(X86Reg::Rsp),
        cond: Condition::Ne,
        width: OpWidth::W8,
    });
    assert!(
        rsp.windows(3).any(|bytes| bytes == [0x0F, 0x95, 0xC2]),
        "SETNE SPL must evaluate into DL: {rsp:02X?}"
    );
    assert!(
        rsp.windows(3).any(|bytes| bytes == [0x88, 0x50, 0x20]),
        "SETNE SPL must partially commit GuestRegs.gpr[4]: {rsp:02X?}"
    );

    let r16 = lower_single_op(OpKind::SetCC {
        dst: x86(X86Reg::R16),
        cond: Condition::Overflow,
        width: OpWidth::W64,
    });
    assert!(
        r16.windows(4)
            .any(|bytes| bytes == [0x48, 0x0F, 0xB6, 0xD2]),
        "SETZUO R16 must zero-extend the predicate to 64 bits: {r16:02X?}"
    );
    assert!(
        r16.windows(7)
            .any(|bytes| bytes == [0x48, 0x89, 0x90, 0x80, 0x00, 0x00, 0x00]),
        "SETZUO R16 must commit GuestRegs.gpr[16]: {r16:02X?}"
    );

    for malformed in [
        OpKind::SetCC {
            dst: x86(X86Reg::R16),
            cond: Condition::Ne,
            width: OpWidth::W16,
        },
        OpKind::SetCC {
            dst: x86(X86Reg::R16),
            cond: Condition::Always,
            width: OpWidth::W64,
        },
    ] {
        assert!(
            matches!(
                lower_single_op_err(malformed),
                LowerError::InvalidOperand { .. }
            ),
            "malformed state-backed SETcc must fail lowering"
        );
    }

    let hinted = OpKind::SetCC {
        dst: x86(X86Reg::R16),
        cond: Condition::Overflow,
        width: OpWidth::W64,
    };
    assert!(matches!(
        lower_single_hinted_op_err(hinted, X86OpHint::Mulx),
        LowerError::InvalidOperand { .. }
    ));
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_state_backed_rsp_rbp_moves_preserve_host_stack_and_guest_widths() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rcx = VReg::Arch(ArchReg::X86(X86Reg::Rcx));
    let rdx = VReg::Arch(ArchReg::X86(X86Reg::Rdx));
    let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
    let rbp = VReg::Arch(ArchReg::X86(X86Reg::Rbp));
    let rsi = VReg::Arch(ArchReg::X86(X86Reg::Rsi));
    let rdi = VReg::Arch(ArchReg::X86(X86Reg::Rdi));
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(
        0x1000,
        OpKind::Mov {
            dst: rax,
            src: SrcOperand::Reg(rsp),
            width: OpWidth::W64,
        },
    );
    builder.push_op(
        0x1001,
        OpKind::Mov {
            dst: rsp,
            src: SrcOperand::Imm64(0x1234_5678_9ABC_DEF0u64 as i64),
            width: OpWidth::W64,
        },
    );
    builder.push_op(
        0x1002,
        OpKind::Mov {
            dst: rbp,
            src: SrcOperand::Reg(rsp),
            width: OpWidth::W64,
        },
    );
    builder.push_op(
        0x1003,
        OpKind::Mov {
            dst: rcx,
            src: SrcOperand::Reg(rbp),
            width: OpWidth::W64,
        },
    );
    builder.push_op(
        0x1004,
        OpKind::Mov {
            dst: rsp,
            src: SrcOperand::Reg(rsi),
            width: OpWidth::W32,
        },
    );
    builder.push_op(
        0x1005,
        OpKind::Mov {
            dst: rsp,
            src: SrcOperand::Reg(rdx),
            width: OpWidth::W16,
        },
    );
    builder.push_op(
        0x1006,
        OpKind::Mov {
            dst: rbp,
            src: SrcOperand::Reg(rdi),
            width: OpWidth::W8,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });

    let mut lowerer = X86_64Lowerer::new();
    let lowered = lowerer
        .lower_function(&builder.finish())
        .expect("lower state-backed stack-register moves");
    assert!(lowered.relocations.is_empty());
    let exec = ExecMem::new(&lowerer.finalize().expect("finalize")).expect("exec memory");

    let initial_rsp = 0x0FED_CBA9_8765_4321;
    let mut regs = GuestRegs::default();
    regs.gpr[2] = 0xA55A;
    regs.gpr[4] = initial_rsp;
    regs.gpr[5] = 0xDEAD_BEEF_CAFE_BABE;
    regs.gpr[6] = 0x8765_4321;
    regs.gpr[7] = 0x7B;
    regs.rflags = 0x8D5;
    exec.run(lowered.entry_offset, &mut regs);

    assert_eq!(regs.gpr[0], initial_rsp, "MOV RAX,RSP source snapshot");
    assert_eq!(regs.gpr[1], 0x1234_5678_9ABC_DEF0, "MOV RCX,RBP chain");
    assert_eq!(regs.gpr[4], 0x8765_A55A, "MOV ESP,ESI then MOV SP,DX");
    assert_eq!(regs.gpr[5], 0x1234_5678_9ABC_DE7B, "MOV BPL,DIL merge");
    const STATUS: u64 = 0x8D5;
    assert_eq!(
        regs.rflags & STATUS,
        STATUS,
        "MOV sequence must preserve status flags"
    );
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_state_backed_gpr_extensions_preserve_widths_flags_and_aliases() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    for kind in [
        OpKind::ZeroExtend {
            dst: x86(X86Reg::Rsp),
            src: x86(X86Reg::Rbx),
            from_width: OpWidth::W8,
            to_width: OpWidth::W16,
        },
        OpKind::SignExtend {
            dst: x86(X86Reg::Rbp),
            src: x86(X86Reg::Rbx),
            from_width: OpWidth::W16,
            to_width: OpWidth::W32,
        },
        OpKind::ZeroExtend {
            dst: x86(X86Reg::R16),
            src: x86(X86Reg::Rcx),
            from_width: OpWidth::W32,
            to_width: OpWidth::W64,
        },
        OpKind::SignExtend {
            dst: x86(X86Reg::Rax),
            src: x86(X86Reg::R17),
            from_width: OpWidth::W32,
            to_width: OpWidth::W64,
        },
        OpKind::ZeroExtend {
            dst: x86(X86Reg::R18),
            src: x86(X86Reg::R18),
            from_width: OpWidth::W8,
            to_width: OpWidth::W16,
        },
        OpKind::ZeroExtend {
            dst: x86(X86Reg::Rsp),
            src: x86(X86Reg::Rdx),
            from_width: OpWidth::W8,
            to_width: OpWidth::W16,
        },
    ] {
        builder.push_op(0x1000, kind);
    }
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut function = builder.finish();
    function.blocks[0].ops[5].x86_hint = Some(X86OpHint::LegacyHighByteReg);

    let mut lowerer = X86_64Lowerer::new();
    let lowered = lowerer
        .lower_function(&function)
        .expect("lower state-backed register extensions");
    let code = lowerer.finalize().expect("finalize register extensions");
    assert!(
        code.windows(4)
            .any(|bytes| bytes == [0x66, 0x0F, 0xB6, 0x50]),
        "W16 MOVZX must extend through the state snapshot: {code:02X?}"
    );
    assert!(
        code.windows(7)
            .any(|bytes| bytes == [0x48, 0x89, 0x90, 0x80, 0x00, 0x00, 0x00]),
        "R16 destination must commit GuestRegs.gpr[16]: {code:02X?}"
    );

    let exec = ExecMem::new(&code).expect("map register extensions");
    let mut regs = GuestRegs::default();
    regs.gpr[1] = 0x0123_4567_89AB_CDEF;
    regs.gpr[2] = 0xA5A5_5A5A_1357_CD00;
    regs.gpr[3] = 0xFEDC_BA98_7654_80A7;
    regs.gpr[4] = 0x1234_5678_9ABC_80F2;
    regs.gpr[5] = 0x0FED_CBA9_8765_8001;
    regs.gpr[17] = 0xB1B2_B3B4_8000_0001;
    regs.gpr[18] = 0xC1C2_C3C4_C5C6_80F1;
    regs.rflags = 0x2 | 0x8D5;
    exec.run(lowered.entry_offset, &mut regs);

    assert_eq!(regs.gpr[0], 0xFFFF_FFFF_8000_0001, "MOVSXD RAX,R17D");
    assert_eq!(regs.gpr[1], 0x0123_4567_89AB_CDEF, "RCX source");
    assert_eq!(regs.gpr[2], 0xA5A5_5A5A_1357_CD00, "RDX source");
    assert_eq!(regs.gpr[3], 0xFEDC_BA98_7654_80A7, "RBX source");
    assert_eq!(regs.gpr[4], 0x1234_5678_9ABC_00CD, "MOVZX SP,DH");
    assert_eq!(regs.gpr[5], 0x0000_0000_FFFF_80A7, "MOVSX EBP,BX");
    assert_eq!(regs.gpr[16], 0x89AB_CDEF, "MOVZX R16,ECX");
    assert_eq!(regs.gpr[18], 0xC1C2_C3C4_C5C6_00F1, "MOVZX R18W,R18B alias");
    assert_eq!(
        regs.rflags & 0x8D5,
        0x8D5,
        "MOVZX/MOVSX/MOVSXD preserve status flags"
    );
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_state_backed_gpr_cmov_preserves_widths_flags_and_aliases() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    const STATUS: u64 = 0x8D5;
    const ZF_SET: u64 = 0x2 | STATUS;
    const ZF_CLEAR: u64 = 0x2 | (STATUS & !(1 << 6));

    struct Case {
        name: &'static str,
        kind: OpKind,
        rflags: u64,
        destination_index: usize,
        expected_destination: u64,
    }

    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    let cases = [
        Case {
            name: "CMOVNE SP,BX true partial destination",
            kind: OpKind::CMove {
                dst: x86(X86Reg::Rsp),
                src: x86(X86Reg::Rbx),
                cond: Condition::Ne,
                width: OpWidth::W16,
            },
            rflags: ZF_CLEAR,
            destination_index: 4,
            expected_destination: 0x1234_5678_9ABC_80A7,
        },
        Case {
            name: "CMOVNE SP,BX false preserves complete destination",
            kind: OpKind::CMove {
                dst: x86(X86Reg::Rsp),
                src: x86(X86Reg::Rbx),
                cond: Condition::Ne,
                width: OpWidth::W16,
            },
            rflags: ZF_SET,
            destination_index: 4,
            expected_destination: 0x1234_5678_9ABC_80F2,
        },
        Case {
            name: "CMOVNE EBP,ESP false zeroes upper dword",
            kind: OpKind::CMove {
                dst: x86(X86Reg::Rbp),
                src: x86(X86Reg::Rsp),
                cond: Condition::Ne,
                width: OpWidth::W32,
            },
            rflags: ZF_SET,
            destination_index: 5,
            expected_destination: 0x8765_8001,
        },
        Case {
            name: "CMOVE EBP,ESP true zeroes upper dword",
            kind: OpKind::CMove {
                dst: x86(X86Reg::Rbp),
                src: x86(X86Reg::Rsp),
                cond: Condition::Eq,
                width: OpWidth::W32,
            },
            rflags: ZF_SET,
            destination_index: 5,
            expected_destination: 0x9ABC_80F2,
        },
        Case {
            name: "CMOVS R16,RBP state-backed destination",
            kind: OpKind::CMove {
                dst: x86(X86Reg::R16),
                src: x86(X86Reg::Rbp),
                cond: Condition::Negative,
                width: OpWidth::W64,
            },
            rflags: ZF_SET,
            destination_index: 16,
            expected_destination: 0x0FED_CBA9_8765_8001,
        },
        Case {
            name: "CMOVP RAX,R16 state-backed source",
            kind: OpKind::CMove {
                dst: x86(X86Reg::Rax),
                src: x86(X86Reg::R16),
                cond: Condition::Parity,
                width: OpWidth::W64,
            },
            rflags: ZF_SET,
            destination_index: 0,
            expected_destination: 0xA1A2_A3A4_A5A6_80F1,
        },
        Case {
            name: "CMOVNE SP,SP alias",
            kind: OpKind::CMove {
                dst: x86(X86Reg::Rsp),
                src: x86(X86Reg::Rsp),
                cond: Condition::Ne,
                width: OpWidth::W16,
            },
            rflags: ZF_CLEAR,
            destination_index: 4,
            expected_destination: 0x1234_5678_9ABC_80F2,
        },
    ];

    for case in cases {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(0x1000, case.kind);
        builder.set_terminator(Terminator::Return { values: vec![] });

        let mut lowerer = X86_64Lowerer::new();
        let lowered = lowerer
            .lower_function(&builder.finish())
            .unwrap_or_else(|error| panic!("{} lowering: {error:?}", case.name));
        let code = lowerer
            .finalize()
            .unwrap_or_else(|error| panic!("{} finalize: {error:?}", case.name));
        let exec = ExecMem::new(&code)
            .unwrap_or_else(|error| panic!("{} executable mapping: {error:?}", case.name));

        let mut regs = GuestRegs::default();
        regs.gpr[0] = 0x0123_4567_89AB_CDEF;
        regs.gpr[1] = 0x1111_2222_3333_4444;
        regs.gpr[2] = 0xA5A5_5A5A_1357_2468;
        regs.gpr[3] = 0xFEDC_BA98_7654_80A7;
        regs.gpr[4] = 0x1234_5678_9ABC_80F2;
        regs.gpr[5] = 0x0FED_CBA9_8765_8001;
        regs.gpr[6] = 0x99AA_BBCC_DDEE_FF00;
        regs.gpr[7] = 0x0F1E_2D3C_4B5A_6978;
        regs.gpr[16] = 0xA1A2_A3A4_A5A6_80F1;
        regs.gpr[31] = 0xF1F2_F3F4_F5F6_F7F8;
        regs.rflags = case.rflags;
        let mut expected = regs;
        expected.gpr[case.destination_index] = case.expected_destination;

        exec.run(lowered.entry_offset, &mut regs);

        assert_eq!(regs.gpr, expected.gpr, "{} GPR file", case.name);
        assert_eq!(
            regs.rflags & STATUS,
            case.rflags & STATUS,
            "{} status flags",
            case.name
        );
    }
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_state_backed_gpr_setcc_preserves_widths_flags_and_host_stack() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    const STATUS: u64 = 0x8D5;
    const ALL_SET: u64 = 0x2 | STATUS;
    const ZF_CLEAR: u64 = ALL_SET & !(1 << 6);
    const OF_CLEAR: u64 = ALL_SET & !(1 << 11);

    struct Case {
        name: &'static str,
        kind: OpKind,
        rflags: u64,
        destination_index: usize,
        expected_destination: u64,
    }

    let x86 = |reg| VReg::Arch(ArchReg::X86(reg));
    let cases = [
        Case {
            name: "SETNE SPL true partial destination",
            kind: OpKind::SetCC {
                dst: x86(X86Reg::Rsp),
                cond: Condition::Ne,
                width: OpWidth::W8,
            },
            rflags: ZF_CLEAR,
            destination_index: 4,
            expected_destination: 0x1234_5678_9ABC_8001,
        },
        Case {
            name: "SETNE SPL false partial destination",
            kind: OpKind::SetCC {
                dst: x86(X86Reg::Rsp),
                cond: Condition::Ne,
                width: OpWidth::W8,
            },
            rflags: ALL_SET,
            destination_index: 4,
            expected_destination: 0x1234_5678_9ABC_8000,
        },
        Case {
            name: "SETE BPL true partial destination",
            kind: OpKind::SetCC {
                dst: x86(X86Reg::Rbp),
                cond: Condition::Eq,
                width: OpWidth::W8,
            },
            rflags: ALL_SET,
            destination_index: 5,
            expected_destination: 0x0FED_CBA9_8765_8001,
        },
        Case {
            name: "SETNE R16B true state-backed EGPR destination",
            kind: OpKind::SetCC {
                dst: x86(X86Reg::R16),
                cond: Condition::Ne,
                width: OpWidth::W8,
            },
            rflags: ZF_CLEAR,
            destination_index: 16,
            expected_destination: 0xA1A2_A3A4_A5A6_8001,
        },
        Case {
            name: "SETZUO R16 true full destination",
            kind: OpKind::SetCC {
                dst: x86(X86Reg::R16),
                cond: Condition::Overflow,
                width: OpWidth::W64,
            },
            rflags: ALL_SET,
            destination_index: 16,
            expected_destination: 1,
        },
        Case {
            name: "SETZUO RSP false full destination",
            kind: OpKind::SetCC {
                dst: x86(X86Reg::Rsp),
                cond: Condition::Overflow,
                width: OpWidth::W64,
            },
            rflags: OF_CLEAR,
            destination_index: 4,
            expected_destination: 0,
        },
        Case {
            name: "SETZUNE RBP true full destination",
            kind: OpKind::SetCC {
                dst: x86(X86Reg::Rbp),
                cond: Condition::Ne,
                width: OpWidth::W64,
            },
            rflags: ZF_CLEAR,
            destination_index: 5,
            expected_destination: 1,
        },
    ];

    for case in cases {
        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(0x1000, case.kind);
        builder.set_terminator(Terminator::Return { values: vec![] });

        let mut lowerer = X86_64Lowerer::new();
        let lowered = lowerer
            .lower_function(&builder.finish())
            .unwrap_or_else(|error| panic!("{} lowering: {error:?}", case.name));
        let code = lowerer
            .finalize()
            .unwrap_or_else(|error| panic!("{} finalize: {error:?}", case.name));
        let exec = ExecMem::new(&code)
            .unwrap_or_else(|error| panic!("{} executable mapping: {error:?}", case.name));

        let mut regs = GuestRegs::default();
        regs.gpr[0] = 0x0123_4567_89AB_CDEF;
        regs.gpr[1] = 0x1111_2222_3333_4444;
        regs.gpr[2] = 0xA5A5_5A5A_1357_2468;
        regs.gpr[3] = 0xFEDC_BA98_7654_80A7;
        regs.gpr[4] = 0x1234_5678_9ABC_80F2;
        regs.gpr[5] = 0x0FED_CBA9_8765_8001;
        regs.gpr[6] = 0x99AA_BBCC_DDEE_FF00;
        regs.gpr[7] = 0x0F1E_2D3C_4B5A_6978;
        regs.gpr[16] = 0xA1A2_A3A4_A5A6_80F1;
        regs.gpr[31] = 0xF1F2_F3F4_F5F6_F7F8;
        regs.rflags = case.rflags;
        let mut expected = regs;
        expected.gpr[case.destination_index] = case.expected_destination;

        exec.run(lowered.entry_offset, &mut regs);

        assert_eq!(regs.gpr, expected.gpr, "{} GPR file", case.name);
        assert_eq!(
            regs.rflags & STATUS,
            case.rflags & STATUS,
            "{} status flags",
            case.name
        );
    }
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_state_backed_stack_add_sub_preserve_host_stack_widths_and_flags() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rdx = VReg::Arch(ArchReg::X86(X86Reg::Rdx));
    let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));
    let rbp = VReg::Arch(ArchReg::X86(X86Reg::Rbp));
    let r16 = VReg::Arch(ArchReg::X86(X86Reg::R16));
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(
        0x1000,
        OpKind::Add {
            dst: rsp,
            src1: rsp,
            src2: SrcOperand::Reg(rax),
            width: OpWidth::W8,
            flags: FlagUpdate::None,
        },
    );
    builder.push_op(
        0x1001,
        OpKind::Sub {
            dst: rbp,
            src1: rbp,
            src2: SrcOperand::Reg(rdx),
            width: OpWidth::W16,
            flags: FlagUpdate::None,
        },
    );
    builder.push_op(
        0x1002,
        OpKind::Add {
            dst: r16,
            src1: rsp,
            src2: SrcOperand::Reg(rbp),
            width: OpWidth::W32,
            flags: FlagUpdate::None,
        },
    );
    builder.push_op(
        0x1003,
        OpKind::Sub {
            dst: rbp,
            src1: rsp,
            src2: SrcOperand::Imm(0x10),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });

    let mut lowerer = X86_64Lowerer::new();
    let lowered = lowerer
        .lower_function(&builder.finish())
        .expect("lower state-backed stack arithmetic");
    let exec = ExecMem::new(&lowerer.finalize().expect("finalize")).expect("exec memory");

    let mut regs = GuestRegs::default();
    regs.gpr[0] = 0x20;
    regs.gpr[2] = 0x20;
    regs.gpr[4] = 0x1111_2222_3333_44F0;
    regs.gpr[5] = 0xAAAA_BBBB_CCCC_DD10;
    regs.rflags = 0x8D5;
    exec.run(lowered.entry_offset, &mut regs);

    assert_eq!(regs.gpr[4], 0x1111_2222_3333_4410, "ADD SPL,AL");
    assert_eq!(regs.gpr[16], 0x2100, "ADD R16D,ESP/EBP snapshot");
    assert_eq!(regs.gpr[5], 0x1111_2222_3333_4400, "SUB RBP,RSP,16");
    const STATUS: u64 = 0x8D5;
    assert_eq!(
        regs.rflags & STATUS,
        STATUS,
        "FlagUpdate::None arithmetic must preserve status flags"
    );
}
#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn return_shape_does_not_elide_state_backed_guest_rsp_updates() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    let rsp = VReg::Arch(ArchReg::X86(X86Reg::Rsp));

    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(
        0x1004,
        OpKind::Add {
            dst: rsp,
            src1: rsp,
            src2: SrcOperand::Imm(8),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });
    let func = builder.finish();

    let mut lowerer = X86_64Lowerer::new();
    let lowered = lowerer
        .lower_function(&func)
        .expect("state-backed return-shape RSP update");
    let exec = ExecMem::new(&lowerer.finalize().expect("finalize")).expect("exec memory");
    let mut regs = GuestRegs::default();
    regs.gpr[4] = 0x1234_5678_9ABC_DEF0;
    exec.run(lowered.entry_offset, &mut regs);
    assert_eq!(
        regs.gpr[4], 0x1234_5678_9ABC_DEF8,
        "guest RSP update must execute rather than becoming a host RET immediate"
    );
}
#[cfg(feature = "smir-jit")]
#[test]
fn lower_helper_backed_immediate_bit_test_consumes_staged_stack_source() {
    // bt qword ptr [rbx],5; hlt
    let (lowered, entry) =
        lower_rex2_block_with_mem_helpers(&[0x48, 0x0F, 0xBA, 0x23, 0x05, 0xF4], true);
    assert!(entry < lowered.len());
    assert!(
        lowered
            .windows(7)
            .any(|bytes| bytes == [0x48, 0x0F, 0xBA, 0x64, 0x24, 0x08, 0x05]),
        "helper-backed BT must consume the caller-owned stack word: {lowered:02X?}"
    );
    let helper_call = host_c_helper_reference(X86_GUEST_LOAD_FN_OFFSET);
    assert_eq!(
        lowered
            .windows(helper_call.len())
            .filter(|bytes| *bytes == helper_call)
            .count(),
        1,
        "memory-source BT must issue exactly one load helper call"
    );
}
#[cfg(feature = "smir-jit")]
#[test]
fn lower_helper_backed_immediate_bit_update_stages_rmw_and_replays_cf() {
    // btr qword ptr [rbx],5; hlt
    let (lowered, entry) =
        lower_rex2_block_with_mem_helpers(&[0x48, 0x0F, 0xBA, 0x33, 0x05, 0xF4], true);
    assert!(entry < lowered.len());
    assert!(
        lowered
            .windows(7)
            .any(|bytes| bytes == [0x48, 0x0F, 0xBA, 0x74, 0x24, 0x10, 0x05]),
        "helper-backed BTR must modify the staged store word: {lowered:02X?}"
    );
    assert!(
        lowered
            .windows(7)
            .any(|bytes| bytes == [0x48, 0x0F, 0xBA, 0x64, 0x24, 0x08, 0x05]),
        "helper-backed BTR must replay CF from the original word: {lowered:02X?}"
    );
    for (offset, name) in [
        (X86_GUEST_LOAD_FN_OFFSET, "load"),
        (X86_GUEST_STORE_FN_OFFSET, "store"),
    ] {
        let helper_call = host_c_helper_reference(offset);
        assert_eq!(
            lowered
                .windows(helper_call.len())
                .filter(|bytes| *bytes == helper_call)
                .count(),
            1,
            "memory-destination BTR must issue exactly one {name} helper call"
        );
    }

    // btc qword ptr [rbx],63; hlt
    let (lowered, entry) =
        lower_rex2_block_with_mem_helpers(&[0x48, 0x0F, 0xBA, 0x3B, 0x3F, 0xF4], true);
    assert!(entry < lowered.len());
    assert!(
        lowered
            .windows(7)
            .any(|bytes| bytes == [0x48, 0x0F, 0xBA, 0x7C, 0x24, 0x10, 0x3F]),
        "helper-backed BTC must modify the staged store word: {lowered:02X?}"
    );
    assert!(
        lowered
            .windows(7)
            .any(|bytes| bytes == [0x48, 0x0F, 0xBA, 0x64, 0x24, 0x08, 0x3F]),
        "helper-backed BTC must replay CF from the original word: {lowered:02X?}"
    );
}
#[cfg(feature = "smir-jit")]
#[test]
fn lower_helper_backed_two_operand_imul_uses_staged_memory_source() {
    for (name, instruction, expected) in [
        (
            "W16 RAX",
            &[0x66, 0x0F, 0xAF, 0x03, 0xF4][..],
            &[0x66, 0x0F, 0xAF, 0x04, 0x24][..],
        ),
        (
            "W32 R8",
            &[0x44, 0x0F, 0xAF, 0x03, 0xF4][..],
            &[0x44, 0x0F, 0xAF, 0x04, 0x24][..],
        ),
        (
            "W64 R9",
            &[0x4C, 0x0F, 0xAF, 0x0B, 0xF4][..],
            &[0x4C, 0x0F, 0xAF, 0x0C, 0x24][..],
        ),
    ] {
        let (lowered, entry) = lower_rex2_block_with_mem_helpers(instruction, true);
        assert!(entry < lowered.len(), "{name}");
        assert!(
            lowered
                .windows(expected.len())
                .any(|bytes| bytes == expected),
            "helper-backed {name} IMUL must consume the staged stack source: {lowered:02X?}"
        );
    }

    let temporary = VReg::Virtual(crate::smir::ir::types::VirtualId(90));
    let r8 = VReg::Arch(ArchReg::X86(X86Reg::R8));
    let mut builder = FunctionBuilder::new(FunctionId(90), 0x1000);
    builder.push_op(
        0x1000,
        OpKind::Load {
            dst: temporary,
            addr: Address::Direct(VReg::Arch(ArchReg::X86(X86Reg::Rbx))),
            width: MemWidth::B8,
            sign: SignExtend::Zero,
        },
    );
    builder.push_op(
        0x1000,
        OpKind::MulS {
            dst_lo: r8,
            dst_hi: None,
            src1: r8,
            src2: SrcOperand::Reg(temporary),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer
        .lower_function(&builder.finish())
        .expect("lower flag-preserving helper-backed IMUL");
    let lowered = lowerer.finalize().expect("finalize flag-preserving IMUL");
    assert!(
        lowered
            .windows(8)
            .any(|bytes| bytes == [0x9C, 0x4C, 0x0F, 0xAF, 0x44, 0x24, 0x08, 0x9D]),
        "NF IMUL must preserve flags around the staged stack source: {lowered:02X?}"
    );
}
#[cfg(feature = "smir-jit")]
#[test]
fn lower_helper_backed_immediate_imul_uses_hint_and_staged_memory_source() {
    for (name, instruction, expected) in [
        (
            "W16 RAX imm16",
            &[0x66, 0x69, 0x03, 0x34, 0x12, 0xF4][..],
            &[0x66, 0x69, 0x04, 0x24, 0x34, 0x12][..],
        ),
        (
            "W32 R8 imm8",
            &[0x44, 0x6B, 0x03, 0xFD, 0xF4][..],
            &[0x44, 0x6B, 0x04, 0x24, 0xFD][..],
        ),
        (
            "W64 R9 imm32",
            &[0x4C, 0x69, 0x0B, 0x78, 0x56, 0x34, 0x12, 0xF4][..],
            &[0x4C, 0x69, 0x0C, 0x24, 0x78, 0x56, 0x34, 0x12][..],
        ),
    ] {
        let (lowered, entry) = lower_rex2_block_with_mem_helpers(instruction, true);
        assert!(entry < lowered.len(), "{name}");
        assert!(
            lowered
                .windows(expected.len())
                .any(|bytes| bytes == expected),
            "helper-backed {name} must preserve the opcode hint and consume the staged source: {lowered:02X?}"
        );
    }

    let temporary = VReg::Virtual(crate::smir::ir::types::VirtualId(91));
    let r8 = VReg::Arch(ArchReg::X86(X86Reg::R8));
    let mut builder = FunctionBuilder::new(FunctionId(91), 0x1000);
    builder.push_op(
        0x1000,
        OpKind::Load {
            dst: temporary,
            addr: Address::Direct(VReg::Arch(ArchReg::X86(X86Reg::Rbx))),
            width: MemWidth::B2,
            sign: SignExtend::Zero,
        },
    );
    builder.push_op(
        0x1000,
        OpKind::MulS {
            dst_lo: r8,
            dst_hi: None,
            src1: temporary,
            src2: SrcOperand::Imm(0x1234),
            width: OpWidth::W16,
            flags: FlagUpdate::None,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut function = builder.finish();
    function.blocks[0].ops[1].x86_hint = Some(X86OpHint::ImulImm32);
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer
        .lower_function(&function)
        .expect("lower flag-preserving helper-backed immediate IMUL");
    let lowered = lowerer
        .finalize()
        .expect("finalize flag-preserving immediate IMUL");
    assert!(
        lowered
            .windows(10)
            .any(|bytes| { bytes == [0x9C, 0x66, 0x44, 0x69, 0x44, 0x24, 0x08, 0x34, 0x12, 0x9D] }),
        "NF immediate IMUL must preserve flags around the shifted staged source: {lowered:02X?}"
    );
}
#[cfg(feature = "smir-jit")]
#[test]
fn lower_helper_backed_memory_cmov_uses_staged_and_state_destinations() {
    for (name, instruction, expected) in [
        (
            "CMOVNE AX,word [RBX]",
            &[0x66, 0x0F, 0x45, 0x03, 0xF4][..],
            &[0x66, 0x0F, 0x45, 0x04, 0x24][..],
        ),
        (
            "CMOVE ECX,dword [RBX]",
            &[0x0F, 0x44, 0x0B, 0xF4][..],
            &[0x0F, 0x44, 0x0C, 0x24][..],
        ),
        (
            "CMOVNE R9,qword [RBX]",
            &[0x4C, 0x0F, 0x45, 0x0B, 0xF4][..],
            &[0x4C, 0x0F, 0x45, 0x0C, 0x24][..],
        ),
    ] {
        let (lowered, entry) = lower_rex2_block_with_mem_helpers(instruction, true);
        assert!(entry < lowered.len(), "{name}");
        assert!(
            lowered
                .windows(expected.len())
                .any(|bytes| bytes == expected),
            "{name} must conditionally read the helper-staged source: {lowered:02X?}"
        );
        assert!(
            lowered
                .windows(5)
                .any(|bytes| bytes == [0x48, 0x89, 0x44, 0x24, 0x10]),
            "{name} helper must stage above saved flags and RAX: {lowered:02X?}"
        );
    }

    let (rsp, _) = lower_rex2_block_with_mem_helpers(&[0x66, 0x0F, 0x45, 0x23, 0xF4], true);
    assert!(
        rsp.windows(6)
            .any(|bytes| bytes == [0x66, 0x0F, 0x45, 0x54, 0x24, 0x10]),
        "CMOVNE SP must conditionally update a state-commit scratch: {rsp:02X?}"
    );
    assert!(
        rsp.windows(4)
            .any(|bytes| bytes == [0x66, 0x89, 0x50, 0x20]),
        "CMOVNE SP must partially commit GuestRegs.gpr[4]: {rsp:02X?}"
    );

    let (rbp, _) = lower_rex2_block_with_mem_helpers(&[0x0F, 0x44, 0x2B, 0xF4], true);
    assert!(
        rbp.windows(4)
            .any(|bytes| bytes == [0x48, 0x89, 0x50, 0x28]),
        "CMOVE EBP must commit the complete conditional result: {rbp:02X?}"
    );
    assert!(
        rbp.windows(4)
            .any(|bytes| bytes == [0x48, 0x89, 0x55, 0x00]),
        "CMOVE EBP must synchronize the prologue's saved guest RBP: {rbp:02X?}"
    );

    let (r16, _) = lower_rex2_block_with_mem_helpers(&[0xD5, 0xC8, 0x45, 0x03, 0xF4], true);
    assert!(
        r16.windows(7)
            .any(|bytes| bytes == [0x48, 0x89, 0x90, 0x80, 0x00, 0x00, 0x00]),
        "CMOVNE R16 must commit canonical GuestRegs.gpr[16]: {r16:02X?}"
    );
}
#[cfg(feature = "smir-jit")]
#[test]
fn lower_helper_backed_memory_extensions_use_staged_and_state_destinations() {
    for (name, instruction, expected) in [
        (
            "MOVZX EAX,byte [RBX]",
            &[0x0F, 0xB6, 0x03, 0xF4][..],
            &[0x0F, 0xB6, 0x04, 0x24][..],
        ),
        (
            "MOVZX R9,word [RBX]",
            &[0x4C, 0x0F, 0xB7, 0x0B, 0xF4][..],
            &[0x4C, 0x0F, 0xB7, 0x0C, 0x24][..],
        ),
        (
            "MOVSX AX,byte [RBX]",
            &[0x66, 0x0F, 0xBE, 0x03, 0xF4][..],
            &[0x66, 0x0F, 0xBE, 0x04, 0x24][..],
        ),
        (
            "MOVSX R10,word [RBX]",
            &[0x4C, 0x0F, 0xBF, 0x13, 0xF4][..],
            &[0x4C, 0x0F, 0xBF, 0x14, 0x24][..],
        ),
        (
            "MOVSXD R12,dword [RBX]",
            &[0x4C, 0x63, 0x23, 0xF4][..],
            &[0x4C, 0x63, 0x24, 0x24][..],
        ),
    ] {
        let (lowered, entry) = lower_rex2_block_with_mem_helpers(instruction, true);
        assert!(entry < lowered.len(), "{name}");
        assert!(
            lowered
                .windows(expected.len())
                .any(|bytes| bytes == expected),
            "{name} must extend the helper-staged stack source: {lowered:02X?}"
        );
        assert!(
            lowered
                .windows(5)
                .any(|bytes| bytes == [0x48, 0x89, 0x44, 0x24, 0x10]),
            "{name} helper must stage above saved flags and RAX: {lowered:02X?}"
        );
    }

    let (rsp, _) = lower_rex2_block_with_mem_helpers(&[0x66, 0x0F, 0xB6, 0x23, 0xF4], true);
    assert!(
        rsp.windows(6)
            .any(|bytes| bytes == [0x66, 0x0F, 0xB6, 0x54, 0x24, 0x10]),
        "MOVZX SP must extend into a state-commit scratch: {rsp:02X?}"
    );
    assert!(
        rsp.windows(4)
            .any(|bytes| bytes == [0x66, 0x89, 0x50, 0x20]),
        "MOVZX SP must partially commit GuestRegs.gpr[4]: {rsp:02X?}"
    );

    let (rbp, _) = lower_rex2_block_with_mem_helpers(&[0x0F, 0xBF, 0x2B, 0xF4], true);
    assert!(
        rbp.windows(4)
            .any(|bytes| bytes == [0x48, 0x89, 0x50, 0x28]),
        "MOVSX EBP must commit GuestRegs.gpr[5]: {rbp:02X?}"
    );
    assert!(
        rbp.windows(4)
            .any(|bytes| bytes == [0x48, 0x89, 0x55, 0x00]),
        "MOVSX EBP must synchronize the prologue's saved guest RBP: {rbp:02X?}"
    );

    let temporary = VReg::Virtual(crate::smir::ir::types::VirtualId(93));
    let mut builder = FunctionBuilder::new(FunctionId(93), 0x1000);
    builder.push_op(
        0x1000,
        OpKind::Load {
            dst: temporary,
            addr: Address::Direct(VReg::Arch(ArchReg::X86(X86Reg::Rbx))),
            width: MemWidth::B2,
            sign: SignExtend::Zero,
        },
    );
    builder.push_op(
        0x1000,
        OpKind::ZeroExtend {
            dst: VReg::Arch(ArchReg::X86(X86Reg::R16)),
            src: temporary,
            from_width: OpWidth::W16,
            to_width: OpWidth::W64,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer
        .lower_function(&builder.finish())
        .expect("lower helper-backed R16 MOVZX");
    let r16 = lowerer.finalize().expect("finalize R16 MOVZX");
    assert!(
        r16.windows(7)
            .any(|bytes| bytes == [0x48, 0x89, 0x90, 0x80, 0x00, 0x00, 0x00]),
        "MOVZX R16 must commit canonical GuestRegs.gpr[16]: {r16:02X?}"
    );
}
#[cfg(feature = "smir-jit")]
#[test]
fn lower_helper_backed_widening_multiply_uses_staged_memory_source() {
    for (name, instruction, expected) in [
        ("MUL byte", &[0xF6, 0x23, 0xF4][..], &[0xF6, 0x24, 0x24][..]),
        (
            "IMUL word",
            &[0x66, 0xF7, 0x2B, 0xF4][..],
            &[0x66, 0xF7, 0x2C, 0x24][..],
        ),
        (
            "MUL dword",
            &[0xF7, 0x23, 0xF4][..],
            &[0xF7, 0x24, 0x24][..],
        ),
        (
            "IMUL qword",
            &[0x48, 0xF7, 0x2B, 0xF4][..],
            &[0x48, 0xF7, 0x2C, 0x24][..],
        ),
    ] {
        let (lowered, entry) = lower_rex2_block_with_mem_helpers(instruction, true);
        assert!(entry < lowered.len(), "{name}");
        assert!(
            lowered
                .windows(expected.len())
                .any(|bytes| bytes == expected),
            "helper-backed {name} must consume the staged stack source: {lowered:02X?}"
        );
    }

    let temporary = VReg::Virtual(crate::smir::ir::types::VirtualId(92));
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rdx = VReg::Arch(ArchReg::X86(X86Reg::Rdx));
    let mut builder = FunctionBuilder::new(FunctionId(92), 0x1000);
    builder.push_op(
        0x1000,
        OpKind::Load {
            dst: temporary,
            addr: Address::Direct(VReg::Arch(ArchReg::X86(X86Reg::Rbx))),
            width: MemWidth::B8,
            sign: SignExtend::Zero,
        },
    );
    builder.push_op(
        0x1000,
        OpKind::MulS {
            dst_lo: rax,
            dst_hi: Some(rdx),
            src1: rax,
            src2: SrcOperand::Reg(temporary),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer
        .lower_function(&builder.finish())
        .expect("lower flag-preserving helper-backed widening IMUL");
    let lowered = lowerer
        .finalize()
        .expect("finalize flag-preserving widening IMUL");
    assert!(
        lowered
            .windows(7)
            .any(|bytes| bytes == [0x9C, 0x48, 0xF7, 0x6C, 0x24, 0x08, 0x9D]),
        "NF widening IMUL must preserve flags around the shifted staged source: {lowered:02X?}"
    );
    assert!(
        lowered
            .windows(5)
            .any(|bytes| bytes == [0x48, 0x89, 0x44, 0x24, 0x10]),
        "load helper must stage the source above its saved flags and RAX: {lowered:02X?}"
    );
}
#[cfg(feature = "smir-jit")]
#[test]
fn lower_optimized_helper_backed_btc_accepts_folded_w64_mask() {
    // btc qword ptr [rbx],63; hlt
    let bytes = [0x48, 0x0F, 0xBA, 0x3B, 0x3F, 0xF4];
    let reader = TestReader {
        base: 0x1000,
        bytes: bytes.to_vec(),
    };
    let mut lifter = X86_64Lifter::strict();
    let mut lctx = LiftContext::new(SourceArch::X86_64);
    let mut block = lifter
        .lift_block(0x1000, &reader, &mut lctx)
        .expect("lift BTC block");
    block.set_terminator(Terminator::Return { values: vec![] });
    let block_id = block.id;
    let mut function = SmirFunction::new(FunctionId(0), block_id, 0x1000);
    function.add_block(block);
    crate::smir::optimize::optimize_function(&mut function, crate::smir::optimize::OptLevel::O2);
    assert!(matches!(
        function.blocks[0].ops[1].kind,
        OpKind::Xor {
            src2: SrcOperand::Imm(i64::MIN),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
            ..
        }
    ));

    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    let result = lowerer
        .lower_function(&function)
        .expect("lower optimized BTC block");
    assert!(result.relocations.is_empty());
    let lowered = lowerer.finalize().expect("finalize optimized BTC");
    assert!(
        lowered
            .windows(7)
            .any(|bytes| bytes == [0x48, 0x0F, 0xBA, 0x7C, 0x24, 0x10, 0x3F]),
        "optimized helper-backed BTC must modify the staged store word: {lowered:02X?}"
    );
    assert!(
        lowered
            .windows(7)
            .any(|bytes| bytes == [0x48, 0x0F, 0xBA, 0x64, 0x24, 0x08, 0x3F]),
        "optimized helper-backed BTC must replay CF from the original word: {lowered:02X?}"
    );
}
#[cfg(feature = "smir-jit")]
#[test]
fn lower_helper_backed_bit_scan_consumes_staged_stack_source() {
    // bsf r8w, word ptr [rbx]; hlt
    let (lowered, entry) =
        lower_rex2_block_with_mem_helpers(&[0x66, 0x44, 0x0F, 0xBC, 0x03, 0xF4], true);
    assert!(entry < lowered.len());
    assert!(
        lowered
            .windows(7)
            .any(|bytes| bytes == [0x66, 0x44, 0x0F, 0xBC, 0x44, 0x24, 0x08]),
        "helper-backed BSF must consume the caller-owned stack word: {lowered:02X?}"
    );
    assert!(
        lowered
            .windows(5)
            .any(|bytes| bytes == [0x4C, 0x8B, 0x44, 0x24, 0x10]),
        "zero-source BSF must restore the saved full destination: {lowered:02X?}"
    );
    let helper_call = host_c_helper_reference(X86_GUEST_LOAD_FN_OFFSET);
    assert_eq!(
        lowered
            .windows(helper_call.len())
            .filter(|bytes| *bytes == helper_call)
            .count(),
        1,
        "memory-source bit scan must issue exactly one load helper call"
    );
}
