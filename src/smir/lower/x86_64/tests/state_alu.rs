//! State-backed x86 Group-1 bitwise/compare lowering coverage.
//!
//! Guest RSP/RBP live in the `GuestRegs` file while a native region executes,
//! so `AND`/`OR`/`XOR`/`ADC`/`SBB`/`CMP`/`TEST` naming them must compute from
//! that file instead of from the host registers of the same name.

use super::*;
use crate::smir::OpId;
use crate::smir::lower::x86_64::*;

fn x86(reg: X86Reg) -> VReg {
    VReg::Arch(ArchReg::X86(reg))
}

/// GuestRegs slot offset for an architectural GPR index.
const RSP_SLOT: u8 = 4 * 8;
const RBP_SLOT: u8 = 5 * 8;

#[test]
fn state_backed_group1_reads_computes_and_commits_through_the_guest_file() {
    // AND RSP,-16: the classic stack-alignment idiom.
    let bytes = lower_single_op(OpKind::And {
        dst: x86(X86Reg::Rsp),
        src1: x86(X86Reg::Rsp),
        src2: SrcOperand::Imm(-16),
        width: OpWidth::W64,
        flags: FlagUpdate::All,
    });
    assert!(
        bytes.windows(4).any(|b| b == [0x48, 0x8B, 0x50, RSP_SLOT]),
        "must read the guest RSP slot: {bytes:02X?}"
    );
    assert!(
        bytes.windows(4).any(|b| b == [0x48, 0x83, 0xE2, 0xF0]),
        "must apply AND with a sign-extended imm8: {bytes:02X?}"
    );
    assert!(
        bytes.windows(4).any(|b| b == [0x48, 0x89, 0x50, RSP_SLOT]),
        "must commit the guest RSP slot: {bytes:02X?}"
    );
    assert!(
        !bytes.contains(&0x9C) && !bytes.contains(&0x9D),
        "a flag-publishing form must not save/restore RFLAGS: {bytes:02X?}"
    );

    // CMP RBP,RAX publishes flags and must not write any destination slot.
    let bytes = lower_single_op(OpKind::Cmp {
        src1: x86(X86Reg::Rbp),
        src2: SrcOperand::Reg(x86(X86Reg::Rax)),
        width: OpWidth::W64,
    });
    assert!(
        bytes.windows(4).any(|b| b == [0x48, 0x8B, 0x50, RBP_SLOT]),
        "must read the guest RBP slot: {bytes:02X?}"
    );
    assert!(
        bytes.windows(3).any(|b| b == [0x48, 0x8B, 0x38]),
        "must read the guest RAX slot: {bytes:02X?}"
    );
    assert!(
        bytes.windows(3).any(|b| b == [0x48, 0x39, 0xFA]),
        "must compare the two reloaded values: {bytes:02X?}"
    );
    assert!(
        !bytes.windows(4).any(|b| b == [0x48, 0x89, 0x50, RBP_SLOT]),
        "CMP must not commit a destination slot: {bytes:02X?}"
    );
    assert!(
        !bytes.windows(4).any(|b| b == [0x48, 0x89, 0x55, 0x00]),
        "CMP must not rewrite the saved guest RBP word: {bytes:02X?}"
    );

    // TEST ESP,0FFh: a 32-bit flag-only form.
    let bytes = lower_single_op(OpKind::Test {
        src1: x86(X86Reg::Rsp),
        src2: SrcOperand::Imm(0xFF),
        width: OpWidth::W32,
    });
    assert!(
        bytes.windows(3).any(|b| b == [0x8B, 0x50, RSP_SLOT]),
        "must read the guest RSP slot at 32-bit width: {bytes:02X?}"
    );
    assert!(
        bytes
            .windows(6)
            .any(|b| b == [0xF7, 0xC2, 0xFF, 0x00, 0x00, 0x00]),
        "must apply TEST with an imm32: {bytes:02X?}"
    );

    // XOR RBP,RBP with suppressed flags (APX NF) must bracket the sequence with
    // PUSHFQ/POPFQ and keep the saved guest RBP word coherent.
    let bytes = lower_single_op(OpKind::Xor {
        dst: x86(X86Reg::Rbp),
        src1: x86(X86Reg::Rbp),
        src2: SrcOperand::Reg(x86(X86Reg::Rbp)),
        width: OpWidth::W64,
        flags: FlagUpdate::None,
    });
    assert!(
        bytes.contains(&0x9C) && bytes.contains(&0x9D),
        "a flag-suppressed form must save and restore RFLAGS: {bytes:02X?}"
    );
    assert!(
        bytes.windows(3).any(|b| b == [0x48, 0x31, 0xFA]),
        "must XOR the two reloaded values: {bytes:02X?}"
    );
    assert!(
        bytes.windows(4).any(|b| b == [0x48, 0x89, 0x50, RBP_SLOT]),
        "must commit the guest RBP slot: {bytes:02X?}"
    );
    assert!(
        bytes.windows(4).any(|b| b == [0x48, 0x89, 0x55, 0x00]),
        "must synchronize the saved guest RBP word: {bytes:02X?}"
    );

    // Every remaining Group-1 selector must reach its own host opcode.
    for (name, kind, opcode) in [
        (
            "OR",
            OpKind::Or {
                dst: x86(X86Reg::Rsp),
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            0x09u8,
        ),
        (
            "ADC",
            OpKind::Adc {
                dst: x86(X86Reg::Rsp),
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            0x11,
        ),
        (
            "SBB",
            OpKind::Sbb {
                dst: x86(X86Reg::Rsp),
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            0x19,
        ),
        (
            "AND",
            OpKind::And {
                dst: x86(X86Reg::Rsp),
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            0x21,
        ),
        (
            "XOR",
            OpKind::Xor {
                dst: x86(X86Reg::Rsp),
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            0x31,
        ),
        (
            "TEST",
            OpKind::Test {
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
            },
            0x85,
        ),
    ] {
        let bytes = lower_single_op(kind);
        assert!(
            bytes.windows(3).any(|b| b == [0x48, opcode, 0xFA]),
            "{name} must reach its own host opcode: {bytes:02X?}"
        );
        assert!(
            bytes.windows(4).any(|b| b == [0x48, 0x8B, 0x78, 0x08]),
            "{name} must read the guest RCX slot: {bytes:02X?}"
        );
    }
}

#[test]
fn legacy_state_backed_group1_predicate_rejects_shapes_owned_by_other_paths() {
    for (name, kind) in [
        (
            "64-bit immediate that is not a sign-extended imm32",
            OpKind::And {
                dst: x86(X86Reg::Rsp),
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Imm(0x8000_0000),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        ),
        (
            "Imm64 source operand",
            OpKind::Or {
                dst: x86(X86Reg::Rbp),
                src1: x86(X86Reg::Rbp),
                src2: SrcOperand::Imm64(0x1234_5678_9ABC_DEF0),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        ),
        (
            "virtual source",
            OpKind::Cmp {
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Reg(VReg::Virtual(crate::smir::ir::types::VirtualId(0))),
                width: OpWidth::W64,
            },
        ),
        (
            "vector width",
            OpKind::Xor {
                dst: x86(X86Reg::Rsp),
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W128,
                flags: FlagUpdate::All,
            },
        ),
        (
            "partial flag update",
            OpKind::And {
                dst: x86(X86Reg::Rsp),
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::Specific(crate::smir::ir::flags::FlagSet::CF),
            },
        ),
    ] {
        let op = SmirOp::new(OpId(0), 0x1000, kind);
        assert!(
            x86_state_backed_stack_group1_candidate(&op),
            "{name} must be recognized as a state-backed candidate"
        );
        assert!(
            !x86_state_backed_stack_group1_valid(&op),
            "{name} must not be admitted"
        );
        if matches!(
            name,
            "64-bit immediate that is not a sign-extended imm32" | "Imm64 source operand"
        ) {
            assert!(
                x86_scalar_alu_immediate_valid(&op),
                "dedicated W64 path: {name}"
            );
            assert!(
                !lower_single_op(op.kind.clone()).is_empty(),
                "dedicated W64 lowering: {name}"
            );
        }
    }

    // Byte-lane and MULX hints leave the modeled shape even when the operands
    // are otherwise admitted.
    let hinted = OpKind::And {
        dst: x86(X86Reg::Rsp),
        src1: x86(X86Reg::Rsp),
        src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
        width: OpWidth::W64,
        flags: FlagUpdate::All,
    };
    for hint in [X86OpHint::Mulx, X86OpHint::RexByteReg] {
        let mut op = SmirOp::new(OpId(0), 0x1000, hinted.clone());
        op.x86_hint = Some(hint);
        assert!(x86_state_backed_stack_group1_candidate(&op));
        assert!(!x86_state_backed_stack_group1_valid(&op));
    }

    // An encoding-direction hint does not change the architectural result.
    let mut op = SmirOp::new(OpId(0), 0x1000, hinted);
    op.x86_hint = Some(X86OpHint::AluEncoding(X86AluEncoding::RegRm));
    assert!(x86_state_backed_stack_group1_valid(&op));
}

#[test]
fn group1_without_a_stack_operand_keeps_the_direct_lowering() {
    let op = SmirOp::new(
        OpId(0),
        0x1000,
        OpKind::And {
            dst: x86(X86Reg::Rax),
            src1: x86(X86Reg::Rax),
            src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
            width: OpWidth::W64,
            flags: FlagUpdate::All,
        },
    );
    assert!(!x86_state_backed_stack_group1_candidate(&op));
    assert!(!x86_state_backed_stack_group1_valid(&op));

    let bytes = lower_single_op(op.kind);
    assert!(
        bytes.windows(3).any(|b| b == [0x48, 0x21, 0xC8]),
        "plain AND must stay a single host instruction: {bytes:02X?}"
    );
    assert!(
        !bytes.windows(4).any(|b| b == [0x48, 0x8B, 0x45, 0x18]),
        "plain AND must not load the guest state pointer: {bytes:02X?}"
    );
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_state_backed_group1_matches_architectural_results_and_flags() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    const CF: u64 = 1 << 0;
    const ZF: u64 = 1 << 6;

    struct Case {
        name: &'static str,
        kind: OpKind,
        /// (entry GPR file, entry CF) -> (destination slot value or None, expected CF, expected ZF)
        expect: fn(&[u64; 32], bool) -> (Option<(usize, u64)>, bool, bool),
    }

    let cases = [
        Case {
            name: "AND RSP,-16",
            kind: OpKind::And {
                dst: x86(X86Reg::Rsp),
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Imm(-16),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            expect: |gpr, _| {
                let value = gpr[4] & !0xFu64;
                (Some((4, value)), false, value == 0)
            },
        },
        Case {
            name: "OR RBP,RCX",
            kind: OpKind::Or {
                dst: x86(X86Reg::Rbp),
                src1: x86(X86Reg::Rbp),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            expect: |gpr, _| {
                let value = gpr[5] | gpr[1];
                (Some((5, value)), false, value == 0)
            },
        },
        Case {
            name: "XOR ESP,ECX zero-extending",
            kind: OpKind::Xor {
                dst: x86(X86Reg::Rsp),
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W32,
                flags: FlagUpdate::All,
            },
            expect: |gpr, _| {
                let value = u64::from((gpr[4] as u32) ^ (gpr[1] as u32));
                (Some((4, value)), false, value == 0)
            },
        },
        Case {
            name: "CMP RBP,RBP flags only",
            kind: OpKind::Cmp {
                src1: x86(X86Reg::Rbp),
                src2: SrcOperand::Reg(x86(X86Reg::Rbp)),
                width: OpWidth::W64,
            },
            expect: |_, _| (None, false, true),
        },
        Case {
            name: "TEST RSP,RSP flags only",
            kind: OpKind::Test {
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Reg(x86(X86Reg::Rsp)),
                width: OpWidth::W64,
            },
            expect: |gpr, _| (None, false, gpr[4] == 0),
        },
        Case {
            name: "ADC RSP,RCX consumes the incoming carry",
            kind: OpKind::Adc {
                dst: x86(X86Reg::Rsp),
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            expect: |gpr, carry| {
                let (sum, c1) = gpr[4].overflowing_add(gpr[1]);
                let (value, c2) = sum.overflowing_add(u64::from(carry));
                (Some((4, value)), c1 || c2, value == 0)
            },
        },
        Case {
            name: "SBB RBP,RCX consumes the incoming borrow",
            kind: OpKind::Sbb {
                dst: x86(X86Reg::Rbp),
                src1: x86(X86Reg::Rbp),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
            expect: |gpr, carry| {
                let (difference, b1) = gpr[5].overflowing_sub(gpr[1]);
                let (value, b2) = difference.overflowing_sub(u64::from(carry));
                (Some((5, value)), b1 || b2, value == 0)
            },
        },
    ];

    for case in cases {
        for carry in [false, true] {
            let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
            builder.push_op(0x1000, case.kind.clone());
            builder.set_terminator(Terminator::Return { values: vec![] });

            let mut lowerer = X86_64Lowerer::new();
            let lowered = lowerer
                .lower_function(&builder.finish())
                .unwrap_or_else(|error| panic!("{} lowering: {error:?}", case.name));
            let code = lowerer
                .finalize()
                .unwrap_or_else(|error| panic!("{} finalize: {error:?}", case.name));
            let exec = ExecMem::new(&code)
                .unwrap_or_else(|error| panic!("{} mapping: {error:?}", case.name));

            let mut regs = GuestRegs::default();
            for (index, value) in regs.gpr.iter_mut().enumerate() {
                *value = 0x0F1E_2D3C_4B5A_6978u64
                    .wrapping_add((index as u64).wrapping_mul(0x1111_2222_3333_4444));
            }
            regs.rflags = 0x2 | if carry { CF } else { 0 };
            let entry = regs.gpr;
            let (destination, expect_cf, expect_zf) = (case.expect)(&entry, carry);

            let mut expected = entry;
            if let Some((slot, value)) = destination {
                expected[slot] = value;
            }

            exec.run(lowered.entry_offset, &mut regs);

            assert_eq!(
                regs.gpr, expected,
                "{} GPR file (carry-in {carry})",
                case.name
            );
            assert_eq!(
                regs.rflags & CF != 0,
                expect_cf,
                "{} CF (carry-in {carry})",
                case.name
            );
            assert_eq!(
                regs.rflags & ZF != 0,
                expect_zf,
                "{} ZF (carry-in {carry})",
                case.name
            );
        }
    }
}
