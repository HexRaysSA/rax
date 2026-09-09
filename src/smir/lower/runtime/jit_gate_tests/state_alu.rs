//! Native-admission coverage for state-backed x86 Group-1 stack operations.
//!
//! `and rsp,-16`, `test rsp,0Fh`, `cmp rbp,rax` and the rest of the Group-1
//! family naming guest RSP/RBP were unconditional interpreter frontiers. They
//! now lower through the `GuestRegs` file, while every unmodeled operand class
//! still fails closed.

use super::*;
use crate::smir::lower::SmirLowerer;
use crate::smir::lower::x86_64::{
    x86_scalar_alu_immediate_valid, x86_state_backed_stack_group1_candidate,
    x86_state_backed_stack_group1_valid,
};

fn x86(reg: X86Reg) -> VReg {
    VReg::Arch(ArchReg::X86(reg))
}

fn admitted_shapes() -> Vec<(&'static str, OpKind)> {
    vec![
        (
            "and rsp,-16 stack alignment",
            OpKind::And {
                dst: x86(X86Reg::Rsp),
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Imm(-16),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        ),
        (
            "or rbp,rcx",
            OpKind::Or {
                dst: x86(X86Reg::Rbp),
                src1: x86(X86Reg::Rbp),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        ),
        (
            "xor esp,ecx",
            OpKind::Xor {
                dst: x86(X86Reg::Rsp),
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W32,
                flags: FlagUpdate::All,
            },
        ),
        (
            "adc rsp,rcx",
            OpKind::Adc {
                dst: x86(X86Reg::Rsp),
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        ),
        (
            "sbb rbp,rcx",
            OpKind::Sbb {
                dst: x86(X86Reg::Rbp),
                src1: x86(X86Reg::Rbp),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        ),
        (
            "cmp rbp,rax",
            OpKind::Cmp {
                src1: x86(X86Reg::Rbp),
                src2: SrcOperand::Reg(x86(X86Reg::Rax)),
                width: OpWidth::W64,
            },
        ),
        (
            "cmp rax,rsp with a stack second source",
            OpKind::Cmp {
                src1: x86(X86Reg::Rax),
                src2: SrcOperand::Reg(x86(X86Reg::Rsp)),
                width: OpWidth::W64,
            },
        ),
        (
            "test spl,spl byte form",
            OpKind::Test {
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Reg(x86(X86Reg::Rsp)),
                width: OpWidth::W8,
            },
        ),
        (
            "test bp,1 word form",
            OpKind::Test {
                src1: x86(X86Reg::Rbp),
                src2: SrcOperand::Imm(1),
                width: OpWidth::W16,
            },
        ),
    ]
}

#[test]
fn group1_stack_operations_are_admitted_and_lower_natively() {
    for (name, kind) in admitted_shapes() {
        let op = crate::smir::ir::ops::SmirOp::new(
            crate::smir::ir::types::OpId(0),
            0x1000,
            kind.clone(),
        );
        assert!(op.is_jit_safe(), "{name} must stay on the op whitelist");
        assert!(
            x86_state_backed_stack_group1_candidate(&op),
            "{name} must be a state-backed candidate"
        );
        assert!(
            x86_state_backed_stack_group1_valid(&op),
            "{name} must be an admitted state-backed shape"
        );
        assert!(x86_gate(kind.clone()), "{name} must pass the x86-64 gate");

        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(0x1000, kind);
        builder.set_terminator(Terminator::Return { values: vec![] });
        let mut lowerer = crate::smir::lower::x86_64::X86_64Lowerer::new();
        lowerer
            .lower_function(&builder.finish())
            .unwrap_or_else(|error| panic!("{name} lowering: {error:?}"));
    }
}

#[test]
fn full_width_group1_stack_immediates_use_the_dedicated_scalar_path() {
    for (name, kind) in [
        (
            "64-bit immediate wider than imm32",
            OpKind::And {
                dst: x86(X86Reg::Rsp),
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Imm(0x8000_0000),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        ),
        (
            "Imm64 source",
            OpKind::Or {
                dst: x86(X86Reg::Rbp),
                src1: x86(X86Reg::Rbp),
                src2: SrcOperand::Imm64(0x1234_5678_9ABC_DEF0),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        ),
    ] {
        let op = crate::smir::ir::ops::SmirOp::new(
            crate::smir::ir::types::OpId(0),
            0x1000,
            kind.clone(),
        );
        assert!(x86_state_backed_stack_group1_candidate(&op), "{name}");
        // The legacy RI-only classifier remains narrow. Complete W64
        // constants now have a separate, non-truncating native path.
        assert!(!x86_state_backed_stack_group1_valid(&op), "{name}");
        assert!(x86_scalar_alu_immediate_valid(&op), "{name}");
        assert!(x86_gate(kind.clone()), "{name}");

        let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
        builder.push_op(0x1000, kind);
        builder.set_terminator(Terminator::Return { values: vec![] });
        crate::smir::lower::x86_64::X86_64Lowerer::new()
            .lower_function(&builder.finish())
            .unwrap_or_else(|error| panic!("{name} lowering: {error:?}"));
    }
}

#[test]
fn unmodeled_group1_stack_operands_still_fail_closed() {
    for (name, kind) in [
        (
            "shifted source operand",
            OpKind::Xor {
                dst: x86(X86Reg::Rsp),
                src1: x86(X86Reg::Rsp),
                src2: SrcOperand::Shifted {
                    reg: x86(X86Reg::Rcx),
                    shift: ShiftOp::Lsl,
                    amount: 2,
                },
                width: OpWidth::W64,
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
                flags: FlagUpdate::Specific(FlagSet::CF),
            },
        ),
    ] {
        let op = crate::smir::ir::ops::SmirOp::new(
            crate::smir::ir::types::OpId(0),
            0x1000,
            kind.clone(),
        );
        assert!(
            x86_state_backed_stack_group1_candidate(&op),
            "{name} must be recognized as a state-backed candidate"
        );
        assert!(
            !x86_state_backed_stack_group1_valid(&op),
            "{name} must not be admitted"
        );
        assert!(
            !x86_gate(kind),
            "{name} must be rejected by the x86-64 gate"
        );
    }

    // A byte-lane hint leaves the modeled shape and must be rejected.
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(
        0x1000,
        OpKind::And {
            dst: x86(X86Reg::Rsp),
            src1: x86(X86Reg::Rsp),
            src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
            width: OpWidth::W64,
            flags: FlagUpdate::All,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut hinted = builder.finish();
    hinted.blocks[0].ops[0].x86_hint = Some(X86OpHint::RexByteReg);
    assert!(!x86_state_backed_stack_group1_valid(
        &hinted.blocks[0].ops[0]
    ));
    assert!(!is_native_clobber_safe(&hinted));
}

#[test]
fn an_aligned_stack_frame_region_survives_o2_and_stays_admitted() {
    // sub rsp,0x20 ; and rsp,-16 ; test rsp,rsp ; mov rax,rsp
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(
        0x1000,
        OpKind::Sub {
            dst: x86(X86Reg::Rsp),
            src1: x86(X86Reg::Rsp),
            src2: SrcOperand::Imm(0x20),
            width: OpWidth::W64,
            flags: FlagUpdate::All,
        },
    );
    builder.push_op(
        0x1004,
        OpKind::And {
            dst: x86(X86Reg::Rsp),
            src1: x86(X86Reg::Rsp),
            src2: SrcOperand::Imm(-16),
            width: OpWidth::W64,
            flags: FlagUpdate::All,
        },
    );
    builder.push_op(
        0x1008,
        OpKind::Test {
            src1: x86(X86Reg::Rsp),
            src2: SrcOperand::Reg(x86(X86Reg::Rsp)),
            width: OpWidth::W64,
        },
    );
    builder.push_op(
        0x100B,
        OpKind::Mov {
            dst: x86(X86Reg::Rax),
            src: SrcOperand::Reg(x86(X86Reg::Rsp)),
            width: OpWidth::W64,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut function = builder.finish();
    crate::smir::optimize::optimize_function(&mut function, crate::smir::optimize::OptLevel::O2);

    assert!(
        function
            .blocks
            .iter()
            .flat_map(|block| &block.ops)
            .any(|op| matches!(op.kind, OpKind::And { .. })),
        "O2 must retain the stack alignment"
    );
    assert!(is_native_clobber_safe(&function));
}
