//! Elided scalar memory temporaries cannot escape an exact native span.

use super::*;
use crate::smir::ir::{CallTarget, PhiNode};

fn families() -> Vec<(&'static str, SmirFunction)> {
    let old = VReg::virt(200);
    let result = VReg::virt(201);
    let flags = VReg::virt(202);
    let materialized = VReg::virt(203);
    let load = OpKind::Load {
        dst: old,
        addr: Address::Direct(gpr(3)),
        width: MemWidth::B8,
        sign: SignExtend::Zero,
    };
    let store = OpKind::Store {
        src: result,
        addr: Address::Direct(gpr(3)),
        width: MemWidth::B8,
    };
    let compute = scalar(
        0,
        result,
        old,
        SrcOperand::Imm64(0x8000_0000),
        OpWidth::W64,
        FlagUpdate::None,
    );
    let replay = scalar(
        0,
        flags,
        old,
        SrcOperand::Imm64(0x8000_0000),
        OpWidth::W64,
        FlagUpdate::All,
    );
    let mov_imm = OpKind::Mov {
        dst: materialized,
        src: SrcOperand::Imm64(0x8000_0000),
        width: OpWidth::W64,
    };
    let atomic = |op| OpKind::AtomicRmw {
        dst: old,
        addr: Address::Direct(gpr(3)),
        src: materialized,
        op,
        width: MemWidth::B8,
        order: MemoryOrder::SeqCst,
    };
    vec![
        (
            "source",
            function(vec![
                load.clone(),
                scalar(
                    0,
                    gpr(0),
                    old,
                    SrcOperand::Imm64(0x8000_0000),
                    OpWidth::W64,
                    FlagUpdate::All,
                ),
            ]),
        ),
        (
            "RMW",
            function(vec![
                load.clone(),
                compute.clone(),
                store.clone(),
                replay.clone(),
            ]),
        ),
        (
            "flagless RMW",
            function(vec![load.clone(), compute, store.clone()]),
        ),
        (
            "atomic",
            function(vec![mov_imm.clone(), atomic(AtomicOp::Add), replay]),
        ),
        (
            "atomic swap",
            function(vec![mov_imm, atomic(AtomicOp::Swap)]),
        ),
        (
            "folded source copy",
            function(vec![
                load.clone(),
                OpKind::Mov {
                    dst: gpr(4),
                    src: SrcOperand::Reg(old),
                    width: OpWidth::W64,
                },
            ]),
        ),
        (
            "folded source zero",
            function(vec![
                load.clone(),
                OpKind::Mov {
                    dst: gpr(5),
                    src: SrcOperand::Imm(0),
                    width: OpWidth::W64,
                },
            ]),
        ),
        (
            "folded RMW copy",
            function(vec![
                load.clone(),
                OpKind::Mov {
                    dst: result,
                    src: SrcOperand::Reg(old),
                    width: OpWidth::W64,
                },
                store.clone(),
            ]),
        ),
        (
            "folded RMW zero",
            function(vec![
                load.clone(),
                OpKind::Mov {
                    dst: result,
                    src: SrcOperand::Imm(0),
                    width: OpWidth::W64,
                },
                store,
            ]),
        ),
        (
            "folded RMW direct store",
            function(vec![
                load,
                OpKind::Store {
                    src: old,
                    addr: Address::Direct(gpr(3)),
                    width: MemWidth::B8,
                },
            ]),
        ),
    ]
}

fn owned(function: &SmirFunction) -> Vec<VReg> {
    function.blocks[0]
        .ops
        .iter()
        .flat_map(|op| op.kind.dests())
        .filter(|reg| matches!(reg, VReg::Virtual(_)))
        .collect()
}

fn terminators(temporary: VReg) -> Vec<Terminator> {
    vec![
        Terminator::Return {
            values: vec![temporary],
        },
        Terminator::CondBranch {
            cond: temporary,
            true_target: BlockId(1),
            false_target: BlockId(1),
        },
        Terminator::Switch {
            index: temporary,
            targets: vec![BlockId(1)],
            default: BlockId(1),
        },
        Terminator::IndirectBranch {
            target: temporary,
            possible_targets: vec![BlockId(1)],
        },
        Terminator::IndirectBranchMem {
            addr: Address::Direct(temporary),
            possible_targets: vec![BlockId(1)],
        },
        Terminator::Call {
            target: CallTarget::Indirect(temporary),
            args: vec![],
            continuation: BlockId(1),
        },
        Terminator::Call {
            target: CallTarget::GuestAddr(0x3000),
            args: vec![temporary],
            continuation: BlockId(1),
        },
        Terminator::Call {
            target: CallTarget::IndirectMem(Address::Direct(temporary)),
            args: vec![],
            continuation: BlockId(1),
        },
        Terminator::TailCall {
            target: CallTarget::Indirect(temporary),
            args: vec![],
        },
        Terminator::TailCall {
            target: CallTarget::GuestAddr(0x3000),
            args: vec![temporary],
        },
        Terminator::TailCall {
            target: CallTarget::X86IndirectMemAddr32(Address::Direct(temporary)),
            args: vec![],
        },
    ]
}

fn escaped_non_op_cases() -> Vec<(String, SmirFunction)> {
    let mut cases = Vec::new();
    for (name, original) in families() {
        assert_lowered(&original, name);
        for temporary in owned(&original) {
            for terminator in terminators(temporary) {
                let label = format!("{name} {temporary:?} {terminator:?}");
                let mut function = original.clone();
                function.blocks[0].set_terminator(terminator);
                cases.push((label, function));
            }
            for phi in [
                PhiNode {
                    dst: temporary,
                    sources: vec![(BlockId(1), gpr(0))],
                },
                PhiNode {
                    dst: VReg::virt(0xFFFF),
                    sources: vec![(BlockId(1), temporary)],
                },
            ] {
                let mut function = original.clone();
                function.blocks[0].phis.push(phi);
                cases.push((format!("{name} {temporary:?} phi"), function));
            }
        }
    }
    cases
}

#[test]
fn scalar_memory_gate_rejects_elided_virtuals_in_phis_and_terminators() {
    for (name, function) in escaped_non_op_cases() {
        assert!(
            !is_native_clobber_safe_excluding(&function, &HashMap::new(), true),
            "{name}"
        );
    }
}

#[test]
fn scalar_memory_lowerer_rejects_elided_virtuals_before_any_byte_emission() {
    for (name, function) in escaped_non_op_cases() {
        let mut lowerer = X86_64Lowerer::new();
        lowerer.set_mem_helpers(true);
        assert!(lowerer.lower_function(&function).is_err(), "{name}");
        assert!(
            lowerer.finalize().unwrap().is_empty(),
            "{name}: rejected after byte emission"
        );
    }
}

#[test]
fn scalar_memory_virtuals_cannot_escape_to_successors_even_if_excluded() {
    for (name, original) in families() {
        for temporary in owned(&original) {
            for redefinition in [false, true] {
                let mut function = original.clone();
                function.blocks[0].set_terminator(Terminator::Branch { target: BlockId(1) });
                let mut successor = SmirBlock::new(BlockId(1), PC + 0x100);
                let kind = if redefinition {
                    OpKind::Mov {
                        dst: temporary,
                        src: SrcOperand::Imm64(1),
                        width: OpWidth::W64,
                    }
                } else {
                    OpKind::Mov {
                        dst: gpr(0),
                        src: SrcOperand::Reg(temporary),
                        width: OpWidth::W64,
                    }
                };
                successor
                    .ops
                    .push(SmirOp::new(OpId(0xFFFF), PC + 0x100, kind));
                successor.set_terminator(Terminator::Return { values: vec![] });
                function.add_block(successor);
                for excluded in [HashMap::new(), HashMap::from([(BlockId(1), PC + 0x100)])] {
                    assert!(
                        !is_native_clobber_safe_excluding(&function, &excluded, true),
                        "{name} {temporary:?} redefine={redefinition} excluded={excluded:?}"
                    );
                }
                let mut lowerer = X86_64Lowerer::new();
                lowerer.set_mem_helpers(true);
                assert!(
                    lowerer.lower_function(&function).is_err(),
                    "{name} {temporary:?} redefine={redefinition}"
                );
                assert!(lowerer.finalize().unwrap().is_empty());
            }
        }
    }
}
