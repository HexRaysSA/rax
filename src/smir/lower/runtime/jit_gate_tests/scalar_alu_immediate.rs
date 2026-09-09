//! Full-width scalar constants must survive optimization and native admission.

use super::*;
use crate::smir::ir::ops::SmirOp;
use crate::smir::ir::types::{AtomicOp, MemoryOrder, OpId};
use crate::smir::ir::{SmirBlock, SmirFunction};
use crate::smir::lower::SmirLowerer;
use crate::smir::lower::x86_64::X86_64Lowerer;
use crate::smir::optimize::{OptLevel, optimize_function};
use std::collections::HashMap;

mod closure;
#[cfg(target_arch = "x86_64")]
mod native;

const PC: u64 = 0x8C00;
const VALUES: [i64; 14] = [
    0,
    1,
    -1,
    i32::MIN as i64 - 1,
    i32::MIN as i64,
    i32::MIN as i64 + 1,
    i32::MAX as i64 - 1,
    i32::MAX as i64,
    i32::MAX as i64 + 1,
    0xFFFF_FFFF,
    i64::MIN,
    i64::MAX,
    0x0123_4567_89AB_CDEF,
    0xAAAA_AAAA_AAAA_AAAAu64 as i64,
];
const LEVELS: [OptLevel; 3] = [OptLevel::O0, OptLevel::O1, OptLevel::O2];

fn gpr(index: u8) -> VReg {
    VReg::Arch(ArchReg::X86(X86Reg::gpr(index)))
}

fn scalar(
    group: u8,
    dst: VReg,
    lhs: VReg,
    rhs: SrcOperand,
    width: OpWidth,
    flags: FlagUpdate,
) -> OpKind {
    match group {
        0 => OpKind::Add {
            dst,
            src1: lhs,
            src2: rhs,
            width,
            flags,
        },
        1 => OpKind::Or {
            dst,
            src1: lhs,
            src2: rhs,
            width,
            flags,
        },
        2 => OpKind::Adc {
            dst,
            src1: lhs,
            src2: rhs,
            width,
            flags,
        },
        3 => OpKind::Sbb {
            dst,
            src1: lhs,
            src2: rhs,
            width,
            flags,
        },
        4 => OpKind::And {
            dst,
            src1: lhs,
            src2: rhs,
            width,
            flags,
        },
        5 => OpKind::Sub {
            dst,
            src1: lhs,
            src2: rhs,
            width,
            flags,
        },
        6 => OpKind::Xor {
            dst,
            src1: lhs,
            src2: rhs,
            width,
            flags,
        },
        7 => OpKind::Cmp {
            src1: lhs,
            src2: rhs,
            width,
        },
        8 => OpKind::Test {
            src1: lhs,
            src2: rhs,
            width,
        },
        _ => panic!("test group outside Group 1/TEST"),
    }
}

fn immediate(value: i64, imm64: bool) -> SrcOperand {
    if imm64 {
        SrcOperand::Imm64(value)
    } else {
        SrcOperand::Imm(value)
    }
}

fn function(ops: Vec<OpKind>) -> SmirFunction {
    let mut block = SmirBlock::new(BlockId(0), PC);
    block.ops = ops
        .into_iter()
        .enumerate()
        .map(|(index, kind)| SmirOp::new(OpId(index as u16), PC, kind))
        .collect();
    block.set_terminator(Terminator::Return { values: vec![] });
    let mut function = SmirFunction::new(FunctionId(0), block.id, PC);
    function.add_block(block);
    function
}

fn assert_lowered(function: &SmirFunction, label: &str) {
    assert!(
        is_native_clobber_safe_excluding(function, &HashMap::new(), true),
        "{label}: admission rejected {:#?}",
        function.blocks[0].ops
    );
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_vector_mem_helpers(true);
    lowerer.set_jit_fault_deopt_guards(true);
    lowerer
        .lower_function(function)
        .unwrap_or_else(|error| panic!("{label}: {error:?}"));
    assert!(!lowerer.finalize().unwrap().is_empty(), "{label}");
}

#[test]
fn every_w64_immediate_group_register_and_alias_admits_and_lowers() {
    let mut profiles = 0;
    for group in 0..=8 {
        for source in 0..32 {
            for destination in [source, (source + 17) & 31] {
                for value in VALUES {
                    for imm64 in [false, true] {
                        for flags in [FlagUpdate::None, FlagUpdate::All] {
                            let function = function(vec![scalar(
                                group,
                                gpr(destination),
                                gpr(source),
                                immediate(value, imm64),
                                OpWidth::W64,
                                flags,
                            )]);
                            let label = format!(
                                "group={group} r{destination},r{source},{value:#x} imm64={imm64} {flags:?}"
                            );
                            assert_lowered(&function, &label);
                            profiles += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(profiles, 9 * 32 * 2 * VALUES.len() * 2 * 2);
}

#[test]
fn optimized_w64_immediate_operations_keep_live_flags_and_values_at_every_level() {
    for level in LEVELS {
        for group in 0..=8 {
            for source in [0, 4, 5, 11, 16, 31] {
                for value in [0x8000_0000, i64::MIN, -1] {
                    for flags in [FlagUpdate::None, FlagUpdate::All] {
                        let mut function = function(vec![scalar(
                            group,
                            gpr(source),
                            gpr(source),
                            SrcOperand::Imm(value),
                            OpWidth::W64,
                            flags,
                        )]);
                        optimize_function(&mut function, level);
                        assert_lowered(
                            &function,
                            &format!("{level:?} group={group} r{source} {value:#x} {flags:?}"),
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn memory_source_w64_immediates_admit_and_lower_all_nine_groups() {
    let loaded = VReg::virt(200);
    for level in LEVELS {
        for group in 0..=8 {
            for destination in 0..32 {
                for value in VALUES {
                    for imm64 in [false, true] {
                        for flags in [FlagUpdate::None, FlagUpdate::All] {
                            let mut function = function(vec![
                                OpKind::Load {
                                    dst: loaded,
                                    addr: Address::Direct(gpr(destination)),
                                    width: MemWidth::B8,
                                    sign: SignExtend::Zero,
                                },
                                scalar(
                                    group,
                                    gpr(destination),
                                    loaded,
                                    immediate(value, imm64),
                                    OpWidth::W64,
                                    flags,
                                ),
                            ]);
                            optimize_function(&mut function, level);
                            assert_lowered(
                                &function,
                                &format!(
                                    "memory source {level:?} r{destination} group={group} {value:#x} imm64={imm64} {flags:?}"
                                ),
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn memory_rmw_w64_immediates_preserve_the_exact_compute_store_replay_shape() {
    let old = VReg::virt(200);
    let result = VReg::virt(201);
    let flags_result = VReg::virt(202);
    for level in LEVELS {
        for group in 0..=6 {
            for value in VALUES {
                for imm64 in [false, true] {
                    for replay in [false, true] {
                        let source = immediate(value, imm64);
                        let mut ops = vec![
                            OpKind::Load {
                                dst: old,
                                addr: Address::Direct(gpr(4)),
                                width: MemWidth::B8,
                                sign: SignExtend::Zero,
                            },
                            scalar(
                                group,
                                result,
                                old,
                                source.clone(),
                                OpWidth::W64,
                                FlagUpdate::None,
                            ),
                            OpKind::Store {
                                src: result,
                                addr: Address::Direct(gpr(4)),
                                width: MemWidth::B8,
                            },
                        ];
                        if replay {
                            ops.push(scalar(
                                group,
                                flags_result,
                                old,
                                immediate(value, !imm64),
                                OpWidth::W64,
                                FlagUpdate::All,
                            ));
                        }
                        let mut function = function(ops);
                        optimize_function(&mut function, level);
                        assert_lowered(
                            &function,
                            &format!(
                                "RMW {level:?} group={group} {value:#x} imm64={imm64} replay={replay}"
                            ),
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn existing_atomic_classes_accept_full_width_materializers_and_folded_replays() {
    let source = VReg::virt(200);
    let old = VReg::virt(201);
    let flags_result = VReg::virt(202);
    for level in LEVELS {
        for (group, op) in [
            (0, AtomicOp::Add),
            (1, AtomicOp::Or),
            (4, AtomicOp::And),
            (5, AtomicOp::Sub),
            (6, AtomicOp::Xor),
        ] {
            for value in VALUES {
                for imm64 in [false, true] {
                    for folded in [false, true] {
                        let rhs = if folded {
                            immediate(value, !imm64)
                        } else {
                            SrcOperand::Reg(source)
                        };
                        let mut function = function(vec![
                            OpKind::Mov {
                                dst: source,
                                src: immediate(value, imm64),
                                width: OpWidth::W64,
                            },
                            OpKind::AtomicRmw {
                                dst: old,
                                addr: Address::Direct(gpr(5)),
                                src: source,
                                op,
                                width: MemWidth::B8,
                                order: MemoryOrder::SeqCst,
                            },
                            scalar(group, flags_result, old, rhs, OpWidth::W64, FlagUpdate::All),
                        ]);
                        optimize_function(&mut function, level);
                        assert_lowered(
                            &function,
                            &format!(
                                "atomic {level:?} group={group} {value:#x} imm64={imm64} folded={folded}"
                            ),
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn full_width_immediate_admission_rejects_unmodeled_register_flags_and_hints() {
    let base = scalar(
        0,
        gpr(0),
        gpr(0),
        SrcOperand::Imm64(0x8000_0000),
        OpWidth::W64,
        FlagUpdate::All,
    );
    let mut cases = vec![
        function(vec![scalar(
            0,
            VReg::virt(1),
            gpr(0),
            SrcOperand::Imm64(0x8000_0000),
            OpWidth::W64,
            FlagUpdate::All,
        )]),
        function(vec![scalar(
            0,
            gpr(0),
            VReg::virt(1),
            SrcOperand::Imm64(0x8000_0000),
            OpWidth::W64,
            FlagUpdate::All,
        )]),
        function(vec![scalar(
            0,
            gpr(0),
            gpr(0),
            SrcOperand::Imm64(0x8000_0000),
            OpWidth::W128,
            FlagUpdate::All,
        )]),
        function(vec![scalar(
            2,
            gpr(0),
            gpr(0),
            SrcOperand::Imm(0x8000_0000),
            OpWidth::W64,
            FlagUpdate::Specific(FlagSet::CF),
        )]),
    ];
    let mut wrong_hint = function(vec![base]);
    wrong_hint.blocks[0].ops[0].x86_hint = Some(X86OpHint::RexByteReg);
    cases.push(wrong_hint);
    for function in cases {
        assert!(
            !is_native_clobber_safe_excluding(&function, &HashMap::new(), true),
            "{:#?}",
            function.blocks[0].ops
        );
    }
}

#[test]
fn full_width_memory_immediates_reject_broken_ssa_width_pc_and_replay_contracts() {
    let old = VReg::virt(200);
    let result = VReg::virt(201);
    let replay = VReg::virt(202);
    let address = Address::Direct(gpr(4));
    let base = function(vec![
        OpKind::Load {
            dst: old,
            addr: address.clone(),
            width: MemWidth::B8,
            sign: SignExtend::Zero,
        },
        scalar(
            0,
            result,
            old,
            SrcOperand::Imm64(0x8000_0000),
            OpWidth::W64,
            FlagUpdate::None,
        ),
        OpKind::Store {
            src: result,
            addr: address,
            width: MemWidth::B8,
        },
        scalar(
            0,
            replay,
            old,
            SrcOperand::Imm(0x8000_0000),
            OpWidth::W64,
            FlagUpdate::All,
        ),
    ]);
    assert_lowered(&base, "mixed-representation RMW");
    let mut mutations = Vec::new();
    let mut wrong = base.clone();
    wrong.blocks[0].ops[3].kind = scalar(
        0,
        replay,
        old,
        SrcOperand::Imm64(0x8000_0001),
        OpWidth::W64,
        FlagUpdate::All,
    );
    mutations.push(("different full replay constant", wrong));
    let mut wrong = base.clone();
    wrong.blocks[0].ops[3].guest_pc += 1;
    mutations.push(("different replay PC", wrong));
    let mut wrong = base.clone();
    wrong.blocks[0].ops[1].x86_hint = Some(X86OpHint::RexByteReg);
    mutations.push(("unsupported compute hint", wrong));
    let mut wrong = base.clone();
    wrong.blocks[0].ops[3].x86_hint = Some(X86OpHint::Mulx);
    mutations.push(("unsupported replay hint", wrong));
    let mut wrong = base.clone();
    wrong.blocks[0].ops[1].kind = scalar(
        0,
        result,
        old,
        SrcOperand::Imm64(0x8000_0000),
        OpWidth::W32,
        FlagUpdate::None,
    );
    mutations.push(("compute width differs from memory", wrong));
    let mut wrong = base.clone();
    wrong.blocks[0].ops.push(SmirOp::new(
        OpId(4),
        PC + 1,
        OpKind::Mov {
            dst: gpr(0),
            src: SrcOperand::Reg(old),
            width: OpWidth::W64,
        },
    ));
    mutations.push(("loaded temporary escapes exact shape", wrong));
    let mut wrong = base.clone();
    wrong.blocks[0].ops.push(SmirOp::new(
        OpId(4),
        PC + 1,
        OpKind::Mov {
            dst: result,
            src: SrcOperand::Imm64(1),
            width: OpWidth::W64,
        },
    ));
    mutations.push(("result has multiple definitions", wrong));
    for (label, wrong) in mutations {
        assert!(
            !is_native_clobber_safe_excluding(&wrong, &HashMap::new(), true),
            "{label}: {wrong:#?}"
        );
    }
}

#[test]
fn folded_memory_shapes_reject_inexact_copy_zero_and_replay_dependencies() {
    let old = VReg::virt(200);
    let result = VReg::virt(201);
    let flags_result = VReg::virt(202);
    let load = OpKind::Load {
        dst: old,
        addr: Address::Direct(gpr(5)),
        width: MemWidth::B8,
        sign: SignExtend::Zero,
    };
    let store = OpKind::Store {
        src: result,
        addr: Address::Direct(gpr(5)),
        width: MemWidth::B8,
    };
    for constant in [false, true] {
        let source = if constant {
            SrcOperand::Imm(0)
        } else {
            SrcOperand::Reg(old)
        };
        let group = if constant { 4 } else { 0 };
        let base = function(vec![
            load.clone(),
            OpKind::Mov {
                dst: result,
                src: source,
                width: OpWidth::W64,
            },
            store.clone(),
            scalar(
                group,
                flags_result,
                old,
                SrcOperand::Imm(0),
                OpWidth::W64,
                FlagUpdate::All,
            ),
        ]);
        assert_lowered(&base, "exact folded RMW");
        let mut wrong = base.clone();
        wrong.blocks[0].ops[3].kind = scalar(
            2,
            flags_result,
            old,
            SrcOperand::Imm(0),
            OpWidth::W64,
            FlagUpdate::All,
        );
        assert!(
            !is_native_clobber_safe_excluding(&wrong, &HashMap::new(), true),
            "ADC 0 is not an unconditional identity"
        );
        let mut wrong = base.clone();
        wrong.blocks[0].ops[1].kind = OpKind::Mov {
            dst: result,
            src: SrcOperand::Imm(1),
            width: OpWidth::W64,
        };
        assert!(
            !is_native_clobber_safe_excluding(&wrong, &HashMap::new(), true),
            "constant 1 is outside folded zero shape"
        );
    }
    let base = function(vec![
        load,
        OpKind::Mov {
            dst: gpr(5),
            src: SrcOperand::Reg(old),
            width: OpWidth::W64,
        },
    ]);
    assert_lowered(&base, "exact folded memory source");
    let mut wrong = base.clone();
    wrong.blocks[0].ops[1].kind = OpKind::Mov {
        dst: gpr(5),
        src: SrcOperand::Reg(VReg::virt(201)),
        width: OpWidth::W64,
    };
    assert!(!is_native_clobber_safe_excluding(
        &wrong,
        &HashMap::new(),
        true
    ));
    let mut wrong = base;
    wrong.blocks[0].ops[1].guest_pc += 1;
    assert!(!is_native_clobber_safe_excluding(
        &wrong,
        &HashMap::new(),
        true
    ));
}

#[test]
fn atomic_immediate_materialization_rejects_width_definition_and_hint_mismatches() {
    let source = VReg::virt(200);
    let old = VReg::virt(201);
    let flags_result = VReg::virt(202);
    let base = function(vec![
        OpKind::Mov {
            dst: source,
            src: SrcOperand::Imm64(0x8000_0000),
            width: OpWidth::W64,
        },
        OpKind::AtomicRmw {
            dst: old,
            addr: Address::Direct(gpr(3)),
            src: source,
            op: AtomicOp::Add,
            width: MemWidth::B8,
            order: MemoryOrder::SeqCst,
        },
        scalar(
            0,
            flags_result,
            old,
            SrcOperand::Imm(0x8000_0000),
            OpWidth::W64,
            FlagUpdate::All,
        ),
    ]);
    assert_lowered(&base, "exact atomic materializer");
    let mut cases = Vec::new();
    let mut wrong = base.clone();
    wrong.blocks[0].ops[0].kind = OpKind::Mov {
        dst: source,
        src: SrcOperand::Imm64(0x8000_0000),
        width: OpWidth::W32,
    };
    cases.push(wrong);
    let mut wrong = base.clone();
    wrong.blocks[0].ops[0].x86_hint = Some(X86OpHint::RexByteReg);
    cases.push(wrong);
    let mut wrong = base.clone();
    wrong.blocks[0].ops[2].x86_hint = Some(X86OpHint::Mulx);
    cases.push(wrong);
    let mut wrong = base.clone();
    wrong.blocks[0].ops.push(SmirOp::new(
        OpId(3),
        PC + 1,
        OpKind::Mov {
            dst: source,
            src: SrcOperand::Imm64(7),
            width: OpWidth::W64,
        },
    ));
    cases.push(wrong);
    let mut wrong = base;
    wrong.blocks[0].ops[2].kind = scalar(
        0,
        flags_result,
        old,
        SrcOperand::Imm(0x8000_0001),
        OpWidth::W64,
        FlagUpdate::All,
    );
    cases.push(wrong);
    for wrong in cases {
        assert!(
            !is_native_clobber_safe_excluding(&wrong, &HashMap::new(), true),
            "{wrong:#?}"
        );
    }
}
