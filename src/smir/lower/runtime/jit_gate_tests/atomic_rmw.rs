//! Native admission for LOCK-prefixed x86 memory read-modify-write.

use super::*;
use crate::smir::ir::types::{AtomicOp, MemoryOrder};
use crate::smir::lower::runtime::x86_jit_mem_atomic_rmw_sequence_len;

fn x86(reg: X86Reg) -> VReg {
    VReg::Arch(ArchReg::X86(reg))
}

fn virt(id: u32) -> VReg {
    VReg::Virtual(crate::smir::ir::types::VirtualId(id))
}

const PC: u64 = 0x1000;

fn addr() -> Address {
    Address::BaseOffset {
        base: x86(X86Reg::Rdi),
        offset: 592,
        disp_size: DispSize::Disp32,
    }
}

fn mov_imm(dst: VReg, value: i64, width: OpWidth) -> OpKind {
    OpKind::Mov {
        dst,
        src: SrcOperand::Imm(value),
        width,
    }
}

fn atomic(dst: VReg, src: VReg, op: AtomicOp, width: MemWidth) -> OpKind {
    OpKind::AtomicRmw {
        dst,
        addr: addr(),
        src,
        op,
        width,
        order: MemoryOrder::SeqCst,
    }
}

fn or_flags(dst: VReg, old: VReg, src: VReg, width: OpWidth) -> OpKind {
    OpKind::Or {
        dst,
        src1: old,
        src2: SrcOperand::Reg(src),
        width,
        flags: FlagUpdate::All,
    }
}

fn function(ops: Vec<OpKind>) -> crate::smir::ir::SmirFunction {
    let mut builder = FunctionBuilder::new(FunctionId(0), PC);
    for op in ops {
        builder.push_op(PC, op);
    }
    builder.set_terminator(Terminator::Return { values: vec![] });
    builder.finish()
}

fn counts(
    block: &crate::smir::ir::SmirBlock,
) -> (
    std::collections::HashMap<VReg, usize>,
    std::collections::HashMap<VReg, usize>,
) {
    let mut definitions = std::collections::HashMap::new();
    let mut uses = std::collections::HashMap::new();
    for op in &block.ops {
        for reg in op.kind.dests() {
            if matches!(reg, VReg::Virtual(_)) {
                *definitions.entry(reg).or_insert(0usize) += 1;
            }
        }
        for reg in op.kind.source_vregs() {
            if matches!(reg, VReg::Virtual(_)) {
                *uses.entry(reg).or_insert(0usize) += 1;
            }
        }
    }
    (definitions, uses)
}

fn sequence_len(ops: Vec<OpKind>) -> Option<usize> {
    let function = function(ops);
    let block = function.entry_block().unwrap();
    let (definitions, uses) = counts(block);
    x86_jit_mem_atomic_rmw_sequence_len(block, 0, true, &definitions, &uses)
}

fn gate(ops: Vec<OpKind>, allow_mem: bool) -> bool {
    is_native_clobber_safe_excluding(&function(ops), &std::collections::HashMap::new(), allow_mem)
}

#[test]
fn every_lifted_locked_alu_shape_is_recognized() {
    // `lock or byte [rdi+592],1` with the architectural flags still live.
    assert_eq!(
        sequence_len(vec![
            mov_imm(virt(0), 1, OpWidth::W8),
            atomic(virt(1), virt(0), AtomicOp::Or, MemWidth::B1),
            or_flags(virt(2), virt(1), virt(0), OpWidth::W8),
        ]),
        Some(3)
    );
    // The same instruction after optimization proved the flags dead.
    assert_eq!(
        sequence_len(vec![
            mov_imm(virt(0), 1, OpWidth::W8),
            atomic(virt(1), virt(0), AtomicOp::Or, MemWidth::B1),
        ]),
        Some(2)
    );
    // A register source needs no materialization.
    assert_eq!(
        sequence_len(vec![
            atomic(virt(1), x86(X86Reg::Rcx), AtomicOp::Add, MemWidth::B8),
            OpKind::Add {
                dst: virt(2),
                src1: virt(1),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        ]),
        Some(2)
    );
    // `lock xadd dword [rdi+592],eax`: the pre-operation value is written back.
    assert_eq!(
        sequence_len(vec![
            mov_imm(virt(0), 1, OpWidth::W32),
            atomic(virt(1), virt(0), AtomicOp::Add, MemWidth::B4),
            OpKind::Mov {
                dst: x86(X86Reg::Rax),
                src: SrcOperand::Reg(virt(1)),
                width: OpWidth::W32,
            },
        ]),
        Some(3)
    );
    // Flag replay plus write-back is the full four-operation form.
    assert_eq!(
        sequence_len(vec![
            mov_imm(virt(0), 1, OpWidth::W32),
            atomic(virt(1), virt(0), AtomicOp::Add, MemWidth::B4),
            OpKind::Add {
                dst: virt(2),
                src1: virt(1),
                src2: SrcOperand::Reg(virt(0)),
                width: OpWidth::W32,
                flags: FlagUpdate::All,
            },
            OpKind::Mov {
                dst: x86(X86Reg::Rax),
                src: SrcOperand::Reg(virt(1)),
                width: OpWidth::W32,
            },
        ]),
        Some(4)
    );
}

#[test]
fn locked_inc_dec_and_folded_immediate_replays_are_recognized() {
    // `lock dec dword [rdi+592]` updates memory with SUB 1 but publishes the
    // unary DEC flag contract, which leaves CF unchanged.
    assert_eq!(
        sequence_len(vec![
            mov_imm(virt(0), 1, OpWidth::W32),
            atomic(virt(1), virt(0), AtomicOp::Sub, MemWidth::B4),
            OpKind::Dec {
                dst: virt(2),
                src: virt(1),
                width: OpWidth::W32,
                flags: FlagUpdate::All,
            },
        ]),
        Some(3)
    );
    assert_eq!(
        sequence_len(vec![
            mov_imm(virt(0), 1, OpWidth::W8),
            atomic(virt(1), virt(0), AtomicOp::Add, MemWidth::B1),
            OpKind::Inc {
                dst: virt(2),
                src: virt(1),
                width: OpWidth::W8,
                flags: FlagUpdate::All,
            },
        ]),
        Some(3)
    );
    // Constant propagation can fold the materialized immediate into the replay.
    assert_eq!(
        sequence_len(vec![
            mov_imm(virt(0), 4, OpWidth::W32),
            atomic(virt(1), virt(0), AtomicOp::Or, MemWidth::B4),
            OpKind::Or {
                dst: virt(2),
                src1: virt(1),
                src2: SrcOperand::Imm(4),
                width: OpWidth::W32,
                flags: FlagUpdate::All,
            },
        ]),
        Some(3)
    );

    // The unary replay is only exact for a memory update by exactly one, and
    // only for the matching direction.
    assert_eq!(
        sequence_len(vec![
            mov_imm(virt(0), 2, OpWidth::W32),
            atomic(virt(1), virt(0), AtomicOp::Sub, MemWidth::B4),
            OpKind::Dec {
                dst: virt(2),
                src: virt(1),
                width: OpWidth::W32,
                flags: FlagUpdate::All,
            },
        ]),
        None
    );
    assert_eq!(
        sequence_len(vec![
            mov_imm(virt(0), 1, OpWidth::W32),
            atomic(virt(1), virt(0), AtomicOp::Add, MemWidth::B4),
            OpKind::Dec {
                dst: virt(2),
                src: virt(1),
                width: OpWidth::W32,
                flags: FlagUpdate::All,
            },
        ]),
        None
    );
    assert_eq!(
        sequence_len(vec![
            atomic(virt(1), x86(X86Reg::Rcx), AtomicOp::Add, MemWidth::B4),
            OpKind::Inc {
                dst: virt(2),
                src: virt(1),
                width: OpWidth::W32,
                flags: FlagUpdate::All,
            },
        ]),
        None
    );
}

#[test]
fn unmodeled_locked_shapes_fail_closed() {
    // Only the Group-1 arithmetic/logic operations and XCHG have an exact
    // native form.
    for op in [
        AtomicOp::Nand,
        AtomicOp::Max,
        AtomicOp::Min,
        AtomicOp::Umax,
        AtomicOp::Umin,
        AtomicOp::Neg,
    ] {
        assert_eq!(
            sequence_len(vec![
                mov_imm(virt(0), 1, OpWidth::W32),
                atomic(virt(1), virt(0), op, MemWidth::B4),
            ]),
            None,
            "{op:?} must fail closed"
        );
    }
    // A weaker ordering is not the LOCK-prefixed shape the lifter emits.
    assert_eq!(
        sequence_len(vec![
            mov_imm(virt(0), 1, OpWidth::W32),
            OpKind::AtomicRmw {
                dst: virt(1),
                addr: addr(),
                src: virt(0),
                op: AtomicOp::Or,
                width: MemWidth::B4,
                order: MemoryOrder::Relaxed,
            },
        ]),
        None
    );
    // An unconsumed loaded value must not be left dangling in a virtual.
    assert_eq!(
        sequence_len(vec![
            mov_imm(virt(0), 1, OpWidth::W32),
            atomic(virt(1), virt(0), AtomicOp::Or, MemWidth::B4),
            OpKind::Mov {
                dst: x86(X86Reg::Rax),
                src: SrcOperand::Reg(virt(1)),
                width: OpWidth::W8,
            },
        ]),
        None
    );
    // A byte write-back is ambiguous between SPL and AH-class registers.
    assert_eq!(
        sequence_len(vec![
            mov_imm(virt(0), 1, OpWidth::W8),
            atomic(virt(1), virt(0), AtomicOp::Add, MemWidth::B1),
            OpKind::Mov {
                dst: x86(X86Reg::Rax),
                src: SrcOperand::Reg(virt(1)),
                width: OpWidth::W8,
            },
        ]),
        None
    );
    // A state-backed write-back destination has no identity host register.
    assert_eq!(
        sequence_len(vec![
            mov_imm(virt(0), 1, OpWidth::W64),
            atomic(virt(1), virt(0), AtomicOp::Add, MemWidth::B8),
            OpKind::Mov {
                dst: x86(X86Reg::Rsp),
                src: SrcOperand::Reg(virt(1)),
                width: OpWidth::W64,
            },
        ]),
        None
    );
    // A narrower materializer is not the exact W64 source contract.
    assert_eq!(
        sequence_len(vec![
            mov_imm(virt(0), -1, OpWidth::W32),
            atomic(virt(1), virt(0), AtomicOp::Or, MemWidth::B8),
        ]),
        None
    );
}

#[test]
fn full_width_locked_immediates_use_exact_materialized_sources() {
    for op in [
        AtomicOp::Add,
        AtomicOp::Or,
        AtomicOp::And,
        AtomicOp::Sub,
        AtomicOp::Xor,
        AtomicOp::Swap,
    ] {
        for value in [0x8000_0000, i32::MIN as i64 - 1, i64::MIN, i64::MAX] {
            for source in [SrcOperand::Imm(value), SrcOperand::Imm64(value)] {
                let ops = vec![
                    OpKind::Mov {
                        dst: virt(0),
                        src: source,
                        width: OpWidth::W64,
                    },
                    atomic(virt(1), virt(0), op, MemWidth::B8),
                ];
                assert_eq!(sequence_len(ops.clone()), Some(2), "{op:?} {value:#x}");
                assert!(gate(ops.clone(), true), "{op:?} {value:#x}");
                assert!(!gate(ops.clone(), false), "memory helpers are required");
                let mut malformed = function(ops);
                malformed.blocks[0].ops[0].x86_hint = Some(X86OpHint::RexByteReg);
                assert!(
                    !is_native_clobber_safe_excluding(
                        &malformed,
                        &std::collections::HashMap::new(),
                        true
                    ),
                    "materializer metadata {op:?} {value:#x}"
                );
            }
        }
    }
}

#[test]
fn exchange_forms_are_admitted_and_publish_no_flags() {
    // `xchg [rdi+592],rcx` replaces the element outright; the loaded value may
    // be written back to an architectural GPR or dropped entirely.
    assert_eq!(
        sequence_len(vec![atomic(
            virt(1),
            x86(X86Reg::Rcx),
            AtomicOp::Swap,
            MemWidth::B8
        )]),
        Some(1)
    );
    assert_eq!(
        sequence_len(vec![
            atomic(virt(1), x86(X86Reg::Rcx), AtomicOp::Swap, MemWidth::B8),
            OpKind::Mov {
                dst: x86(X86Reg::Rcx),
                src: SrcOperand::Reg(virt(1)),
                width: OpWidth::W64,
            },
        ]),
        Some(2)
    );
    // XCHG writes no flags, so a Group-1 replay is not part of its shape.
    assert_eq!(
        sequence_len(vec![
            atomic(virt(1), x86(X86Reg::Rcx), AtomicOp::Swap, MemWidth::B8),
            OpKind::Add {
                dst: virt(2),
                src1: virt(1),
                src2: SrcOperand::Reg(x86(X86Reg::Rcx)),
                width: OpWidth::W64,
                flags: FlagUpdate::All,
            },
        ]),
        None
    );
    assert!(gate(
        vec![atomic(
            virt(1),
            x86(X86Reg::Rcx),
            AtomicOp::Swap,
            MemWidth::B8
        )],
        true
    ));
    assert!(!gate(
        vec![atomic(
            virt(1),
            x86(X86Reg::Rcx),
            AtomicOp::Swap,
            MemWidth::B8
        )],
        false
    ));
}

#[test]
fn locked_rmw_regions_are_admitted_only_under_memory_jit() {
    for ops in [
        vec![
            mov_imm(virt(0), 1, OpWidth::W8),
            atomic(virt(1), virt(0), AtomicOp::Or, MemWidth::B1),
        ],
        vec![
            mov_imm(virt(0), 1, OpWidth::W32),
            atomic(virt(1), virt(0), AtomicOp::Add, MemWidth::B4),
            OpKind::Mov {
                dst: x86(X86Reg::Rax),
                src: SrcOperand::Reg(virt(1)),
                width: OpWidth::W32,
            },
        ],
    ] {
        assert!(gate(ops.clone(), true));
        assert!(!gate(ops, false));
    }
}

#[test]
fn an_optimized_locked_set_bit_region_stays_admitted() {
    let mut builder = FunctionBuilder::new(FunctionId(0), PC);
    builder.push_op(PC, mov_imm(virt(0), 2, OpWidth::W8));
    builder.push_op(PC, atomic(virt(1), virt(0), AtomicOp::Or, MemWidth::B1));
    builder.push_op(PC, or_flags(virt(2), virt(1), virt(0), OpWidth::W8));
    builder.push_op(
        PC + 4,
        OpKind::Test {
            src1: x86(X86Reg::Rax),
            src2: SrcOperand::Reg(x86(X86Reg::Rax)),
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
            .any(|op| matches!(op.kind, OpKind::AtomicRmw { .. })),
        "O2 must retain the locked memory update"
    );
    assert!(is_native_clobber_safe_excluding(
        &function,
        &std::collections::HashMap::new(),
        true,
    ));
}
