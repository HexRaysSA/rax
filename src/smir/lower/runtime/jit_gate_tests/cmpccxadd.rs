//! Exact original-VEX CMPccXADD admission and lowering coverage.

use crate::smir::lower::x86_64::test_support::host_c_helper_reference;
use std::collections::HashMap;

use super::*;
use crate::smir::ir::ops::{OpKind, SmirOp, X86AluEncoding, X86OpHint};
use crate::smir::ir::types::{
    Address, ArchReg, BlockId, Condition, FunctionId, MemWidth, MemoryOrder, OpId, VReg, X86Reg,
};
use crate::smir::ir::{SmirBlock, SmirFunction, Terminator, X86InstructionBytes};
use crate::smir::lift::x86_64::X86_64Lifter;
use crate::smir::lift::{ControlFlow, LiftContext, SmirLifter};
use crate::smir::lower::runtime::{
    GuestRegs, is_native_clobber_safe_excluding, is_x86_aarch64_native_clobber_safe_excluding,
    x86_jit_cmpccxadd_sequence,
};
use crate::smir::lower::x86_64::X86_64Lowerer;
use crate::smir::lower::{SmirLowerer, X86_GUEST_CMPCCXADD_FN_OFFSET, X86_GUEST_CPUID_XOP_OFFSET};
use crate::smir::optimize::OptLevel;

const PC: u64 = 0xCC00;
const LEVELS: [OptLevel; 3] = [OptLevel::O0, OptLevel::O1, OptLevel::O2];

fn x86_condition(condition_code: u8) -> Condition {
    match condition_code {
        0x0 => Condition::Overflow,
        0x1 => Condition::NoOverflow,
        0x2 => Condition::Ult,
        0x3 => Condition::Uge,
        0x4 => Condition::Eq,
        0x5 => Condition::Ne,
        0x6 => Condition::Ule,
        0x7 => Condition::Ugt,
        0x8 => Condition::Negative,
        0x9 => Condition::Positive,
        0xA => Condition::Parity,
        0xB => Condition::NoParity,
        0xC => Condition::Slt,
        0xD => Condition::Sge,
        0xE => Condition::Sle,
        0xF => Condition::Sgt,
        _ => unreachable!("four-bit condition code"),
    }
}

fn instruction(cmp: u8, add: u8, base: u8, width: MemWidth, cc: u8) -> Vec<u8> {
    assert!(cmp < 16 && add < 16 && base < 16 && cc < 16);
    assert!(matches!(width, MemWidth::B4 | MemWidth::B8));
    let mut bytes = vec![
        0xC4,
        (if cmp < 8 { 0x80 } else { 0 }) | 0x40 | (if base < 8 { 0x20 } else { 0 }) | 2,
        (u8::from(width == MemWidth::B8) << 7) | ((!add & 0x0F) << 3) | 1,
        0xE0 | cc,
        0x40 | ((cmp & 7) << 3) | (base & 7),
    ];
    if base & 7 == 4 {
        bytes.push(0x24);
    }
    bytes.push(0x20);
    bytes
}

fn lift(bytes: &[u8]) -> SmirFunction {
    let mut lifter = X86_64Lifter::strict();
    let mut context = LiftContext::new(crate::smir::ir::types::SourceArch::X86_64);
    let result = lifter
        .lift_insn(PC, bytes, &mut context)
        .unwrap_or_else(|error| panic!("{bytes:02X?}: {error:?}"));
    assert_eq!(result.bytes_consumed, bytes.len(), "{bytes:02X?}");
    assert!(matches!(result.control_flow, ControlFlow::Fallthrough));

    let mut block = SmirBlock::new(BlockId(0), PC);
    block.ops = result.ops;
    block.set_terminator(Terminator::Return { values: Vec::new() });
    let mut function = SmirFunction::new(FunctionId(0), block.id, PC);
    function.add_block(block);
    function.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(bytes).expect("CMPccXADD instruction provenance"),
    );
    function
}

fn recognize(function: &SmirFunction, allow_mem: bool) -> bool {
    x86_jit_cmpccxadd_sequence(
        &function.blocks[0],
        0,
        allow_mem,
        &function.x86_instruction_bytes,
    )
    .is_some()
}

fn lower(function: &SmirFunction) -> Vec<u8> {
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_jit_fault_deopt_guards(true);
    lowerer
        .lower_function(function)
        .expect("lower exact CMPccXADD");
    lowerer.finalize().expect("finalize exact CMPccXADD")
}

#[test]
fn every_original_vex_condition_width_and_register_pair_is_admitted() {
    let mut admitted = 0usize;
    for cc in 0..16 {
        for width in [MemWidth::B4, MemWidth::B8] {
            for cmp in 0..16 {
                for add in 0..16 {
                    let function = lift(&instruction(cmp, add, 3, width, cc));
                    let [alignment, op] = function.blocks[0].ops.as_slice() else {
                        panic!("expected exact CMPccXADD alignment/atomic pair")
                    };
                    assert!(matches!(
                        &alignment.kind,
                        OpKind::X86CheckAlignmentAc {
                            addr,
                            access_size,
                            alignment,
                            stack_segment: false,
                            natural_alignment: false,
                        } if matches!(
                            addr,
                            Address::BaseOffset {
                                base: VReg::Arch(ArchReg::X86(X86Reg::Rbx)),
                                offset: 0x20,
                                ..
                            }
                        ) && *access_size == width.bytes() as u8
                            && *alignment == width.bytes() as u8
                    ));
                    assert!(
                        matches!(
                            op.kind,
                            OpKind::AtomicCmpXadd {
                                dst_old,
                                cmp: compared,
                                add: added,
                                cond,
                                width: op_width,
                                order: MemoryOrder::SeqCst,
                                ..
                            } if dst_old == compared
                                && compared == VReg::Arch(ArchReg::X86(X86Reg::gpr(cmp)))
                                && added == VReg::Arch(ArchReg::X86(X86Reg::gpr(add)))
                                && cond == x86_condition(cc)
                                && op_width == width
                        ),
                        "{cc:#x} {width:?} cmp={cmp} add={add}: {op:?}"
                    );
                    assert!(recognize(&function, true));
                    assert!(!recognize(&function, false));
                    assert!(is_native_clobber_safe_excluding(
                        &function,
                        &HashMap::new(),
                        true
                    ));
                    admitted += 1;
                }
            }
        }
    }
    assert_eq!(admitted, 16 * 2 * 16 * 16);
}

#[test]
fn all_profiles_and_state_backed_register_classes_lower_through_the_helper() {
    let mut lowered = 0usize;
    for cc in 0..16 {
        for width in [MemWidth::B4, MemWidth::B8] {
            for cmp in [0, 4, 5, 9, 15] {
                for add in [0, 4, 5, 10, 15] {
                    for level in LEVELS {
                        let mut function = lift(&instruction(cmp, add, 12, width, cc));
                        crate::smir::optimize::optimize_function(&mut function, level);
                        assert!(recognize(&function, true), "{level:?}");
                        assert!(is_native_clobber_safe_excluding(
                            &function,
                            &HashMap::new(),
                            true
                        ));
                        let code = lower(&function);
                        let helper_call = host_c_helper_reference(X86_GUEST_CMPCCXADD_FN_OFFSET);
                        assert!(
                            code.windows(helper_call.len())
                                .any(|window| window == helper_call),
                            "{level:?} cc={cc:#x} {width:?} cmp={cmp} add={add}"
                        );
                        lowered += 1;
                    }
                }
            }
        }
    }
    assert_eq!(lowered, 16 * 2 * 5 * 5 * LEVELS.len());
}

#[test]
fn malformed_ir_provenance_and_instruction_boundaries_fail_closed() {
    let bytes = instruction(9, 10, 3, MemWidth::B8, 7);
    let valid = lift(&bytes);
    assert!(recognize(&valid, true));
    let mut malformed = Vec::new();

    let mut missing_provenance = valid.clone();
    missing_provenance.x86_instruction_bytes.clear();
    malformed.push(("missing provenance", missing_provenance));

    let mut evex_provenance = valid.clone();
    evex_provenance.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(&[0x62, 0xEA, 0x65, 0x08, 0xE7, 0x0B]).unwrap(),
    );
    malformed.push(("APX-promoted EVEX provenance", evex_provenance));

    for (name, mutate) in [
        ("destination differs from comparison", 0u8),
        ("virtual comparison operand", 1),
        ("EGPR addend", 2),
        ("unsupported width", 3),
        ("non-sequential order", 4),
        ("unconditional condition", 5),
        ("invalid address", 6),
    ] {
        let mut function = valid.clone();
        let OpKind::AtomicCmpXadd {
            dst_old,
            addr,
            cmp,
            add,
            cond,
            width,
            order,
        } = &mut function.blocks[0].ops[1].kind
        else {
            unreachable!("valid CMPccXADD shape")
        };
        match mutate {
            0 => *dst_old = VReg::Arch(ArchReg::X86(X86Reg::R8)),
            1 => *cmp = VReg::Virtual(crate::smir::ir::types::VirtualId(0)),
            2 => *add = VReg::Arch(ArchReg::X86(X86Reg::R16)),
            3 => *width = MemWidth::B2,
            4 => *order = MemoryOrder::Relaxed,
            5 => *cond = Condition::Always,
            6 => *addr = Address::Direct(VReg::Virtual(crate::smir::ir::types::VirtualId(1))),
            _ => unreachable!(),
        }
        malformed.push((name, function));
    }

    let mut hinted_guard = valid.clone();
    hinted_guard.blocks[0].ops[0].x86_hint = Some(X86OpHint::AluEncoding(X86AluEncoding::RmReg));
    malformed.push(("unexpected alignment hint", hinted_guard));

    let mut hinted_atomic = valid.clone();
    hinted_atomic.blocks[0].ops[1].x86_hint = Some(X86OpHint::AluEncoding(X86AluEncoding::RmReg));
    malformed.push(("unexpected atomic hint", hinted_atomic));

    for (name, mutate) in [
        ("wrong guarded access size", 0_u8),
        ("wrong guarded alignment", 1),
        ("wrong guarded segment class", 2),
        ("APX natural-alignment guard", 3),
        ("guarded address differs from atomic address", 4),
    ] {
        let mut function = valid.clone();
        let OpKind::X86CheckAlignmentAc {
            addr,
            access_size,
            alignment,
            stack_segment,
            natural_alignment,
        } = &mut function.blocks[0].ops[0].kind
        else {
            unreachable!("valid CMPccXADD alignment shape")
        };
        match mutate {
            0 => *access_size = 4,
            1 => *alignment = 4,
            2 => *stack_segment = true,
            3 => *natural_alignment = true,
            4 => *addr = Address::Direct(VReg::Arch(ArchReg::X86(X86Reg::Rax))),
            _ => unreachable!(),
        }
        malformed.push((name, function));
    }

    let mut following_fragment = valid.clone();
    following_fragment.blocks[0]
        .ops
        .push(SmirOp::new(OpId(2), PC, OpKind::Nop));
    malformed.push(("following same-PC fragment", following_fragment));

    let mut preceding_fragment = valid.clone();
    preceding_fragment.blocks[0]
        .ops
        .insert(0, SmirOp::new(OpId(1), PC, OpKind::Nop));
    malformed.push(("preceding same-PC fragment", preceding_fragment));

    let mut mismatched_bytes = valid.clone();
    mismatched_bytes.x86_instruction_bytes.insert(
        (BlockId(0), PC),
        X86InstructionBytes::new(&instruction(8, 10, 3, MemWidth::B8, 7)).unwrap(),
    );
    malformed.push(("operand-mismatched bytes", mismatched_bytes));

    for (name, function) in malformed {
        assert!(
            !function.blocks[0].ops.iter().enumerate().any(|(index, _)| {
                x86_jit_cmpccxadd_sequence(
                    &function.blocks[0],
                    index,
                    true,
                    &function.x86_instruction_bytes,
                )
                .is_some()
            }),
            "{name}"
        );
    }
}

#[test]
fn append_only_helper_offset_matches_the_guest_register_layout() {
    assert_eq!(GuestRegs::default().cmpccxadd_fn, 0);
    assert_eq!(
        std::mem::offset_of!(GuestRegs, cmpccxadd_fn),
        X86_GUEST_CMPCCXADD_FN_OFFSET as usize
    );
    assert_eq!(
        X86_GUEST_CMPCCXADD_FN_OFFSET,
        X86_GUEST_CPUID_XOP_OFFSET + 8
    );
}

#[test]
fn x86_aarch64_bridge_retains_the_translated_memory_frontier() {
    let function = lift(&instruction(9, 10, 3, MemWidth::B8, 5));
    assert!(
        !is_x86_aarch64_native_clobber_safe_excluding(&function, &HashMap::new()),
        "the x86-on-AArch64 identity bridge lacks a translated atomic-memory transaction"
    );
}
