//! Local alignment facts must not replace architectural encoding provenance.

use super::*;
use crate::smir::ir::X86InstructionBytes;
use crate::smir::ir::ops::X86VecAlign;
use crate::smir::ir::types::{DispSize, SourceArch};

const PC: u64 = 0x1000;

fn gpr(reg: X86Reg) -> VReg {
    VReg::Arch(ArchReg::X86(reg))
}

fn vector_load(address: Address, width: VecWidth) -> OpKind {
    OpKind::VLoad {
        dst: VReg::virt(100),
        addr: address,
        width,
    }
}

fn immediate(dst: VReg, value: u64) -> OpKind {
    OpKind::Mov {
        dst,
        src: SrcOperand::Imm64(value as i64),
        width: OpWidth::W64,
    }
}

fn function(ops: Vec<OpKind>) -> SmirFunction {
    let mut block = SmirBlock::new(BlockId(0), PC);
    block.ops = ops
        .into_iter()
        .enumerate()
        .map(|(index, kind)| SmirOp::new(OpId(index as u16), PC + index as u64, kind))
        .collect();
    block.set_terminator(Terminator::Return { values: vec![] });
    let mut function = SmirFunction::new(FunctionId(0), block.id, PC);
    function.add_block(block);
    function
}

fn last_hint(function: &SmirFunction) -> Option<X86OpHint> {
    function.blocks.last().unwrap().ops.last().unwrap().x86_hint
}

fn aligned() -> Option<X86OpHint> {
    Some(X86OpHint::VecAlign(X86VecAlign::Aligned))
}

#[test]
fn unknown_stack_frame_and_cfg_entry_registers_have_no_alignment_fact() {
    for base in [gpr(X86Reg::Rsp), gpr(X86Reg::Rbp)] {
        let mut single = function(vec![vector_load(Address::Direct(base), VecWidth::V128)]);
        assert_eq!(vector_alignment_inference(&mut single), 0, "{base:?}");
        assert_eq!(last_hint(&single), None, "{base:?}");

        // A predecessor fact is not a proof at an arbitrary block entry. In
        // particular, the second predecessor may arrive with an unaligned base.
        let mut cfg = function(vec![immediate(base, 0x1000)]);
        cfg.blocks[0].set_terminator(Terminator::Branch { target: BlockId(2) });
        let mut other = SmirBlock::new(BlockId(1), PC + 0x10);
        other
            .ops
            .push(SmirOp::new(OpId(2), PC + 0x10, immediate(base, 0x1001)));
        other.set_terminator(Terminator::Branch { target: BlockId(2) });
        cfg.add_block(other);
        let mut join = SmirBlock::new(BlockId(2), PC + 0x20);
        join.ops.push(SmirOp::new(
            OpId(3),
            PC + 0x20,
            vector_load(Address::Direct(base), VecWidth::V128),
        ));
        join.set_terminator(Terminator::Return { values: vec![] });
        cfg.add_block(join);
        assert_eq!(vector_alignment_inference(&mut cfg), 0, "CFG {base:?}");
        assert_eq!(last_hint(&cfg), None, "CFG {base:?}");
    }
}

#[test]
fn existing_vector_encoding_hints_are_never_replaced() {
    for hint in [
        X86OpHint::VecAlign(X86VecAlign::Unaligned),
        X86OpHint::VecAlign(X86VecAlign::Aligned),
        X86OpHint::SseMov {
            prefix: X86SsePrefix::Rep,
            opcode: 0x6F,
        },
        X86OpHint::RexByteReg,
        X86OpHint::ShiftGroup6,
    ] {
        for store in [false, true] {
            let kind = if store {
                OpKind::VStore {
                    addr: Address::Absolute(0x1000),
                    src: VReg::virt(100),
                    width: VecWidth::V128,
                }
            } else {
                vector_load(Address::Absolute(0x1000), VecWidth::V128)
            };
            let mut function = function(vec![kind]);
            function.blocks[0].ops[0].x86_hint = Some(hint);
            assert_eq!(
                vector_alignment_inference(&mut function),
                0,
                "{hint:?} store={store}"
            );
            assert_eq!(last_hint(&function), Some(hint));
        }
    }
}

#[test]
fn provenance_is_keyed_by_both_block_and_guest_pc_and_preserves_absent_hints() {
    for store in [false, true] {
        let kind = if store {
            OpKind::VStore {
                addr: Address::Absolute(0x1000),
                src: VReg::virt(100),
                width: VecWidth::V128,
            }
        } else {
            vector_load(Address::Absolute(0x1000), VecWidth::V128)
        };
        let base = function(vec![kind]);
        for (block, guest_pc, expected) in [
            (BlockId(0), PC, None),
            (BlockId(1), PC, aligned()),
            (BlockId(0), PC + 1, aligned()),
        ] {
            let mut function = base.clone();
            function.x86_instruction_bytes.insert(
                (block, guest_pc),
                X86InstructionBytes::new(&[0x90]).unwrap(),
            );
            assert_eq!(
                vector_alignment_inference(&mut function),
                usize::from(expected.is_some())
            );
            assert_eq!(
                last_hint(&function),
                expected,
                "{block:?} {guest_pc:#x} store={store}"
            );
        }
    }
}

#[test]
fn generic_constants_and_masks_retain_only_proven_vector_alignment() {
    let base = gpr(X86Reg::Rax);
    for width in [
        VecWidth::V64,
        VecWidth::V128,
        VecWidth::V256,
        VecWidth::V512,
    ] {
        let bytes = width.bytes() as u64;
        for value in [0, 1, 8, 16, 32, 64, 0x1000, 0x1001, u64::MAX - 63, u64::MAX] {
            let mut function = function(vec![
                immediate(base, value),
                vector_load(Address::Direct(base), width),
            ]);
            let expected = if value % bytes == 0 { aligned() } else { None };
            assert_eq!(
                vector_alignment_inference(&mut function),
                usize::from(expected.is_some())
            );
            assert_eq!(last_hint(&function), expected, "{width:?} {value:#x}");
        }
        for low_zero_bits in 0..=6 {
            let mask = u64::MAX << low_zero_bits;
            let mut function = function(vec![
                OpKind::And {
                    dst: base,
                    src1: gpr(X86Reg::Rbx),
                    src2: SrcOperand::Imm(mask as i64),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
                vector_load(Address::Direct(base), width),
            ]);
            let expected = if (1u64 << low_zero_bits) >= bytes {
                aligned()
            } else {
                None
            };
            vector_alignment_inference(&mut function);
            assert_eq!(last_hint(&function), expected, "{width:?} mask={mask:#x}");
        }
    }
}

#[test]
fn partial_unknown_writes_and_side_effects_invalidate_local_facts() {
    let base = gpr(X86Reg::Rax);
    let unknown = gpr(X86Reg::Rbx);
    let mut mutations = [OpWidth::W8, OpWidth::W16, OpWidth::W32, OpWidth::W64]
        .into_iter()
        .map(|width| OpKind::Mov {
            dst: base,
            src: SrcOperand::Reg(unknown),
            width,
        })
        .collect::<Vec<_>>();
    mutations.extend([
        OpKind::Syscall {
            num: unknown,
            args: vec![],
        },
        OpKind::Swi { imm: 0x80 },
        OpKind::WriteSysReg {
            reg: 0,
            src: unknown,
        },
    ]);
    for mutation in mutations {
        let mut function = function(vec![
            immediate(base, 0x1000),
            mutation.clone(),
            vector_load(Address::Direct(base), VecWidth::V128),
        ]);
        assert_eq!(vector_alignment_inference(&mut function), 0, "{mutation:?}");
        assert_eq!(last_hint(&function), None, "{mutation:?}");
    }
}

#[test]
fn ordinary_memory_preserves_unrelated_facts_but_load_destinations_are_invalidated() {
    let base = gpr(X86Reg::Rax);
    let data = gpr(X86Reg::Rbx);
    let mut preserved = function(vec![
        immediate(base, 0x1000),
        OpKind::Load {
            dst: data,
            addr: Address::Absolute(0x2000),
            width: MemWidth::B8,
            sign: SignExtend::Zero,
        },
        OpKind::Store {
            src: data,
            addr: Address::Absolute(0x2008),
            width: MemWidth::B8,
        },
        vector_load(Address::Direct(base), VecWidth::V128),
        OpKind::VStore {
            addr: Address::Direct(base),
            src: VReg::virt(100),
            width: VecWidth::V128,
        },
        vector_load(Address::Direct(base), VecWidth::V128),
    ]);
    assert_eq!(vector_alignment_inference(&mut preserved), 3);
    for index in 3..6 {
        assert_eq!(preserved.blocks[0].ops[index].x86_hint, aligned());
    }

    let mut overwritten = function(vec![
        immediate(base, 0x1000),
        OpKind::Load {
            dst: base,
            addr: Address::Absolute(0x2000),
            width: MemWidth::B8,
            sign: SignExtend::Zero,
        },
        vector_load(Address::Direct(base), VecWidth::V128),
    ]);
    assert_eq!(vector_alignment_inference(&mut overwritten), 0);
    assert_eq!(last_hint(&overwritten), None);
}

#[test]
fn copies_arithmetic_lea_and_conditional_merges_preserve_only_common_low_bits() {
    let dst = gpr(X86Reg::Rax);
    let source = gpr(X86Reg::Rbx);
    for (operation, expected) in [
        (
            OpKind::Mov {
                dst,
                src: SrcOperand::Reg(source),
                width: OpWidth::W64,
            },
            aligned(),
        ),
        (
            OpKind::Add {
                dst,
                src1: dst,
                src2: SrcOperand::Reg(source),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            aligned(),
        ),
        (
            OpKind::Sub {
                dst,
                src1: dst,
                src2: SrcOperand::Imm(8),
                width: OpWidth::W64,
                flags: FlagUpdate::None,
            },
            None,
        ),
        (
            OpKind::CMove {
                dst,
                src: source,
                cond: Condition::Eq,
                width: OpWidth::W64,
            },
            aligned(),
        ),
        (
            OpKind::Select {
                dst,
                cond: gpr(X86Reg::Rcx),
                src_true: dst,
                src_false: source,
                width: OpWidth::W64,
            },
            aligned(),
        ),
        (
            OpKind::Lea {
                dst,
                addr: Address::BaseOffset {
                    base: source,
                    offset: 16,
                    disp_size: DispSize::Auto,
                },
            },
            aligned(),
        ),
        (
            OpKind::X86Lea {
                dst,
                addr: Address::Direct(source),
                width: OpWidth::W64,
            },
            aligned(),
        ),
        (
            OpKind::X86Lea {
                dst,
                addr: Address::Direct(source),
                width: OpWidth::W16,
            },
            None,
        ),
    ] {
        let mut function = function(vec![
            immediate(dst, 0x1000),
            immediate(source, 0x2010),
            operation.clone(),
            vector_load(Address::Direct(dst), VecWidth::V128),
        ]);
        vector_alignment_inference(&mut function);
        assert_eq!(last_hint(&function), expected, "{operation:?}");
    }

    for conditional in [
        OpKind::CMove {
            dst,
            src: source,
            cond: Condition::Eq,
            width: OpWidth::W64,
        },
        OpKind::Select {
            dst,
            cond: gpr(X86Reg::Rcx),
            src_true: dst,
            src_false: source,
            width: OpWidth::W64,
        },
    ] {
        let mut function = function(vec![
            immediate(dst, 0x1000),
            conditional.clone(),
            vector_load(Address::Direct(dst), VecWidth::V128),
        ]);
        assert_eq!(
            vector_alignment_inference(&mut function),
            0,
            "{conditional:?}"
        );
        assert_eq!(last_hint(&function), None);
    }
}

#[test]
fn call_continuations_start_without_pre_call_register_facts() {
    let base = gpr(X86Reg::Rax);
    let mut function = function(vec![immediate(base, 0x1000)]);
    function.blocks[0].set_terminator(Terminator::Call {
        target: CallTarget::GuestAddr(0x8000),
        args: vec![],
        continuation: BlockId(1),
    });
    let mut continuation = SmirBlock::new(BlockId(1), PC + 0x10);
    continuation.ops.push(SmirOp::new(
        OpId(1),
        PC + 0x10,
        vector_load(Address::Direct(base), VecWidth::V128),
    ));
    continuation.set_terminator(Terminator::Return { values: vec![] });
    function.add_block(continuation);
    assert_eq!(vector_alignment_inference(&mut function), 0);
    assert_eq!(last_hint(&function), None);
}

#[test]
fn w64_shift_alignment_uses_masked_counts_and_wrapping_values() {
    let base = gpr(X86Reg::Rax);
    for source in [0, 1, 8, 16, 64, 1u64 << 63, u64::MAX] {
        for amount in [0i64, 1, 3, 4, 6, 63, 64, 65, 127, 128, 129, -1, i64::MIN] {
            let value = source.wrapping_shl((amount as u32) & 63);
            for width in [VecWidth::V128, VecWidth::V512] {
                let mut function = function(vec![
                    immediate(base, source),
                    OpKind::Shl {
                        dst: base,
                        src: base,
                        amount: SrcOperand::Imm(amount),
                        width: OpWidth::W64,
                        flags: FlagUpdate::None,
                    },
                    vector_load(Address::Direct(base), width),
                ]);
                vector_alignment_inference(&mut function);
                // A trailing-zero proof can be conservative after overflow,
                // but every emitted hint must hold for the concrete result.
                if last_hint(&function).is_some() {
                    assert_eq!(
                        value % width.bytes() as u64,
                        0,
                        "{source:#x} << {amount} {width:?}"
                    );
                }
                if amount & 63 == 0 {
                    let expected = if source % width.bytes() as u64 == 0 {
                        aligned()
                    } else {
                        None
                    };
                    assert_eq!(
                        last_hint(&function),
                        expected,
                        "masked-zero {source:#x} << {amount} {width:?}"
                    );
                }
                if (amount as u64 & 63) >= 6 {
                    assert_eq!(
                        last_hint(&function),
                        aligned(),
                        "masked-large {source:#x} << {amount}"
                    );
                }
            }
        }
    }
}

#[test]
fn wrapped_address_arithmetic_retains_proven_low_bits_without_host_overflow() {
    let base = gpr(X86Reg::Rax);
    let index = gpr(X86Reg::Rbx);
    for (address, expected_address) in [
        (Address::Absolute(0), 0),
        (Address::Absolute(1u64 << 63), 1u64 << 63),
        (
            Address::BaseOffset {
                base,
                offset: 64,
                disp_size: DispSize::Disp32,
            },
            0,
        ),
        (
            Address::BaseOffset {
                base,
                offset: 65,
                disp_size: DispSize::Disp32,
            },
            1,
        ),
        (
            Address::PcRel {
                base: Some(u64::MAX - 63),
                offset: 64,
                disp_size: DispSize::Disp32,
            },
            0,
        ),
        (
            Address::PcRel {
                base: Some(0),
                offset: -64,
                disp_size: DispSize::Disp32,
            },
            u64::MAX - 63,
        ),
        (
            Address::BaseIndexScale {
                base: Some(base),
                index,
                scale: 8,
                disp: 64,
                disp_size: DispSize::Disp32,
            },
            0,
        ),
    ] {
        let mut function = function(vec![
            immediate(base, u64::MAX - 63),
            immediate(index, 1u64 << 63),
            vector_load(address.clone(), VecWidth::V512),
        ]);
        vector_alignment_inference(&mut function);
        let expected = if expected_address % 64 == 0 {
            aligned()
        } else {
            None
        };
        assert_eq!(last_hint(&function), expected, "{address:?}");
    }
}

#[test]
fn address_size_and_segment_bases_require_their_own_proof() {
    let base = gpr(X86Reg::Rax);
    for address in [
        Address::X86Addr32(Box::new(Address::Direct(base))),
        Address::SegmentRel {
            segment: gpr(X86Reg::FsBase),
            base: Some(base),
            index: None,
            scale: 1,
            disp: 0,
        },
        Address::X86Addr32(Box::new(Address::SegmentRel {
            segment: gpr(X86Reg::GsBase),
            base: Some(base),
            index: None,
            scale: 1,
            disp: 0,
        })),
        Address::PcRel {
            base: None,
            offset: 0,
            disp_size: DispSize::Disp32,
        },
    ] {
        let mut function = function(vec![
            immediate(base, 0x1000),
            vector_load(address.clone(), VecWidth::V128),
        ]);
        assert_eq!(vector_alignment_inference(&mut function), 0, "{address:?}");
        assert_eq!(last_hint(&function), None, "{address:?}");
    }
}

#[cfg(feature = "smir-jit")]
#[test]
fn existing_evex_rotate_stack_memory_admits_and_lowers_at_all_optimizer_levels() {
    use crate::smir::lift::x86_64::X86_64Lifter;
    use crate::smir::lift::{LiftContext, SmirLifter};
    use crate::smir::lower::SmirLowerer;
    use crate::smir::lower::runtime::is_native_clobber_safe_excluding;
    use crate::smir::lower::x86_64::X86_64Lowerer;

    // VPRORD xmm1,[rsp],7 and VPRORD xmm1,[rbp],7. This existing replay
    // family is independent of the newly added packed-shift memory support.
    for bytes in [
        &[0x62, 0xF1, 0x75, 0x08, 0x72, 0x04, 0x24, 0x07][..],
        &[0x62, 0xF1, 0x75, 0x08, 0x72, 0x45, 0x00, 0x07][..],
    ] {
        let mut lifter = X86_64Lifter::strict();
        let mut context = LiftContext::new(SourceArch::X86_64);
        let lifted = lifter.lift_insn(PC, bytes, &mut context).unwrap();
        assert_eq!(lifted.bytes_consumed, bytes.len());
        let mut base = function(vec![]);
        base.blocks[0].ops = lifted.ops;
        base.x86_instruction_bytes
            .insert((BlockId(0), PC), X86InstructionBytes::new(bytes).unwrap());
        for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
            let mut function = base.clone();
            optimize_function(&mut function, level);
            assert!(
                is_native_clobber_safe_excluding(&function, &HashMap::new(), true),
                "{bytes:02X?} {level:?}: {:#?}",
                function.blocks[0].ops
            );
            let mut lowerer = X86_64Lowerer::new();
            lowerer.set_mem_helpers(true);
            lowerer.set_preserve_vector_mem_helpers(true);
            lowerer.set_jit_fault_deopt_guards(true);
            lowerer.lower_function(&function).unwrap();
            let code = lowerer.finalize().unwrap();
            assert!(!code.is_empty(), "{bytes:02X?} {level:?}");
        }
    }
}
