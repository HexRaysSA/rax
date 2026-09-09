//! Byte legality, complete graph binding, and native-admission frontiers.

use super::*;
use crate::smir::ir::flags::FlagUpdate;
use crate::smir::ir::ops::{SmirOp, X86OpHint, X86VecAlign};
use crate::smir::ir::types::{ArchReg, MemWidth, OpId, OpWidth, SignExtend, SrcOperand, X86Reg};
use crate::smir::lower::runtime::{X86_GUEST_LOAD_FN_OFFSET, X86_GUEST_STORE_FN_OFFSET};

fn classify(bytes: &[u8]) -> Option<crate::smir::ir::X86EvexVsibMemoryEncoding> {
    X86InstructionBytes::new(bytes)?.evex_vsib_memory_encoding()
}

fn assert_rejected_before_emission(function: &SmirFunction) {
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_vector_mem_helpers(true);
    lowerer.set_native_vector_state_active(true);
    lowerer.set_narrow_vector_opmask_helpers(true);
    lowerer.set_jit_fault_deopt_guards(true);
    assert!(
        lowerer.lower_function(function).is_err(),
        "escaping VSIB virtual must not be lowered"
    );
    assert!(
        lowerer.finalize().unwrap().is_empty(),
        "reject malformed VSIB before any native byte emission"
    );
}

#[test]
fn vsib_classifier_matches_independent_llvm_encodings() {
    // LLVM MC -triple=x86_64 -x86-asm-syntax=intel -show-encoding,
    // independently executed 2026-09-08:
    // VGATHERDPS ZMM1{K3},[RAX+ZMM2*4]
    // VPSCATTERQQ [R29+ZMM30*8-64]{K7},ZMM17
    // VGATHERQPS XMM17{K3},[EAX+XMM30*2]
    for (bytes, scatter, data, index, base, scale, disp, addr32, lanes, apx) in [
        (
            &[0x62, 0xF2, 0x7D, 0x4B, 0x92, 0x0C, 0x90][..],
            false,
            1,
            2,
            0,
            4,
            0,
            false,
            16,
            false,
        ),
        (
            &[0x62, 0x8A, 0xFD, 0x47, 0xA1, 0x4C, 0xF5, 0xF8][..],
            true,
            17,
            30,
            29,
            8,
            -64,
            false,
            8,
            true,
        ),
        (
            &[0x67, 0x62, 0xA2, 0x7D, 0x03, 0x93, 0x0C, 0x70][..],
            false,
            17,
            30,
            0,
            2,
            0,
            true,
            2,
            false,
        ),
    ] {
        let actual = classify(bytes).unwrap();
        assert_eq!(actual.scatter, scatter);
        assert_eq!(actual.data_register, data);
        assert_eq!(actual.index_register, index);
        assert_eq!(actual.base, Some(base));
        assert_eq!(actual.scale, scale);
        assert_eq!(actual.displacement, disp);
        assert_eq!(actual.address_32, addr32);
        assert_eq!(actual.lanes, lanes);
        assert_eq!(actual.requires_apx, apx);
        for level in LEVELS {
            let function = lift(bytes, level);
            assert!(
                sequence(&function, true).is_some(),
                "{bytes:02X?} {level:?}: {:#?}",
                function.blocks[0].ops
            );
        }
    }
}

#[test]
fn vsib_classifier_covers_all_shapes_register_extensions_and_vsib_addresses() {
    assert_eq!(cases().len(), 48);
    for case in cases() {
        for base in [
            None,
            Some(0),
            Some(4),
            Some(5),
            Some(8),
            Some(13),
            Some(16),
            Some(21),
            Some(24),
            Some(29),
            Some(31),
        ] {
            for scale in [1, 2, 4, 8] {
                for addr32 in [false, true] {
                    for segment in [None, Some(0x64), Some(0x65)] {
                        for unused_x4 in [false, true] {
                            let disp8 = base.map(|_| -128);
                            let bytes =
                                case.address(base, scale, disp8, addr32, segment, unused_x4);
                            let actual = classify(&bytes)
                                .unwrap_or_else(|| panic!("{case:?}: {bytes:02X?}"));
                            assert_eq!(actual.scatter, case.scatter);
                            assert_eq!(actual.data_register, case.data);
                            assert_eq!(actual.index_register, case.index);
                            assert_eq!(actual.writemask, case.mask);
                            assert_eq!(actual.width, case.width());
                            assert_eq!(actual.data_elem.bytes(), u32::from(case.data_bytes));
                            assert_eq!(actual.index_elem.bytes(), u32::from(case.index_bytes));
                            assert_eq!(usize::from(actual.lanes), case.lanes());
                            assert_eq!(actual.base, base);
                            assert_eq!(actual.scale, scale);
                            assert_eq!(
                                actual.displacement,
                                if base.is_some() {
                                    -128 * i64::from(case.data_bytes)
                                } else {
                                    0
                                }
                            );
                            assert_eq!(actual.address_32, addr32);
                            assert_eq!(
                                actual.segment,
                                segment.map(|s| if s == 0x64 {
                                    X86Reg::FsBase
                                } else {
                                    X86Reg::GsBase
                                })
                            );
                            assert_eq!(actual.requires_apx, base.is_some_and(|reg| reg >= 16));
                        }
                    }
                }
            }
        }
        for data in 0..32 {
            for index in 0..32 {
                let bytes = Case {
                    data,
                    index,
                    ..case
                }
                .bytes();
                let actual = classify(&bytes);
                if !case.scatter && data == index {
                    assert!(actual.is_none(), "gather destination/index alias");
                } else {
                    let actual = actual.unwrap();
                    assert_eq!((actual.data_register, actual.index_register), (data, index));
                }
            }
        }
    }
}

#[test]
fn vsib_classifier_rejects_reserved_fields_non_vsib_and_inexact_lengths() {
    for case in cases() {
        let bytes = case.bytes();
        for (index, value) in [
            (0, 0xC4),
            (1, (bytes[1] & !7) | 1),
            (2, bytes[2] & !3),
            (2, bytes[2] ^ 8),
            (3, bytes[3] & !7),
            (3, bytes[3] | 0x80),
            (3, bytes[3] | 0x10),
            (3, bytes[3] | 0x60),
            (4, 0xC6),
            (4, 0xC7),
            (5, bytes[5] | 0xC0),
            (5, bytes[5] & !7),
        ] {
            let mut changed = bytes.clone();
            changed[index] = value;
            assert!(classify(&changed).is_none(), "{case:?}: {changed:02X?}");
        }
        for length in 0..bytes.len() {
            assert!(classify(&bytes[..length]).is_none());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(classify(&trailing).is_none());
        for prefix in [0xF0, 0xF2, 0xF3, 0x66, 0x40, 0x48, 0xD5] {
            let mut prefixed = vec![prefix];
            prefixed.extend_from_slice(&bytes);
            assert!(classify(&prefixed).is_none());
        }
        // P0.B4/B3 are ignored when mod=00/SIB.base=101; P1.X4 is unused
        // for every VSIB address and must not select a GPR index or APX guard.
        let mut no_base = case.address(None, 1, None, false, None, true);
        no_base[1] = (no_base[1] | 8) & !0x20;
        let decoded = classify(&no_base).unwrap();
        assert_eq!(decoded.base, None);
        assert!(!decoded.requires_apx);
        assert_eq!(decoded.index_register, case.index);
    }
}

#[test]
fn vsib_all_shapes_match_complete_o0_o1_o2_graphs_and_exact_apx_frontiers() {
    let mut matched = 0;
    for case in cases() {
        for (base, scale, disp8, addr32, segment, x4) in [
            (Some(0), 1, None, false, None, false),
            (Some(4), 2, Some(127), true, Some(0x64), false),
            (Some(5), 8, Some(-128), false, Some(0x65), true),
            (Some(29), 4, Some(-1), true, Some(0x64), true),
            (None, 1, None, true, Some(0x65), true),
            (None, 8, None, false, None, false),
        ] {
            let bytes = case.address(base, scale, disp8, addr32, segment, x4);
            for level in LEVELS {
                let function = lift(&bytes, level);
                let exact = sequence(&function, true).unwrap_or_else(|| {
                    panic!(
                        "{case:?} {bytes:02X?} {level:?}: {:#?}",
                        function.blocks[0].ops
                    )
                });
                assert_eq!(exact.encoding, classify(&bytes).unwrap());
                assert!(sequence(&function, false).is_none());
                let start = usize::from(exact.encoding.requires_apx);
                assert_eq!(exact.consumed + start, function.blocks[0].ops.len());
                let (definitions, uses) = virtual_counts(&function);
                for index in start + 1..function.blocks[0].ops.len() {
                    assert!(
                        x86_jit_evex_vsib_memory_sequence(
                            &function.blocks[0],
                            index,
                            true,
                            &function.x86_instruction_bytes,
                            &definitions,
                            &uses
                        )
                        .is_none(),
                        "interior operation {index} admitted"
                    );
                }
                if start == 1 {
                    let mut missing = function.clone();
                    missing.blocks[0].ops.remove(0);
                    assert!(sequence(&missing, true).is_none());
                } else {
                    let mut extra = function.clone();
                    extra.blocks[0]
                        .ops
                        .insert(0, SmirOp::new(OpId(0xFFFE), PC, OpKind::X86RequireApx));
                    assert!(sequence(&extra, true).is_none());
                }
                matched += 1;
            }
        }
    }
    assert_eq!(matched, 48 * 6 * 3);
}

#[test]
fn vsib_graph_provenance_address_mask_order_and_virtual_alias_mutations_fail_closed() {
    for case in cases() {
        let bytes = case.address(Some(29), 4, Some(-1), true, Some(0x64), true);
        for level in LEVELS {
            let function = lift(&bytes, level);
            assert!(
                sequence(&function, true).is_some(),
                "{case:?} {level:?}: {:#?}",
                function.blocks[0].ops
            );
            let mut bad = function.clone();
            bad.x86_instruction_bytes.clear();
            assert!(sequence(&bad, true).is_none());

            // Every node is semantically owned by one precise guest PC and
            // carries no raw replay hint. Mutating either must close the gate.
            for index in 1..function.blocks[0].ops.len() {
                let mut bad = function.clone();
                bad.blocks[0].ops[index].guest_pc ^= 1;
                assert!(sequence(&bad, true).is_none(), "split PC at {index}");
                let mut bad = function.clone();
                bad.blocks[0].ops[index].x86_hint =
                    Some(X86OpHint::VecAlign(X86VecAlign::Unaligned));
                assert!(sequence(&bad, true).is_none(), "hint at {index}");
            }
            let index_extract = function.blocks[0]
                .ops
                .iter()
                .position(|op| {
                    matches!(
                        op.kind,
                        OpKind::VExtractLane {
                            sign: SignExtend::Sign,
                            ..
                        }
                    )
                })
                .unwrap();
            let memory = function.blocks[0]
                .ops
                .iter()
                .position(|op| {
                    matches!(op.kind, OpKind::PredLoad { .. } | OpKind::PredStore { .. })
                })
                .unwrap();
            let mask_clear = function.blocks[0]
                .ops
                .iter()
                .position(|op| {
                    matches!(
                        op.kind,
                        OpKind::And {
                            dst: VReg::Arch(ArchReg::X86(X86Reg::K(_))),
                            ..
                        }
                    )
                })
                .unwrap();
            let (predicate, address_virtual) = match &function.blocks[0].ops[memory].kind {
                OpKind::PredLoad { cond, addr, .. } | OpKind::PredStore { cond, addr, .. } => {
                    let crate::smir::ir::types::Address::SegmentRel {
                        base: Some(base), ..
                    } = addr
                    else {
                        panic!("FS-relative VSIB");
                    };
                    (*cond, *base)
                }
                _ => unreachable!(),
            };
            let mut bad = function.clone();
            if let OpKind::VExtractLane { sign, .. } = &mut bad.blocks[0].ops[index_extract].kind {
                *sign = SignExtend::Zero;
            }
            assert!(sequence(&bad, true).is_none(), "unsigned vector index");
            let mut bad = function.clone();
            if let OpKind::VExtractLane { dst, .. } = &mut bad.blocks[0].ops[index_extract].kind {
                *dst = predicate;
            }
            assert!(
                sequence(&bad, true).is_none(),
                "virtual predicate/address alias"
            );
            let mut bad = function.clone();
            match &mut bad.blocks[0].ops[memory].kind {
                OpKind::PredLoad { width, .. } | OpKind::PredStore { width, .. } => {
                    *width = if case.data_bytes == 4 {
                        MemWidth::B8
                    } else {
                        MemWidth::B4
                    }
                }
                _ => unreachable!(),
            }
            assert!(sequence(&bad, true).is_none(), "memory width mismatch");
            let mut bad = function.clone();
            if let OpKind::And { src2, .. } = &mut bad.blocks[0].ops[mask_clear].kind {
                *src2 = SrcOperand::Imm(-3);
            }
            assert!(sequence(&bad, true).is_none(), "wrong completed mask bit");
            let mut bad = function.clone();
            bad.blocks[0].ops.swap(memory, mask_clear);
            assert!(
                sequence(&bad, true).is_none(),
                "mask committed before memory access"
            );
            let mut bad = function.clone();
            let truncation = bad.blocks[0]
                .ops
                .iter_mut()
                .find(|op| {
                    matches!(
                        op.kind,
                        OpKind::Mov {
                            width: OpWidth::W32,
                            ..
                        }
                    )
                })
                .unwrap();
            if let OpKind::Mov { width, .. } = &mut truncation.kind {
                *width = OpWidth::W64;
            }
            assert!(sequence(&bad, true).is_none(), "missing addr32 truncation");
            let mut bad = function.clone();
            bad.blocks[0].ops.push(SmirOp::new(
                OpId(0xFFFF),
                PC + bytes.len() as u64,
                OpKind::Mov {
                    dst: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
                    src: SrcOperand::Reg(address_virtual),
                    width: OpWidth::W64,
                },
            ));
            assert!(
                sequence(&bad, true).is_none(),
                "internal value escapes guest frontier"
            );
            let mut bad = function.clone();
            bad.blocks[0].ops.push(SmirOp::new(
                OpId(0xFFFF),
                PC,
                OpKind::And {
                    dst: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
                    src1: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
                    src2: SrcOperand::Imm(1),
                    width: OpWidth::W64,
                    flags: FlagUpdate::None,
                },
            ));
            assert!(sequence(&bad, true).is_none(), "unmatched same-PC tail");
        }
    }
}

#[test]
fn vsib_native_admission_and_lowering_cover_all_48_shapes_at_o0_o1_o2() {
    // RED before native admission is wired; this cannot pass merely because
    // the independent byte classifier and structural matcher recognize it.
    let mut lowerings = 0;
    for case in cases() {
        for level in LEVELS {
            let function = lift(&case.bytes(), level);
            assert!(sequence(&function, true).is_some());
            let (code, _) = lower(&function);
            for (offset, expected) in [
                (
                    X86_GUEST_LOAD_FN_OFFSET,
                    if case.scatter { 0 } else { case.lanes() },
                ),
                (
                    X86_GUEST_STORE_FN_OFFSET,
                    if case.scatter { case.lanes() } else { 0 },
                ),
            ] {
                // Each guarded lane emits exactly one scalar helper call:
                // CALL qword [RAX+disp32] = FF 90 followed by the ABI offset.
                let mut call = vec![0xFF, 0x90];
                call.extend_from_slice(&offset.to_le_bytes());
                assert_eq!(
                    code.windows(call.len())
                        .filter(|window| *window == call.as_slice())
                        .count(),
                    expected,
                    "{case:?} {level:?}: helper offset {offset:#x}"
                );
            }
            // Explicit linear-size regression budget: 4096 B per unrolled
            // lane plus 4096 B for guards, completion, and the region frame.
            // This is a test budget, not an architectural size limit.
            let byte_budget = 4096 * (case.lanes() + 1);
            assert!(
                code.len() <= byte_budget,
                "{case:?} {level:?}: {} B exceeds {byte_budget} B",
                code.len()
            );
            lowerings += 1;
        }
    }
    assert_eq!(lowerings, 48 * LEVELS.len());
}

#[test]
fn vsib_exact_graph_rejects_internal_values_in_phi_and_every_terminator_operand() {
    use crate::smir::ir::{CallTarget, PhiNode};
    for case in cases() {
        let original = lift(&case.bytes(), OptLevel::O0);
        let temporary = original.blocks[0]
            .ops
            .iter()
            .find_map(|op| match op.kind {
                OpKind::VExtractLane { dst, .. } => Some(dst),
                _ => None,
            })
            .unwrap();
        let terminators = [
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
                addr: crate::smir::ir::types::Address::Direct(temporary),
                possible_targets: vec![BlockId(1)],
            },
            Terminator::Return {
                values: vec![temporary],
            },
            Terminator::Call {
                target: CallTarget::Indirect(temporary),
                args: vec![],
                continuation: BlockId(1),
            },
            Terminator::TailCall {
                target: CallTarget::Indirect(temporary),
                args: vec![],
            },
            Terminator::Call {
                target: CallTarget::GuestAddr(0x3000),
                args: vec![temporary],
                continuation: BlockId(1),
            },
        ];
        for terminator in terminators {
            let mut function = original.clone();
            function.blocks[0].set_terminator(terminator);
            assert!(
                sequence(&function, true).is_none(),
                "{case:?}: elided temporary escapes through {:?}",
                function.blocks[0].terminator
            );
            assert_rejected_before_emission(&function);
        }
        for phi in [
            PhiNode {
                dst: temporary,
                sources: vec![(BlockId(1), VReg::Arch(ArchReg::X86(X86Reg::Rax)))],
            },
            PhiNode {
                dst: VReg::Virtual(crate::smir::ir::types::VirtualId(0xFFFF)),
                sources: vec![(BlockId(1), temporary)],
            },
        ] {
            let mut function = original.clone();
            function.blocks[0].phis.push(phi);
            assert!(
                sequence(&function, true).is_none(),
                "{case:?}: elided temporary escapes through phi"
            );
            assert_rejected_before_emission(&function);
        }
    }
}

#[test]
fn vsib_function_gate_rejects_internal_value_used_in_successor_block() {
    for case in cases() {
        let mut function = lift(&case.bytes(), OptLevel::O0);
        let temporary = function.blocks[0]
            .ops
            .iter()
            .find_map(|op| match op.kind {
                OpKind::VExtractLane { dst, .. } => Some(dst),
                _ => None,
            })
            .unwrap();
        function.blocks[0].set_terminator(Terminator::Branch { target: BlockId(1) });
        let mut next = SmirBlock::new(BlockId(1), PC + 0x100);
        next.ops.push(SmirOp::new(
            OpId(0xFFFC),
            PC + 0x100,
            OpKind::Mov {
                dst: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
                src: SrcOperand::Reg(temporary),
                width: OpWidth::W64,
            },
        ));
        next.set_terminator(Terminator::Return { values: Vec::new() });
        function.add_block(next);
        assert!(
            !is_native_clobber_safe_excluding(&function, &HashMap::new(), true),
            "{case:?}: VSIB virtual is not materialized for a successor"
        );
        assert_rejected_before_emission(&function);
    }
}
