use super::*;

#[test]
fn scalar_fp16_complex_memory_replay_canonicalizes_llig_crash_encodings() {
    // Full-suite run 34016200409 at db124b723b343f0fe7dfe04ddf10e12ed11fc9c4
    // trapped with SIGILL at 62 F6 0E E1 57 04 24: scalar VFMADDCSH with
    // L'L=11b. Intel SDM Vol. 2A 2.8.9 assigns these scalar operations to
    // E10, which ignores L'L. Emit the equivalent canonical L'L=00b form.
    // Each expected image below is independently assembled with LLVM 22.1.7:
    // {vfmaddcsh,vfcmaddcsh,vfmulcsh,vfcmulcsh} xmm0{k1}{z},xmm30,[rsp].
    let anchors = [
        (
            ComplexOperation::Accumulate,
            [0x62, 0xF6, 0x0E, 0x81, 0x57, 0x04, 0x24],
        ),
        (
            ComplexOperation::ConjugateAccumulate,
            [0x62, 0xF6, 0x0F, 0x81, 0x57, 0x04, 0x24],
        ),
        (
            ComplexOperation::Multiply,
            [0x62, 0xF6, 0x0E, 0x81, 0xD7, 0x04, 0x24],
        ),
        (
            ComplexOperation::ConjugateMultiply,
            [0x62, 0xF6, 0x0F, 0x81, 0xD7, 0x04, 0x24],
        ),
    ];
    for (operation, expected) in anchors {
        for ll in 0..=3 {
            let case = ScalarComplexMemoryCase {
                operation,
                source1: 30,
                ll,
                control: MaskControl::Zero,
            };
            let source = X86InstructionBytes::new(&case.bytes()).unwrap();
            let encoding = source.evex_packed_fp16_complex_memory_encoding().unwrap();
            let X86EvexPackedFp16ComplexMemoryReplay::Broadcast { stack_instruction } =
                encoding.replay
            else {
                panic!("{case:?}: scalar complex source was not helper-staged")
            };
            assert_eq!(stack_instruction.as_slice(), expected, "{case:?}");
            for level in LEVELS {
                let function = optimize(lift_scalar_case(case), level);
                assert_eq!(function.x86_instruction_bytes[&(BlockId(0), PC)], source);
                let (code, _) = lower_scalar(&function, case);
                assert_eq!(
                    code.windows(expected.len())
                        .filter(|window| *window == expected)
                        .count(),
                    1,
                    "{level:?} {case:?}: missing canonical scalar complex replay"
                );
                if ll != 0 {
                    let mut noncanonical = expected;
                    noncanonical[3] |= ll << 5;
                    assert!(
                        !code
                            .windows(noncanonical.len())
                            .any(|window| window == noncanonical),
                        "{level:?} {case:?}: ignored guest L'L leaked into native replay"
                    );
                }
            }
        }
    }
}

#[test]
fn scalar_fp16_complex_classifier_exhaustively_rewrites_952_320_control_and_apx_cells() {
    let mut accepted = 0usize;
    for operation in ComplexOperation::ALL {
        for ll in 0..=3u8 {
            for destination in 0..32u8 {
                for source1 in 0..32u8 {
                    if destination == source1 {
                        continue;
                    }
                    for mask in 0..8u8 {
                        for zeroing in [false, true] {
                            if zeroing && mask == 0 {
                                continue;
                            }
                            let canonical = scalar_memory_encoding(
                                operation,
                                destination,
                                source1,
                                ll,
                                mask,
                                zeroing,
                                3,
                            );
                            for base_high in [false, true] {
                                for index_high in [false, true] {
                                    let mut bytes = canonical;
                                    bytes[1] |= u8::from(base_high) << 3;
                                    if index_high {
                                        bytes[2] &= !0x04;
                                    }
                                    let encoding = X86InstructionBytes::new(&bytes)
                                        .unwrap()
                                        .evex_packed_fp16_complex_memory_encoding()
                                        .unwrap_or_else(|| panic!("{bytes:02X?}"));
                                    assert_eq!(encoding.width, VecWidth::V128, "{bytes:02X?}");
                                    assert_eq!(encoding.destination, destination, "{bytes:02X?}");
                                    assert_eq!(encoding.source1, source1, "{bytes:02X?}");
                                    assert_eq!(
                                        encoding.writemask,
                                        (mask != 0).then_some(mask),
                                        "{bytes:02X?}"
                                    );
                                    assert_eq!(encoding.zeroing, zeroing, "{bytes:02X?}");
                                    assert!(encoding.scalar, "{bytes:02X?}");
                                    assert_eq!(
                                        encoding.accumulate,
                                        operation.accumulate(),
                                        "{bytes:02X?}"
                                    );
                                    assert_eq!(
                                        encoding.conjugate,
                                        operation.conjugate(),
                                        "{bytes:02X?}"
                                    );
                                    assert!(!encoding.needs_avx512vl, "{bytes:02X?}");
                                    let X86EvexPackedFp16ComplexMemoryReplay::Broadcast {
                                        stack_instruction,
                                    } = encoding.replay
                                    else {
                                        panic!(
                                            "scalar replay was not staged through [rsp]: {bytes:02X?}"
                                        )
                                    };
                                    assert_eq!(
                                        stack_instruction.as_slice(),
                                        scalar_stack_encoding(
                                            operation,
                                            destination,
                                            source1,
                                            mask,
                                            zeroing,
                                        ),
                                        "{bytes:02X?}"
                                    );
                                    accepted += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(accepted, 4 * 4 * 32 * 31 * 15 * 2 * 2);
}

#[test]
fn scalar_fp16_complex_classifier_owns_only_four_opcodes_and_fails_closed() {
    for opcode in 0..=u8::MAX {
        let mut bytes = scalar_memory_encoding(ComplexOperation::Accumulate, 0, 1, 0, 0, false, 3);
        bytes[4] = opcode;
        assert_eq!(
            X86InstructionBytes::new(&bytes)
                .unwrap()
                .evex_packed_fp16_complex_memory_encoding()
                .is_some(),
            matches!(opcode, 0x56 | 0x57 | 0xD6 | 0xD7),
            "{bytes:02X?}"
        );
    }

    let valid = scalar_memory_encoding(ComplexOperation::ConjugateAccumulate, 0, 1, 2, 1, false, 3)
        .to_vec();
    let mut malformed = vec![valid[..valid.len() - 1].to_vec()];
    let mut trailing = valid.clone();
    trailing.push(0);
    malformed.push(trailing);
    let mut register = valid.clone();
    register[5] |= 0xC0;
    malformed.push(register);
    let mut broadcast = valid.clone();
    broadcast[3] |= 0x10;
    malformed.push(broadcast);
    let mut zero_k0 = valid.clone();
    zero_k0[3] = (zero_k0[3] & !7) | 0x80;
    malformed.push(zero_k0);
    let mut destination_alias = valid.clone();
    destination_alias[2] = 0x7C | ComplexOperation::ConjugateAccumulate.pp();
    destination_alias[3] |= 0x08;
    malformed.push(destination_alias);
    let mut forbidden_legacy = valid.clone();
    forbidden_legacy.insert(0, 0x66);
    malformed.push(forbidden_legacy);
    let mut lock = valid.clone();
    lock.insert(0, 0xF0);
    malformed.push(lock);
    for (index, mask) in [
        (1, 0x01), // MAP6 -> unowned map.
        (2, 0x80), // W0 -> W1.
        (2, 0x03), // F3 -> unowned pp=00.
        (4, 0x04), // Scalar complex -> unowned opcode.
    ] {
        let mut bytes = valid.clone();
        bytes[index] ^= mask;
        malformed.push(bytes);
    }

    for bytes in malformed {
        assert!(
            X86InstructionBytes::new(&bytes)
                .unwrap()
                .evex_packed_fp16_complex_memory_encoding()
                .is_none(),
            "{bytes:02X?}"
        );
    }

    // Intel SDM Vol. 2A section 2.7.10 states that EVEX.L'L is generally
    // ignored for scalar instructions. The scalar lifter therefore accepts
    // 11b, while the packed form retains the reserved-vector-length rejection.
    let scalar_ll3 = scalar_memory_encoding(ComplexOperation::Multiply, 0, 1, 3, 0, false, 3);
    let mut packed_ll3 = scalar_ll3;
    packed_ll3[4] &= !1;
    assert!(
        X86InstructionBytes::new(&scalar_ll3)
            .unwrap()
            .evex_packed_fp16_complex_memory_encoding()
            .is_some()
    );
    assert!(
        X86InstructionBytes::new(&packed_ll3)
            .unwrap()
            .evex_packed_fp16_complex_memory_encoding()
            .is_none()
    );
}

#[test]
fn scalar_fp16_complex_stack_replays_match_four_independent_llvm_23_anchors() {
    // Produced independently by llvm-mc 23.0.0git. The memory encodings cover
    // all four mnemonics, low/high vector registers, SIB/disp8 addressing,
    // and merge/zero masking. The `[rsp]` encodings independently anchor the
    // byte sequences synthesized by the classifier.
    let anchors: [(&[u8], &[u8], ComplexOperation, u8, u8, Option<u8>, bool); 4] = [
        (
            &[0x62, 0xF6, 0x67, 0x08, 0x57, 0x08],
            &[0x62, 0xF6, 0x67, 0x08, 0x57, 0x0C, 0x24],
            ComplexOperation::ConjugateAccumulate,
            1,
            3,
            None,
            false,
        ),
        (
            &[0x62, 0xC6, 0x6E, 0x82, 0x57, 0x49, 0x08],
            &[0x62, 0xE6, 0x6E, 0x82, 0x57, 0x0C, 0x24],
            ComplexOperation::Accumulate,
            17,
            18,
            Some(2),
            true,
        ),
        (
            &[0x62, 0x06, 0x0F, 0x07, 0xD7, 0x3C, 0x5A],
            &[0x62, 0x66, 0x0F, 0x07, 0xD7, 0x3C, 0x24],
            ComplexOperation::ConjugateMultiply,
            31,
            30,
            Some(7),
            false,
        ),
        (
            &[0x62, 0xF6, 0x76, 0x08, 0xD7, 0x43, 0x10],
            &[0x62, 0xF6, 0x76, 0x08, 0xD7, 0x04, 0x24],
            ComplexOperation::Multiply,
            0,
            1,
            None,
            false,
        ),
    ];
    for (memory, stack, operation, destination, source1, mask, zeroing) in anchors {
        let encoding = X86InstructionBytes::new(memory)
            .unwrap()
            .evex_packed_fp16_complex_memory_encoding()
            .unwrap_or_else(|| panic!("{memory:02X?}"));
        assert!(encoding.scalar, "{memory:02X?}");
        assert_eq!(encoding.destination, destination, "{memory:02X?}");
        assert_eq!(encoding.source1, source1, "{memory:02X?}");
        assert_eq!(encoding.writemask, mask, "{memory:02X?}");
        assert_eq!(encoding.zeroing, zeroing, "{memory:02X?}");
        assert_eq!(encoding.accumulate, operation.accumulate(), "{memory:02X?}");
        assert_eq!(encoding.conjugate, operation.conjugate(), "{memory:02X?}");
        let X86EvexPackedFp16ComplexMemoryReplay::Broadcast { stack_instruction } = encoding.replay
        else {
            panic!("{memory:02X?}")
        };
        assert_eq!(stack_instruction.as_slice(), stack, "{memory:02X?}");
    }
}

#[test]
fn all_72_scanner_cells_and_24_additional_llig_cells_optimize_admit_and_lower_exactly() {
    let mut scanner_cells = 0usize;
    let mut llig_cells = 0usize;
    let mut lowerings = 0usize;
    for operation in ComplexOperation::ALL {
        for source1 in [1, 15] {
            for ll in 0..=3 {
                for control in MaskControl::ALL {
                    let case = ScalarComplexMemoryCase {
                        operation,
                        source1,
                        ll,
                        control,
                    };
                    if ll < 3 {
                        scanner_cells += 1;
                    } else {
                        llig_cells += 1;
                    }
                    for level in LEVELS {
                        let function = optimize(lift_scalar_case(case), level);
                        let exact = sequence(&function, true).unwrap_or_else(|| {
                            panic!("{level:?} {case:?}: {:#?}", function.blocks[0].ops)
                        });
                        assert_eq!(
                            exact.memory_size,
                            MemWidth::B4.bytes(),
                            "{level:?} {case:?}"
                        );
                        assert_eq!(
                            exact.consumed,
                            function.blocks[0].ops.len(),
                            "{level:?} {case:?}"
                        );
                        assert!(exact.encoding.scalar, "{level:?} {case:?}");
                        assert_eq!(exact.encoding.width, VecWidth::V128, "{level:?} {case:?}");
                        assert!(!exact.encoding.needs_avx512vl, "{level:?} {case:?}");
                        let (code, _) = lower_scalar(&function, case);
                        let expected = case.expected_replay();
                        assert_eq!(
                            code.windows(expected.len())
                                .filter(|window| *window == expected)
                                .count(),
                            1,
                            "{level:?} {case:?}: {code:02X?}"
                        );
                        assert!(
                            code.windows(5).any(|window| window == [0xBA, 4, 0, 0, 0]),
                            "{level:?} {case:?}: missing exact 4-byte helper width"
                        );
                        lowerings += 1;
                    }
                }
            }
        }
    }
    assert_eq!(scanner_cells, 72);
    assert_eq!(llig_cells, 24);
    assert_eq!(lowerings, (scanner_cells + llig_cells) * LEVELS.len());
}

#[test]
fn scalar_fp16_complex_apx_r16_r17_sib_address_is_helper_owned() {
    // VFMADDCSH xmm16{k1},xmm17,[r16+r17*2+4]. Scalar disp8=1 scales by
    // the 4-byte source. APX B4/X4 affect helper address calculation only.
    let bytes = [0x62, 0xEE, 0x72, 0x01, 0x57, 0x44, 0x48, 0x01];
    let expected = [0x62, 0xE6, 0x76, 0x01, 0x57, 0x04, 0x24];
    let base = lift_scalar_bytes(&bytes);
    let case = ScalarComplexMemoryCase {
        operation: ComplexOperation::Accumulate,
        source1: 17,
        ll: 0,
        control: MaskControl::Merge,
    };
    for level in LEVELS {
        let function = optimize(base.clone(), level);
        assert!(
            function.blocks[0].ops.iter().any(|op| matches!(
                op.kind,
                OpKind::PredLoad {
                    addr: Address::BaseIndexScale {
                        base: Some(VReg::Arch(ArchReg::X86(X86Reg::R16))),
                        index: VReg::Arch(ArchReg::X86(X86Reg::R17)),
                        scale: 2,
                        disp: 4,
                        disp_size: DispSize::Disp8,
                    },
                    width: MemWidth::B4,
                    ..
                }
            )),
            "{level:?}: {:#?}",
            function.blocks[0].ops
        );
        let exact = sequence(&function, true).expect("APX scalar complex sequence");
        assert_eq!(exact.encoding.destination, 16);
        assert_eq!(exact.encoding.source1, 17);
        let X86EvexPackedFp16ComplexMemoryReplay::Broadcast { stack_instruction } =
            exact.encoding.replay
        else {
            unreachable!()
        };
        assert_eq!(stack_instruction.as_slice(), expected);
        let (code, _) = lower_scalar(&function, case);
        assert!(
            code.windows(expected.len())
                .any(|window| window == expected)
        );
    }
}

#[test]
fn scalar_fp16_complex_rip_addr32_segment_and_sib_addresses_remain_helper_owned() {
    let case = ScalarComplexMemoryCase {
        operation: ComplexOperation::Multiply,
        source1: 30,
        ll: 1,
        control: MaskControl::Zero,
    };
    let x86 = |register| VReg::Arch(ArchReg::X86(register));

    let mut rip = case.bytes().to_vec();
    rip[5] = (rip[5] & 0x38) | 5;
    rip.extend_from_slice(&0x20i32.to_le_bytes());
    let mut addr32 = case.bytes().to_vec();
    addr32.insert(0, 0x67);
    let mut fs = case.bytes().to_vec();
    fs.insert(0, 0x64);
    let mut gs_addr32_sib = case.bytes().to_vec();
    gs_addr32_sib[5] = (gs_addr32_sib[5] & 0x38) | 0x44;
    gs_addr32_sib.push(0x8B); // [ebx + ecx*4 + disp8]
    gs_addr32_sib.push(2); // Scalar tuple: 2 * 4-byte source = 8 bytes.
    gs_addr32_sib.insert(0, 0x67);
    gs_addr32_sib.insert(0, 0x65);

    let address_cases = [
        (
            "RIP+disp32",
            rip,
            Address::PcRel {
                offset: 0x20,
                disp_size: DispSize::Disp32,
                base: Some(PC + 10),
            },
        ),
        (
            "addr32 base",
            addr32,
            Address::X86Addr32(Box::new(Address::Direct(x86(X86Reg::Rbx)))),
        ),
        (
            "FS base",
            fs,
            Address::SegmentRel {
                segment: x86(X86Reg::FsBase),
                base: Some(x86(X86Reg::Rbx)),
                index: None,
                scale: 1,
                disp: 0,
            },
        ),
        (
            "GS addr32 SIB",
            gs_addr32_sib,
            Address::X86Addr32(Box::new(Address::SegmentRel {
                segment: x86(X86Reg::GsBase),
                base: Some(x86(X86Reg::Rbx)),
                index: Some(x86(X86Reg::Rcx)),
                scale: 4,
                disp: 8,
            })),
        ),
    ];
    for (name, bytes, expected_address) in address_cases {
        let base = lift_scalar_bytes(&bytes);
        for level in LEVELS {
            let function = optimize(base.clone(), level);
            assert!(
                function.blocks[0].ops.iter().any(|op| match &op.kind {
                    OpKind::Load { addr, .. }
                    | OpKind::PredLoad { addr, .. }
                    | OpKind::Lea { addr, .. } => addr == &expected_address,
                    _ => false,
                }),
                "{name} {level:?}: {:#?}",
                function.blocks[0].ops
            );
            let exact = sequence(&function, true)
                .unwrap_or_else(|| panic!("{name} {level:?}: {:#?}", function.blocks[0].ops));
            let X86EvexPackedFp16ComplexMemoryReplay::Broadcast { stack_instruction } =
                exact.encoding.replay
            else {
                unreachable!()
            };
            assert_eq!(stack_instruction.as_slice(), case.expected_replay());
            let (code, _) = lower_scalar(&function, case);
            assert!(
                code.windows(case.expected_replay().len())
                    .any(|window| window == case.expected_replay()),
                "{name} {level:?}"
            );
        }
    }
}

#[test]
fn masked_scalar_fp16_complex_lowering_has_one_precise_bit_zero_guard() {
    for operation in ComplexOperation::ALL {
        for control in [MaskControl::Merge, MaskControl::Zero] {
            let case = ScalarComplexMemoryCase {
                operation,
                source1: 17,
                ll: 3,
                control,
            };
            let (code, _) = lower_scalar(&lift_scalar_case(case), case);
            let guard = [
                0x9C,
                0x50,
                0xC4,
                0xE1,
                0xFB,
                0x93,
                0xC0 | case.mask(),
                0xF7,
                0xC0,
                1,
                0,
                0,
                0,
                0x0F,
                0x84,
            ];
            let matches: Vec<_> = code
                .windows(guard.len())
                .enumerate()
                .filter_map(|(index, window)| (window == guard).then_some(index))
                .collect();
            assert_eq!(matches.len(), 1, "{case:?}: {code:02X?}");
            let displacement_at = matches[0] + guard.len();
            assert_eq!(
                &code[displacement_at + 4..displacement_at + 6],
                &[0x58, 0x9D]
            );
            let inactive = (displacement_at + 4) as i64
                + i64::from(i32::from_le_bytes(
                    code[displacement_at..displacement_at + 4]
                        .try_into()
                        .unwrap(),
                ));
            let inactive = usize::try_from(inactive).expect("forward inactive target");
            assert_eq!(&code[inactive..inactive + 2], &[0x58, 0x9D]);
            assert_eq!(code[inactive - 5], 0xE9);
            let execute = inactive as i64
                + i64::from(i32::from_le_bytes(
                    code[inactive - 4..inactive].try_into().unwrap(),
                ));
            assert_eq!(usize::try_from(execute).unwrap(), inactive + 2);
            assert_eq!(
                &code[inactive + 2..inactive + 2 + case.expected_replay().len()],
                case.expected_replay()
            );
        }
    }
}

#[test]
fn scalar_fp16_complex_sequence_fails_closed_for_provenance_graph_and_ssa_mutations() {
    for (case, level) in [
        (
            ScalarComplexMemoryCase {
                operation: ComplexOperation::ConjugateAccumulate,
                source1: 17,
                ll: 3,
                control: MaskControl::Merge,
            },
            OptLevel::O0,
        ),
        (
            ScalarComplexMemoryCase {
                operation: ComplexOperation::Multiply,
                source1: 1,
                ll: 2,
                control: MaskControl::None,
            },
            OptLevel::O2,
        ),
    ] {
        let function = optimize(lift_scalar_case(case), level);
        assert!(sequence(&function, true).is_some(), "{case:?}");
        let (definitions, uses) = virtual_counts(&function);
        assert!(
            x86_jit_evex_packed_fp16_complex_memory_sequence(
                &function.blocks[0],
                0,
                false,
                &function.x86_instruction_bytes,
                &definitions,
                &uses,
            )
            .is_none(),
            "{case:?}: memory-disabled matcher"
        );

        let mut missing_provenance = function.clone();
        missing_provenance.x86_instruction_bytes.clear();
        assert_scalar_rejected("missing provenance", &missing_provenance);

        let mut wrong_provenance = function.clone();
        let other = if case.operation == ComplexOperation::Multiply {
            ComplexOperation::Accumulate
        } else {
            ComplexOperation::Multiply
        };
        let bytes = scalar_memory_encoding(
            other,
            case.destination(),
            case.source1,
            case.ll,
            case.mask(),
            case.zeroing(),
            3,
        );
        wrong_provenance
            .x86_instruction_bytes
            .insert((BlockId(0), PC), X86InstructionBytes::new(&bytes).unwrap());
        assert_scalar_rejected("wrong provenance", &wrong_provenance);

        let mut wrong_width = function.clone();
        let load = wrong_width.blocks[0]
            .ops
            .iter_mut()
            .find(|op| matches!(op.kind, OpKind::Load { .. } | OpKind::PredLoad { .. }))
            .unwrap();
        match &mut load.kind {
            OpKind::Load { width, .. } | OpKind::PredLoad { width, .. } => {
                *width = MemWidth::B8;
            }
            _ => unreachable!(),
        }
        assert_scalar_rejected("wrong scalar load width", &wrong_width);

        let mut wrong_address = function.clone();
        let load = wrong_address.blocks[0]
            .ops
            .iter_mut()
            .find(|op| matches!(op.kind, OpKind::Load { .. } | OpKind::PredLoad { .. }))
            .unwrap();
        match &mut load.kind {
            OpKind::Load { addr, .. } | OpKind::PredLoad { addr, .. } => {
                *addr = Address::Direct(VReg::Virtual(VirtualId(0xFF00)));
            }
            _ => unreachable!(),
        }
        assert_scalar_rejected("nonarchitectural address", &wrong_address);

        let mut wrong_broadcast = function.clone();
        let broadcast = wrong_broadcast.blocks[0]
            .ops
            .iter_mut()
            .find(|op| matches!(op.kind, OpKind::VBroadcast { .. }))
            .unwrap();
        let OpKind::VBroadcast { lanes, .. } = &mut broadcast.kind else {
            unreachable!()
        };
        *lanes = 2;
        assert_scalar_rejected("wrong scalar broadcast lanes", &wrong_broadcast);

        let mut wrong_round = function.clone();
        let complex = wrong_round.blocks[0]
            .ops
            .iter_mut()
            .find(|op| matches!(op.kind, OpKind::X86FP16Complex { .. }))
            .unwrap();
        let OpKind::X86FP16Complex { round, .. } = &mut complex.kind else {
            unreachable!()
        };
        *round = FpRoundMode::RoundNearest;
        assert_scalar_rejected("wrong rounding", &wrong_round);

        let mut wrong_scalar = function.clone();
        let complex = wrong_scalar.blocks[0]
            .ops
            .iter_mut()
            .find(|op| matches!(op.kind, OpKind::X86FP16Complex { .. }))
            .unwrap();
        let OpKind::X86FP16Complex { scalar, .. } = &mut complex.kind else {
            unreachable!()
        };
        *scalar = false;
        assert_scalar_rejected("wrong scalar semantic", &wrong_scalar);

        let mut wrong_operation = function.clone();
        let complex = wrong_operation.blocks[0]
            .ops
            .iter_mut()
            .find(|op| matches!(op.kind, OpKind::X86FP16Complex { .. }))
            .unwrap();
        let OpKind::X86FP16Complex { accumulate, .. } = &mut complex.kind else {
            unreachable!()
        };
        *accumulate = !*accumulate;
        assert_scalar_rejected("wrong complex operation", &wrong_operation);

        let mut wrong_hint = function.clone();
        wrong_hint.blocks[0]
            .ops
            .iter_mut()
            .find(|op| matches!(op.kind, OpKind::X86FP16Complex { .. }))
            .unwrap()
            .x86_hint = Some(crate::smir::ir::ops::X86OpHint::MovImmModRm);
        assert_scalar_rejected("wrong complex hint", &wrong_hint);

        let mut hinted_memory = function.clone();
        let address_index = sequence(&hinted_memory, true).unwrap().address_offset;
        hinted_memory.blocks[0].ops[address_index].x86_hint =
            Some(crate::smir::ir::ops::X86OpHint::MovImmModRm);
        assert_scalar_rejected("hinted memory", &hinted_memory);

        let mut wrong_pc = function.clone();
        wrong_pc.blocks[0]
            .ops
            .iter_mut()
            .find(|op| matches!(op.kind, OpKind::X86FP16Complex { .. }))
            .unwrap()
            .guest_pc += 1;
        assert_scalar_rejected("split guest PC", &wrong_pc);

        if case.mask() != 0 {
            let mut wrong_condition = function.clone();
            let condition = wrong_condition.blocks[0]
                .ops
                .iter_mut()
                .find(|op| matches!(op.kind, OpKind::And { .. }))
                .unwrap();
            let OpKind::And { src2, .. } = &mut condition.kind else {
                unreachable!()
            };
            *src2 = crate::smir::ir::types::SrcOperand::Imm(2);
            assert_scalar_rejected("wrong mask bit", &wrong_condition);
        }

        let mut tail = function.clone();
        tail.blocks[0].ops.push(SmirOp::new(
            OpId(0xFFFF),
            PC,
            OpKind::Mov {
                dst: VReg::Virtual(VirtualId(0xFFFF)),
                src: crate::smir::ir::types::SrcOperand::Imm(0),
                width: crate::smir::ir::types::OpWidth::W64,
            },
        ));
        assert_scalar_rejected("same-PC tail", &tail);
    }
}

#[test]
fn scalar_fp16_complex_lowerer_rejects_the_avx_only_vector_bridge() {
    let case = ScalarComplexMemoryCase {
        operation: ComplexOperation::Multiply,
        source1: 30,
        ll: 3,
        control: MaskControl::Zero,
    };
    let function = lift_scalar_case(case);
    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_vector_mem_helpers(true);
    lowerer.set_avx_ymm16_vector_state(true);
    assert!(lowerer.lower_function(&function).is_err());
}
