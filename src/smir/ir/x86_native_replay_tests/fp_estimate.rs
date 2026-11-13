//! Exact source-byte replay classification for legacy/VEX reciprocal estimates.

use super::*;

fn legacy_encoding(scalar: bool, rex: Option<u8>, opcode: u8, modrm: u8) -> Vec<u8> {
    assert!(matches!(opcode, 0x52 | 0x53));
    let mut bytes = Vec::new();
    if scalar {
        bytes.push(0xF3);
    }
    if let Some(rex) = rex {
        assert!(matches!(rex, 0x40..=0x4F));
        bytes.push(rex);
    }
    bytes.extend([0x0F, opcode, modrm]);
    bytes
}

fn c4_encoding(
    extension_bits: u8,
    w: bool,
    encoded_vvvv: u8,
    l: bool,
    pp: u8,
    opcode: u8,
    modrm: u8,
) -> [u8; 5] {
    assert_eq!(extension_bits & !0xE0, 0);
    assert!(encoded_vvvv < 16 && pp < 4);
    assert!(matches!(opcode, 0x52 | 0x53));
    [
        0xC4,
        extension_bits | 1,
        (u8::from(w) << 7) | (encoded_vvvv << 3) | (u8::from(l) << 2) | pp,
        opcode,
        modrm,
    ]
}

fn c5_encoding(
    encoded_r: bool,
    encoded_vvvv: u8,
    l: bool,
    pp: u8,
    opcode: u8,
    modrm: u8,
) -> [u8; 4] {
    assert!(encoded_vvvv < 16 && pp < 4);
    assert!(matches!(opcode, 0x52 | 0x53));
    [
        0xC5,
        (u8::from(encoded_r) << 7) | (encoded_vvvv << 3) | (u8::from(l) << 2) | pp,
        opcode,
        modrm,
    ]
}

#[test]
fn classifier_accepts_all_82688_defined_canonical_register_images() {
    let mut accepted = 0usize;
    for scalar in [false, true] {
        for rex in std::iter::once(None).chain((0x40u8..=0x4F).map(Some)) {
            for opcode in [0x52u8, 0x53] {
                for reg_rm in 0u8..=0x3F {
                    let bytes = legacy_encoding(scalar, rex, opcode, 0xC0 | reg_rm);
                    let instruction = X86InstructionBytes::new(&bytes).unwrap();
                    assert_eq!(
                        instruction.legacy_vex_register_fp_estimate_needs_avx(),
                        Some(false),
                        "{bytes:02X?}"
                    );
                    assert_eq!(instruction.vex_fp_estimate_destination_index(), None);
                    accepted += 1;
                }
            }
        }
    }

    for extension in 0u8..8 {
        let extension_bits = extension << 5;
        for w in [false, true] {
            for encoded_vvvv in 0u8..16 {
                for l in [false, true] {
                    for pp in 0u8..4 {
                        for opcode in [0x52u8, 0x53] {
                            for reg_rm in 0u8..=0x3F {
                                let bytes = c4_encoding(
                                    extension_bits,
                                    w,
                                    encoded_vvvv,
                                    l,
                                    pp,
                                    opcode,
                                    0xC0 | reg_rm,
                                );
                                let instruction = X86InstructionBytes::new(&bytes).unwrap();
                                let expected =
                                    (pp == 2 || (pp == 0 && encoded_vvvv == 15)).then_some(true);
                                assert_eq!(
                                    instruction.legacy_vex_register_fp_estimate_needs_avx(),
                                    expected,
                                    "{bytes:02X?}"
                                );
                                if expected.is_some() {
                                    assert_eq!(
                                        instruction.vex_fp_estimate_destination_index(),
                                        Some(
                                            ((reg_rm >> 3) & 7)
                                                | (u8::from(extension_bits & 0x80 == 0) << 3)
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

    for encoded_r in [false, true] {
        for encoded_vvvv in 0u8..16 {
            for l in [false, true] {
                for pp in 0u8..4 {
                    for opcode in [0x52u8, 0x53] {
                        for reg_rm in 0u8..=0x3F {
                            let bytes =
                                c5_encoding(encoded_r, encoded_vvvv, l, pp, opcode, 0xC0 | reg_rm);
                            let instruction = X86InstructionBytes::new(&bytes).unwrap();
                            let expected =
                                (pp == 2 || (pp == 0 && encoded_vvvv == 15)).then_some(true);
                            assert_eq!(
                                instruction.legacy_vex_register_fp_estimate_needs_avx(),
                                expected,
                                "{bytes:02X?}"
                            );
                            if expected.is_some() {
                                assert_eq!(
                                    instruction.vex_fp_estimate_destination_index(),
                                    Some(((reg_rm >> 3) & 7) | (u8::from(!encoded_r) << 3)),
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
    assert_eq!(accepted, 82_688);

    // Independently assembled with LLVM 23.0.0git.
    for (bytes, needs_avx, destination) in [
        (&[0x0F, 0x53, 0xCB][..], false, None), // rcpps xmm1,xmm3
        (&[0xF3, 0x45, 0x0F, 0x52, 0xCB][..], false, None), // rsqrtss xmm9,xmm11
        (&[0xC4, 0x41, 0x7C, 0x53, 0xCB][..], true, Some(9)), // vrcpps ymm9,ymm11
        (&[0xC4, 0x41, 0x2A, 0x52, 0xCB][..], true, Some(9)), // vrsqrtss xmm9,xmm10,xmm11
    ] {
        let instruction = X86InstructionBytes::new(bytes).unwrap();
        assert_eq!(
            instruction.legacy_vex_register_fp_estimate_needs_avx(),
            Some(needs_avx),
            "{bytes:02X?}"
        );
        assert_eq!(
            instruction.vex_fp_estimate_destination_index(),
            destination,
            "{bytes:02X?}"
        );
    }
}

#[test]
fn native_estimate_encoding_changes_only_ignored_scalar_l_and_keeps_guest_bytes() {
    for extension in 0u8..8 {
        for w in [false, true] {
            for encoded_vvvv in 0u8..16 {
                for l in [false, true] {
                    for pp in 0u8..4 {
                        for opcode in [0x52u8, 0x53] {
                            for reg_rm in 0u8..=0x3F {
                                let bytes = c4_encoding(
                                    extension << 5,
                                    w,
                                    encoded_vvvv,
                                    l,
                                    pp,
                                    opcode,
                                    0xC0 | reg_rm,
                                );
                                let instruction = X86InstructionBytes::new(&bytes).unwrap();
                                let mut expected = bytes;
                                if pp == 2 {
                                    expected[2] &= !4;
                                }
                                let valid = pp == 2 || (pp == 0 && encoded_vvvv == 15);
                                assert_eq!(
                                    instruction.vex_fp_estimate_native_encoding(),
                                    valid.then(|| X86InstructionBytes::new(&expected).unwrap()),
                                    "{bytes:02X?}"
                                );
                                assert_eq!(instruction.as_slice(), bytes);
                            }
                        }
                    }
                }
            }
        }
    }
    for encoded_r in [false, true] {
        for encoded_vvvv in 0u8..16 {
            for l in [false, true] {
                for pp in 0u8..4 {
                    for opcode in [0x52u8, 0x53] {
                        for reg_rm in 0u8..=0x3F {
                            let bytes =
                                c5_encoding(encoded_r, encoded_vvvv, l, pp, opcode, 0xC0 | reg_rm);
                            let instruction = X86InstructionBytes::new(&bytes).unwrap();
                            let mut expected = bytes;
                            if pp == 2 {
                                expected[1] &= !4;
                            }
                            let valid = pp == 2 || (pp == 0 && encoded_vvvv == 15);
                            assert_eq!(
                                instruction.vex_fp_estimate_native_encoding(),
                                valid.then(|| X86InstructionBytes::new(&expected).unwrap()),
                                "{bytes:02X?}"
                            );
                            assert_eq!(instruction.as_slice(), bytes);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn classifier_rejects_every_structural_memory_and_reserved_frontier() {
    let invalid: &[&[u8]] = &[
        &[0xF0, 0x0F, 0x53, 0xC1],       // LOCK prefix
        &[0x66, 0x0F, 0x53, 0xC1],       // wrong mandatory prefix
        &[0xF2, 0x0F, 0x52, 0xC1],       // wrong mandatory prefix
        &[0xF3, 0x40, 0x66, 0x0F, 0x53], // malformed byte order
        &[0x0F, 0x53, 0x01],             // legacy memory source
        &[0x0F, 0x51, 0xC1],             // wrong opcode
        &[0x0F, 0x53, 0xC1, 0],          // trailing byte
        &[0xC4, 0xE2, 0x78, 0x53, 0xC1], // VEX map 0F38
        &[0xC4, 0xE1, 0x70, 0x53, 0xC1], // packed reserved vvvv
        &[0xC4, 0xE1, 0x79, 0x53, 0xC1], // 66 mandatory prefix
        &[0xC4, 0xE1, 0x7B, 0x52, 0xC1], // F2 mandatory prefix
        &[0xC4, 0xE1, 0x7A, 0x53, 0x01], // VEX memory source
        &[0xC4, 0xE1, 0x7A, 0x51, 0xC1], // wrong opcode
        &[0xC5, 0x70, 0x52, 0xC1],       // packed reserved vvvv
        &[0xC5, 0x79, 0x53, 0xC1],       // 66 mandatory prefix
        &[0xC5, 0x7B, 0x53, 0xC1],       // F2 mandatory prefix
        &[0xC5, 0x7A, 0x53, 0x01],       // VEX memory source
        &[0xC5, 0x7A, 0x53, 0xC1, 0],    // trailing byte
    ];
    for bytes in invalid {
        let instruction = X86InstructionBytes::new(bytes).unwrap();
        assert_eq!(
            instruction.legacy_vex_register_fp_estimate_needs_avx(),
            None,
            "{bytes:02X?}"
        );
        assert_eq!(
            instruction.vex_fp_estimate_destination_index(),
            None,
            "{bytes:02X?}"
        );
    }
}

#[test]
fn dedicated_and_aggregate_spans_require_exact_defined_source_provenance() {
    for bytes in [
        &[0xF3, 0x45, 0x0F, 0x52, 0xCB][..],
        &[0xC4, 0x41, 0x2E, 0x53, 0xCB][..],
    ] {
        let pc = 0x5253;
        let mut block = SmirBlock::new(BlockId(35), pc);
        block.push_op(SmirOp::new(OpId(0), pc, OpKind::Nop));
        block.push_op(SmirOp::new(OpId(1), pc, OpKind::Nop));
        let instruction = X86InstructionBytes::new(bytes).unwrap();
        let provenance = HashMap::from([((block.id, pc), instruction)]);

        for spans in [
            x86_legacy_vex_fp_estimate_replay_spans(&block, &provenance),
            x86_native_replay_spans(&block, &provenance),
        ] {
            let span = spans.get(&0).unwrap_or_else(|| panic!("{bytes:02X?}"));
            assert_eq!(span.end, 2);
            assert_eq!(span.instruction, instruction);
            assert!(!span.needs_avx512vl);
            assert!(!span.needs_avx512dq);
            assert!(!span.needs_avx512fp16);
        }

        block.push_op(SmirOp::new(OpId(2), pc + bytes.len() as u64, OpKind::Nop));
        block.push_op(SmirOp::new(OpId(3), pc, OpKind::Nop));
        assert!(x86_native_replay_spans(&block, &provenance).is_empty());
    }
}
