//! Packed integer reads across decode, deferred I/O, and restoration.
use super::*;
use packed_multiply::bytes;

#[path = "../../../../tools/hvf/intel_mmio_packed_narrow.rs"]
mod packed_narrow;
#[path = "../../../../tools/hvf/intel_mmio_packed_vectors.rs"]
mod packed_vectors;

#[test]
fn packed_narrowing_matches_x86_ram_and_completes_once() {
    check_packed_device_reads(&packed_narrow::CASES);
}

#[test]
fn packed_horizontal_matches_x86_ram_and_completes_once() {
    check_packed_device_reads(&packed_vectors::HORIZONTAL_CASES);
}

#[test]
fn packed_unsigned_matches_x86_ram_and_completes_once() {
    check_packed_device_reads(&packed_vectors::UNSIGNED_CASES);
}

#[test]
fn packed_sign_matches_x86_ram_and_completes_once() {
    check_packed_device_reads(&packed_vectors::SIGN_CASES);
}

#[test]
fn packed_absolute_memory_forms_complete_once_after_restore() {
    let mut rejected = Vec::new();
    for case in &packed_vectors::ABSOLUTE_CASES {
        let name = case.mnemonic;
        for (code, form, width) in case.unary_forms() {
            let vex = form != "legacy";
            let encoding = match (vex, width) {
                (false, _) => Encoding::Legacy,
                (true, 16) => Encoding::Vex128,
                (true, _) => Encoding::Vex256,
            };
            let (context, mut memory, mut exit) = fixture(&code);
            if vex {
                exit.linear += 3;
                exit.physical += 3;
            }
            let plan = match prepare(&context, &mut memory, exit) {
                Ok(plan) => plan,
                Err(error) => {
                    rejected.push(format!("{name} {code:02x?}: {error}"));
                    continue;
                }
            };
            assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
            assert_eq!(plan.length, code.len() as u64);
            assert!(memory.reads.iter().all(|&(addr, _)| addr != exit.physical));
            let Action::UnaryVector(input) = plan.action else {
                panic!("{name} {code:02x?}: {:?}", plan.action);
            };
            assert_eq!(input.encoding, encoding);
            let decoded = instruction_metadata::decode(64, context.rip, &code).unwrap();
            assert!(decoded.operands_complete);
            assert_eq!(
                decoded.mnemonic,
                format!("{}{name}", if vex { "v" } else { "" })
            );
            let [target, source] = decoded.operands.as_slice() else {
                panic!("{decoded:?}");
            };
            assert_eq!(target.kind, OperandKind::Register);
            assert_eq!(source.kind, OperandKind::Memory);
            assert_eq!(
                (target.read, target.write, source.read, source.write),
                (false, true, true, false)
            );
            assert_eq!(source.width_bits, width as u32 * 8);

            for ([_, input_bytes], result) in case.sources.into_iter().zip(case.results) {
                let reply = bytes(input_bytes);
                let expected = bytes(result);
                let mut pending = mmio::InputState::default();
                pending.begin_unary_vector(input.clone()).unwrap();
                let wire = rax::codec::serialize(&pending).unwrap();
                let restored: mmio::InputState = rax::codec::deserialize_strict(&wire).unwrap();
                restored.validate_checkpoint().unwrap();
                for mut state in [pending, restored] {
                    assert_eq!(state.descriptor(), Some((width as u8, None)));
                    let mut host = Host::default();
                    state.complete(&mut host, &reply[..width]);
                    state.complete(&mut host, &reply[..width]);
                    let expected = if width == 32 {
                        Write::Ymm(15, expected)
                    } else {
                        Write::Xmm(15, expected[..16].try_into().unwrap(), vex)
                    };
                    assert_eq!(host.0, [expected, Write::Retire(plan.length)]);
                }
            }
            exit.qualification = 0x182;
            assert!(prepare(&context, &mut memory, exit).is_err());

            let mut register_code = code;
            if vex {
                register_code.pop();
            }
            *register_code.last_mut().unwrap() = 0xff;
            let decoded = instruction_metadata::decode(64, context.rip, &register_code).unwrap();
            assert_eq!(decoded.operands[1].kind, OperandKind::Register);
            let (context, mut memory, exit) = fixture(&register_code);
            assert!(prepare(&context, &mut memory, exit).is_err());
        }
    }
    assert!(rejected.is_empty(), "{}", rejected.join("\n"));
}

#[test]
fn packed_absolute_rejects_mmio_for_unhandled_forms_before_device_access() {
    for opcode in 0x1c..=0x1e {
        for code in [
            vec![0x0f, 0x38, opcode, 0x07],             // MMX destination.
            vec![0xf0, 0x66, 0x0f, 0x38, opcode, 0x07], // LOCK.
            vec![0xc4, 0xe2, 0x78, opcode, 0x07],       // Missing mandatory prefix.
            vec![0xc4, 0xe2, 0x71, opcode, 0x07],       // Reserved VEX.vvvv.
            vec![0x62, 0xf2, 0x7d, 0x08, opcode, 0x07], // EVEX destination.
            vec![0x66, 0x0f, 0x38, opcode, 0x07],       // Misaligned legacy input.
        ] {
            let (mut context, mut memory, mut exit) = fixture(&code);
            context.registers[7] += 1;
            exit.linear += 1;
            exit.physical += 1;
            assert!(prepare(&context, &mut memory, exit).is_err(), "{code:02x?}");
            assert!(memory.reads.iter().all(|&(addr, _)| addr != exit.physical));
        }
    }
}

#[test]
fn prior_unary_shuffle_wire_record_still_completes() {
    // Legacy codec layout: Some, pending UnaryShuffle (11), XMM15, VEX.128
    // (1), length 5, Doublewords (0), control 1b, no failure or saved reply.
    let wire = [
        1, 11, 0, 0, 0, 15, 1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1b, 0, 0,
    ];
    let mut pending: mmio::InputState = rax::codec::deserialize_strict(&wire).unwrap();
    pending.validate_checkpoint().unwrap();
    assert_eq!(rax::codec::serialize(&pending).unwrap(), wire);
    let mut host = Host::default();
    pending.complete(&mut host, &[1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0]);
    assert_eq!(
        host.0,
        [
            Write::Xmm(15, [4, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0], true),
            Write::Retire(5)
        ]
    );
}

fn check_packed_device_reads(cases: &[packed_vectors::Case]) {
    let mut rejected = Vec::new();
    for case in cases {
        for (code, form, width) in case.forms() {
            let label = (case.mnemonic, form);
            let vex = form != "legacy";
            let (context, mut memory, mut exit) = fixture(&code);
            if vex {
                exit.linear += 3;
                exit.physical += 3;
            }
            let plan = match prepare(&context, &mut memory, exit) {
                Ok(plan) => plan,
                Err(error) => {
                    rejected.push(format!("{label:?}: {error}"));
                    continue;
                }
            };
            assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
            assert!(memory.reads.iter().all(|&(addr, _)| addr != exit.physical));
            let Action::VectorLogic { input, source } = plan.action else {
                panic!("{label:?}: unexpected action {:?}", plan.action);
            };
            let encoding = match (vex, width) {
                (false, _) => Encoding::Legacy,
                (true, 16) => Encoding::Vex128,
                (true, _) => Encoding::Vex256,
            };
            assert_eq!((source, input.index), (if vex { 8 } else { 15 }, 15));
            assert_eq!(input.encoding, encoding);
            assert_eq!(input.length, code.len() as u64);
            assert_eq!(usize::from(input.memory_size()), width);

            let metadata = instruction_metadata::decode(64, context.rip, &code).unwrap();
            let name = format!("{}{}", if vex { "v" } else { "" }, case.mnemonic);
            assert_eq!(metadata.mnemonic, name);
            assert!(metadata.operands_complete);
            let device = metadata.operands.last().unwrap();
            assert_eq!(device.kind, OperandKind::Memory);
            assert!(device.read && !device.write);
            assert_eq!(device.width_bits, width as u32 * 8);

            for ([left, right], expected) in case.sources.into_iter().zip(case.results) {
                let mut pending = mmio::InputState::default();
                pending
                    .begin_vector_logic(input.clone(), bytes(left))
                    .unwrap();
                let wire = rax::codec::serialize(&pending).unwrap();
                let restored: mmio::InputState = rax::codec::deserialize_strict(&wire).unwrap();
                restored.validate_checkpoint().unwrap();
                assert_eq!(restored.descriptor(), Some((width as u8, None)));
                let reply = bytes(right);
                let expected = bytes(expected);
                let effect = if width == 32 {
                    Write::Ymm(15, expected)
                } else {
                    Write::Xmm(15, expected[..16].try_into().unwrap(), vex)
                };
                for mut transaction in [pending, restored] {
                    let mut host = Host::default();
                    transaction.complete(&mut host, &reply[..width]);
                    transaction.complete(&mut host, &reply[..width]);
                    assert_eq!(host.0.len(), 2, "{label:?}");
                    assert_eq!(host.0[0], effect, "{label:?}");
                    assert_eq!(host.0[1], Write::Retire(plan.length), "{label:?}");
                }
            }
            exit.qualification = 0x182;
            assert!(prepare(&context, &mut memory, exit).is_err(), "{label:?}");

            // Keep the stateless register form visible, while excluding it from MMIO.
            let mut register_code = code;
            if vex {
                register_code.pop();
            }
            *register_code.last_mut().unwrap() = 0xff;
            let decoded = instruction_metadata::decode(64, context.rip, &register_code).unwrap();
            assert_eq!(decoded.mnemonic, name);
            assert_eq!(decoded.operands.last().unwrap().kind, OperandKind::Register);
            let (context, mut memory, exit) = fixture(&register_code);
            assert!(prepare(&context, &mut memory, exit).is_err(), "{label:?}");
        }
    }
    assert!(rejected.is_empty(), "{}", rejected.join("\n"));
}

#[test]
fn packed_narrowing_requires_legacy_alignment_and_allocated_prefixes() {
    check_packed_legacy_admission(&packed_narrow::CASES);
    for code in [
        &[0xc5, 0x38, 0x63, 0x3f][..],         // VEX PACKSSWB without 66.
        &[0xc4, 0x62, 0x38, 0x2b, 0x3f],       // VEX PACKUSDW without 66.
        &[0x62, 0x71, 0x3d, 0x08, 0x63, 0x3f], // EVEX operand shape.
    ] {
        let (context, mut memory, exit) = fixture(code);
        assert!(prepare(&context, &mut memory, exit).is_err(), "{code:02x?}");
        assert!(memory.reads.iter().all(|&(addr, _)| addr != exit.physical));
    }
}

#[test]
fn packed_horizontal_requires_legacy_alignment_and_allocated_prefixes() {
    check_packed_prefix_admission(&packed_vectors::HORIZONTAL_CASES);
}

#[test]
fn packed_unsigned_requires_legacy_alignment_and_allocated_prefixes() {
    check_packed_prefix_admission(&packed_vectors::UNSIGNED_CASES);
}

#[test]
fn packed_sign_requires_legacy_alignment_and_allocated_prefixes() {
    check_packed_prefix_admission(&packed_vectors::SIGN_CASES);
}

fn check_packed_prefix_admission(cases: &[packed_vectors::Case]) {
    check_packed_legacy_admission(cases);
    for case in cases {
        for (mut code, form, _) in case.forms() {
            if form != "legacy" {
                let control = if code[0] == 0xc5 { 1 } else { 2 };
                code[control] &= !3;
                let (context, mut memory, mut exit) = fixture(&code);
                exit.linear += 3;
                exit.physical += 3;
                assert!(prepare(&context, &mut memory, exit).is_err(), "{code:02x?}");
                assert!(memory.reads.iter().all(|&(addr, _)| addr != exit.physical));
            }
        }
    }
}

fn check_packed_legacy_admission(cases: &[packed_vectors::Case]) {
    for case in cases {
        let code = case.legacy();
        let (mut context, mut memory, mut exit) = fixture(&code);
        context.registers[7] += 1;
        exit.linear += 1;
        exit.physical += 1;
        assert_eq!(
            prepare(&context, &mut memory, exit).unwrap_err(),
            "misaligned legacy vector logic MMIO input",
            "{}",
            case.mnemonic
        );
        assert!(memory.reads.iter().all(|&(addr, _)| addr != exit.physical));
        let locked = [&[0xf0][..], &code].concat();
        for invalid in [&code[1..], locked.as_slice()] {
            let (context, mut memory, exit) = fixture(invalid);
            assert!(prepare(&context, &mut memory, exit).is_err());
        }
    }
}
