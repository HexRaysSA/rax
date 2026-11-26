//! Packed logical instructions with a read-only device operand.
use super::*;
use mmio::vector_logic::Encoding;
use rax::isa::x86_64::instruction_metadata::{self, OperandKind};
use sha2::{Digest, Sha256};

#[path = "../../../../tools/hvf/intel_mmio_packed_multiply.rs"]
mod packed_multiply;
#[path = "../../../../tools/hvf/intel_mmio_packed_shuffle.rs"]
mod packed_shuffle;
#[path = "vector_aes.rs"]
mod vector_aes;
#[path = "vector_aes_unary.rs"]
mod vector_aes_unary;
#[path = "vector_immediate_blend.rs"]
mod vector_immediate_blend;
#[path = "vector_narrow.rs"]
mod vector_narrow;
#[path = "vector_permutation.rs"]
mod vector_permutation;
#[path = "vector_register_blend.rs"]
mod vector_register_blend;

const FORMS: [(u8, u8, &str); 12] = [
    (0, 0x54, "andps"),
    (0, 0x55, "andnps"),
    (0, 0x56, "orps"),
    (0, 0x57, "xorps"),
    (1, 0x54, "andpd"),
    (1, 0x55, "andnpd"),
    (1, 0x56, "orpd"),
    (1, 0x57, "xorpd"),
    (1, 0xdb, "pand"),
    (1, 0xdf, "pandn"),
    (1, 0xeb, "por"),
    (1, 0xef, "pxor"),
];

#[test]
fn two_source_permute_halves_matches_every_ram_control_after_restore() {
    use packed_shuffle::{
        PERMUTE_HALVES, immediate_reply, permute_halves_code, permute_halves_expected, source,
    };

    let mut observations = Sha256::new();
    let reply = immediate_reply();
    for (mnemonic, opcode) in PERMUTE_HALVES {
        for control in u8::MIN..=u8::MAX {
            let code = permute_halves_code(opcode, control);
            let label = (mnemonic, control);
            let (context, mut memory, mut exit) = fixture(&code);
            exit.linear += 3;
            exit.physical += 3;
            let decoded = instruction_metadata::decode(64, context.rip, &code)
                .unwrap_or_else(|error| panic!("{label:?}: {error:?}"));
            assert_eq!(decoded.mnemonic, mnemonic);
            assert!(decoded.operands_complete);
            assert_eq!(decoded.operands[2].width_bits, 256);
            assert_eq!(decoded.operands[3].value, u64::from(control));
            let plan = prepare(&context, &mut memory, exit).unwrap();
            assert_eq!(
                (plan.linear, plan.physical, plan.length),
                (exit.linear, exit.physical, 7)
            );
            assert!(
                memory
                    .reads
                    .iter()
                    .all(|&(address, _)| address != exit.physical)
            );
            let Action::VectorLogic {
                input,
                source: first,
            } = plan.action
            else {
                panic!("{label:?}: unexpected action {:?}", plan.action);
            };
            assert_eq!(
                (input.index, input.encoding, first),
                (15, Encoding::Vex256, 8)
            );
            let mut pending = mmio::InputState::default();
            pending.begin_vector_logic(input, source()).unwrap();
            let saved = rax::codec::serialize(&pending).unwrap();
            let mut restored: mmio::InputState = rax::codec::deserialize_strict(&saved).unwrap();
            restored.validate_checkpoint().unwrap();
            assert_eq!(restored.descriptor(), Some((32, None)));
            let mut host = Host::default();
            restored.complete(&mut host, &reply);
            restored.complete(&mut host, &reply);
            let [Write::Ymm(15, actual), Write::Retire(7)] = host.0.as_slice() else {
                panic!("{label:?}: unexpected completion {:?}", host.0);
            };
            assert_eq!(*actual, permute_halves_expected(control), "{label:?}");
            observations.update(actual);
        }
    }
    assert_eq!(
        format!("{:x}", observations.finalize()),
        "c75e2212d0cf632e5e47c206b4f665aed25e4487ace402f51239aeb1a3500174"
    );
}

#[test]
fn two_source_permute_halves_refuses_reserved_and_register_only_encodings() {
    for (_, opcode) in packed_shuffle::PERMUTE_HALVES {
        let legal = packed_shuffle::permute_halves_code(opcode, 0x88);
        for (index, replacement) in [
            (2, 0x39), // L=0
            (2, 0xbd), // W=1
            (2, 0x3c), // Missing mandatory 66
        ] {
            let mut code = legal;
            code[index] = replacement;
            assert!(instruction_metadata::decode(64, 0x1000, &code).is_err());
        }

        let register = [0xc4, 0x63, 0x3d, opcode, 0xff, 0x88];
        assert!(instruction_metadata::decode(64, 0x1000, &register).is_ok());
        let (context, mut memory, exit) = fixture(&register);
        assert!(prepare(&context, &mut memory, exit).is_err());

        let (context, mut memory, mut exit) = fixture(&legal);
        exit.linear += 3;
        exit.physical += 3;
        let Action::VectorLogic { mut input, .. } =
            prepare(&context, &mut memory, exit).unwrap().action
        else {
            panic!("expected a pending vector read");
        };
        // A malformed saved descriptor must not select a 128-bit completion.
        input.encoding = Encoding::Vex128;
        assert!(
            mmio::InputState::default()
                .begin_vector_logic(input, packed_shuffle::source())
                .is_err()
        );
    }
}

#[test]
fn packed_byte_shuffle_preserves_lanes_and_restores_once() {
    use packed_shuffle::{CONTROL, EXPECTED, FORMS, source};

    for (name, code, width) in FORMS {
        let vex = name != "legacy";
        let (context, mut memory, mut exit) = fixture(code);
        if vex {
            exit.linear += 3;
            exit.physical += 3;
        }
        let meta = instruction_metadata::decode(64, context.rip, code).unwrap();
        assert!(meta.operands_complete, "{name}: {meta:?}");
        assert_eq!(meta.mnemonic, if vex { "vpshufb" } else { "pshufb" });

        let plan = prepare(&context, &mut memory, exit).unwrap();
        assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
        assert_eq!(plan.length, code.len() as u64);
        assert!(memory.reads.iter().all(|&(addr, _)| addr != exit.physical));
        let Action::VectorLogic {
            input,
            source: source_index,
        } = plan.action
        else {
            panic!("{name}: unexpected action {:?}", plan.action);
        };
        let encoding = match (vex, width) {
            (false, _) => Encoding::Legacy,
            (true, 16) => Encoding::Vex128,
            (true, _) => Encoding::Vex256,
        };
        assert_eq!((input.index, input.encoding), (15, encoding));
        assert_eq!(source_index, if vex { 8 } else { 15 });

        let mut pending = mmio::InputState::default();
        pending.begin_vector_logic(input, source()).unwrap();
        let saved = rax::codec::serialize(&pending).unwrap();
        let mut restored: mmio::InputState = rax::codec::deserialize_strict(&saved).unwrap();
        restored.validate_checkpoint().unwrap();
        assert_eq!(restored.descriptor(), Some((width as u8, None)));
        let expected = if width == 32 {
            Write::Ymm(15, EXPECTED)
        } else {
            Write::Xmm(15, EXPECTED[..16].try_into().unwrap(), vex)
        };
        let mut host = Host::default();
        restored.complete(&mut host, &CONTROL[..width]);
        restored.complete(&mut host, &CONTROL[..width]);
        assert_eq!(host.0, [expected, Write::Retire(plan.length)], "{name}");

        exit.qualification = 0x182;
        assert!(prepare(&context, &mut memory, exit).is_err(), "{name}");
    }
}

#[test]
fn register_mask_blend_projects_the_captured_vector_operands() {
    for (mnemonic, raw, vex) in [
        ("blendvps", &[0x66, 0x44, 0x0f, 0x38, 0x14, 0x3f][..], false),
        ("blendvpd", &[0x66, 0x44, 0x0f, 0x38, 0x15, 0x3f][..], false),
        ("pblendvb", &[0x66, 0x44, 0x0f, 0x38, 0x10, 0x3f][..], false),
        (
            "vblendvps",
            &[0xc4, 0x63, 0x3d, 0x4a, 0x7f, 3, 0xff][..],
            true,
        ),
        (
            "vblendvpd",
            &[0xc4, 0x63, 0x3d, 0x4b, 0x7f, 3, 0xff][..],
            true,
        ),
        (
            "vpblendvb",
            &[0xc4, 0x63, 0x3d, 0x4c, 0x7f, 3, 0xff][..],
            true,
        ),
    ] {
        let (context, mut memory, mut exit) = fixture(raw);
        if vex {
            exit.linear += 3;
            exit.physical += 3;
        }
        let metadata = instruction_metadata::decode(64, context.rip, raw).unwrap();
        assert_eq!(metadata.mnemonic, mnemonic);
        let mask = metadata.operands.last().unwrap();
        assert_eq!(mask.kind, OperandKind::Register);
        assert_eq!(mask.reg, if vex { "ymm15" } else { "xmm0" });
        assert!(mask.read && !mask.write);
        let plan = prepare(&context, &mut memory, exit).unwrap();
        assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
    }
}

#[test]
fn packed_byte_shuffle_rejects_non_device_forms_and_misaligned_legacy() {
    for code in [
        &[0x0f, 0x38, 0x00, 0x3f][..],               // MMX bank.
        &[0x66, 0x44, 0x0f, 0x38, 0x00, 0xff],       // Register operand.
        &[0xc4, 0x62, 0x39, 0x00, 0xff],             // VEX register operand.
        &[0xc4, 0x62, 0x38, 0x00, 0x3f],             // Wrong VEX mandatory prefix.
        &[0xf0, 0x66, 0x44, 0x0f, 0x38, 0x00, 0x3f], // LOCK.
    ] {
        let (context, mut memory, exit) = fixture(code);
        assert!(prepare(&context, &mut memory, exit).is_err(), "{code:02x?}");
        assert!(memory.reads.iter().all(|&(addr, _)| addr != exit.physical));
    }
    let (_, code, _) = packed_shuffle::FORMS[0];
    let (mut context, mut memory, mut exit) = fixture(code);
    context.registers[7] += 1;
    exit.linear += 1;
    exit.physical += 1;
    let error = prepare(&context, &mut memory, exit).unwrap_err();
    assert!(error.contains("misaligned"), "{error}");
}

#[test]
fn packed_immediate_shuffle_keeps_control_and_both_sources_across_checkpoint() {
    use packed_shuffle::{immediate_cases, immediate_reply, source};

    let reply = immediate_reply();
    for case in immediate_cases() {
        let vex = case.encoding != "legacy";
        let label = (case.mnemonic, case.encoding);
        let (context, mut memory, mut exit) = fixture(&case.code);
        if vex {
            exit.linear += 3;
            exit.physical += 3;
        }
        let meta = instruction_metadata::decode(64, context.rip, &case.code)
            .unwrap_or_else(|failure| panic!("{label:?}: {failure:?}"));
        assert!(meta.operands_complete, "{label:?}: {meta:?}");
        assert_eq!(
            meta.mnemonic,
            format!("{}{}", if vex { "v" } else { "" }, case.mnemonic)
        );
        let control = meta.operands.last().unwrap();
        assert_eq!(control.kind, OperandKind::Immediate);
        assert_eq!(
            (control.width_bits, control.value),
            (8, u64::from(*case.code.last().unwrap()))
        );
        assert!(
            instruction_metadata::decode(64, context.rip, &case.code[..case.code.len() - 1])
                .is_err()
        );

        let plan = prepare(&context, &mut memory, exit).unwrap();
        assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
        assert_eq!(plan.length, case.code.len() as u64);
        assert!(memory.reads.iter().all(|&(addr, _)| addr != exit.physical));
        let Action::VectorLogic {
            input,
            source: source_index,
        } = plan.action
        else {
            panic!("{label:?}: unexpected action {:?}", plan.action);
        };
        assert_eq!((input.index, source_index), (15, if vex { 8 } else { 15 }));
        let mut pending = mmio::InputState::default();
        pending.begin_vector_logic(input, source()).unwrap();
        let saved = rax::codec::serialize(&pending).unwrap();
        let mut restored: mmio::InputState = rax::codec::deserialize_strict(&saved).unwrap();
        restored.validate_checkpoint().unwrap();
        assert_eq!(restored.descriptor(), Some((case.width as u8, None)));
        let expected = if case.width == 32 {
            Write::Ymm(15, case.expected)
        } else {
            Write::Xmm(15, case.expected[..16].try_into().unwrap(), vex)
        };
        let mut host = Host::default();
        restored.complete(&mut host, &reply[..case.width]);
        restored.complete(&mut host, &reply[..case.width]);
        assert_eq!(host.0, [expected, Write::Retire(plan.length)], "{label:?}");
    }
}

#[test]
fn packed_immediate_shuffle_preserves_legacy_alignment_and_rejects_non_device_forms() {
    for case in packed_shuffle::immediate_cases()
        .into_iter()
        .filter(|case| case.encoding == "legacy")
    {
        let (mut context, mut memory, mut exit) = fixture(&case.code);
        context.registers[7] += 1;
        exit.linear += 1;
        exit.physical += 1;
        let error = prepare(&context, &mut memory, exit).unwrap_err();
        assert!(error.contains("misaligned"), "{}: {error}", case.mnemonic);
        assert!(memory.reads.iter().all(|&(addr, _)| addr != exit.physical));
    }
    for code in [
        &[0x44, 0x0f, 0xc6, 0xff, 0x1b][..],   // register source
        &[0x0f, 0x3a, 0x0f, 0x3f, 13],         // MMX bank
        &[0xc5, 0x3a, 0xc6, 0x7f, 3, 0x1b],    // wrong VEX prefix
        &[0xf0, 0x44, 0x0f, 0xc6, 0x3f, 0x1b], // LOCK
    ] {
        let (context, mut memory, exit) = fixture(code);
        assert!(prepare(&context, &mut memory, exit).is_err(), "{code:02x?}");
        assert!(memory.reads.iter().all(|&(addr, _)| addr != exit.physical));
    }
}

#[test]
fn unary_packed_shuffle_plans_read_only_device_operands() {
    for case in packed_shuffle::unary_cases() {
        let vex = case.encoding != "legacy";
        let label = (case.mnemonic, case.encoding);
        let (context, mut memory, mut exit) = fixture(&case.code);
        if vex {
            exit.linear += 3;
            exit.physical += 3;
        }
        let meta = instruction_metadata::decode(64, context.rip, &case.code)
            .unwrap_or_else(|error| panic!("{label:?}: {error:?}"));
        assert_eq!(
            meta.mnemonic,
            format!("{}{}", if vex { "v" } else { "" }, case.mnemonic)
        );
        assert!(meta.operands_complete);
        let [target, device, control] = meta.operands.as_slice() else {
            panic!("{label:?}: {:?}", meta.operands);
        };
        let width = (case.width * 8) as u32;
        assert_eq!(target.kind, OperandKind::Register);
        assert_eq!(target.reg, if width == 256 { "ymm15" } else { "xmm15" });
        assert_eq!(
            (target.width_bits, target.read, target.write),
            (width, false, true)
        );
        assert_eq!(device.kind, OperandKind::Memory);
        assert_eq!(
            (device.width_bits, device.read, device.write),
            (width, true, false)
        );
        assert_eq!(control.kind, OperandKind::Immediate);
        assert_eq!((control.width_bits, control.value), (8, 0x1b));
        assert!(
            instruction_metadata::decode(64, context.rip, &case.code[..case.code.len() - 1])
                .is_err()
        );
        let plan = prepare(&context, &mut memory, exit).unwrap();
        assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
        assert_eq!(plan.length, case.code.len() as u64);
        assert!(
            memory
                .reads
                .iter()
                .all(|&(address, _)| address != exit.physical)
        );
    }
}

#[test]
fn unary_packed_shuffle_retains_every_immediate_through_pending_io() {
    let reply = packed_shuffle::immediate_reply();
    for mut case in packed_shuffle::unary_cases() {
        let vex = case.encoding != "legacy";
        let (element_bits, first_bit) = match case.mnemonic {
            "pshufd" => (32, 0),
            "pshufhw" => (16, 64),
            "pshuflw" => (16, 0),
            _ => unreachable!(),
        };
        let element_mask = (1u128 << element_bits) - 1;
        let selection_mask = (u128::MAX >> (128 - 4 * element_bits)) << first_bit;
        for immediate in 0..=255 {
            *case.code.last_mut().unwrap() = immediate;
            let (context, mut memory, mut exit) = fixture(&case.code);
            if vex {
                exit.linear += 3;
                exit.physical += 3;
            }
            let plan = prepare(&context, &mut memory, exit).unwrap();
            let Action::UnaryVector(input) = plan.action else {
                panic!("{:?}", plan.action);
            };
            let mut pending = mmio::InputState::default();
            pending.begin_unary_vector(input).unwrap();
            let saved = rax::codec::serialize(&pending).unwrap();
            let mut restored: mmio::InputState = rax::codec::deserialize_strict(&saved).unwrap();
            restored.validate_checkpoint().unwrap();
            assert_eq!(restored.descriptor(), Some((case.width as u8, None)));

            let mut expected = [0; 32];
            for offset in (0..case.width).step_by(16) {
                let lane = u128::from_le_bytes(reply[offset..offset + 16].try_into().unwrap());
                let mut result = lane & !selection_mask;
                for destination in 0..4 {
                    let source = u32::from((immediate >> (2 * destination)) & 3);
                    let element = (lane >> (first_bit + element_bits * source)) & element_mask;
                    result |= element << (first_bit + element_bits * destination);
                }
                expected[offset..offset + 16].copy_from_slice(&result.to_le_bytes());
            }
            if immediate == 0x1b {
                assert_eq!(expected, case.expected);
                let mut short = restored.clone();
                let mut host = Host::default();
                short.complete(&mut host, &reply[..case.width - 1]);
                assert!(short.failure().is_some());
                assert!(short.pending());
                assert!(host.0.is_empty());
            }
            let expected = if case.width == 32 {
                Write::Ymm(15, expected)
            } else {
                Write::Xmm(15, expected[..16].try_into().unwrap(), vex)
            };
            let mut host = Host::default();
            restored.complete(&mut host, &reply[..case.width]);
            restored.complete(&mut host, &reply[..case.width]);
            assert_eq!(
                host.0,
                [expected, Write::Retire(plan.length)],
                "{} {} immediate {immediate:#04x}",
                case.mnemonic,
                case.encoding
            );
        }
    }
}

#[test]
fn unary_packed_shuffle_rejects_non_device_and_reserved_forms() {
    for case in packed_shuffle::unary_cases() {
        let (mut context, mut memory, mut exit) = fixture(&case.code);
        if case.encoding == "legacy" {
            context.registers[7] += 1;
            exit.linear += 1;
            exit.physical += 1;
            let error = prepare(&context, &mut memory, exit).unwrap_err();
            assert!(error.contains("misaligned"), "{}: {error}", case.mnemonic);
            context.registers[7] -= 1;
            exit.linear -= 1;
            exit.physical -= 1;
        } else {
            exit.linear += 3;
            exit.physical += 3;
        }
        exit.qualification = 0x182;
        assert!(prepare(&context, &mut memory, exit).is_err());
        assert!(
            memory
                .reads
                .iter()
                .all(|&(address, _)| address != exit.physical)
        );
    }
    for code in [
        &[0x0f, 0x70, 0x3f, 0x1b][..],               // MMX.
        &[0x66, 0x44, 0x0f, 0x70, 0xff, 0x1b],       // Register source.
        &[0xc5, 0x79, 0x70, 0xff, 0x1b],             // VEX register source.
        &[0xc5, 0x78, 0x70, 0x7f, 3, 0x1b],          // Wrong mandatory selector.
        &[0xc5, 0x71, 0x70, 0x7f, 3, 0x1b],          // Reserved vvvv.
        &[0x62, 0x71, 0x7d, 0x08, 0x70, 0x3f, 0x1b], // EVEX.
        &[0xf0, 0x66, 0x44, 0x0f, 0x70, 0x3f, 0x1b], // LOCK.
    ] {
        let (context, mut memory, exit) = fixture(code);
        assert!(prepare(&context, &mut memory, exit).is_err(), "{code:02x?}");
        assert!(
            memory
                .reads
                .iter()
                .all(|&(address, _)| address != exit.physical)
        );
    }
}

#[test]
fn packed_align_right_uses_unsigned_immediates_in_both_lanes() {
    use packed_shuffle::{immediate_cases, immediate_reply, source};

    let mut case = immediate_cases()
        .into_iter()
        .find(|case| case.mnemonic == "palignr" && case.encoding == "vex256")
        .unwrap();
    let left = source();
    let reply = immediate_reply();
    let mut last = [0; 32];
    last[0] = left[15];
    last[16] = left[31];
    for (count, expected) in [
        (0, reply),
        (16, left),
        (31, last),
        (32, [0; 32]),
        (255, [0; 32]),
    ] {
        *case.code.last_mut().unwrap() = count;
        let (context, mut memory, mut exit) = fixture(&case.code);
        exit.linear += 3;
        exit.physical += 3;
        let plan = prepare(&context, &mut memory, exit).unwrap();
        let Action::VectorLogic { input, .. } = plan.action else {
            panic!("{count}")
        };
        let mut pending = mmio::InputState::default();
        pending.begin_vector_logic(input, left).unwrap();
        let mut host = Host::default();
        pending.complete(&mut host, &reply);
        assert_eq!(
            host.0,
            [Write::Ymm(15, expected), Write::Retire(plan.length)],
            "{count}"
        );
    }
}

#[test]
fn packed_unpack_interleaves_each_lane_and_restores_once() {
    let mut failures = Vec::new();
    for (opcode, element, upper) in [
        (0x60, 1, false),
        (0x61, 2, false),
        (0x62, 4, false),
        (0x6c, 8, false),
        (0x68, 1, true),
        (0x69, 2, true),
        (0x6a, 4, true),
        (0x6d, 8, true),
    ] {
        for (code, encoding) in [
            (&[0x66, 0x44, 0x0f, opcode, 0x3f][..], Encoding::Legacy),
            (&[0xc5, 0x39, opcode, 0x7f, 3], Encoding::Vex128),
            (&[0xc5, 0x3d, opcode, 0x7f, 3], Encoding::Vex256),
            (&[0xc4, 0x61, 0xb9, opcode, 0x7f, 3], Encoding::Vex128),
            (&[0xc4, 0x61, 0xbd, opcode, 0x7f, 3], Encoding::Vex256),
        ] {
            let (context, mut memory, mut exit) = fixture(code);
            let vex = encoding != Encoding::Legacy;
            if vex {
                exit.linear += 3;
                exit.physical += 3;
            }
            let plan = match prepare(&context, &mut memory, exit) {
                Ok(plan) => plan,
                Err(error) => {
                    failures.push(format!("{code:02x?}: {error}"));
                    continue;
                }
            };
            assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
            assert_eq!(plan.length, code.len() as u64);
            assert!(
                memory
                    .reads
                    .iter()
                    .all(|&(address, _)| address != exit.physical)
            );
            let Action::VectorLogic { input, source } = plan.action else {
                panic!("wrong action for {code:02x?}: {:?}", plan.action);
            };
            assert_eq!(
                (source, input.index, input.encoding),
                (if vex { 8 } else { 15 }, 15, encoding)
            );
            let width = usize::from(encoding.size());
            let left = std::array::from_fn(|index| index as u8);
            let right: [u8; 32] = std::array::from_fn(|index| 0xff - index as u8);
            let mut expected = Vec::with_capacity(width);
            for lane in (0..width).step_by(16) {
                let start = lane + if upper { 8 } else { 0 };
                for element_start in (start..start + 8).step_by(element) {
                    expected.extend_from_slice(&left[element_start..][..element]);
                    expected.extend_from_slice(&right[element_start..][..element]);
                }
            }
            let mut pending = mmio::InputState::default();
            pending.begin_vector_logic(input, left).unwrap();
            let record = rax::codec::serialize(&pending).unwrap();
            let mut restored: mmio::InputState = rax::codec::deserialize_strict(&record).unwrap();
            restored.validate_checkpoint().unwrap();
            assert_eq!(restored.descriptor(), Some((width as u8, None)));
            let mut host = Host::default();
            restored.complete(&mut host, &right[..width]);
            restored.complete(&mut host, &right[..width]);
            let expected = if width == 32 {
                Write::Ymm(15, expected.try_into().unwrap())
            } else {
                Write::Xmm(15, expected.try_into().unwrap(), vex)
            };
            assert_eq!(
                host.0,
                [expected, Write::Retire(plan.length)],
                "{code:02x?}"
            );
            exit.qualification = 0x182;
            assert!(prepare(&context, &mut memory, exit).is_err());
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn vector_logical_device_inputs_plan_legacy_vex128_and_vex256() {
    let mut failures = Vec::new();
    for (prefix, opcode, name) in FORMS {
        let legacy = [0x66, 0x44, 0x0f, opcode, 0x3f];
        let vex = 0x38 | prefix;
        for (code, encoding) in [
            (&legacy[usize::from(prefix == 0)..], Encoding::Legacy),
            (&[0xc5, vex, opcode, 0x7f, 3], Encoding::Vex128),
            (&[0xc4, 0x61, vex, opcode, 0x7f, 3], Encoding::Vex128),
            (&[0xc5, vex | 4, opcode, 0x7f, 3], Encoding::Vex256),
            (&[0xc4, 0x61, vex | 4, opcode, 0x7f, 3], Encoding::Vex256),
        ] {
            let (context, mut memory, mut exit) = fixture(code);
            let vector = encoding != Encoding::Legacy;
            exit.qualification = 0x181;
            if vector {
                exit.linear += 3;
                exit.physical += 3;
            }
            match prepare(&context, &mut memory, exit) {
                Ok(plan) => {
                    assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
                    assert_eq!(plan.length, code.len() as u64);
                    let Action::VectorLogic { input, source } = plan.action else {
                        panic!("wrong action for {code:02x?}: {:?}", plan.action);
                    };
                    assert_eq!(
                        (input.encoding, input.index, input.length),
                        (encoding, 15, plan.length)
                    );
                    assert_eq!(source, if vector { 8 } else { 15 });
                    assert!(
                        memory
                            .reads
                            .iter()
                            .all(|&(address, _)| address != exit.physical)
                    );

                    let meta = instruction_metadata::decode(64, context.rip, code).unwrap();
                    let expected_name = if vector {
                        format!("v{name}")
                    } else {
                        name.into()
                    };
                    assert_eq!(meta.mnemonic, expected_name);
                    assert_eq!(meta.operands.len(), if vector { 3 } else { 2 });
                    let (bank, width) = if encoding == Encoding::Vex256 {
                        ("ymm", 256)
                    } else {
                        ("xmm", 128)
                    };
                    let target = &meta.operands[0];
                    assert_eq!(target.reg, format!("{bank}15"));
                    assert_eq!(
                        (target.width_bits, target.read, target.write),
                        (width, !vector, true)
                    );
                    if vector {
                        let left = &meta.operands[1];
                        assert_eq!(left.reg, format!("{bank}8"));
                        assert_eq!(
                            (left.width_bits, left.read, left.write),
                            (width, true, false)
                        );
                    }
                    let right = meta.operands.last().unwrap();
                    assert_eq!(right.kind, OperandKind::Memory);
                    assert_eq!(
                        (right.width_bits, right.read, right.write),
                        (width, true, false)
                    );
                    exit.qualification = 0x182;
                    assert!(prepare(&context, &mut memory, exit).is_err());
                }
                Err(error) => failures.push(format!("{name} {code:02x?} {error}")),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn vector_logic_rejects_misaligned_legacy_and_encodings_without_a_device_operand() {
    for code in [
        &[0x44, 0x0f, 0x54, 0x7f, 3][..],      // Misaligned ANDPS.
        &[0x66, 0x0f, 0xeb, 0x47, 3],          // Misaligned POR.
        &[0x0f, 0x54, 0xc7],                   // Register-only ANDPS.
        &[0xc5, 0x3d, 0xef, 0xff],             // Register-only VPXOR.
        &[0xc5, 0x3a, 0x54, 0x3f],             // Reserved mandatory prefix for VAND.
        &[0xc4, 0x62, 0x38, 0x54, 0x3f],       // Opcode outside VEX map 0F.
        &[0x66, 0x0f, 0x38, 0x37, 0x47, 3],    // Misaligned PCMPGTQ.
        &[0x0f, 0x74, 0x07],                   // MMX PCMPEQB.
        &[0xc4, 0x62, 0x3a, 0x29, 0x3f],       // Reserved VPCMPEQQ mandatory prefix.
        &[0x0f, 0xec, 0x07],                   // MMX PADDSB.
        &[0xc5, 0x39, 0xd8, 0xff],             // VPSUBUSB with a register source.
        &[0xc5, 0x3a, 0xed, 0x3f],             // Reserved VPADDSW mandatory prefix.
        &[0x66, 0x44, 0x0f, 0x60, 0x7f, 3],    // Misaligned PUNPCKLBW.
        &[0x0f, 0x68, 0x07],                   // MMX PUNPCKHBW.
        &[0xc5, 0x39, 0x69, 0xff],             // VPUNPCKHWD with a register source.
        &[0xc5, 0x3a, 0x6d, 0x3f],             // Reserved VPUNPCKHQDQ mandatory prefix.
        &[0x62, 0x71, 0x3d, 0x28, 0x6c, 0x3f], // EVEX VPUNPCKLQDQ.
    ] {
        let (context, mut memory, mut exit) = fixture(code);
        exit.qualification = 0x181;
        if code.last() == Some(&3) {
            exit.linear += 3;
            exit.physical += 3;
        }
        assert!(prepare(&context, &mut memory, exit).is_err(), "{code:02x?}");
        assert!(
            memory
                .reads
                .iter()
                .all(|&(address, _)| address != exit.physical)
        );
    }
    let ymm2 = instruction_metadata::decode(32, 0x1000, &[0xc5, 0xed, 0xef, 0x07]).unwrap();
    assert_eq!(ymm2.operands[1].reg, "ymm2");
    assert!(instruction_metadata::decode(32, 0x1000, &[0xc5, 0xbd, 0xef, 0x07]).is_err());
}

#[derive(Debug, PartialEq, Eq)]
enum Write {
    Xmm(u8, [u8; 16], bool),
    Ymm(u8, [u8; 32]),
    Retire(u64),
}

#[derive(Default)]
struct Host(Vec<Write>);

impl mmio::CompletionAccess for Host {
    type Error = &'static str;

    fn write_gpr(&mut self, _: usize, _: u64) -> Result<(), Self::Error> {
        panic!("packed logical read changed a GPR");
    }

    fn write_rflags(&mut self, _: u64) -> Result<(), Self::Error> {
        panic!("packed logical read changed RFLAGS");
    }

    fn write_xmm(&mut self, index: u8, value: [u8; 16], zero: bool) -> Result<(), String> {
        self.0.push(Write::Xmm(index, value, zero));
        Ok(())
    }

    fn write_ymm(&mut self, index: u8, value: [u8; 32]) -> Result<(), String> {
        self.0.push(Write::Ymm(index, value));
        Ok(())
    }

    fn finish_instruction(&mut self, length: u64) -> Result<(), Self::Error> {
        self.0.push(Write::Retire(length));
        Ok(())
    }
}

#[test]
fn packed_integer_products_match_the_ram_oracle_and_complete_once() {
    use packed_multiply::{CASES, PATTERNS, bytes};

    let mut rejected = Vec::new();
    for case in CASES {
        for (code, form, width) in case.forms() {
            let (context, mut memory, mut exit) = fixture(&code);
            let vex = form != "legacy";
            if vex {
                exit.linear += 3;
                exit.physical += 3;
            }
            let plan = match prepare(&context, &mut memory, exit) {
                Ok(plan) => plan,
                Err(error) => {
                    rejected.push(format!("{} {form}: {error}", case.mnemonic));
                    continue;
                }
            };
            assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
            assert!(
                memory
                    .reads
                    .iter()
                    .all(|&(address, _)| address != exit.physical)
            );
            let Action::VectorLogic { input, source } = plan.action else {
                panic!(
                    "unexpected action for {} {form}: {:?}",
                    case.mnemonic, plan.action
                );
            };
            assert_eq!(source, if vex { 8 } else { 15 });
            assert_eq!((input.index, input.length), (15, code.len() as u64));
            assert_eq!(usize::from(input.memory_size()), width);
            let expected_encoding = match (vex, width) {
                (false, _) => Encoding::Legacy,
                (true, 16) => Encoding::Vex128,
                (true, _) => Encoding::Vex256,
            };
            assert_eq!(input.encoding, expected_encoding);

            for ([left, right], result) in PATTERNS.into_iter().zip(case.results) {
                let mut pending = mmio::InputState::default();
                pending
                    .begin_vector_logic(input.clone(), bytes(left))
                    .unwrap();
                let wire = rax::codec::serialize(&pending).unwrap();
                let restored: mmio::InputState = rax::codec::deserialize_strict(&wire).unwrap();
                restored.validate_checkpoint().unwrap();
                assert_eq!(restored.descriptor(), Some((width as u8, None)));
                let reply = bytes(right);
                let result = bytes(result);
                let expected = if width == 32 {
                    Write::Ymm(15, result)
                } else {
                    Write::Xmm(15, result[..16].try_into().unwrap(), vex)
                };
                for mut transaction in [pending, restored] {
                    let mut host = Host::default();
                    transaction.complete(&mut host, &reply[..width]);
                    transaction.complete(&mut host, &reply[..width]);
                    assert_eq!(host.0.len(), 2, "{} {form}", case.mnemonic);
                    assert_eq!(host.0[0], expected, "{} {form}", case.mnemonic);
                    assert_eq!(host.0[1], Write::Retire(input.length));
                }
            }

            let mut register_code = code;
            if vex {
                register_code.pop();
            }
            *register_code.last_mut().unwrap() = 0xff;
            let metadata = instruction_metadata::decode(64, context.rip, &register_code).unwrap();
            let mnemonic = if vex {
                format!("v{}", case.mnemonic)
            } else {
                case.mnemonic.to_owned()
            };
            assert_eq!(metadata.mnemonic, mnemonic);
            assert_eq!(
                metadata.operands.last().unwrap().kind,
                OperandKind::Register
            );
            assert_eq!(
                metadata.operands.last().unwrap().width_bits,
                width as u32 * 8
            );
            let (context, mut memory, exit) = fixture(&register_code);
            assert!(prepare(&context, &mut memory, exit).is_err());
        }
    }
    assert!(rejected.is_empty(), "{}", rejected.join("\n"));
}

#[test]
fn packed_integer_multiply_rejects_wrong_directions_prefixes_and_alignment() {
    for case in packed_multiply::CASES {
        let code = case.legacy();
        let (context, mut memory, mut exit) = fixture(&code);
        exit.linear += 1;
        exit.physical += 1;
        assert_eq!(
            prepare(&context, &mut memory, exit).unwrap_err(),
            "misaligned legacy vector logic MMIO input",
            "{}",
            case.mnemonic
        );
        let (context, mut memory, mut exit) = fixture(&code);
        exit.qualification = 0x182;
        assert!(prepare(&context, &mut memory, exit).is_err());
        let rep = [&[0xf3][..], code.as_slice()].concat();
        for wrong in [&code[1..], rep.as_slice()] {
            let (context, mut memory, exit) = fixture(wrong);
            assert!(prepare(&context, &mut memory, exit).is_err());
        }
    }
}

fn assert_comparison_completion(
    input: &mmio::vector_logic::Input,
    element: usize,
    equal: bool,
    mnemonic: &str,
) {
    let width = usize::from(input.encoding.size());
    let max = i64::MAX >> (64 - element * 8);
    let boundary = if element == 1 { 8 } else { 0x100 };
    let pairs = [
        (7, 7, true, false),
        (-6, 3, false, false),
        (0, -1, false, true),
        (!max, max, false, false),
        (-2, -3, false, true),
        (boundary, boundary - 1, false, true),
        (boundary - 1, boundary, false, false),
        (!max, !max, true, false),
    ];
    for rotation in 0..pairs.len() {
        let mut left = [0; 32];
        let mut reply = [0; 32];
        let mut result = [0; 32];
        for start in (0..width).step_by(element) {
            let (x, y, matches, greater) = pairs[(start / element + rotation) % pairs.len()];
            let lane = start..start + element;
            let applies = if equal { matches } else { greater };
            left[lane.clone()].copy_from_slice(&x.to_le_bytes()[..element]);
            reply[lane.clone()].copy_from_slice(&y.to_le_bytes()[..element]);
            result[lane].fill(if applies { 0xff } else { 0 });
        }
        let mut pending = mmio::InputState::default();
        pending.begin_vector_logic(input.clone(), left).unwrap();
        let record = rax::codec::serialize(&pending).unwrap();
        let mut restored: mmio::InputState = rax::codec::deserialize_strict(&record).unwrap();
        restored.validate_checkpoint().unwrap();
        let mut host = Host::default();
        restored.complete(&mut host, &reply[..width]);
        let write = if width == 32 {
            Write::Ymm(15, result)
        } else {
            let clear_upper = input.encoding == Encoding::Vex128;
            Write::Xmm(15, result[..16].try_into().unwrap(), clear_upper)
        };
        assert_eq!(
            host.0,
            [write, Write::Retire(input.length)],
            "{mnemonic}, {:?}, rotation {rotation}",
            input.encoding
        );
        assert!(restored.ready().is_ok());
        restored.complete(&mut host, &reply[..width]);
        assert_eq!(host.0.len(), 2);
    }
}

#[test]
fn packed_integer_comparisons_plan_and_complete_device_reads() {
    let mut failures = Vec::new();
    for (map, opcode, mnemonic, element, equal) in [
        (1, 0x74, "pcmpeqb", 1, true),
        (1, 0x75, "pcmpeqw", 2, true),
        (1, 0x76, "pcmpeqd", 4, true),
        (2, 0x29, "pcmpeqq", 8, true),
        (1, 0x64, "pcmpgtb", 1, false),
        (1, 0x65, "pcmpgtw", 2, false),
        (1, 0x66, "pcmpgtd", 4, false),
        (2, 0x37, "pcmpgtq", 8, false),
    ] {
        let mut legacy = vec![0x66, 0x44, 0x0f];
        if map == 2 {
            legacy.push(0x38);
        }
        legacy.extend([opcode, 0x3f]);
        for (code, encoding) in [
            (legacy.as_slice(), Encoding::Legacy),
            (&[0xc4, 0x60 | map, 0x39, opcode, 0x7f, 3], Encoding::Vex128),
            (&[0xc4, 0x60 | map, 0x3d, opcode, 0x7f, 3], Encoding::Vex256),
        ] {
            let (context, mut memory, mut exit) = fixture(code);
            exit.qualification = 0x181;
            let vex = encoding != Encoding::Legacy;
            if vex {
                exit.linear += 3;
                exit.physical += 3;
            }
            let own_mnemonic = if vex {
                format!("v{mnemonic}")
            } else {
                mnemonic.into()
            };
            match prepare(&context, &mut memory, exit) {
                Ok(plan) => {
                    let meta = instruction_metadata::decode(64, context.rip, code).unwrap();
                    assert_eq!(meta.mnemonic, own_mnemonic, "{code:02x?}");
                    let Action::VectorLogic { input, source } = plan.action else {
                        panic!("wrong action for {code:02x?}: {:?}", plan.action);
                    };
                    assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
                    assert_eq!(
                        (input.encoding, input.index, input.length),
                        (encoding, 15, code.len() as u64)
                    );
                    assert_eq!(source, if vex { 8 } else { 15 });
                    assert!(
                        memory
                            .reads
                            .iter()
                            .all(|&(address, _)| address != exit.physical)
                    );
                    assert_comparison_completion(&input, element, equal, &own_mnemonic);
                }
                Err(error) => failures.push(format!("{own_mnemonic} {code:02x?} {error}")),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn packed_integer_add_subtract_wrap_each_device_source_lane() {
    let mut failures = Vec::new();
    for (opcode, name, element, subtract) in [
        (0xfc, "paddb", 1, false),
        (0xfd, "paddw", 2, false),
        (0xfe, "paddd", 4, false),
        (0xd4, "paddq", 8, false),
        (0xf8, "psubb", 1, true),
        (0xf9, "psubw", 2, true),
        (0xfa, "psubd", 4, true),
        (0xfb, "psubq", 8, true),
    ] {
        for (code, encoding) in [
            (&[0x66, 0x44, 0x0f, opcode, 0x3f][..], Encoding::Legacy),
            (&[0xc5, 0x39, opcode, 0x7f, 3], Encoding::Vex128),
            (&[0xc4, 0x61, 0x39, opcode, 0x7f, 3], Encoding::Vex128),
            (&[0xc5, 0x3d, opcode, 0x7f, 3], Encoding::Vex256),
            (&[0xc4, 0x61, 0x3d, opcode, 0x7f, 3], Encoding::Vex256),
        ] {
            let (context, mut memory, mut exit) = fixture(code);
            exit.qualification = 0x181;
            let vex = encoding != Encoding::Legacy;
            if vex {
                exit.linear += 3;
                exit.physical += 3;
            }
            let plan = match prepare(&context, &mut memory, exit) {
                Ok(plan) => plan,
                Err(error) => {
                    failures.push(format!("{name} {code:02x?} {error}"));
                    continue;
                }
            };
            assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
            let Action::VectorLogic { input, source } = plan.action else {
                panic!("wrong action for {code:02x?}: {:?}", plan.action);
            };
            assert_eq!(source, if vex { 8 } else { 15 });
            assert_eq!(
                (input.encoding, input.index, input.length),
                (encoding, 15, code.len() as u64)
            );
            let width = usize::from(encoding.size());
            let modulus = 1_u128 << (8 * element);
            let pairs = [(modulus - 1, 1), (0, 1), (modulus / 2, modulus / 2), (7, 9)];
            for rotation in 0..pairs.len() {
                let mut left = [0_u8; 32];
                let mut reply = [0_u8; 32];
                let mut expected = [0_u8; 32];
                for start in (0..width).step_by(element) {
                    let (x, y) = pairs[(start / element + rotation) % pairs.len()];
                    let lane = start..start + element;
                    left[lane.clone()].copy_from_slice(&x.to_le_bytes()[..element]);
                    reply[lane.clone()].copy_from_slice(&y.to_le_bytes()[..element]);
                    let result = if subtract { x + modulus - y } else { x + y };
                    expected[lane].copy_from_slice(&(result % modulus).to_le_bytes()[..element]);
                }
                let mut pending = mmio::InputState::default();
                pending.begin_vector_logic(input.clone(), left).unwrap();
                let record = rax::codec::serialize(&pending).unwrap();
                let mut restored: mmio::InputState =
                    rax::codec::deserialize_strict(&record).unwrap();
                restored.validate_checkpoint().unwrap();
                let mut host = Host::default();
                restored.complete(&mut host, &reply[..width]);
                let expected = if width == 32 {
                    Write::Ymm(15, expected)
                } else {
                    Write::Xmm(15, expected[..16].try_into().unwrap(), vex)
                };
                assert_eq!(
                    host.0,
                    [expected, Write::Retire(input.length)],
                    "{name} {code:02x?}"
                );
                restored.complete(&mut host, &reply[..width]);
                assert_eq!(host.0.len(), 2);
            }
            exit.qualification = 0x182;
            assert!(prepare(&context, &mut memory, exit).is_err());
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn packed_integer_saturation_completes_each_device_source_lane() {
    let mut failures = Vec::new();
    for (opcode, name, element, signed, subtract) in [
        (0xec, "paddsb", 1, true, false),
        (0xed, "paddsw", 2, true, false),
        (0xdc, "paddusb", 1, false, false),
        (0xdd, "paddusw", 2, false, false),
        (0xe8, "psubsb", 1, true, true),
        (0xe9, "psubsw", 2, true, true),
        (0xd8, "psubusb", 1, false, true),
        (0xd9, "psubusw", 2, false, true),
    ] {
        let legacy = [0x66, 0x44, 0x0f, opcode, 0x3f];
        for (code, encoding) in [
            (&legacy[..], Encoding::Legacy),
            (&[0xc5, 0x39, opcode, 0x7f, 3], Encoding::Vex128),
            (&[0xc4, 0x61, 0x39, opcode, 0x7f, 3], Encoding::Vex128),
            (&[0xc5, 0x3d, opcode, 0x7f, 3], Encoding::Vex256),
            (&[0xc4, 0x61, 0x3d, opcode, 0x7f, 3], Encoding::Vex256),
        ] {
            let (context, mut memory, mut exit) = fixture(code);
            exit.qualification = 0x181;
            let vex = encoding != Encoding::Legacy;
            if vex {
                exit.linear += 3;
                exit.physical += 3;
            }
            let plan = match prepare(&context, &mut memory, exit) {
                Ok(plan) => plan,
                Err(error) => {
                    failures.push(format!("{name} {code:02x?} {error}"));
                    continue;
                }
            };
            let Action::VectorLogic { input, source } = plan.action else {
                panic!("wrong action for {code:02x?}: {:?}", plan.action);
            };
            assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
            assert_eq!(source, if vex { 8 } else { 15 });
            assert_eq!(
                (input.encoding, input.index, input.length),
                (encoding, 15, code.len() as u64)
            );
            assert!(
                memory
                    .reads
                    .iter()
                    .all(|&(address, _)| address != exit.physical)
            );

            let (min, max) = if signed {
                let limit = 1_i32 << (8 * element - 1);
                (-limit, limit - 1)
            } else {
                (0, (1_i32 << (8 * element)) - 1)
            };
            let pairs = [
                (max, 1),
                (min, 1),
                (min, min),
                (max, min),
                (max, max),
                (7, 9),
                (17, 9),
                (0, 0),
            ];
            let width = usize::from(encoding.size());
            let mut left = [0; 32];
            let mut reply = [0; 32];
            let mut expected = [0; 32];
            for start in (0..width).step_by(element) {
                let (x, y) = pairs[start / element % pairs.len()];
                let lane = start..start + element;
                left[lane.clone()].copy_from_slice(&x.to_le_bytes()[..element]);
                reply[lane.clone()].copy_from_slice(&y.to_le_bytes()[..element]);
                let value = if subtract { x - y } else { x + y };
                expected[lane].copy_from_slice(&value.clamp(min, max).to_le_bytes()[..element]);
            }
            let mut pending = mmio::InputState::default();
            pending.begin_vector_logic(input.clone(), left).unwrap();
            let record = rax::codec::serialize(&pending).unwrap();
            let mut restored: mmio::InputState = rax::codec::deserialize_strict(&record).unwrap();
            restored.validate_checkpoint().unwrap();
            assert_eq!(restored.descriptor(), Some((width as u8, None)));
            let mut host = Host::default();
            restored.complete(&mut host, &reply[..width]);
            restored.complete(&mut host, &reply[..width]);
            let expected = if width == 32 {
                Write::Ymm(15, expected)
            } else {
                Write::Xmm(15, expected[..16].try_into().unwrap(), vex)
            };
            assert_eq!(
                host.0,
                [expected, Write::Retire(input.length)],
                "{name} {code:02x?}"
            );
            exit.qualification = 0x182;
            assert!(prepare(&context, &mut memory, exit).is_err());
        }
        let (context, mut memory, mut exit) = fixture(&legacy);
        exit.qualification = 0x181;
        exit.linear += 1;
        exit.physical += 1;
        match prepare(&context, &mut memory, exit) {
            Err(error) if error == "misaligned legacy vector logic MMIO input" => {}
            outcome => failures.push(format!("{name} misaligned legacy read: {outcome:?}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn packed_integer_min_max_resumes_the_decoded_device_read_once() {
    let mut failures = Vec::new();
    for (map, opcode, name, element, signed, maximum) in [
        (2, 0x38, "pminsb", 1, true, false),
        (1, 0xda, "pminub", 1, false, false),
        (1, 0xea, "pminsw", 2, true, false),
        (2, 0x3a, "pminuw", 2, false, false),
        (2, 0x39, "pminsd", 4, true, false),
        (2, 0x3b, "pminud", 4, false, false),
        (2, 0x3c, "pmaxsb", 1, true, true),
        (1, 0xde, "pmaxub", 1, false, true),
        (1, 0xee, "pmaxsw", 2, true, true),
        (2, 0x3e, "pmaxuw", 2, false, true),
        (2, 0x3d, "pmaxsd", 4, true, true),
        (2, 0x3f, "pmaxud", 4, false, true),
    ] {
        let mut legacy = vec![0x66, 0x44, 0x0f];
        if map == 2 {
            legacy.push(0x38);
        }
        legacy.extend([opcode, 0x3f]);
        let form = [
            (legacy.as_slice(), Encoding::Legacy),
            (&[0xc4, 0x60 | map, 0x39, opcode, 0x7f, 3], Encoding::Vex128),
            (&[0xc4, 0x60 | map, 0x3d, opcode, 0x7f, 3], Encoding::Vex256),
            (&[0xc5, 0x39, opcode, 0x7f, 3], Encoding::Vex128),
            (&[0xc5, 0x3d, opcode, 0x7f, 3], Encoding::Vex256),
        ];
        let (min, max) = if signed {
            let magnitude = 1_i64 << (8 * element - 1);
            (-magnitude, magnitude - 1)
        } else {
            (0, (1_i64 << (8 * element)) - 1)
        };
        let pairs = [
            (min, max),
            (max, min),
            (max, max),
            (min + 1, min),
            (7, 12),
            (9, 7),
        ];
        for &(code, encoding) in &form[..if map == 1 { 5 } else { 3 }] {
            let (context, mut memory, mut exit) = fixture(code);
            exit.qualification = 0x181;
            let vex = encoding != Encoding::Legacy;
            if vex {
                exit.linear += 3;
                exit.physical += 3;
            }
            let plan = match prepare(&context, &mut memory, exit) {
                Ok(plan) => plan,
                Err(error) => {
                    failures.push(format!("{name} {code:02x?}: {error}"));
                    continue;
                }
            };
            let Action::VectorLogic { input, source } = plan.action else {
                panic!("wrong action for {code:02x?}: {:?}", plan.action);
            };
            assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
            assert_eq!(source, if vex { 8 } else { 15 });
            assert_eq!(
                (input.encoding, input.index, input.length),
                (encoding, 15, code.len() as u64)
            );
            assert!(
                memory
                    .reads
                    .iter()
                    .all(|&(address, _)| address != exit.physical)
            );
            let width = usize::from(encoding.size());
            for rotation in [0, 3] {
                let mut left = [0; 32];
                let mut reply = [0; 32];
                let mut expected = [0; 32];
                for start in (0..width).step_by(element) {
                    let (x, y) = pairs[(start / element + rotation) % pairs.len()];
                    let lane = start..start + element;
                    left[lane.clone()].copy_from_slice(&x.to_le_bytes()[..element]);
                    reply[lane.clone()].copy_from_slice(&y.to_le_bytes()[..element]);
                    let result = if maximum { x.max(y) } else { x.min(y) };
                    expected[lane].copy_from_slice(&result.to_le_bytes()[..element]);
                }
                let mut pending = mmio::InputState::default();
                pending.begin_vector_logic(input.clone(), left).unwrap();
                let record = rax::codec::serialize(&pending).unwrap();
                let mut restored: mmio::InputState =
                    rax::codec::deserialize_strict(&record).unwrap();
                restored.validate_checkpoint().unwrap();
                assert_eq!(restored.descriptor(), Some((width as u8, None)));
                let mut host = Host::default();
                restored.complete(&mut host, &reply[..width]);
                restored.complete(&mut host, &reply[..width]);
                let expected = if width == 32 {
                    Write::Ymm(15, expected)
                } else {
                    Write::Xmm(15, expected[..16].try_into().unwrap(), vex)
                };
                assert_eq!(
                    host.0,
                    [expected, Write::Retire(input.length)],
                    "{name} {code:02x?}"
                );
            }
            exit.qualification = 0x182;
            assert!(prepare(&context, &mut memory, exit).is_err());
        }
        let (context, mut memory, mut exit) = fixture(&legacy);
        exit.qualification = 0x181;
        exit.linear += 1;
        exit.physical += 1;
        match prepare(&context, &mut memory, exit) {
            Err(error) if error == "misaligned legacy vector logic MMIO input" => {}
            outcome => failures.push(format!("{name} misaligned legacy read: {outcome:?}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn vector_logic_retires_a_serialized_input_once_with_the_encoded_upper_lane_rule() {
    let left: [u8; 8] = [0x5a, 0xa5, 0xf0, 0x0f, 0x73, 0x48, 0xbe, 0x19];
    let right: [u8; 8] = [0x33, 0x77, 0xaa, 0x55, 0x86, 0xb1, 0xc3, 0xed];
    let left = std::array::from_fn(|i| left[i % 8].rotate_left((i / 8) as u32));
    let right: [u8; 33] = std::array::from_fn(|i| right[i % 8].rotate_left((i / 8) as u32));
    for (opcode, bits) in [
        (0xdb, [0x12_u8, 0x25, 0xa0, 0x05, 0x02, 0x00, 0x82, 0x09]),
        (0xdf, [0x21, 0x52, 0x0a, 0x50, 0x84, 0xb1, 0x41, 0xe4]),
        (0xeb, [0x7b, 0xf7, 0xfa, 0x5f, 0xf7, 0xf9, 0xff, 0xfd]),
        (0xef, [0x69, 0xd2, 0x5a, 0x5a, 0xf5, 0xf9, 0x7d, 0xf4]),
    ] {
        let result: [u8; 32] = std::array::from_fn(|i| bits[i % 8].rotate_left((i / 8) as u32));
        for (code, width, clear_upper) in [
            (&[0x66, 0x44, 0x0f, opcode, 0x3f][..], 16, false),
            (&[0xc5, 0x39, opcode, 0x3f], 16, true),
            (&[0xc5, 0x3d, opcode, 0x3f], 32, false),
        ] {
            let (context, mut memory, mut exit) = fixture(code);
            exit.qualification = 0x181;
            let plan = prepare(&context, &mut memory, exit).unwrap();
            let Action::VectorLogic { input, .. } = plan.action else {
                panic!("wrong action for {code:02x?}: {:?}", plan.action);
            };
            let mut source = mmio::InputState::default();
            source.begin_vector_logic(input, left).unwrap();
            let binary = rax::codec::serialize(&source).unwrap();
            for count in [width - 1, width, width + 1] {
                let mut pending: mmio::InputState =
                    rax::codec::deserialize_strict(&binary).unwrap();
                assert_eq!(pending.descriptor(), Some((width as u8, None)));
                pending.validate_checkpoint().unwrap();
                let mut host = Host::default();
                pending.complete(&mut host, &right[..count]);
                if count == width {
                    let write = if width == 32 {
                        Write::Ymm(15, result)
                    } else {
                        Write::Xmm(15, result[..16].try_into().unwrap(), clear_upper)
                    };
                    assert_eq!(host.0, [write, Write::Retire(plan.length)]);
                    assert!(pending.ready().is_ok());
                } else {
                    assert!(pending.failure().is_some());
                    assert!(host.0.is_empty());
                }
                pending.complete(&mut host, &right[..width]);
                assert_eq!(host.0.len(), if count == width { 2 } else { 0 });
            }
        }
    }
}

#[test]
fn packed_uniform_shifts_read_one_xmm_count_and_restore_once() {
    let mut failures = Vec::new();
    for (opcode, name, element, left_shift, arithmetic) in [
        (0xf1, "psllw", 2, true, false),
        (0xf2, "pslld", 4, true, false),
        (0xf3, "psllq", 8, true, false),
        (0xd1, "psrlw", 2, false, false),
        (0xd2, "psrld", 4, false, false),
        (0xd3, "psrlq", 8, false, false),
        (0xe1, "psraw", 2, false, true),
        (0xe2, "psrad", 4, false, true),
    ] {
        for (code, encoding) in [
            (&[0x66, 0x44, 0x0f, opcode, 0x3f][..], Encoding::Legacy),
            (&[0xc5, 0x39, opcode, 0x7f, 3], Encoding::Vex128),
            (&[0xc5, 0x3d, opcode, 0x7f, 3], Encoding::Vex256),
            (&[0xc4, 0x61, 0x39, opcode, 0x7f, 3], Encoding::Vex128),
            (&[0xc4, 0x61, 0x3d, opcode, 0x7f, 3], Encoding::Vex256),
            (&[0xc4, 0x61, 0xb9, opcode, 0x7f, 3], Encoding::Vex128),
            (&[0xc4, 0x61, 0xbd, opcode, 0x7f, 3], Encoding::Vex256),
        ] {
            let (mut context, mut memory, mut exit) = fixture(code);
            let vex = encoding != Encoding::Legacy;
            exit.linear += 0xff0;
            exit.physical += 0xff0;
            context.registers[7] = exit.linear - if vex { 3 } else { 0 };
            // A mistaken 32-byte read would overlap guest RAM and be rejected.
            memory.bytes(exit.physical + 16, &[0xa5]);
            let plan = match prepare(&context, &mut memory, exit) {
                Ok(plan) => plan,
                Err(error) => {
                    failures.push(format!("{name} {code:02x?}: {error}"));
                    continue;
                }
            };
            assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
            let Action::VectorLogic { input, source } = plan.action else {
                panic!("wrong action for {name} {code:02x?}: {:?}", plan.action);
            };
            assert_eq!(source, if vex { 8 } else { 15 });
            assert_eq!(
                (input.encoding, input.index, input.length),
                (encoding, 15, code.len() as u64)
            );
            let metadata = instruction_metadata::decode(64, context.rip, code).unwrap();
            let count_operand = metadata.operands.last().unwrap();
            assert_eq!(count_operand.kind, OperandKind::Memory);
            assert_eq!(count_operand.width_bits, 128);
            assert!(
                memory
                    .reads
                    .iter()
                    .all(|&(address, _)| address < exit.physical)
            );

            let width = usize::from(encoding.size());
            let bits = (8 * element) as u64;
            let limit = 1_i128 << (bits - 1);
            let lanes = [-limit, limit - 1, -0x1234, 0x1235, -1, 1, 0];
            for count in [0, 1, bits - 1, bits, bits + 1, 0x100, u64::MAX] {
                let mut left = [0; 32];
                let mut expected = [0; 32];
                for (index, start) in (0..width).step_by(element).enumerate() {
                    let lane = lanes[index % lanes.len()];
                    let raw = lane.rem_euclid(2 * limit);
                    let result = if arithmetic {
                        lane >> count.min(bits - 1)
                    } else if count >= bits {
                        0
                    } else if left_shift {
                        raw << count
                    } else {
                        raw >> count
                    };
                    left[start..start + element].copy_from_slice(&lane.to_le_bytes()[..element]);
                    expected[start..start + element]
                        .copy_from_slice(&result.to_le_bytes()[..element]);
                }
                let mut reply = [0xff; 16];
                reply[..8].copy_from_slice(&count.to_le_bytes());

                let mut pending = mmio::InputState::default();
                pending.begin_vector_logic(input.clone(), left).unwrap();
                let record = rax::codec::serialize(&pending).unwrap();
                let mut restored: mmio::InputState =
                    rax::codec::deserialize_strict(&record).unwrap();
                restored.validate_checkpoint().unwrap();
                assert_eq!(restored.descriptor(), Some((16, None)));
                let mut host = Host::default();
                restored.complete(&mut host, &reply);
                restored.complete(&mut host, &reply);
                let expected = if encoding == Encoding::Vex256 {
                    Write::Ymm(15, expected)
                } else {
                    Write::Xmm(15, expected[..16].try_into().unwrap(), vex)
                };
                assert_eq!(
                    host.0,
                    [expected, Write::Retire(input.length)],
                    "{name} {code:02x?} count {count}"
                );
            }
            for invalid_reply in [&[0; 15][..], &[0; 32]] {
                let mut pending = mmio::InputState::default();
                pending.begin_vector_logic(input.clone(), [0; 32]).unwrap();
                let mut host = Host::default();
                pending.complete(&mut host, invalid_reply);
                assert!(host.0.is_empty());
            }
            exit.qualification = 0x182;
            assert!(prepare(&context, &mut memory, exit).is_err());
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn packed_uniform_shifts_reject_other_forms_and_misaligned_sse() {
    for code in [
        &[0x66, 0x44, 0x0f, 0xf1, 0x7f, 3][..], // Misaligned legacy PSLLW.
        &[0x0f, 0xf1, 0x07],                    // MMX PSLLW.
        &[0x66, 0x0f, 0x71, 0xf0, 0x01],        // Immediate PSLLW.
        &[0xc5, 0x3d, 0xf1, 0xff],              // Register-count VPSLLW.
        &[0x62, 0x71, 0x3d, 0x28, 0xf1, 0x3f],  // EVEX VPSLLW.
    ] {
        let (context, mut memory, mut exit) = fixture(code);
        if code.last() == Some(&3) {
            exit.linear += 3;
            exit.physical += 3;
        }
        assert!(prepare(&context, &mut memory, exit).is_err(), "{code:02x?}");
        assert!(
            memory
                .reads
                .iter()
                .all(|&(address, _)| address < exit.physical)
        );
    }
}

#[test]
fn avx2_variable_shifts_read_every_device_count_and_restore_once() {
    let mut failures = Vec::new();
    for (opcode, w, mnemonic, left_shift, arithmetic) in [
        (0x45, 0, "vpsrlvd", false, false),
        (0x45, 0x80, "vpsrlvq", false, false),
        (0x46, 0, "vpsravd", false, true),
        (0x47, 0, "vpsllvd", true, false),
        (0x47, 0x80, "vpsllvq", true, false),
    ] {
        let element = if w == 0 { 4 } else { 8 };
        let bits = (8 * element) as u64;
        let limit = 1_i128 << (bits - 1);
        let lanes = [-limit, limit - 1, -0x1234, 0x1235, -1, 1, 0, 0x188];
        let counts = [0, 1, bits - 1, bits, bits + 1, 0x100, u64::MAX];
        for (encoding, l) in [(Encoding::Vex128, 0), (Encoding::Vex256, 4)] {
            let width = usize::from(encoding.size());
            for (code_bits, p0, vvvv, target, source) in [
                (64, 0x62, 0x38, 15, 8),
                (64, 0x62, 0, 15, 15),
                (32, 0xe2, 0x68, 7, 2),
            ] {
                let code = [0xc4, p0, w | vvvv | l | 1, opcode, 0x7f, 3];
                let (mut context, mut memory, mut exit) = fixture(&code);
                context.code_bits = code_bits;
                // A VEX device operand may be unaligned and cross a page.
                exit.linear += 4096 - width as u64 + 3;
                exit.physical += 4096 - width as u64 + 3;
                context.registers[7] = exit.linear - 3;
                let following = exit.physical + width as u64;
                memory.bytes(following, &[0xa5]);
                let plan = match prepare(&context, &mut memory, exit) {
                    Ok(plan) => plan,
                    Err(error) => {
                        failures.push(format!("{mnemonic} {code_bits}-bit {code:02x?}: {error}"));
                        continue;
                    }
                };
                let Action::VectorLogic {
                    input,
                    source: decoded_source,
                } = plan.action
                else {
                    panic!("wrong action for {mnemonic}: {:?}", plan.action);
                };
                assert_eq!(decoded_source, source);
                assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
                assert_eq!(
                    (input.encoding, input.index, input.length),
                    (encoding, target, code.len() as u64)
                );
                assert_eq!(usize::from(input.memory_size()), width);

                for round in 0..counts.len() {
                    let mut left = [0; 32];
                    let mut reply = [0; 32];
                    let mut expected = [0; 32];
                    for (index, start) in (0..width).step_by(element).enumerate() {
                        let lane = lanes[index];
                        let raw = lane.rem_euclid(2 * limit);
                        let count = counts[(index + round) % counts.len()];
                        let result = if arithmetic {
                            lane >> count.min(bits - 1)
                        } else if count >= bits {
                            0
                        } else if left_shift {
                            raw << count
                        } else {
                            raw >> count
                        };
                        let range = start..start + element;
                        left[range.clone()].copy_from_slice(&lane.to_le_bytes()[..element]);
                        reply[range.clone()].copy_from_slice(&count.to_le_bytes()[..element]);
                        expected[range].copy_from_slice(&result.to_le_bytes()[..element]);
                    }
                    let mut pending = mmio::InputState::default();
                    pending.begin_vector_logic(input.clone(), left).unwrap();
                    let record = rax::codec::serialize(&pending).unwrap();
                    let mut restored: mmio::InputState =
                        rax::codec::deserialize_strict(&record).unwrap();
                    restored.validate_checkpoint().unwrap();
                    assert_eq!(restored.descriptor(), Some((width as u8, None)));
                    let mut host = Host::default();
                    restored.complete(&mut host, &reply[..width]);
                    restored.complete(&mut host, &reply[..width]);
                    let expected = if width == 32 {
                        Write::Ymm(target, expected)
                    } else {
                        Write::Xmm(target, expected[..16].try_into().unwrap(), true)
                    };
                    assert_eq!(
                        host.0,
                        [expected, Write::Retire(input.length)],
                        "{mnemonic} {code_bits}-bit {code:02x?} round {round}"
                    );
                    for bad_size in [width - 1, width + 1] {
                        let mut restored: mmio::InputState =
                            rax::codec::deserialize_strict(&record).unwrap();
                        let mut host = Host::default();
                        restored.complete(&mut host, &[0; 33][..bad_size]);
                        assert!(host.0.is_empty());
                        assert!(restored.failure().is_some());
                    }
                }
                memory.bytes(following - 1, &[0xa5]);
                assert!(prepare(&context, &mut memory, exit).is_err());
                memory.bytes.remove(&(following - 1));
                exit.qualification = 0x182;
                assert!(prepare(&context, &mut memory, exit).is_err());
                assert!(memory.reads.iter().all(|&(addr, _)| addr < exit.physical));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn avx2_variable_shift_rejects_non_mmio_and_reserved_encodings() {
    for code in [
        &[0xc4, 0x62, 0x39, 0x47, 0xff][..],   // Register count.
        &[0xc4, 0x62, 0x39, 0x47, 0x7f],       // Truncated displacement.
        &[0xc4, 0x62, 0xb9, 0x46, 0x3f],       // Reserved VEX.W=1 arithmetic shift.
        &[0xc4, 0x62, 0x3a, 0x47, 0x3f],       // Reserved mandatory prefix.
        &[0xc5, 0x39, 0x47, 0x3f],             // Wrong VEX map.
        &[0x66, 0x44, 0x0f, 0x38, 0x47, 0x3f], // Legacy map.
        &[0x62, 0x72, 0x3d, 0x28, 0x47, 0x3f], // EVEX.
    ] {
        let (context, mut memory, exit) = fixture(code);
        assert!(prepare(&context, &mut memory, exit).is_err(), "{code:02x?}");
        assert!(memory.reads.iter().all(|&(addr, _)| addr < exit.physical));
    }
}
