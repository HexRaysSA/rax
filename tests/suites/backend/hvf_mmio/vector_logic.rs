//! Packed logical instructions with a read-only device operand.
use super::*;
use mmio::vector_logic::Encoding;
use rax::isa::x86_64::instruction_metadata::{self, OperandKind};

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
        &[0x44, 0x0f, 0x54, 0x7f, 3][..],   // Misaligned ANDPS.
        &[0x66, 0x0f, 0xeb, 0x47, 3],       // Misaligned POR.
        &[0x0f, 0x54, 0xc7],                // Register-only ANDPS.
        &[0xc5, 0x3d, 0xef, 0xff],          // Register-only VPXOR.
        &[0xc5, 0x3a, 0x54, 0x3f],          // Reserved mandatory prefix for VAND.
        &[0xc4, 0x62, 0x38, 0x54, 0x3f],    // Opcode outside VEX map 0F.
        &[0x66, 0x0f, 0x38, 0x37, 0x47, 3], // Misaligned PCMPGTQ.
        &[0x0f, 0x74, 0x07],                // MMX PCMPEQB.
        &[0xc4, 0x62, 0x3a, 0x29, 0x3f],    // Reserved VPCMPEQQ mandatory prefix.
        &[0x0f, 0xec, 0x07],                // MMX PADDSB.
        &[0xc5, 0x39, 0xd8, 0xff],          // VPSUBUSB with a register source.
        &[0xc5, 0x3a, 0xed, 0x3f],          // Reserved VPADDSW mandatory prefix.
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
