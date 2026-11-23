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
        &[0x44, 0x0f, 0x54, 0x7f, 3][..], // Misaligned ANDPS.
        &[0x66, 0x0f, 0xeb, 0x47, 3],     // Misaligned POR.
        &[0x0f, 0x54, 0xc7],              // Register-only ANDPS.
        &[0xc5, 0x3d, 0xef, 0xff],        // Register-only VPXOR.
        &[0xc5, 0x3a, 0x54, 0x3f],        // Reserved mandatory prefix for VAND.
        &[0xc4, 0x62, 0x38, 0x54, 0x3f],  // Opcode outside VEX map 0F.
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

#[test]
fn vector_logic_retires_a_serialized_input_once_with_the_encoded_upper_lane_rule() {
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
