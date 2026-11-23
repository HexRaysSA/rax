//! Flag-only packed vector tests with a device source operand.
use super::*;
use mmio::vector_logic::Encoding;
use rax::isa::x86_64::instruction_metadata::{self, OperandKind};

const PTEST: [u8; 6] = [0x66, 0x44, 0x0f, 0x38, 0x17, 0x3f];

fn vex(opcode: u8, wide: bool, w: bool) -> [u8; 6] {
    let prefix = 0x79 | (u8::from(wide) << 2) | (u8::from(w) << 7);
    [0xc4, 0x62, prefix, opcode, 0x7f, 3]
}

#[test]
fn packed_vector_tests_plan_the_device_source() {
    let mut failures = Vec::new();
    let forms = [
        PTEST,
        vex(0x17, false, false),
        vex(0x17, true, false),
        vex(0x17, false, true),
        vex(0x17, true, true),
        vex(0x0e, false, false),
        vex(0x0e, true, false),
        vex(0x0f, false, false),
        vex(0x0f, true, false),
    ];
    for code in forms {
        let (context, mut memory, mut record) = fixture(&code);
        if code[0] == 0xc4 {
            record.linear += 3;
            record.physical += 3;
        }
        match prepare(&context, &mut memory, record) {
            Ok(plan) => {
                assert_eq!(plan.length, code.len() as u64);
                assert_eq!(
                    (plan.linear, plan.physical),
                    (record.linear, record.physical)
                );
                let Action::VectorBitTest { input, source } = plan.action else {
                    panic!("unexpected action for {code:02x?}: {:?}", plan.action);
                };
                assert_eq!(source, 15);
                let encoding = if code[0] == 0x66 {
                    Encoding::Legacy
                } else if code[2] & 4 != 0 {
                    Encoding::Vex256
                } else {
                    Encoding::Vex128
                };
                assert_eq!((input.encoding, input.length), (encoding, plan.length));
                let metadata = instruction_metadata::decode(64, context.rip, &code).unwrap();
                let [left, right] = metadata.operands.as_slice() else {
                    panic!("unexpected operands: {:?}", metadata.operands);
                };
                assert_eq!(left.kind, OperandKind::Register);
                assert_eq!(right.kind, OperandKind::Memory);
                for operand in [left, right] {
                    assert_eq!(operand.width_bits, u32::from(encoding.size()) * 8);
                    assert!(operand.read && !operand.write);
                }
                assert!(
                    memory
                        .reads
                        .iter()
                        .all(|&(address, _)| address != record.physical)
                );
                record.qualification = 0x182;
                assert!(prepare(&context, &mut memory, record).is_err());
            }
            Err(error) => failures.push(format!("{code:02x?} {error}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn packed_vector_tests_reject_reserved_encodings_register_forms_and_unaligned_legacy() {
    let bad_prefix = [0xc4, 0x62, 0x78, 0x17, 0x7f, 3];
    let bad_vvvv = [0xc4, 0x62, 0x71, 0x17, 0x7f, 3];
    for (code, offset) in [
        (&[0x66, 0x44, 0x0f, 0x38, 0x17, 0x7f, 3][..], 3),
        (&[0x66, 0x44, 0x0f, 0x38, 0x17, 0xff], 0),
        (&[0xc4, 0x62, 0x79, 0x0f, 0xff], 0),
        (&vex(0x0e, false, true), 3),
        (&vex(0x0f, true, true), 3),
        (&bad_prefix, 3),
        (&bad_vvvv, 3),
    ] {
        let (context, mut memory, mut record) = fixture(code);
        record.linear += offset;
        record.physical += offset;
        assert!(
            prepare(&context, &mut memory, record).is_err(),
            "{code:02x?}"
        );
        assert!(
            memory
                .reads
                .iter()
                .all(|&(address, _)| address != record.physical)
        );
    }
}

#[test]
fn packed_vector_tests_restore_the_source_and_publish_only_defined_flags_once() {
    #[derive(Default)]
    struct Host {
        flags: Option<u64>,
        retired: usize,
    }
    impl mmio::CompletionAccess for Host {
        type Error = &'static str;

        fn write_gpr(&mut self, _: usize, _: u64) -> Result<(), Self::Error> {
            panic!("packed bit test changed a GPR");
        }

        fn write_rflags(&mut self, flags: u64) -> Result<(), Self::Error> {
            assert!(self.flags.replace(flags).is_none());
            Ok(())
        }

        fn finish_instruction(&mut self, length: u64) -> Result<(), Self::Error> {
            assert!(self.flags.is_some());
            assert_eq!(length, 6);
            self.retired += 1;
            Ok(())
        }
    }

    for (code, width, stride) in [
        (PTEST, 16, 1),
        (vex(0x17, true, true), 32, 1),
        (vex(0x0e, false, false), 16, 4),
        (vex(0x0e, true, false), 32, 4),
        (vex(0x0f, false, false), 16, 8),
        (vex(0x0f, true, false), 32, 8),
    ] {
        let (mut context, mut memory, mut record) = fixture(&code);
        context.rflags = 0xed7;
        if code[0] == 0xc4 {
            record.linear += 3;
            record.physical += 3;
        }
        let plan = prepare(&context, &mut memory, record).unwrap();
        let Action::VectorBitTest { input, .. } = plan.action else {
            panic!("unexpected action for {code:02x?}: {:?}", plan.action);
        };
        for (overlap, missing) in [(false, false), (false, true), (true, false), (true, true)] {
            let mut left = [0x4a; 32];
            let mut right = [if stride == 1 { 0 } else { 0x37 }; 33];
            if overlap {
                left[stride - 1] |= 0x80;
                right[stride - 1] |= 0x80;
            }
            if missing {
                right[width - 1] |= 0x80;
            }
            let mut pending = mmio::InputState::default();
            pending.begin_vector_bit_test(input.clone(), left).unwrap();
            let wire = rax::codec::serialize(&pending).unwrap();
            for count in [width - 1, width, width + 1] {
                let mut restored: mmio::InputState = rax::codec::deserialize_strict(&wire).unwrap();
                assert_eq!(restored.descriptor(), Some((width as u8, None)));
                restored.validate_checkpoint().unwrap();
                let mut host = Host::default();
                restored.complete(&mut host, &right[..count]);
                let valid = count == width;
                let expected = 0x602 | (u64::from(!overlap) << 6) | u64::from(!missing);
                assert_eq!(host.flags, valid.then_some(expected));
                assert_eq!(restored.ready().is_ok(), valid);
                restored.complete(&mut host, &right[..width]);
                assert_eq!(host.retired, usize::from(valid));
            }
        }
    }
}
