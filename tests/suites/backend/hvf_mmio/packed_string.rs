//! SSE4.2 string compares issue one possibly unaligned 16-byte device read.
use super::*;

fn encodings(opcode: u8, control: u8) -> [[u8; 8]; 4] {
    [
        [0x66, 0x44, 0x0f, 0x3a, opcode, 0x7f, 3, control],
        [0x66, 0x4c, 0x0f, 0x3a, opcode, 0x7f, 3, control],
        [0xc4, 0x63, 0x79, opcode, 0x7f, 3, control, 0xf4],
        [0xc4, 0x63, 0xf9, opcode, 0x7f, 3, control, 0xf4],
    ]
}

#[test]
fn packed_string_comparisons_plan_unaligned_device_input() {
    let mut failures = Vec::new();
    for opcode in 0x60..=0x63 {
        for code in encodings(opcode, 0x1a) {
            let (context, mut memory, mut exit) = fixture(&code);
            exit.linear += 3;
            exit.physical += 3;
            match prepare(&context, &mut memory, exit) {
                Ok(plan) => {
                    assert_eq!(plan.length, if code[0] == 0x66 { 8 } else { 7 });
                    assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
                    assert!(matches!(
                        plan.action,
                        Action::PackedString { source: 15, .. }
                    ));
                    assert!(
                        memory
                            .reads
                            .iter()
                            .all(|&(address, _)| address != exit.physical)
                    );
                    exit.qualification = 0x182;
                    assert!(prepare(&context, &mut memory, exit).is_err());
                }
                Err(error) => failures.push(format!("{code:02x?}: {error}")),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn packed_string_rejects_reserved_encodings_and_register_sources() {
    for code in [
        [0xc4, 0x63, 0x7d, 0x63, 0x7f, 3, 0, 0xf4],    // L=1
        [0xc4, 0x63, 0x71, 0x63, 0x7f, 3, 0, 0xf4],    // vvvv encoded as 1110
        [0xc4, 0x63, 0x78, 0x63, 0x7f, 3, 0, 0xf4],    // no mandatory prefix
        [0xc4, 0x63, 0x79, 0x63, 0xff, 0, 0xf4, 0xf4], // register source
        [0xf3, 0x66, 0x0f, 0x3a, 0x63, 0x7f, 3, 0],    // REP with a legacy compare
    ] {
        let (context, mut memory, mut exit) = fixture(&code);
        exit.linear += 3;
        exit.physical += 3;
        assert!(prepare(&context, &mut memory, exit).is_err(), "{code:02x?}");
    }
}

#[test]
fn packed_string_restores_inputs_and_publishes_destination_and_flags_once() {
    #[derive(Debug, PartialEq, Eq)]
    enum Write {
        Gpr(usize, u64),
        Xmm(u8, u128, bool),
        Flags(u64),
        Retire(u64),
    }

    #[derive(Default)]
    struct Host(Vec<Write>);

    impl mmio::CompletionAccess for Host {
        type Error = &'static str;

        fn write_gpr(&mut self, index: usize, value: u64) -> Result<(), Self::Error> {
            self.0.push(Write::Gpr(index, value));
            Ok(())
        }

        fn write_xmm(
            &mut self,
            index: u8,
            value: [u8; 16],
            zero_upper: bool,
        ) -> Result<(), String> {
            self.0
                .push(Write::Xmm(index, u128::from_le_bytes(value), zero_upper));
            Ok(())
        }

        fn write_rflags(&mut self, flags: u64) -> Result<(), Self::Error> {
            self.0.push(Write::Flags(flags));
            Ok(())
        }

        fn finish_instruction(&mut self, length: u64) -> Result<(), Self::Error> {
            self.0.push(Write::Retire(length));
            Ok(())
        }
    }

    let mut left = [b'x'; 16];
    left[..3].copy_from_slice(b"A\0B");
    let mut right = [b'd'; 17];
    right[..4].copy_from_slice(b"ZBA\0");
    for opcode in 0x60..=0x63 {
        for (form, code) in encodings(opcode, 0).into_iter().enumerate() {
            let (mut context, mut memory, mut exit) = fixture(&code);
            context.registers[0] = 0x0000_0001_0000_0001;
            context.registers[2] = 0x0000_0001_ffff_fffd;
            context.rflags = 0xed7;
            exit.linear += 3;
            exit.physical += 3;
            let plan = prepare(&context, &mut memory, exit).unwrap();
            let Action::PackedString { input, .. } = plan.action else {
                panic!("unexpected action for {code:02x?}: {:?}", plan.action);
            };
            let wides = opcode < 0x62 && form % 2 == 1;
            let expected_write = if opcode % 2 == 0 {
                Write::Xmm(0, if wides { 14 } else { 4 }, form >= 2)
            } else {
                Write::Gpr(1, if wides { 1 } else { 2 })
            };
            let expected = [
                expected_write,
                Write::Flags(if wides { 0x603 } else { 0x6c3 }),
                Write::Retire(plan.length),
            ];
            let mut pending = mmio::InputState::default();
            pending.begin_packed_string(input, left).unwrap();
            let wire = rax::codec::serialize(&pending).unwrap();
            for count in [15, 16, 17] {
                let mut restored: mmio::InputState = rax::codec::deserialize_strict(&wire).unwrap();
                assert_eq!(restored.descriptor(), Some((16, None)));
                restored.validate_checkpoint().unwrap();
                let mut host = Host::default();
                restored.complete(&mut host, &right[..count]);
                assert_eq!(restored.ready().is_ok(), count == 16);
                restored.complete(&mut host, &right[..16]);
                if count == 16 {
                    assert_eq!(host.0, expected, "{code:02x?}");
                } else {
                    assert!(host.0.is_empty(), "{code:02x?}");
                }
            }
        }
    }
}
