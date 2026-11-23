//! Eight-byte memory transfers with a preserved or explicitly merged XMM lane.
use super::*;
use mmio::xmm_lane::{Lane, Transfer};
use rax::isa::x86_64::instruction_metadata::{self, OperandKind};

#[test]
fn xmm_lane_moves_plan_unaligned_qword_loads_and_stores() {
    for (prefix, lane, legacy_name, vex_name) in [
        (0, 0, "movlps", "vmovlps"),
        (0, 1, "movhps", "vmovhps"),
        (1, 0, "movlpd", "vmovlpd"),
        (1, 1, "movhpd", "vmovhpd"),
    ] {
        for load in [true, false] {
            let opcode = 0x12 + lane * 4 + u8::from(!load);
            let vex = if load { 0x38 } else { 0x78 } | prefix;
            let legacy = [0x66, 0x44, 0x0f, opcode, 0x7f, 3];
            for (code, expected_name, vector) in [
                (&legacy[usize::from(prefix == 0)..], legacy_name, false),
                (&[0xc5, vex, opcode, 0x7f, 3], vex_name, true),
                (&[0xc4, 0x61, vex, opcode, 0x7f, 3], vex_name, true),
            ] {
                let (context, mut ram, mut record) = fixture(code);
                record.linear += 3;
                record.physical += 3;
                record.qualification = if load { 0x181 } else { 0x182 };
                let plan = prepare(&context, &mut ram, record).unwrap_or_else(|error| {
                    panic!("{expected_name} {code:02x?} must plan an eight-byte transfer: {error}")
                });
                assert_eq!(plan.length, code.len() as u64);
                let expected_lane = if lane == 0 { Lane::Low } else { Lane::High };
                let transfer = match plan.action {
                    Action::XmmLaneRead {
                        transfer,
                        source,
                        zero_upper,
                    } if load => {
                        assert_eq!(source, if vector { 8 } else { 15 });
                        assert_eq!(zero_upper, vector);
                        transfer
                    }
                    Action::XmmLaneWrite(transfer) if !load => transfer,
                    other => panic!("wrong lane action for {code:02x?}: {other:?}"),
                };
                assert_eq!(
                    (transfer.index, transfer.lane, transfer.length),
                    (15, expected_lane, plan.length)
                );
                assert_eq!(
                    (plan.linear, plan.physical),
                    (record.linear, record.physical)
                );
                assert!(
                    ram.reads
                        .iter()
                        .all(|&(address, _)| address != record.physical)
                );

                let meta = instruction_metadata::decode(64, context.rip, code).unwrap();
                let operands = &meta.operands;
                assert_eq!(meta.mnemonic, expected_name);
                let memory = if load {
                    operands.last().unwrap()
                } else {
                    &operands[0]
                };
                assert_eq!(memory.kind, OperandKind::Memory);
                assert_eq!(memory.width_bits, 64);
                assert_eq!((memory.read, memory.write), (load, !load));
                let xmm15 = &operands[usize::from(!load)];
                assert_eq!(xmm15.reg, "xmm15");
                assert_eq!((xmm15.read, xmm15.write), (!load || !vector, load));
                if load && vector {
                    assert_eq!((operands.len(), operands[1].reg.as_str()), (3, "xmm8"));
                    assert!(operands[1].read && !operands[1].write);
                } else {
                    assert_eq!(operands.len(), 2);
                }

                record.qualification ^= 3;
                assert!(prepare(&context, &mut ram, record).is_err());
            }
        }
    }
}

#[test]
fn malformed_vex_lane_encodings_and_register_only_forms_do_not_plan_device_io() {
    for (code, read) in [
        (&[0xc5, 0x3c, 0x12, 0x3f][..], true), // VEX.L=1.
        (&[0xc5, 0x3d, 0x16, 0x3f], true),
        (&[0xc5, 0x70, 0x13, 0x3f], false), // Store's inverted vvvv is reserved.
        (&[0xc4, 0x61, 0x71, 0x17, 0x3f], false),
        (&[0x0f, 0x16, 0xc0], true), // MOVLHPS has no memory operand.
        (&[0xc5, 0x38, 0x12, 0xff], true), // VMOVHLPS has no memory operand.
        (&[0x66, 0x0f, 0x17, 0xc0], false),
        (&[0xc5, 0x79, 0x13, 0xff], false),
    ] {
        let (context, mut ram, mut record) = fixture(code);
        record.qualification = if read { 0x181 } else { 0x182 };
        assert!(prepare(&context, &mut ram, record).is_err(), "{code:02x?}");
    }
    let valid = [0xc4, 0xe1, 0x68, 0x12, 0x07];
    let invalid = [0xc4, 0xe1, 0x38, 0x12, 0x07];
    let meta = instruction_metadata::decode(32, 0x1000, &valid).unwrap();
    assert_eq!(meta.operands[1].reg, "xmm2");
    assert!(instruction_metadata::decode(32, 0x1000, &invalid).is_err());
}

#[test]
fn xmm_lane_read_completes_from_serialized_pending_state() {
    #[derive(Default)]
    struct Host {
        vector: Option<(u8, [u8; 16], bool)>,
        length: Option<u64>,
    }
    impl mmio::CompletionAccess for Host {
        type Error = &'static str;

        fn write_gpr(&mut self, _: usize, _: u64) -> Result<(), Self::Error> {
            panic!("lane load changed a GPR");
        }

        fn write_rflags(&mut self, _: u64) -> Result<(), Self::Error> {
            panic!("lane load changed RFLAGS");
        }

        fn write_xmm(&mut self, index: u8, result: [u8; 16], zero: bool) -> Result<(), String> {
            assert!(self.vector.replace((index, result, zero)).is_none());
            Ok(())
        }

        fn finish_instruction(&mut self, length: u64) -> Result<(), Self::Error> {
            assert!(self.vector.is_some());
            assert!(self.length.replace(length).is_none());
            Ok(())
        }
    }

    let payload = [0x71; 9];
    let preserved = [0xab; 8];
    for (index, lane) in [(0, Lane::Low), (15, Lane::High)] {
        for zero in [false, true] {
            let transfer = Transfer {
                index,
                lane,
                length: 5,
            };
            let encoded = {
                let mut source = mmio::InputState::default();
                source.begin_xmm_lane(transfer, preserved, zero).unwrap();
                assert!(source.validate_checkpoint().is_ok());
                rax::codec::serialize(&source).unwrap()
            };
            for size in [7, 8, 9] {
                let mut pending: mmio::InputState =
                    rax::codec::deserialize_strict(&encoded).unwrap();
                assert_eq!(pending.descriptor(), Some((8, None)));
                assert!(pending.validate_checkpoint().is_ok());
                let mut host = Host::default();
                pending.complete(&mut host, &payload[..size]);
                if size == 8 {
                    let (target, value, cleared) = host.vector.unwrap();
                    assert_eq!((target, cleared), (index, zero));
                    assert_eq!(lane.bytes(&value), [0x71; 8]);
                    assert_eq!(lane.preserved().bytes(&value), preserved);
                    assert_eq!(host.length, Some(5));
                    assert!(pending.ready().is_ok());
                } else {
                    assert!(pending.failure().is_some());
                    assert!(host.vector.is_none() && host.length.is_none());
                }
                pending.complete(&mut host, &payload[..8]);
                assert_eq!(host.length, (size == 8).then_some(5));
            }
        }
    }
}
