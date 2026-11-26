use super::*;
use sha2::{Digest, Sha256};

#[path = "../../../../tools/hvf/intel_mmio_register_blend.rs"]
mod register_blend;

#[test]
fn register_mask_blend_keeps_the_live_mask_across_pending_restore() {
    let cases = register_blend::cases();
    assert_eq!(cases.len(), 255);
    let mut observations = Sha256::new();
    for (index, case) in cases.into_iter().enumerate() {
        let vex = case.is_vex();
        let (context, mut memory, mut exit) = fixture(&case.code);
        if vex {
            exit.linear += 3;
            exit.physical += 3;
        }
        let meta = instruction_metadata::decode(64, context.rip, &case.code).unwrap();
        assert_eq!(meta.mnemonic, case.mnemonic);
        let mask_operand = meta.operands.last().unwrap();
        assert_eq!(mask_operand.kind, OperandKind::Register);
        assert_eq!(mask_operand.width_bits, case.width as u32 * 8);
        assert!(mask_operand.read && !mask_operand.write);
        let plan = prepare(&context, &mut memory, exit).unwrap();
        assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
        assert_eq!(plan.length, case.code.len() as u64);
        assert!(
            memory
                .reads
                .iter()
                .all(|&(address, _)| address != exit.physical)
        );
        let Action::VectorMaskBlend {
            input,
            source,
            mask,
        } = plan.action
        else {
            panic!("{index}: unexpected action {:?}", plan.action);
        };
        assert_eq!(
            (input.index, source, mask),
            (15, if vex { 8 } else { 15 }, case.bank)
        );
        let input = input.capture_blend_mask(&case.mask).unwrap();
        let mut pending = mmio::InputState::default();
        pending
            .begin_vector_logic(input, register_blend::LEFT)
            .unwrap();
        let saved = rax::codec::serialize(&pending).unwrap();
        let mut restored: mmio::InputState = rax::codec::deserialize_strict(&saved).unwrap();
        restored.validate_checkpoint().unwrap();
        assert_eq!(restored.descriptor(), Some((case.width as u8, None)));
        let reply = &register_blend::REPLY[..case.width];
        let mut host = Host::default();
        restored.complete(&mut host, reply);
        restored.complete(&mut host, reply);
        let result = match host.0.as_slice() {
            [Write::Ymm(15, bytes), Write::Retire(length)] if case.width == 32 => {
                assert_eq!(*length, plan.length);
                *bytes
            }
            [Write::Xmm(15, bytes, zero_upper), Write::Retire(length)] if case.width == 16 => {
                assert_eq!((*zero_upper, *length), (vex, plan.length));
                let mut result = if vex { [0; 32] } else { register_blend::LEFT };
                result[..16].copy_from_slice(bytes);
                result
            }
            _ => panic!("{index}: unexpected completion {:?}", host.0),
        };
        assert_eq!(result, case.expected, "{index}");
        observations.update(result);
    }
    assert_eq!(
        format!("{:x}", observations.finalize()),
        "1c0772b6b25e06c5bcc2b1117519d260025295a34e74fab84885fe9579f27405"
    );
}

#[test]
fn register_mask_blend_rejects_reserved_and_non_device_forms() {
    for opcode in [0x4a, 0x4b, 0x4c] {
        for code in [
            &[0xc4, 0x63, 0xbd, opcode, 0x7f, 3, 0xff][..], // VEX.W1.
            &[0xc4, 0x63, 0x3d, opcode, 0xff, 0xff][..],    // Register source.
            &[0xc4, 0x63, 0x3c, opcode, 0x7f, 3, 0xff][..], // Wrong mandatory prefix.
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
    for opcode in [0x10, 0x14, 0x15] {
        let (mut context, mut memory, mut exit) = fixture(&[0x66, 0x44, 0x0f, 0x38, opcode, 0x3f]);
        context.registers[7] += 1;
        exit.linear += 1;
        exit.physical += 1;
        let error = prepare(&context, &mut memory, exit).unwrap_err();
        assert!(error.contains("misaligned"), "{error}");
        assert!(
            memory
                .reads
                .iter()
                .all(|&(address, _)| address != exit.physical)
        );
    }
}
