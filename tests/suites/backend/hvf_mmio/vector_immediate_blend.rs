use super::*;
use sha2::{Digest, Sha256};

#[path = "../../../../tools/hvf/intel_mmio_packed_blend.rs"]
mod packed_blend;

#[test]
fn packed_immediate_blend_projects_device_reads_and_matches_every_ram_mask() {
    use packed_blend::{LEFT, REPLY, forms};

    let mut observations = Sha256::new();
    let forms = forms();
    assert_eq!(forms.len(), 17);
    for form in forms {
        let vex = form.is_vex();
        for mask in u8::MIN..=u8::MAX {
            let code = form.code(mask);
            let label = (form.mnemonic, form.encoding, mask);
            let (context, mut memory, mut exit) = fixture(&code);
            if vex {
                exit.linear += 3;
                exit.physical += 3;
            }
            let meta = instruction_metadata::decode(64, context.rip, &code)
                .unwrap_or_else(|error| panic!("{label:?}: {error:?}"));
            assert_eq!(meta.mnemonic, form.mnemonic);
            assert!(meta.operands_complete);
            let control = meta.operands.last().unwrap();
            assert_eq!(
                (control.kind, control.width_bits, control.value),
                (OperandKind::Immediate, 8, u64::from(mask))
            );
            let plan = prepare(&context, &mut memory, exit)
                .unwrap_or_else(|error| panic!("{label:?}: {error}"));
            assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
            assert_eq!(plan.length, code.len() as u64);
            assert!(
                memory
                    .reads
                    .iter()
                    .all(|&(address, _)| address != exit.physical)
            );
            let Action::VectorLogic { input, source } = plan.action else {
                panic!("{label:?}: unexpected action {:?}", plan.action);
            };
            assert_eq!((input.index, source), (15, if vex { 8 } else { 15 }));

            let mut pending = mmio::InputState::default();
            pending.begin_vector_logic(input, LEFT).unwrap();
            let saved = rax::codec::serialize(&pending).unwrap();
            let mut restored: mmio::InputState = rax::codec::deserialize_strict(&saved).unwrap();
            restored.validate_checkpoint().unwrap();
            assert_eq!(restored.descriptor(), Some((form.width as u8, None)));
            let reply = &REPLY[..form.width];
            let mut host = Host::default();
            restored.complete(&mut host, reply);
            restored.complete(&mut host, reply);
            let result = match host.0.as_slice() {
                [Write::Ymm(15, bytes), Write::Retire(7)] if form.width == 32 => *bytes,
                [Write::Xmm(15, bytes, zero_upper), Write::Retire(7)] if form.width == 16 => {
                    assert_eq!(*zero_upper, vex, "{label:?}");
                    let mut result = LEFT;
                    result[..16].copy_from_slice(bytes);
                    if *zero_upper {
                        result[16..].fill(0);
                    }
                    result
                }
                _ => panic!("{label:?}: unexpected completion {:?}", host.0),
            };
            assert_eq!(result, form.expected(mask), "{label:?}");
            observations.update(result);
        }
    }
    // Concatenated YMM15 from the independent x86 RAM run, in form and mask order.
    assert_eq!(
        format!("{:x}", observations.finalize()),
        "6a57bb9dc894bf9086023b04340cde3e586c52795b663ce5d4f8bf58a26483ad"
    );
}

#[test]
fn packed_immediate_blend_rejects_reserved_and_non_device_forms() {
    for form in packed_blend::forms()
        .into_iter()
        .filter(|form| !form.is_vex())
    {
        let code = form.code(0x80);
        let (mut context, mut memory, mut exit) = fixture(&code);
        context.registers[7] += 1;
        exit.linear += 1;
        exit.physical += 1;
        assert!(
            prepare(&context, &mut memory, exit)
                .unwrap_err()
                .contains("misaligned")
        );
        assert!(
            memory
                .reads
                .iter()
                .all(|&(address, _)| address != exit.physical)
        );
    }

    for code in [
        &[0x66, 0x44, 0x0f, 0x3a, 0x02, 0x3f, 0xa5][..], // VPBLENDD requires VEX.
        &[0xc4, 0x63, 0xb9, 0x02, 0x7f, 3, 0xa5],        // VEX.W1 is reserved.
        &[0xc4, 0x63, 0xbd, 0x02, 0x7f, 3, 0xa5],
        &[0xc4, 0x63, 0x38, 0x0d, 0x7f, 3, 0xa5], // Wrong mandatory prefix.
        &[0x66, 0x44, 0x0f, 0x3a, 0x0c, 0xff, 0xa5], // Register operand.
        &[0xc4, 0x63, 0x39, 0x02, 0xff, 0xa5],
        &[0xf0, 0x66, 0x44, 0x0f, 0x3a, 0x0e, 0x3f, 0xa5], // LOCK.
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
