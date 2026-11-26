//! Full-register AVX2 permutations of a device operand.
use super::packed_shuffle::{
    PERMUTE_DOUBLEWORDS, PERMUTE_QUADWORDS, immediate_reply, permute_doublewords_code,
    permute_doublewords_expected, permute_indices, permute_quadwords_code,
    permute_quadwords_expected,
};
use super::*;

fn check_completion(
    code: &[u8],
    mnemonic: &str,
    indices: Option<[u8; 32]>,
    reply: [u8; 32],
    expected: [u8; 32],
) -> [u8; 32] {
    let (context, mut ram, mut exit) = fixture(code);
    exit.linear += 3;
    exit.physical += 3;
    let plan = prepare(&context, &mut ram, exit)
        .unwrap_or_else(|error| panic!("{mnemonic} {code:02x?}: {error}"));
    assert_eq!(
        (plan.physical, plan.linear, plan.length),
        (exit.physical, exit.linear, code.len() as u64)
    );
    assert!(
        ram.reads
            .iter()
            .all(|&(address, _)| address != exit.physical)
    );
    let decoded = instruction_metadata::decode(64, context.rip, code).unwrap();
    assert_eq!(decoded.mnemonic, mnemonic);
    let device = &decoded.operands[if indices.is_some() { 2 } else { 1 }];
    assert_eq!((device.kind, device.width_bits), (OperandKind::Memory, 256));
    assert!(device.read && !device.write && !device.conditional);

    let mut pending = mmio::InputState::default();
    match (plan.action, indices) {
        (Action::VectorLogic { mut input, source }, Some(indices)) => {
            assert_eq!(
                (input.index, input.encoding, source),
                (15, Encoding::Vex256, 8)
            );
            input.encoding = Encoding::Vex128;
            assert!(pending.begin_vector_logic(input.clone(), indices).is_err());
            input.encoding = Encoding::Vex256;
            pending.begin_vector_logic(input, indices).unwrap();
        }
        (Action::UnaryVector(mut input), None) => {
            assert_eq!(input.encoding, Encoding::Vex256);
            input.encoding = Encoding::Vex128;
            assert!(pending.begin_unary_vector(input.clone()).is_err());
            input.encoding = Encoding::Vex256;
            pending.begin_unary_vector(input).unwrap();
        }
        (action, _) => panic!("{mnemonic}: {action:?}"),
    }
    let saved = rax::codec::serialize(&pending).unwrap();
    let mut restored: mmio::InputState = rax::codec::deserialize_strict(&saved).unwrap();
    restored.validate_checkpoint().unwrap();
    assert_eq!(restored.descriptor(), Some((32, None)));
    let mut host = Host::default();
    let mut short = restored.clone();
    short.complete(&mut host, &reply[..31]);
    assert!(short.failure().is_some() && short.pending() && host.0.is_empty());
    restored.complete(&mut host, &reply);
    restored.complete(&mut host, &reply);
    let [Write::Ymm(15, actual), Write::Retire(length)] = host.0.as_slice() else {
        panic!("{mnemonic}: {:?}", host.0);
    };
    assert_eq!((*actual, *length), (expected, plan.length), "{code:02x?}");
    *actual
}

#[test]
fn full_permutations_resume_with_the_captured_indices() {
    let reply = immediate_reply();
    let mut observed = Sha256::new();
    for (mnemonic, opcode) in PERMUTE_DOUBLEWORDS {
        for pattern in 0..16 {
            let indices = permute_indices(pattern);
            let expected = permute_doublewords_expected(&indices, &reply);
            observed.update(check_completion(
                &permute_doublewords_code(opcode),
                mnemonic,
                Some(indices),
                reply,
                expected,
            ));
        }
    }
    for (mnemonic, opcode) in PERMUTE_QUADWORDS {
        for control in 0..=u8::MAX {
            let expected = permute_quadwords_expected(control, &reply);
            observed.update(check_completion(
                &permute_quadwords_code(opcode, control),
                mnemonic,
                None,
                reply,
                expected,
            ));
        }
    }
    assert_eq!(
        format!("{:x}", observed.finalize()),
        "5e5e6dc2ef8139990934f98c94c891fa306d605f5f98a275d22cc3a2defeab01"
    );
}

#[test]
fn full_permutations_reject_reserved_fields_and_non_read_exits() {
    for (mut code, wrong_fields) in PERMUTE_DOUBLEWORDS
        .map(|(_, opcode)| {
            (
                permute_doublewords_code(opcode).to_vec(),
                [0x39, 0xbd, 0x3c],
            )
        })
        .into_iter()
        .chain(PERMUTE_QUADWORDS.map(|(_, opcode)| {
            (
                permute_quadwords_code(opcode, 0x1b).to_vec(),
                [0xf9, 0x7d, 0xfc],
            )
        }))
    {
        for flags in wrong_fields {
            let mut invalid = code.clone();
            invalid[2] = flags;
            assert!(
                instruction_metadata::decode(64, 0x1000, &invalid).is_err(),
                "{invalid:02x?}"
            );
        }
        if code.len() == 7 {
            let mut invalid = code.clone();
            invalid[2] &= !8; // Reserved vvvv in the immediate forms.
            assert!(instruction_metadata::decode(64, 0x1000, &invalid).is_err());
        }
        let (context, mut ram, mut exit) = fixture(&code);
        exit.linear += 3;
        exit.physical += 3;
        exit.qualification = 0x182;
        assert!(prepare(&context, &mut ram, exit).is_err());
        assert!(
            ram.reads
                .iter()
                .all(|&(address, _)| address != exit.physical)
        );

        code[4] = 0xff;
        code.remove(5); // No displacement in the register form.
        assert!(instruction_metadata::decode(64, 0x1000, &code).is_ok());
        let (context, mut ram, exit) = fixture(&code);
        assert!(prepare(&context, &mut ram, exit).is_err());
    }
}
