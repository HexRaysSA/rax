//! AVX permutations of a device operand.
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

fn lane_permutation_code(encoding: Encoding, double: bool, control: Option<u8>) -> Vec<u8> {
    let width = if encoding == Encoding::Vex256 { 4 } else { 0 };
    let element = u8::from(double);
    if let Some(control) = control {
        vec![0xc4, 0x63, 0x79 | width, 4 + element, 0x7f, 3, control]
    } else {
        // The register data source aliases the destination.
        vec![0xc4, 0x62, 1 | width, 0x0c + element, 0x7f, 3]
    }
}

fn check_lane_permutation(
    encoding: Encoding,
    double: bool,
    control: Option<u8>,
    reply: &[u8],
) -> [u8; 32] {
    let code = lane_permutation_code(encoding, double, control);
    let (context, mut ram, mut exit) = fixture(&code);
    exit.linear += 3;
    exit.physical += 3;
    let width = usize::from(encoding.size());
    let decoded = instruction_metadata::decode(64, context.rip, &code)
        .unwrap_or_else(|error| panic!("{code:02x?}: {error:?}"));
    assert_eq!(
        decoded.mnemonic,
        if double { "vpermilpd" } else { "vpermilps" }
    );
    let memory = &decoded.operands[if control.is_some() { 1 } else { 2 }];
    assert_eq!(memory.kind, OperandKind::Memory);
    assert_eq!(memory.width_bits as usize, width * 8);
    assert!(memory.read && !memory.write && !memory.conditional);
    let plan = prepare(&context, &mut ram, exit).unwrap();
    assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
    assert_eq!(plan.length, code.len() as u64);
    assert!(
        ram.reads
            .iter()
            .all(|&(address, _)| address != exit.physical)
    );

    let source = immediate_reply();
    let mut pending = mmio::InputState::default();
    match (plan.action, control) {
        (Action::VectorLogic { input, source: 15 }, None) => {
            let mut invalid = input.clone();
            invalid.encoding = Encoding::Legacy;
            assert!(pending.begin_vector_logic(invalid, source).is_err());
            pending.begin_vector_logic(input, source).unwrap();
        }
        (Action::UnaryVector(input), Some(_)) => {
            if double {
                let mut invalid = input.clone();
                invalid.encoding = Encoding::Legacy;
                assert!(pending.begin_unary_vector(invalid).is_err());
            }
            pending.begin_unary_vector(input).unwrap();
        }
        (action, _) => panic!("{code:02x?}: {action:?}"),
    }
    let bytes = rax::codec::serialize(&pending).unwrap();
    let mut restored: mmio::InputState = rax::codec::deserialize_strict(&bytes).unwrap();
    restored.validate_checkpoint().unwrap();
    assert_eq!(restored.descriptor(), Some((width as u8, None)));

    let data = if control.is_some() {
        reply
    } else {
        &source[..width]
    };
    let element = if double { 8 } else { 4 };
    let expected: Vec<u8> = data
        .chunks_exact(16)
        .enumerate()
        .flat_map(|(lane, data)| {
            (0..16 / element).flat_map(move |slot| {
                let output = lane * 16 / element + slot;
                let selector = match (control, double) {
                    (Some(imm), false) => (imm >> (2 * slot)) & 3,
                    (Some(imm), true) => (imm >> output) & 1,
                    (None, false) => reply[output * 4] & 3,
                    (None, true) => (reply[output * 8] & 2) / 2,
                };
                let start = usize::from(selector) * element;
                data[start..start + element].iter().copied()
            })
        })
        .collect();
    let mut host = Host::default();
    let mut short = restored.clone();
    short.complete(&mut host, &reply[..width - 1]);
    assert!(short.failure().is_some() && short.pending() && host.0.is_empty());
    restored.complete(&mut host, reply);
    restored.complete(&mut host, reply);
    match host.0.as_slice() {
        [Write::Xmm(15, actual, true), Write::Retire(length)] if width == 16 => {
            assert_eq!(actual.as_slice(), expected, "{code:02x?}");
            assert_eq!(*length, plan.length);
            let mut full = [0; 32];
            full[..16].copy_from_slice(actual);
            full
        }
        [Write::Ymm(15, actual), Write::Retire(length)] if width == 32 => {
            assert_eq!(actual.as_slice(), expected, "{code:02x?}");
            assert_eq!(*length, plan.length);
            *actual
        }
        writes => panic!("{code:02x?}: {writes:?}"),
    }
}

#[test]
fn lane_permutations_retain_both_control_forms_after_restore() {
    let data = immediate_reply();
    let mut observed = Sha256::new();
    for encoding in [Encoding::Vex128, Encoding::Vex256] {
        let width = usize::from(encoding.size());
        for double in [false, true] {
            for control in 0..=u8::MAX {
                observed.update(check_lane_permutation(
                    encoding,
                    double,
                    Some(control),
                    &data[..width],
                ));
            }
            for pattern in 0..32 {
                let controls = std::array::from_fn::<_, 32, _>(|byte| {
                    let element = if double { 8 } else { 4 };
                    if byte % element == 0 {
                        let output = byte / element;
                        let selected = (output + byte / 16 + (pattern >> (output % 3))) % 4;
                        0x80 | (((pattern ^ byte) * 4) | selected) as u8
                    } else {
                        data[byte]
                    }
                });
                observed.update(check_lane_permutation(
                    encoding,
                    double,
                    None,
                    &controls[..width],
                ));
            }
        }
    }
    assert_eq!(
        format!("{:x}", observed.finalize()),
        "0e7f55ac725f1c315ce5d2e77e35597c8d19c4eee27a67da9b6658fae0c88032"
    );
}

#[test]
fn lane_permutations_reject_reserved_fields_and_non_read_exits() {
    for encoding in [Encoding::Vex128, Encoding::Vex256] {
        for double in [false, true] {
            for control in [None, Some(0x9b)] {
                let mut code = lane_permutation_code(encoding, double, control);
                // W0 and the mandatory 66pp prefix.
                for field in [0x80, 2] {
                    let mut invalid = code.clone();
                    invalid[2] ^= field;
                    assert!(instruction_metadata::decode(64, 0x1000, &invalid).is_err());
                }
                if control.is_some() {
                    let mut invalid = code.clone();
                    invalid[2] &= !8;
                    assert!(instruction_metadata::decode(64, 0x1000, &invalid).is_err());
                    assert!(instruction_metadata::decode(64, 0x1000, &code[..6]).is_err());
                }
                let (context, mut ram, mut exit) = fixture(&code);
                exit.qualification = 0x182;
                exit.linear += 3;
                exit.physical += 3;
                assert!(prepare(&context, &mut ram, exit).is_err());
                assert!(
                    ram.reads
                        .iter()
                        .all(|&(address, _)| address != exit.physical)
                );
                code[4] = 0xff;
                code.remove(5);
                assert!(instruction_metadata::decode(64, 0x1000, &code).is_ok());
                let (context, mut ram, exit) = fixture(&code);
                assert!(prepare(&context, &mut ram, exit).is_err());
            }
        }
    }
}
