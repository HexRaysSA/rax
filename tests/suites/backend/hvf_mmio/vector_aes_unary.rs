//! Device-source AESIMC and AESKEYGENASSIST transactions.
use super::*;

#[test]
fn aes_single_source_device_results_match_ram_after_restore() {
    let patterns = [0, 5, 10, 15];
    let seed: [u8; 32] = std::array::from_fn(|i| ((i * 17) ^ (i / 3 * 29) ^ 177) as u8);
    let mut observations: [Sha256; 2] = std::array::from_fn(|_| Sha256::new());
    let cases = (0..16).map(|pattern| (pattern, None)).chain(
        patterns
            .into_iter()
            .flat_map(|pattern| (0..=u8::MAX).map(move |immediate| (pattern, Some(immediate)))),
    );
    for (pattern, immediate) in cases {
        let source: [u8; 16] =
            std::array::from_fn(|i| (pattern * 43 + i * 73).wrapping_sub(i % 5 * 19) as u8);
        for (index, encoding) in [Encoding::Legacy, Encoding::Vex128].into_iter().enumerate() {
            let vex = encoding == Encoding::Vex128;
            let (map, opcode, name) = if immediate.is_some() {
                (3, 0xdf, "aeskeygenassist")
            } else {
                (2, 0xdb, "aesimc")
            };
            let (mut code, name) = if vex {
                (
                    vec![0xc4, 0x60 | map, 0x79, opcode, 0x7f, 3],
                    format!("v{name}"),
                )
            } else {
                (
                    vec![
                        0x66,
                        0x44,
                        0x0f,
                        if map == 3 { 0x3a } else { 0x38 },
                        opcode,
                        0x3f,
                    ],
                    name.to_owned(),
                )
            };
            if let Some(immediate) = immediate {
                code.push(immediate);
            }
            let (context, mut memory, mut exit) = fixture(&code);
            if vex {
                exit.linear += 3;
                exit.physical += 3;
            }
            let decoded = instruction_metadata::decode(64, context.rip, &code).unwrap();
            assert_eq!(decoded.mnemonic, name);
            assert!(decoded.operands_complete);
            assert_eq!(decoded.operands.len(), 2 + usize::from(immediate.is_some()));
            let [destination, device, ..] = decoded.operands.as_slice() else {
                unreachable!()
            };
            assert!(destination.write && !destination.read);
            assert_eq!(destination.reg, "xmm15");
            assert_eq!(device.kind, OperandKind::Memory);
            assert_eq!(device.width_bits, 128);
            if let Some(immediate) = immediate {
                assert_eq!(decoded.operands[2].value, u64::from(immediate));
            }
            let plan = prepare(&context, &mut memory, exit).unwrap();
            assert_eq!(
                (plan.linear, plan.physical, plan.length),
                (exit.linear, exit.physical, code.len() as u64)
            );
            assert!(
                !memory
                    .reads
                    .iter()
                    .any(|&(address, _)| address == exit.physical)
            );
            let Action::UnaryVector(input) = plan.action else {
                panic!("expected one device source");
            };
            assert_eq!(input.encoding, encoding);
            let mut state = mmio::InputState::default();
            state.begin_unary_vector(input).unwrap();
            let bytes = rax::codec::serialize(&state).unwrap();
            let mut restored: mmio::InputState = rax::codec::deserialize_strict(&bytes).unwrap();
            restored.validate_checkpoint().unwrap();
            assert_eq!(restored.descriptor(), Some((16, None)));
            let mut host = Host::default();
            restored.complete(&mut host, &source);
            restored.complete(&mut host, &source);
            let [Write::Xmm(15, actual, zero_upper), Write::Retire(length)] = host.0.as_slice()
            else {
                panic!("unexpected AES source completion {:?}", host.0);
            };
            assert_eq!((*zero_upper, *length), (vex, code.len() as u64));
            let mut result = seed;
            result[..16].copy_from_slice(actual);
            if *zero_upper {
                result[16..].fill(0);
            }
            observations[index].update(result);
        }
    }
    assert_eq!(
        observations.map(|value| format!("{:x}", value.finalize())),
        [
            "a04cf238edb60f254621ae017fd6e6b5fc1b13e96a7c2d1309e6127978714c4f",
            "0f523ef2f2e9fcdcc94e933aa250dc5211e82b56f15bf2febb887db83c56dc6c",
        ],
    );
}

#[test]
fn aes_single_source_vex_rejects_reserved_width_and_register_field() {
    for mut code in [
        vec![0xc4, 0x62, 0x79, 0xdb, 0x3f],
        vec![0xc4, 0x63, 0x79, 0xdf, 0x3f, 0xe5],
    ] {
        assert!(instruction_metadata::decode(64, 0x1000, &code).is_ok());
        for bad in [0x7d, 0x71] {
            code[2] = bad;
            assert!(instruction_metadata::decode(64, 0x1000, &code).is_err());
        }
    }
}
