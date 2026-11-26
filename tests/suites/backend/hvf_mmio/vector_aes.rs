//! AES round operations with a device key and a retained source register.
use super::*;

#[test]
fn aes_round_device_reads_match_independent_ram_after_restore() {
    let mut observations: [Sha256; 3] = std::array::from_fn(|_| Sha256::new());
    for (opcode, mnemonic) in [
        (0xdc, "aesenc"),
        (0xdd, "aesenclast"),
        (0xde, "aesdec"),
        (0xdf, "aesdeclast"),
    ] {
        for pattern in 0..16 {
            let source: [u8; 32] =
                std::array::from_fn(|i| (pattern * 37 + i / 16 * 61 + i % 16 * 23) as u8);
            let reply: [u8; 32] = std::array::from_fn(|i| {
                (pattern * 11 + i % 16 * 13).wrapping_sub(i / 16 * 43) as u8
            });
            for (slot, encoding) in [Encoding::Legacy, Encoding::Vex128, Encoding::Vex256]
                .into_iter()
                .enumerate()
            {
                let (code, name, size, expected_source) = match encoding {
                    Encoding::Legacy => (
                        vec![0x66, 0x44, 0x0f, 0x38, opcode, 0x3f],
                        mnemonic.to_owned(),
                        16,
                        15,
                    ),
                    Encoding::Vex128 => (
                        vec![0xc4, 0x62, 0x39, opcode, 0x7f, 3],
                        format!("v{mnemonic}"),
                        16,
                        8,
                    ),
                    Encoding::Vex256 => (
                        vec![0xc4, 0x62, 0x3d, opcode, 0x7f, 3],
                        format!("v{mnemonic}"),
                        32,
                        8,
                    ),
                };
                let (context, mut memory, mut exit) = fixture(&code);
                if encoding != Encoding::Legacy {
                    exit.linear += 3;
                    exit.physical += 3;
                }
                let decoded = instruction_metadata::decode(64, context.rip, &code).unwrap();
                assert_eq!(decoded.mnemonic, name);
                let plan = prepare(&context, &mut memory, exit).unwrap();
                assert_eq!(
                    (plan.linear, plan.physical, plan.length),
                    (exit.linear, exit.physical, 6)
                );
                assert!(
                    !memory
                        .reads
                        .iter()
                        .any(|&(address, _)| address == exit.physical)
                );
                let Action::VectorLogic {
                    input,
                    source: first,
                } = plan.action
                else {
                    panic!("expected a device-backed AES read");
                };
                assert_eq!(
                    (input.index, input.encoding, first),
                    (15, encoding, expected_source)
                );
                let mut state = mmio::InputState::default();
                state.begin_vector_logic(input, source).unwrap();
                let bytes = rax::codec::serialize(&state).unwrap();
                let mut restored: mmio::InputState =
                    rax::codec::deserialize_strict(&bytes).unwrap();
                restored.validate_checkpoint().unwrap();
                assert_eq!(restored.descriptor(), Some((size as u8, None)));
                let mut host = Host::default();
                restored.complete(&mut host, &reply[..size]);
                restored.complete(&mut host, &reply[..size]);
                let mut result = source;
                match host.0.as_slice() {
                    [Write::Xmm(15, actual, zero_upper), Write::Retire(6)]
                        if encoding != Encoding::Vex256 =>
                    {
                        assert_eq!(*zero_upper, encoding == Encoding::Vex128);
                        result[..16].copy_from_slice(actual);
                        if *zero_upper {
                            result[16..].fill(0);
                        }
                    }
                    [Write::Ymm(15, actual), Write::Retire(6)] if encoding == Encoding::Vex256 => {
                        result = *actual;
                    }
                    _ => panic!("unexpected AES completion {:?}", host.0),
                }
                observations[slot].update(result);
            }
        }
    }
    // Independent QEMU RAM results in Legacy, VEX.128, and VEX.256 order.
    assert_eq!(
        observations.map(|digest| format!("{:x}", digest.finalize())),
        [
            "9d04a7592cb6c0926f6ae0c912b986341c70018a9c750d772dfc06d46cb5209b",
            "193ede1511573b51b2e2dcfcfb3c5437fbda4d53786d9e42ebac755f39c817b3",
            "2119874106c8dafbd0ac281c4f495155dbceaa1af5cbef90dc4d51238eeadf70",
        ]
    );
}

#[test]
fn aes_round_device_reads_reject_wrong_direction_and_misaligned_legacy() {
    for opcode in 0xdc..=0xdf {
        let legacy = [0x66, 0x44, 0x0f, 0x38, opcode, 0x7f, 3];
        let (context, mut memory, mut exit) = fixture(&legacy);
        exit.linear += 3;
        exit.physical += 3;
        assert_eq!(
            prepare(&context, &mut memory, exit).unwrap_err(),
            "misaligned legacy vector logic MMIO input"
        );
        let vex = [0xc4, 0x62, 0x39, opcode, 0x3f];
        let (context, mut memory, mut exit) = fixture(&vex);
        exit.qualification = 0x182;
        assert_eq!(
            prepare(&context, &mut memory, exit).unwrap_err(),
            "vector logic MMIO requires a complete device read operand"
        );
        let register_only = [0xc4, 0x62, 0x39, opcode, 0xff];
        let (context, mut memory, exit) = fixture(&register_only);
        assert_eq!(
            prepare(&context, &mut memory, exit).unwrap_err(),
            "vector logic MMIO requires a complete device read operand"
        );
    }
}
