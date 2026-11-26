//! Carry-less products with a single device read and a retained source register.
use super::*;

#[test]
fn carryless_product_device_reads_match_ram_after_restore() {
    let mut observations: [Sha256; 3] = std::array::from_fn(|_| Sha256::new());

    for pattern in 0..8usize {
        let source: [u8; 32] =
            std::array::from_fn(|i| (pattern * 37 + i / 16 * 61 + i % 16 * 23) as u8);
        let reply: [u8; 32] =
            std::array::from_fn(|i| (pattern * 11 + i % 16 * 13).wrapping_sub(i / 16 * 43) as u8);
        for control in u8::MIN..=u8::MAX {
            let wig = if control & 2 == 0 { 0 } else { 0x80 };
            let legacy = [0x66, 0x44, 0x0f, 0x3a, 0x44, 0x3f, control];
            let vex128 = [0xc4, 0x63, 0x39 | wig, 0x44, 0x7f, 3, control];
            let vex256 = [0xc4, 0x63, 0x3d | wig, 0x44, 0x7f, 3, control];
            for (slot, (encoding, code, read_width, source_index)) in [
                (Encoding::Legacy, legacy, 16, 15),
                (Encoding::Vex128, vex128, 16, 8),
                (Encoding::Vex256, vex256, 32, 8),
            ]
            .into_iter()
            .enumerate()
            {
                let label = (pattern, control, encoding);
                let (context, mut memory, mut exit) = fixture(&code);
                if encoding != Encoding::Legacy {
                    exit.linear += 3;
                    exit.physical += 3;
                }
                let decoded = instruction_metadata::decode(64, context.rip, &code)
                    .unwrap_or_else(|error| panic!("{label:?}: {error:?}"));
                let name = if encoding == Encoding::Legacy {
                    "pclmulqdq"
                } else {
                    "vpclmulqdq"
                };
                assert_eq!(decoded.mnemonic, name, "{label:?}");
                let [.., operand, immediate] = decoded.operands.as_slice() else {
                    panic!("{label:?}: missing memory operand or control");
                };
                assert_eq!(operand.kind, OperandKind::Memory, "{label:?}");
                assert_eq!(operand.width_bits, u32::from(read_width) * 8, "{label:?}");
                assert_eq!(
                    (immediate.kind, immediate.width_bits, immediate.value),
                    (OperandKind::Immediate, 8, u64::from(control)),
                    "{label:?}"
                );
                let plan = prepare(&context, &mut memory, exit)
                    .unwrap_or_else(|error| panic!("{label:?}: {error}"));
                let Action::VectorLogic {
                    input,
                    source: first,
                } = plan.action
                else {
                    panic!("{label:?}: unexpected plan {:?}", plan.action);
                };
                assert_eq!(
                    (input.index, input.encoding, first),
                    (15, encoding, source_index)
                );
                assert_eq!(
                    (plan.linear, plan.physical, plan.length),
                    (exit.linear, exit.physical, 7)
                );
                assert!(
                    memory
                        .reads
                        .iter()
                        .all(|&(address, _)| address != exit.physical)
                );

                let mut input_state = mmio::InputState::default();
                input_state.begin_vector_logic(input, source).unwrap();
                let saved = rax::codec::serialize(&input_state).unwrap();
                let mut restored: mmio::InputState =
                    rax::codec::deserialize_strict(&saved).unwrap();
                restored.validate_checkpoint().unwrap();
                assert_eq!(restored.descriptor(), Some((read_width, None)));
                let mut host = Host::default();
                restored.complete(&mut host, &reply[..usize::from(read_width)]);
                restored.complete(&mut host, &reply[..usize::from(read_width)]);

                let mut result = source;
                match host.0.as_slice() {
                    [Write::Xmm(15, xmm, zero_upper), Write::Retire(7)]
                        if encoding != Encoding::Vex256 =>
                    {
                        assert_eq!(*zero_upper, encoding == Encoding::Vex128, "{label:?}");
                        result[..16].copy_from_slice(xmm);
                        if *zero_upper {
                            result[16..].fill(0);
                        }
                    }
                    [Write::Ymm(15, ymm), Write::Retire(7)] if encoding == Encoding::Vex256 => {
                        result = *ymm;
                    }
                    other => panic!("{label:?}: unexpected completion {other:?}"),
                }
                observations[slot].update(result);
            }
        }
    }

    // The wide reference combines two independently executed VEX.128 lanes.
    assert_eq!(
        observations.map(|digest| format!("{:x}", digest.finalize())),
        [
            "10cde6acbec40bf6276c4d179f3c3553b4e7ac3b73585ab0dae342b67105d415",
            "55e6b3a71c3e623c74e49867ac41305828a88cfc7bf4d27e167393a6068d0f92",
            "57e0f47199084f728a22ca25b0e2b92253bd18d1721d7c6b185438c811cd5a15",
        ]
    );
}

#[test]
fn carryless_product_rejects_misalignment_and_non_device_operands() {
    let legacy = [0x66, 0x44, 0x0f, 0x3a, 0x44, 0x7f, 3, 0x11];
    let (context, mut memory, mut exit) = fixture(&legacy);
    exit.linear += 3;
    exit.physical += 3;
    assert_eq!(
        prepare(&context, &mut memory, exit).unwrap_err(),
        "misaligned legacy vector logic MMIO input"
    );

    let vex = [0xc4, 0x63, 0xb9, 0x44, 0x3f, 0x11];
    let (context, mut memory, mut exit) = fixture(&vex);
    exit.qualification = 0x182;
    assert_eq!(
        prepare(&context, &mut memory, exit).unwrap_err(),
        "vector logic MMIO requires a complete device read operand"
    );

    let register_only = [0xc4, 0x63, 0x3d, 0x44, 0xff, 0x11];
    let (context, mut memory, exit) = fixture(&register_only);
    assert_eq!(
        prepare(&context, &mut memory, exit).unwrap_err(),
        "vector logic MMIO requires a complete device read operand"
    );
}
