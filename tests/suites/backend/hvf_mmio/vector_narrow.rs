//! Saturating packed reads across decode, deferred I/O, and restoration.
use super::*;
use packed_multiply::bytes;

#[path = "../../../../tools/hvf/intel_mmio_packed_narrow.rs"]
mod packed_narrow;

#[test]
fn packed_narrowing_matches_x86_ram_and_completes_once() {
    let mut rejected = Vec::new();
    for case in packed_narrow::CASES {
        for (code, form, width) in case.forms() {
            let label = (case.mnemonic, form);
            let vex = form != "legacy";
            let (context, mut memory, mut exit) = fixture(&code);
            if vex {
                exit.linear += 3;
                exit.physical += 3;
            }
            let plan = match prepare(&context, &mut memory, exit) {
                Ok(plan) => plan,
                Err(error) => {
                    rejected.push(format!("{label:?}: {error}"));
                    continue;
                }
            };
            assert_eq!((plan.linear, plan.physical), (exit.linear, exit.physical));
            assert!(memory.reads.iter().all(|&(addr, _)| addr != exit.physical));
            let Action::VectorLogic { input, source } = plan.action else {
                panic!("{label:?}: unexpected action {:?}", plan.action);
            };
            let encoding = match (vex, width) {
                (false, _) => Encoding::Legacy,
                (true, 16) => Encoding::Vex128,
                (true, _) => Encoding::Vex256,
            };
            assert_eq!((source, input.index), (if vex { 8 } else { 15 }, 15));
            assert_eq!(input.encoding, encoding);
            assert_eq!(input.length, code.len() as u64);
            assert_eq!(usize::from(input.memory_size()), width);

            let metadata = instruction_metadata::decode(64, context.rip, &code).unwrap();
            let name = format!("{}{}", if vex { "v" } else { "" }, case.mnemonic);
            assert_eq!(metadata.mnemonic, name);
            assert!(metadata.operands_complete);
            let device = metadata.operands.last().unwrap();
            assert_eq!(device.kind, OperandKind::Memory);
            assert!(device.read && !device.write);
            assert_eq!(device.width_bits, width as u32 * 8);

            for ([left, right], expected) in case.sources.into_iter().zip(case.results) {
                let mut pending = mmio::InputState::default();
                pending
                    .begin_vector_logic(input.clone(), bytes(left))
                    .unwrap();
                let wire = rax::codec::serialize(&pending).unwrap();
                let restored: mmio::InputState = rax::codec::deserialize_strict(&wire).unwrap();
                restored.validate_checkpoint().unwrap();
                assert_eq!(restored.descriptor(), Some((width as u8, None)));
                let reply = bytes(right);
                let expected = bytes(expected);
                let effect = if width == 32 {
                    Write::Ymm(15, expected)
                } else {
                    Write::Xmm(15, expected[..16].try_into().unwrap(), vex)
                };
                for mut transaction in [pending, restored] {
                    let mut host = Host::default();
                    transaction.complete(&mut host, &reply[..width]);
                    transaction.complete(&mut host, &reply[..width]);
                    assert_eq!(host.0.len(), 2, "{label:?}");
                    assert_eq!(host.0[0], effect, "{label:?}");
                    assert_eq!(host.0[1], Write::Retire(plan.length), "{label:?}");
                }
            }
            exit.qualification = 0x182;
            assert!(prepare(&context, &mut memory, exit).is_err(), "{label:?}");

            // Keep the stateless register form visible, while excluding it from MMIO.
            let mut register_code = code;
            if vex {
                register_code.pop();
            }
            *register_code.last_mut().unwrap() = 0xff;
            let decoded = instruction_metadata::decode(64, context.rip, &register_code).unwrap();
            assert_eq!(decoded.mnemonic, name);
            assert_eq!(decoded.operands.last().unwrap().kind, OperandKind::Register);
            let (context, mut memory, exit) = fixture(&register_code);
            assert!(prepare(&context, &mut memory, exit).is_err(), "{label:?}");
        }
    }
    assert!(rejected.is_empty(), "{}", rejected.join("\n"));
}

#[test]
fn packed_narrowing_requires_legacy_alignment_and_allocated_prefixes() {
    for case in packed_narrow::CASES {
        let code = case.legacy();
        let (mut context, mut memory, mut exit) = fixture(&code);
        context.registers[7] += 1;
        exit.linear += 1;
        exit.physical += 1;
        assert_eq!(
            prepare(&context, &mut memory, exit).unwrap_err(),
            "misaligned legacy vector logic MMIO input",
            "{}",
            case.mnemonic
        );
        assert!(memory.reads.iter().all(|&(addr, _)| addr != exit.physical));
        let locked = [&[0xf0][..], &code].concat();
        for invalid in [&code[1..], locked.as_slice()] {
            let (context, mut memory, exit) = fixture(invalid);
            assert!(prepare(&context, &mut memory, exit).is_err());
        }
    }
    for code in [
        &[0xc5, 0x38, 0x63, 0x3f][..],         // VEX PACKSSWB without 66.
        &[0xc4, 0x62, 0x38, 0x2b, 0x3f],       // VEX PACKUSDW without 66.
        &[0x62, 0x71, 0x3d, 0x08, 0x63, 0x3f], // EVEX operand shape.
    ] {
        let (context, mut memory, exit) = fixture(code);
        assert!(prepare(&context, &mut memory, exit).is_err(), "{code:02x?}");
        assert!(memory.reads.iter().all(|&(addr, _)| addr != exit.physical));
    }
}
