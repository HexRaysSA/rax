//! Complete opcode63 metadata and native MMIO sign-extension admission.
use super::*;
use isa::x86_64::instruction_metadata;

fn instruction(bits: u32, destination: usize, register_source: bool) -> Vec<u8> {
    let mut code = Vec::new();
    if bits == 16 {
        code.push(0x66);
    }
    let rex = 0x40 | if bits == 64 { 8 } else { 0 } | if destination >= 8 { 4 } else { 0 };
    if rex != 0x40 {
        code.push(rex);
    }
    code.extend_from_slice(&[
        0x63,
        (if register_source { 0xc0 } else { 0 }) | ((destination as u8 & 7) << 3) | 7,
    ]);
    code
}

#[test]
fn movsxd_metadata_represents_all_legal_widths_and_operand_directions() {
    for bits in [16, 32, 64] {
        for destination in 0..16 {
            for register_source in [false, true] {
                let code = instruction(bits, destination, register_source);
                let decoded = instruction_metadata::decode(64, 0x1000, &code).unwrap();
                assert_eq!(decoded.mnemonic, "movsxd", "{code:02x?}");
                assert!(decoded.operands_complete, "incomplete MOVSXD {code:02x?}");
                assert_eq!(decoded.size as usize, code.len());
                assert_eq!(decoded.operands.len(), 2);
                let output = &decoded.operands[0];
                assert_eq!(output.kind, instruction_metadata::OperandKind::Register);
                assert_eq!(output.width_bits, bits);
                assert!(!output.read && output.write && !output.conditional);
                let input = &decoded.operands[1];
                assert_eq!(input.width_bits, bits.min(32));
                assert!(input.read && !input.write && !input.conditional);
                assert_eq!(
                    input.kind,
                    if register_source {
                        instruction_metadata::OperandKind::Register
                    } else {
                        instruction_metadata::OperandKind::Memory
                    }
                );
                assert_eq!(RegisterPart::parse(&output.reg).unwrap().index, destination);
            }
        }
    }
}

#[test]
fn movsxd_mmio_completes_all_destinations_sign_edges_and_saved_pending_reads() {
    for bits in [16, 32, 64] {
        for destination in 0..16 {
            let code = instruction(bits, destination, false);
            let (context, mut memory, exit) = fixture(&code);
            let plan = prepare(&context, &mut memory, exit)
                .unwrap_or_else(|error| panic!("MOVSXD {code:02x?}: {error}"));
            let Action::Read(input) = plan.action else {
                panic!("MOVSXD must read device memory")
            };
            let size = usize::try_from(bits.min(32) / 8).unwrap();
            assert_eq!(usize::from(input.size), size);
            assert_eq!(input.destination.index, destination);
            assert_eq!(input.destination.bits, bits);
            assert_eq!(input.length as usize, code.len());
            for value in [
                0u32,
                1,
                0x7fff,
                0x8000,
                0xffff,
                0x7fff_ffff,
                0x8000_0000,
                u32::MAX,
            ] {
                let bytes = value.to_le_bytes();
                let expected = match bits {
                    16 => (context.registers[destination] & !0xffff) | u64::from(value & 0xffff),
                    32 => u64::from(value),
                    64 => value as i32 as i64 as u64,
                    _ => unreachable!(),
                };
                let mut pending = mmio::InputState::default();
                pending.begin(input.clone()).unwrap();
                let encoded = rax::codec::serialize(&pending).unwrap();
                let mut restored: mmio::InputState =
                    rax::codec::deserialize_strict(&encoded).unwrap();
                let mut host = CompletionHost {
                    flags: 0x8d7,
                    ..CompletionHost::default()
                };
                restored.complete(&mut host, &bytes[..size]);
                assert_eq!(restored.ready(), Ok(()));
                assert_eq!(
                    (host.index, host.value, host.length),
                    (destination, expected, code.len() as u64)
                );
                assert_eq!(host.flags, 0x8d7);
                assert_eq!(host.calls, ["gpr", "finish"]);
            }
            for short in 0..size {
                let mut pending = mmio::InputState::default();
                pending.begin(input.clone()).unwrap();
                let mut host = CompletionHost::default();
                pending.complete(&mut host, &vec![0; short]);
                assert!(pending.ready().is_err());
                assert!(host.calls.is_empty());
            }
        }
    }
}

#[test]
fn movsxd_admission_retains_legacy_arpl_and_rejects_invalid_exit_or_lock() {
    for bits in [16, 32] {
        let decoded = instruction_metadata::decode(bits, 0x1000, &[0x63, 0x07]).unwrap();
        assert_eq!(decoded.mnemonic, "arpl");
        assert!(!decoded.operands_complete);
    }
    for bits in [16, 32, 64] {
        let code = instruction(bits, 15, false);
        let (context, mut memory, mut exit) = fixture(&code);
        exit.qualification = 0x182;
        assert!(prepare(&context, &mut memory, exit).is_err());
        let mut locked = vec![0xf0];
        locked.extend_from_slice(&code);
        assert!(instruction_metadata::decode(64, 0x1000, &locked).is_err());
        let (context, mut memory, exit) = fixture(&locked);
        assert!(prepare(&context, &mut memory, exit).is_err());
        for length in 0..code.len() {
            assert!(instruction_metadata::decode(64, 0x1000, &code[..length]).is_err());
        }
    }
}

#[test]
fn native_kvm_records_match_all_registers_memory_and_flags() {
    const CASES: &[u8] = include_bytes!("../../../fixtures/hvf/mmio-movsxd-v1/cases.bin");
    const RECORDS: &[u8] = include_bytes!("../../../fixtures/hvf/mmio-movsxd-v1/records.bin");
    assert_eq!(CASES.len(), 768 * 168);
    assert_eq!(compare_guest_records(CASES, RECORDS), (768, 0));
}
