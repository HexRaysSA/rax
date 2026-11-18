//! Legacy MOVBE MMIO planning and decoded operand admission.
use super::*;
use isa::x86_64::instruction_metadata::{self, OperandKind};

const WORD_LOAD: &[u8] = &[0x66, 0x0f, 0x38, 0xf0, 0x07];
const DWORD_LOAD: &[u8] = &[0x0f, 0x38, 0xf0, 0x07];
const QWORD_LOAD: &[u8] = &[0x48, 0x0f, 0x38, 0xf0, 0x07];
const WORD_STORE: &[u8] = &[0x66, 0x0f, 0x38, 0xf1, 0x07];
const DWORD_STORE: &[u8] = &[0x0f, 0x38, 0xf1, 0x07];
const QWORD_STORE: &[u8] = &[0x48, 0x0f, 0x38, 0xf1, 0x07];

#[test]
fn movbe_input_reverses_device_bytes_and_preserves_gpr_width_rules_after_restore() {
    let device = [0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x12, 0x13, 0x14];
    for (code, size, register, expected) in [
        (WORD_LOAD, 2, 0, 0x1234_5678_9abc_aabb),
        (DWORD_LOAD, 4, 0, 0x0000_0000_aabb_ccdd),
        (QWORD_LOAD, 8, 0, 0xaabb_ccdd_1112_1314),
        // REX.R selects R8 rather than RAX without changing the word width.
        (
            &[0x66, 0x44, 0x0f, 0x38, 0xf0, 0x07],
            2,
            8,
            0x1234_5678_9abc_aabb,
        ),
    ] {
        let (context, mut ram, exit) = fixture(code);
        let plan = prepare(&context, &mut ram, exit).unwrap();
        assert_eq!((plan.physical, plan.linear), (exit.physical, exit.linear));
        let Action::Read(input) = plan.action else {
            panic!("MOVBE load must produce an input");
        };
        assert_eq!(usize::from(input.size), size);
        assert_eq!(input.destination.index, register);
        let mut pending = mmio::InputState::default();
        pending.begin(input).unwrap();
        let encoded = rax::codec::serialize(&pending).unwrap();
        let mut restored: mmio::InputState = rax::codec::deserialize_strict(&encoded).unwrap();
        restored.validate_checkpoint().unwrap();
        assert_eq!(restored.descriptor().unwrap().0, size as u8);
        let mut host = CompletionHost {
            flags: 0x8d7,
            ..CompletionHost::default()
        };
        restored.complete(&mut host, &device[..size]);
        assert_eq!(restored.ready(), Ok(()));
        assert_eq!(host.index, register);
        assert_eq!(host.value, expected);
        assert_eq!(host.flags, 0x8d7);
        assert_eq!(host.length, code.len() as u64);
        assert_eq!(host.calls, ["gpr", "finish"]);
    }
}

#[test]
fn movbe_output_reverses_only_the_source_register_bytes_in_the_transfer() {
    let register = 0x1234_5678_9abc_def0u64.to_be_bytes();
    for (code, size) in [(WORD_STORE, 2), (DWORD_STORE, 4), (QWORD_STORE, 8)] {
        let (context, mut ram, mut exit) = fixture(code);
        exit.qualification = 0x182;
        let plan = prepare(&context, &mut ram, exit).unwrap();
        assert_eq!((plan.physical, plan.linear), (exit.physical, exit.linear));
        assert_eq!(plan.length, code.len() as u64);
        let Action::Write(bytes) = plan.action else {
            panic!("MOVBE store must produce an output");
        };
        assert_eq!(bytes, register[8 - size..]);
    }
}

#[test]
fn movbe_metadata_preserves_operand_effects_in_every_legacy_code_size() {
    for (bits, code, operand_bits) in [
        (16, WORD_LOAD, 32),
        (16, DWORD_LOAD, 16),
        (32, WORD_LOAD, 16),
        (32, DWORD_LOAD, 32),
        (64, QWORD_LOAD, 64),
        (16, WORD_STORE, 32),
        (16, DWORD_STORE, 16),
        (32, WORD_STORE, 16),
        (32, DWORD_STORE, 32),
        (64, QWORD_STORE, 64),
    ] {
        let decoded = instruction_metadata::decode(bits, 0x1000, code).unwrap();
        assert_eq!(decoded.mnemonic, "movbe");
        assert!(decoded.operands_complete);
        assert_eq!(decoded.size as usize, code.len());
        let [destination, source] = decoded.operands.as_slice() else {
            panic!("expected two operands");
        };
        assert!(!destination.read && destination.write && !destination.conditional);
        assert!(source.read && !source.write && !source.conditional);
        assert_eq!(destination.width_bits, operand_bits);
        assert_eq!(source.width_bits, operand_bits);
        let storing = code.contains(&0xf1);
        assert_eq!(destination.kind == OperandKind::Memory, storing);
        assert_eq!(source.kind == OperandKind::Memory, !storing);
        for length in 0..code.len() {
            assert!(instruction_metadata::decode(bits, 0x1000, &code[..length]).is_err());
        }
    }
}

#[test]
fn movbe_mmio_rejects_crc32_lock_register_only_and_inconsistent_exit() {
    for code in [DWORD_LOAD, DWORD_STORE] {
        for prefix in [0xf0, 0xf2] {
            let mut bytes = vec![prefix];
            bytes.extend_from_slice(code);
            assert!(instruction_metadata::decode(64, 0x1000, &bytes).is_err());
            let (context, mut ram, exit) = fixture(&bytes);
            assert!(prepare(&context, &mut ram, exit).is_err());
        }
        let mut register_only = code.to_vec();
        register_only[code.len() - 1] |= 0xc0;
        assert!(matches!(
            instruction_metadata::decode(64, 0x1000, &register_only),
            Err(instruction_metadata::DecodeFailure::Invalid)
        ));
        let (context, mut ram, mut exit) = fixture(code);
        exit.qualification = if code.contains(&0xf1) { 0x181 } else { 0x182 };
        assert!(prepare(&context, &mut ram, exit).is_err());
    }
}

#[test]
fn movbe_input_descriptor_rejects_byte_mismatched_width_and_high_lane() {
    for (size, bits, shift) in [(1, 8, 0), (2, 32, 0), (4, 32, 8), (4, 64, 0)] {
        let input = Input {
            destination: RegisterPart {
                index: 0,
                bits,
                shift,
            },
            original: 0,
            size,
            extension: Extension::ByteSwap,
            length: 4,
        };
        assert!(mmio::InputState::default().begin(input).is_err());
    }
}
