//! Integer ALU operands fetched from a device require ordinary reads, not RMW.
use super::*;

const ALU: &[(&str, u8)] = &[
    ("add", 0x03),
    ("adc", 0x13),
    ("sub", 0x2b),
    ("sbb", 0x1b),
    ("and", 0x23),
    ("or", 0x0b),
    ("xor", 0x33),
    ("cmp", 0x3b),
    ("test", 0x85),
];

fn encoding(opcode: u8, size: u8, modrm: u8) -> Vec<u8> {
    let mut code = match size {
        2 => vec![0x66],
        8 => vec![0x48],
        _ => vec![],
    };
    code.extend_from_slice(&[opcode - u8::from(size == 1), modrm]);
    code
}

fn admitted(code: &[u8]) {
    let (context, mut memory, record) = fixture(code);
    let before = memory.bytes.clone();
    let plan = prepare(&context, &mut memory, record).unwrap();
    assert_eq!(plan.physical, record.physical);
    assert_eq!(plan.length, code.len() as u64);
    assert_eq!(memory.bytes, before);
    assert!(
        !memory
            .reads
            .iter()
            .any(|&(address, _)| address == record.physical)
    );
}

#[test]
fn device_read_alu_families_admit_all_scalar_widths_before_any_device_access() {
    for &(_, opcode) in ALU {
        for size in [1, 2, 4, 8] {
            admitted(&encoding(opcode, size, 0x07));
        }
    }
}

#[test]
fn compare_and_test_memory_left_register_forms_remain_read_only() {
    for opcode in [0x39, 0x85] {
        for size in [1, 2, 4, 8] {
            admitted(&encoding(opcode, size, 0x0f));
        }
    }
}

#[test]
fn immediate_compare_and_test_admit_short_and_full_signed_encodings() {
    for code in [
        &[0x80, 0x3f, 0xff][..],
        &[0x66, 0x83, 0x3f, 0xff],
        &[0x83, 0x3f, 0xff],
        &[0x48, 0x83, 0x3f, 0xff],
        &[0xf6, 0x07, 0x80],
        &[0x66, 0xf7, 0x07, 0x00, 0x80],
        &[0xf7, 0x07, 0x00, 0x00, 0x00, 0x80],
        &[0x48, 0xf7, 0x07, 0xff, 0xff, 0xff, 0xff],
    ] {
        admitted(code);
    }
}

#[test]
fn legacy_and_compatibility_code_modes_admit_device_read_alu_operations() {
    for bits in [16, 32] {
        for &(_, opcode) in ALU {
            let code = [opcode, 0x07];
            let (mut context, mut memory, record) = fixture(&code);
            context.code_bits = bits;
            if bits == 16 {
                context.registers[3] = 0;
                context.segments[3] = record.linear;
            }
            assert_eq!(prepare(&context, &mut memory, record).unwrap().length, 2);
        }
    }
}

#[test]
fn read_alu_rejects_write_qualifications_before_device_access() {
    for qualification in [0x182, 0x183] {
        let (context, mut memory, mut record) = fixture(&[0x03, 0x07]);
        record.qualification = qualification;
        assert!(prepare(&context, &mut memory, record).is_err());
        assert!(
            !memory
                .reads
                .iter()
                .any(|&(address, _)| address == record.physical)
        );
    }
}

fn alu(code: &[u8], flags: u64, register: u64) -> mmio::AluReadInput {
    let (mut context, mut memory, record) = fixture(code);
    context.rflags = flags;
    context.registers[0] = register;
    let Action::AluRead(input) = prepare(&context, &mut memory, record).unwrap().action else {
        panic!()
    };
    input
}

#[test]
fn compare_orders_and_immediates_update_only_the_defined_flags() {
    let control = 2 | (1 << 9) | (1 << 10) | (1 << 16);
    for (opcode, expected) in [(0x39, 0x95), (0x3b, 0)] {
        let input = alu(&[opcode, 0x07], control, 2);
        let (register, flags, length) = input.completion(&1u32.to_le_bytes()).unwrap();
        assert_eq!(register, None);
        assert_eq!(length, 2);
        let flags = flags.unwrap();
        assert_eq!(flags & 0x8d5, expected);
        assert_eq!(flags & !0x8d5, control);
    }
    for code in [
        &[0x80, 0x3f, 0xff][..],
        &[0x66, 0x83, 0x3f, 0xff],
        &[0x83, 0x3f, 0xff],
        &[0x48, 0x83, 0x3f, 0xff],
    ] {
        let input = alu(code, control, 0);
        let (register, flags, _) = input
            .completion(&vec![0xff; usize::from(input.size)])
            .unwrap();
        assert_eq!(register, None);
        assert_eq!(flags.unwrap() & 0x8d5, 0x44);
    }
    let input = alu(&[0x48, 0xf7, 0x07, 0, 0, 0, 0x80], control, 0);
    let (register, flags, _) = input
        .completion(&0x8000000000000000u64.to_le_bytes())
        .unwrap();
    assert_eq!(register, None);
    assert_eq!(flags.unwrap() & 0x8c5, 0x84); // TEST imm32 sign extends; AF undefined.
}

#[test]
fn captured_carry_and_partial_registers_survive_delayed_reply() {
    for (code, original, data, expected, arithmetic) in [
        (
            &[0x13, 0x07][..],
            0xfeedcafeffffffff,
            &[0, 0, 0, 0][..],
            0,
            0x55,
        ),
        (
            &[0x12, 0x27][..],
            0x112233445566ff88,
            &[1][..],
            0x1122334455660188,
            0x11,
        ),
    ] {
        let input = alu(code, 3, original);
        let mut pending = mmio::InputState::default();
        pending.begin_alu_read(input).unwrap();
        let mut host = CompletionHost::default(); // Current host flags do not supply carry.
        pending.complete(&mut host, data);
        assert_eq!(host.calls, ["gpr", "writeflags", "finish"]);
        assert_eq!((host.index, host.value), (0, expected));
        assert_eq!(host.flags & 0x8d5, arithmetic);
        assert!(pending.ready().is_ok());
    }
}

#[test]
fn qword_signed_overflow_boundaries_preserve_nonarithmetic_flags() {
    let control = 2 | (1 << 9) | (1 << 10) | (1 << 16);
    for (opcode, original, result, arithmetic) in [
        (0x03, 0x7fffffffffffffffu64, 0x8000000000000000, 0x894),
        (0x2b, 0x8000000000000000, 0x7fffffffffffffff, 0x814),
    ] {
        let input = alu(&[0x48, opcode, 0x07], control, original);
        let (register, flags, _) = input.completion(&1u64.to_le_bytes()).unwrap();
        assert_eq!(register, Some((0, result)));
        let flags = flags.unwrap();
        assert_eq!(flags & 0x8d5, arithmetic);
        assert_eq!(flags & !0x8d5, control);
    }
}

#[test]
fn flags_only_completion_skips_gprs_and_publishes_once() {
    let input = alu(&[0x39, 0x07], 2, 2);
    let mut pending = mmio::InputState::default();
    pending.begin_alu_read(input.clone()).unwrap();
    assert!(pending.begin(super::pending()).is_err());
    let mut host = CompletionHost::default();
    pending.complete(&mut host, &1u32.to_le_bytes());
    assert_eq!(host.calls, ["writeflags", "finish"]);
    assert!(pending.ready().is_ok());
    pending.complete(&mut host, &1u32.to_le_bytes());
    assert_eq!(host.calls, ["writeflags", "finish"]);
    assert!(pending.ready().is_err());
}

#[test]
fn alu_reply_width_and_every_publication_failure_stop_before_another_commit() {
    for (code, cases) in [
        (
            &[0x03, 0x07][..],
            vec![
                ("gpr", vec!["gpr"]),
                ("writeflags", vec!["gpr", "writeflags"]),
                ("finish", vec!["gpr", "writeflags", "finish"]),
            ],
        ),
        (
            &[0x39, 0x07][..],
            vec![
                ("writeflags", vec!["writeflags"]),
                ("finish", vec!["writeflags", "finish"]),
            ],
        ),
    ] {
        let input = alu(code, 2, 2);
        for (failure, calls) in cases {
            let mut pending = mmio::InputState::default();
            pending.begin_alu_read(input.clone()).unwrap();
            let mut host = CompletionHost {
                fail: Some(failure),
                ..Default::default()
            };
            pending.complete(&mut host, &1u32.to_le_bytes());
            assert_eq!(host.calls, calls);
            assert!(pending.ready().is_err());
            pending.complete(&mut host, &1u32.to_le_bytes());
            assert_eq!(host.calls, calls);
        }
        for reply in [&[][..], &[1, 2][..], &[0; 8][..]] {
            let mut pending = mmio::InputState::default();
            pending.begin_alu_read(input.clone()).unwrap();
            let mut host = CompletionHost::default();
            pending.complete(&mut host, reply);
            assert!(host.calls.is_empty());
            assert!(pending.ready().is_err());
        }
    }
}

#[path = "../../../../tools/hvf/mmio_alu_compare.rs"]
mod oracle;

#[test]
fn independent_alu_guest_records_match_complete_product_publication() {
    let (count, mismatches) = oracle::compare(
        include_bytes!("../../../fixtures/hvf/mmio-alu-read-v1/cases.bin"),
        include_bytes!("../../../fixtures/hvf/mmio-alu-read-v1/records.bin"),
    );
    assert_eq!(count, 5768);
    assert_eq!(mismatches, 0);
}
