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
fn adx_device_reads_preserve_the_other_flags_across_pending_restore() {
    use rax::isa::x86_64::flags::bits::{CF, OF};

    for (prefix, flag) in [(0x66, CF), (0xf3, OF)] {
        for width in [4, 8] {
            let mut code = vec![prefix];
            if width == 8 {
                code.push(0x48);
            }
            code.extend([0x0f, 0x38, 0xf6, 0x07]);
            admitted(&code);
            let mask = u64::MAX >> (64 - 8 * width);
            for (dest, source, carry_in, result, carry_out) in [
                (u64::MAX, 0u64, false, mask, false),
                (u64::MAX, 0, true, 0, true),
                (u64::MAX, 1, false, 0, true),
                (
                    0xffff_ffff_0000_0002,
                    3,
                    true,
                    0xffff_ffff_0000_0006 & mask,
                    false,
                ),
            ] {
                let preserved = 0xad7 & !flag;
                let flags = preserved | if carry_in { flag } else { 0 };
                let expected_flags = preserved | if carry_out { flag } else { 0 };
                let input = alu(&code, flags, dest);
                let reply = source.to_le_bytes();
                assert!(input.completion(&reply[..width - 1]).is_err());
                let mut pending = mmio::InputState::default();
                pending.begin_alu_read(input).unwrap();
                let encoded = rax::codec::serialize(&pending).unwrap();
                let mut restored: mmio::InputState =
                    rax::codec::deserialize_strict(&encoded).unwrap();
                restored.validate_checkpoint().unwrap();
                assert_eq!(restored.descriptor(), Some((width as u8, None)));
                let mut host = CompletionHost::default();
                restored.complete(&mut host, &reply[..width]);
                assert_eq!(
                    (host.index, host.value, host.flags),
                    (0, result, expected_flags)
                );
                assert_eq!(host.length, code.len() as u64);
                assert_eq!(host.calls, ["gpr", "writeflags", "finish"]);
                assert!(restored.ready().is_ok());
            }
        }
    }
}

#[test]
fn adx_device_reads_keep_dword_operands_in_legacy_code_modes() {
    for prefix in [0x66, 0xf3] {
        let code = [prefix, 0x0f, 0x38, 0xf6, 0x07];
        for bits in [16, 32] {
            let (mut context, mut memory, record) = fixture(&code);
            context.code_bits = bits;
            if bits == 16 {
                context.registers[3] = 0; // ModR/M 07 addresses [BX].
                context.segments[3] = record.linear;
            }
            let plan = prepare(&context, &mut memory, record).unwrap();
            assert!(matches!(plan.action, Action::AluRead(input) if input.size == 4));
            assert_eq!(plan.length, code.len() as u64);
        }
    }
}

#[test]
fn adx_neighboring_prefixes_and_register_forms_do_not_access_a_device() {
    for code in [
        &[0x0f, 0x38, 0xf6, 0x07][..], // WRSS, without the ADX mandatory prefix.
        &[0xf2, 0x66, 0x0f, 0x38, 0xf6, 0x07],
        &[0xf0, 0x66, 0x0f, 0x38, 0xf6, 0x07],
        &[0xf3, 0x0f, 0x38, 0xf6, 0xc7],
    ] {
        let (context, mut memory, record) = fixture(code);
        assert!(
            prepare(&context, &mut memory, record).is_err(),
            "{code:02x?}"
        );
        assert!(
            memory
                .reads
                .iter()
                .all(|&(address, _)| address != record.physical)
        );
    }
}

#[test]
fn popcnt_replies_preserve_device_width_flags_and_pending_state() {
    let original = 0xfedc_ba98_7654_3210;
    let control = 2 | (1 << 9) | (1 << 10) | (1 << 16);
    let status = 0x8d5;
    for (code, size, count) in [
        (&[0x66, 0xf3, 0x0f, 0xb8, 0x07][..], 2, 2),
        (&[0xf3, 0x0f, 0xb8, 0x07][..], 4, 3),
        (&[0xf3, 0x48, 0x0f, 0xb8, 0x07][..], 8, 5),
    ] {
        admitted(code);
        for (operand, expected_count, expected_status) in
            [(0u64, 0, 0x40), (0x8000_0001_8000_8001, count, 0)]
        {
            let mut pending = mmio::InputState::default();
            pending
                .begin_alu_read(alu(code, control | status, original))
                .unwrap();
            let encoded = rax::codec::serialize(&pending).unwrap();
            let mut restored: mmio::InputState = rax::codec::deserialize_strict(&encoded).unwrap();
            restored.validate_checkpoint().unwrap();
            assert_eq!(restored.descriptor().unwrap().0, size);
            let mut host = CompletionHost::default();
            restored.complete(&mut host, &operand.to_le_bytes()[..usize::from(size)]);
            let expected = (if size == 2 { original & !0xffff } else { 0 }) | expected_count;
            assert_eq!(
                (host.index, host.value, host.flags),
                (0, expected, control | expected_status)
            );
            assert_eq!(host.length, code.len() as u64);
            assert_eq!(host.calls, ["gpr", "writeflags", "finish"]);
            assert!(restored.ready().is_ok());
        }
    }
}

#[test]
fn bit_scan_replies_resume_once_and_leave_the_zero_source_destination_alone() {
    let original = 0xfedc_ba98_7654_3210;
    let status_without_zf = 0x895;
    let control = 2 | (1 << 9) | (1 << 10) | (1 << 16);
    for (opcode, reverse) in [(0xbc, false), (0xbd, true)] {
        for (prefix, size) in [(&[0x66][..], 2), (&[][..], 4), (&[0x48][..], 8)] {
            let code = [prefix, &[0x0f, opcode, 0x07]].concat();
            admitted(&code);
            let top = u32::from(size) * 8 - 1;
            for (operand, bit) in [
                (0, None),
                (1u64 << top, Some(top)),
                ((1u64 << top) | 4, Some(if reverse { top } else { 2 })),
            ] {
                let incoming = control | status_without_zf | if bit.is_some() { 0x40 } else { 0 };
                let mut pending = mmio::InputState::default();
                let input = alu(&code, incoming, original);
                assert!(input.completion(&[0; 8][..usize::from(size - 1)]).is_err());
                pending.begin_alu_read(input).unwrap();
                let encoded = rax::codec::serialize(&pending).unwrap();
                let mut restored: mmio::InputState =
                    rax::codec::deserialize_strict(&encoded).unwrap();
                restored.validate_checkpoint().unwrap();
                assert_eq!(restored.descriptor().unwrap().0, size);

                let mut host = CompletionHost::default();
                restored.complete(&mut host, &operand.to_le_bytes()[..usize::from(size)]);
                if let Some(bit) = bit {
                    let preserved = if size == 2 { original & !0xffff } else { 0 };
                    assert_eq!((host.index, host.value), (0, preserved | u64::from(bit)));
                    assert_eq!(host.calls, ["gpr", "writeflags", "finish"]);
                } else {
                    assert_eq!(host.calls, ["writeflags", "finish"]);
                }
                assert_eq!(host.flags, incoming ^ 0x40);
                assert_eq!(host.length, code.len() as u64);
                assert!(restored.ready().is_ok());
            }
        }
    }
}

#[test]
fn bit_scan_legacy_code_modes_use_the_resolved_operand_size() {
    for (bits, prefix, size) in [
        (16, &[][..], 2),
        (16, &[0x66][..], 4),
        (32, &[][..], 4),
        (32, &[0x66][..], 2),
    ] {
        for opcode in [0xbc, 0xbd] {
            let code = [prefix, &[0x0f, opcode, 0x07]].concat();
            let (mut context, mut memory, record) = fixture(&code);
            context.code_bits = bits;
            if bits == 16 {
                context.registers[3] = 0;
                context.segments[3] = record.linear;
            }
            let plan = prepare(&context, &mut memory, record).unwrap();
            let Action::AluRead(input) = plan.action else {
                panic!("expected scalar read")
            };
            assert_eq!(input.size, size);
            assert_eq!(plan.length, code.len() as u64);
        }
    }
}

#[test]
fn f3_bit_scan_alias_replies_follow_the_native_instruction() {
    const ORIGINAL: u64 = 0xfedc_ba98_7654_3210;
    const ALWAYS_RETAINED: u64 = 2 | 0x894 | (1 << 9) | (1 << 10) | (1 << 16);
    for (tzcnt, lzcnt) in [(false, false), (false, true), (true, false), (true, true)] {
        for (opcode, count, reverse) in [(0xbc, tzcnt, false), (0xbd, lzcnt, true)] {
            for (prefix, size, mode) in [
                (&[][..], 4, 64),
                (&[0x66][..], 2, 64),
                (&[0x48][..], 8, 64),
                (&[][..], 4, 32),
                (&[][..], 2, 16),
            ] {
                let width = u64::from(size) * 8;
                let top = width - 1;
                let high = 1u64 << top;
                let code = [&[0xf3][..], prefix, &[0x0f, opcode, 0x07]].concat();
                let cases = if reverse {
                    [
                        (0, None, width),
                        (1, Some(0), top),
                        (high, Some(top), 0),
                        (high | 4, Some(top), 0),
                    ]
                } else {
                    [
                        (0, None, width),
                        (1, Some(0), 0),
                        (high, Some(top), top),
                        (high | 4, Some(2), 2),
                    ]
                };
                for (source, scan, zeros) in cases {
                    for flags in [0, 0x41] {
                        let (mut context, mut memory, record) = fixture(&code);
                        context.bit_count = mmio::BitCountDecoding { tzcnt, lzcnt };
                        context.code_bits = mode;
                        if mode == 16 {
                            context.registers[3] = 0;
                            context.segments[3] = record.linear;
                        }
                        context.rflags = ALWAYS_RETAINED | flags;
                        context.registers[0] = ORIGINAL;
                        let plan = prepare(&context, &mut memory, record).unwrap();
                        assert_eq!(
                            (plan.physical, plan.length),
                            (record.physical, code.len() as u64)
                        );
                        assert!(
                            memory
                                .reads
                                .iter()
                                .all(|&(address, _)| address != record.physical)
                        );
                        let Action::AluRead(input) = plan.action else {
                            panic!("expected ordinary read");
                        };
                        assert_eq!(input.size, size);
                        assert!(input.completion(&[0; 8][..usize::from(size - 1)]).is_err());
                        let mut pending = mmio::InputState::default();
                        pending.begin_alu_read(input).unwrap();
                        let serialized = rax::codec::serialize(&pending).unwrap();
                        let mut restored: mmio::InputState =
                            rax::codec::deserialize_strict(&serialized).unwrap();
                        restored.validate_checkpoint().unwrap();
                        let mut host = CompletionHost::default();
                        restored.complete(&mut host, &source.to_le_bytes()[..usize::from(size)]);

                        if let Some(value) = if count { Some(zeros) } else { scan } {
                            let preserved = if size == 2 { ORIGINAL & !0xffff } else { 0 };
                            assert_eq!((host.index, host.value), (0, preserved | value));
                            assert_eq!(host.calls, ["gpr", "writeflags", "finish"]);
                        } else {
                            assert_eq!(host.calls, ["writeflags", "finish"]);
                        }
                        let expected_flags = if count {
                            u64::from(source == 0) | (u64::from(zeros == 0) << 6)
                        } else {
                            (flags & 1) | (u64::from(source == 0) << 6)
                        };
                        assert_eq!(host.flags, ALWAYS_RETAINED | expected_flags);
                        assert_eq!(host.length, code.len() as u64);
                        assert!(restored.ready().is_ok());
                    }
                }
            }
        }
    }
}

#[test]
fn bit_scan_and_count_reject_lock_and_inconsistent_exits() {
    for opcode in [0xbc, 0xbd] {
        for (code, qualification) in [
            (&[0xf0, 0x0f, opcode, 0x07][..], 0x181),
            (&[0xf3, 0xf0, 0x0f, opcode, 0x07][..], 0x181),
            (&[0x0f, opcode, 0xc7][..], 0x181),
            (&[0xf3, 0x0f, opcode, 0xc7][..], 0x181),
            (&[0x0f, opcode, 0x07][..], 0x182),
            (&[0xf3, 0x0f, opcode, 0x07][..], 0x182),
        ] {
            let (context, mut memory, mut record) = fixture(code);
            record.qualification = qualification;
            assert!(prepare(&context, &mut memory, record).is_err(), "{code:x?}");
            assert!(
                memory
                    .reads
                    .iter()
                    .all(|&(address, _)| address != record.physical)
            );
        }
    }
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
