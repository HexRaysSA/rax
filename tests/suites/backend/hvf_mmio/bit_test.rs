//! BT reads a signed memory bit string and publishes CF without a device write.
use super::*;

#[path = "../../../../tools/hvf/mmio_bt_compare.rs"]
mod reference;

#[test]
fn physical_intel_bit_test_records_match_read_planning_and_completion() {
    assert_eq!(
        reference::compare(
            include_bytes!("../../../fixtures/hvf/mmio-bit-test-v1/cases.bin"),
            include_bytes!("../../../fixtures/hvf/mmio-bit-test-v1/records.bin"),
        ),
        (2808, 0)
    );
}

fn encoding(size: u8, immediate: Option<u8>, source: usize) -> Vec<u8> {
    let mut code = if size == 2 { vec![0x66] } else { vec![] };
    let rex = u8::from(size == 8) * 8 | u8::from(source >= 8) * 4;
    if rex != 0 {
        code.push(0x40 | rex);
    }
    if let Some(bit) = immediate {
        code.extend_from_slice(&[0x0f, 0xba, 0x27, bit]);
    } else {
        code.extend_from_slice(&[0x0f, 0xa3, ((source as u8 & 7) << 3) | 7]);
    }
    code
}

fn input(size: u8, immediate: Option<u8>, offset: i64, flags: u64) -> mmio::AluReadInput {
    let code = encoding(size, immediate, 0);
    let (mut context, mut memory, mut record) = fixture(&code);
    context.registers[0] = offset as u64;
    context.rflags = flags;
    if immediate.is_none() {
        record.linear = record
            .linear
            .wrapping_add((offset.div_euclid(i64::from(size) * 8) * i64::from(size)) as u64);
        record.physical = record.linear;
    }
    let Action::AluRead(input) = prepare(&context, &mut memory, record).unwrap().action else {
        panic!("BT must use an ordinary device read")
    };
    assert!(
        !memory
            .reads
            .iter()
            .any(|&(address, _)| address == record.physical)
    );
    input
}

#[test]
fn signed_register_bit_strings_select_the_correct_word_before_device_access() {
    for size in [2, 4, 8] {
        let bits = i64::from(size) * 8;
        let (minimum, maximum) = match size {
            2 => (i64::from(i16::MIN), i64::from(i16::MAX)),
            4 => (i64::from(i32::MIN), i64::from(i32::MAX)),
            _ => (-1024, 1024), // Keep the target within canonical fixture memory.
        };
        for offset in [
            minimum,
            -bits - 1,
            -bits,
            -1,
            0,
            1,
            bits - 1,
            bits,
            bits + 1,
            maximum,
        ] {
            for source in [0, 1, 4, 8, 15] {
                let (mut context, mut memory, mut record) = fixture(&encoding(size, None, source));
                context.registers[source] = offset as u64;
                record.linear = record
                    .linear
                    .wrapping_add((offset.div_euclid(bits) * i64::from(size)) as u64);
                record.physical = record.linear;
                let before = memory.bytes.clone();
                let plan = prepare(&context, &mut memory, record).unwrap();
                assert_eq!(plan.physical, record.physical);
                assert_eq!(memory.bytes, before);
                assert!(matches!(plan.action, Action::AluRead(_)));
                assert!(
                    !memory
                        .reads
                        .iter()
                        .any(|&(address, _)| address == record.physical)
                );
            }
        }
    }
}

#[test]
fn every_immediate_byte_selects_a_bit_without_adjusting_the_base_address() {
    for size in [2, 4, 8] {
        for immediate in 0..=255 {
            let input = input(size, Some(immediate), i64::MIN, 0x8d7);
            let bit = immediate & (size * 8 - 1);
            for memory in [0, 1u64 << bit] {
                let bytes = memory.to_le_bytes();
                let (register, flags, _) = input.completion(&bytes[..usize::from(size)]).unwrap();
                assert_eq!(register, None);
                assert_eq!(flags, Some((0x8d7 & !1) | u64::from(memory != 0)));
            }
        }
    }
}

#[test]
fn source_free_pending_bit_tests_preserve_zero_flag_and_complete_only_once() {
    for size in [2, 4, 8] {
        for offset in [-1, 0, i64::from(size) * 8] {
            for flags in [2, 0x8d7] {
                let mut pending = mmio::InputState::default();
                pending
                    .begin_alu_read(input(size, None, offset, flags))
                    .unwrap();
                let json = serde_json::to_vec(&pending).unwrap();
                let binary = rax::codec::serialize(&pending).unwrap();
                drop(pending);
                for mut restored in [
                    serde_json::from_slice::<mmio::InputState>(&json).unwrap(),
                    rax::codec::deserialize_strict::<mmio::InputState>(&binary).unwrap(),
                ] {
                    restored.validate_checkpoint().unwrap();
                    assert_eq!(restored.descriptor(), Some((size, None)));
                    let mut host = CompletionHost::default();
                    restored.complete(&mut host, &vec![0xff; usize::from(size)]);
                    assert_eq!(host.calls, ["writeflags", "finish"]);
                    assert_eq!(host.flags, flags | 1);
                    assert!(restored.ready().is_ok());
                    restored.complete(&mut host, &vec![0; usize::from(size)]);
                    assert_eq!(host.calls, ["writeflags", "finish"]);
                    assert!(restored.ready().is_err());
                }
            }
        }
    }
}

#[test]
fn legacy_code_modes_admit_read_only_bit_tests() {
    for (bits, code, size) in [
        (16, &[0x0f, 0xa3, 0x07][..], 2),
        (16, &[0x66, 0x0f, 0xa3, 0x07][..], 4),
        (32, &[0x0f, 0xa3, 0x07][..], 4),
        (32, &[0x66, 0x0f, 0xa3, 0x07][..], 2),
    ] {
        let (mut context, mut memory, record) = fixture(code);
        context.code_bits = bits;
        context.registers[0] = 0;
        if bits == 16 {
            context.registers[3] = 0;
            context.segments[3] = record.linear;
        }
        let Action::AluRead(input) = prepare(&context, &mut memory, record).unwrap().action else {
            panic!("BT read")
        };
        assert_eq!(input.size, size);
    }
}

#[test]
fn bit_string_addressing_handles_base_aliasing_and_address_size_wrap() {
    for size in [2, 4, 8] {
        let (mut context, mut memory, mut record) = fixture(&encoding(size, None, 7));
        context.registers[7] = 0x1000;
        // The original base is also the bit index: 4096 bits = 512 bytes.
        record.linear = 0x1200;
        record.physical = 0x1200;
        assert_eq!(
            prepare(&context, &mut memory, record).unwrap().physical,
            0x1200
        );
    }
    for (code, address) in [
        (&[0x67, 0x0f, 0xa3, 0x07][..], 0xffff_fffc),
        (&[0x67, 0x48, 0x0f, 0xa3, 0x07][..], 0xffff_fff8),
    ] {
        let (mut context, mut memory, mut record) = fixture(code);
        context.registers[0] = u64::MAX;
        context.registers[7] = 0x1_0000_0000;
        record.linear = address;
        record.physical = address;
        assert_eq!(
            prepare(&context, &mut memory, record).unwrap().physical,
            address
        );
    }
}

#[test]
fn invalid_bit_test_records_reject_before_device_effects() {
    for size in [2, 4, 8] {
        for rejection in 0..6 {
            let mut code = encoding(size, Some(1), 0);
            if rejection == 0 {
                code.insert(0, 0xf0);
            }
            if rejection == 5 {
                code.pop();
            }
            let (context, mut memory, mut record) = fixture(&code);
            match rejection {
                1 => record.qualification = 0x182,
                2 => record.qualification = 0x183,
                3 => record.linear += 1,
                4 => memory.bytes(record.physical, &[0; 8]),
                _ => (),
            }
            assert!(prepare(&context, &mut memory, record).is_err());
            assert!(
                !memory
                    .reads
                    .iter()
                    .any(|&(address, _)| address == record.physical)
            );
        }
    }
}

#[test]
fn malformed_pending_bit_tests_reject_before_register_publication() {
    let mut pending = mmio::InputState::default();
    pending
        .begin_alu_read(input(2, Some(15), 0, 0x8d7))
        .unwrap();
    let json = serde_json::to_value(&pending).unwrap();
    for corruption in 0..5 {
        let mut malformed = json.clone();
        let descriptor = &mut malformed["pending"]["AluRead"];
        match corruption {
            0 => descriptor["operation"]["BitTest"] = 16.into(),
            1 => descriptor["size"] = 1.into(),
            2 => descriptor["memory_left"] = false.into(),
            3 => descriptor["other"] = 1.into(),
            _ => descriptor["length"] = 0.into(),
        }
        let mut restored: mmio::InputState = serde_json::from_value(malformed).unwrap();
        assert!(restored.validate_checkpoint().is_err());
        let mut host = CompletionHost::default();
        restored.complete(&mut host, &[0xff; 2]);
        assert!(host.calls.is_empty());
        assert!(restored.ready().is_err());
    }
}
