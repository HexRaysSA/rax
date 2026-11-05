use super::*;

#[path = "../../../../tools/hvf/mmio_rmw_compare.rs"]
mod reference;

fn code(size: u8, group: u8, count: u8) -> Vec<u8> {
    let mut result = match size {
        2 => vec![0x66],
        8 => vec![0x48],
        _ => Vec::new(),
    };
    result.extend_from_slice(&[if size == 1 { 0xc0 } else { 0xc1 }, (group << 3) | 7, count]);
    result
}

fn plan(size: u8, group: u8, count: u8) -> mmio::RmwInput {
    let (mut context, mut memory, mut record) = fixture(&code(size, group, count));
    context.rflags = 0x8d7;
    record.qualification = 0x183;
    let Action::Rmw(input) = prepare(&context, &mut memory, record).unwrap().action else {
        panic!("expected scalar shift transaction")
    };
    input
}

#[test]
fn independent_intel_shift_records_preserve_gprs_neighbors_and_defined_flags() {
    let cases = include_bytes!("../../../fixtures/hvf/mmio-shifts-v1/cases.bin");
    let records = include_bytes!("../../../fixtures/hvf/mmio-shifts-v1/records.bin");
    assert_eq!(reference::compare(cases, records), (12672, 0));
}

#[test]
fn full_turns_and_masked_zero_counts_have_distinct_carry_rules() {
    for (size, group, count, old, expected, flags) in [
        // ROL8/8 updates CF from the result even though the value is unchanged.
        (1, 0, 8, 0x80u64, 0x80u64, 0x8d6),
        // RCL8/9 and RCR16/17 leave all flags unchanged.
        (1, 2, 9, 0x80, 0x80, 0x8d7),
        (2, 3, 17, 0x8000, 0x8000, 0x8d7),
        (2, 1, 16, 0x8001, 0x8001, 0x8d7),
        (4, 4, 32, 0x8000_0001, 0x8000_0001, 0x8d7),
        (
            8,
            7,
            64,
            0x8000_0000_0000_0001,
            0x8000_0000_0000_0001,
            0x8d7,
        ),
    ] {
        let input = plan(size, group, count);
        let bytes = &old.to_le_bytes()[..usize::from(size)];
        let mut changed = bytes.to_vec();
        input.operation.apply(&mut changed).unwrap();
        assert_eq!(changed, expected.to_le_bytes()[..usize::from(size)]);
        assert_eq!(input.completion(bytes).unwrap().1, Some(flags));
    }
}

#[test]
fn shift_counts_and_flags_continue_after_source_free_pending_codec_roundtrips() {
    for size in [1, 2, 4, 8] {
        for group in 0..8 {
            for count in [0, 1, 255] {
                let input = plan(size, group, count);
                let before = &0x8123_4567_89ab_cde0u64.to_le_bytes()[..usize::from(size)];
                let expected = input.completion(before).unwrap();
                let mut pending = mmio::InputState::default();
                pending.begin_rmw(input).unwrap();
                let json = serde_json::to_vec(&pending).unwrap();
                let binary = rax::codec::serialize(&pending).unwrap();
                drop(pending);
                for mut restored in [
                    serde_json::from_slice::<mmio::InputState>(&json).unwrap(),
                    rax::codec::deserialize_strict::<mmio::InputState>(&binary).unwrap(),
                ] {
                    restored.validate_checkpoint().unwrap();
                    let mut host = CompletionHost::default();
                    restored.complete(&mut host, before);
                    assert_eq!(expected.0, None);
                    assert_eq!(host.calls, ["writeflags", "finish"]);
                    assert_eq!((Some(host.flags), host.length), (expected.1, expected.2));
                    assert!(!restored.pending());
                    assert!(restored.ready().is_ok());
                }
            }
        }
    }
}

#[test]
fn shift_admission_rejects_lock_step_wrong_ept_and_truncation_before_effects() {
    for group in 0..8 {
        for size in [1, 2, 4, 8] {
            let code = code(size, group, 1);
            for rejection in 0..5 {
                let mut bytes = code.clone();
                if rejection == 0 {
                    bytes.insert(0, 0xf0);
                } else if rejection == 1 {
                    bytes.pop();
                }
                let (mut context, mut memory, mut record) = fixture(&bytes);
                record.qualification = 0x183;
                match rejection {
                    2 => context.rflags |= 1 << 8,
                    3 => record.qualification = 0x181,
                    4 => record.vectoring_information = 1 << 31,
                    _ => (),
                }
                let before = memory.bytes.clone();
                assert!(prepare(&context, &mut memory, record).is_err());
                assert_eq!(memory.bytes, before);
            }
        }
    }
}

#[test]
fn legacy_and_addr32_shift_plans_use_the_same_validated_effective_address() {
    for bits in [16, 32, 64] {
        let bytes = if bits == 64 {
            &[0x67, 0xd3, 0x27][..]
        } else {
            &[0xd3, 0x27]
        };
        let (mut context, mut memory, mut record) = fixture(bytes);
        context.code_bits = bits;
        context.registers[1] = 0xffff_0000_0000_0001;
        if bits == 16 {
            context.registers[3] = 0;
            context.segments[3] = record.linear;
        } else if bits == 64 {
            context.registers[7] |= 0xffff_1234_0000_0000;
        }
        record.qualification = 0x182;
        let Action::Rmw(input) = prepare(&context, &mut memory, record).unwrap().action else {
            panic!("expected shift")
        };
        let size = if bits == 16 { 2 } else { 4 };
        assert_eq!(input.size, size);
        let mut bytes = 1u64.to_le_bytes()[..usize::from(size)].to_vec();
        input.operation.apply(&mut bytes).unwrap();
        assert_eq!(bytes, 2u64.to_le_bytes()[..usize::from(size)]);
    }
}

#[test]
fn forged_shift_carry_and_completion_failures_remain_fenced_after_checkpoint() {
    let input = plan(8, 2, 1);
    let mut malformed = serde_json::to_value(&input).unwrap();
    malformed["operation"]["Shift"]["carry"] = false.into();
    let malformed: mmio::RmwInput = serde_json::from_value(malformed).unwrap();
    assert!(malformed.validate().is_err());
    for (failure, calls) in [
        ("writeflags", vec!["writeflags"]),
        ("finish", vec!["writeflags", "finish"]),
    ] {
        let mut pending = mmio::InputState::default();
        pending.begin_rmw(input.clone()).unwrap();
        let mut host = CompletionHost {
            fail: Some(failure),
            ..Default::default()
        };
        pending.complete(&mut host, &1u64.to_le_bytes());
        assert_eq!(host.calls, calls);
        let binary = rax::codec::serialize(&pending).unwrap();
        let mut restored: mmio::InputState = rax::codec::deserialize_strict(&binary).unwrap();
        restored.validate_checkpoint().unwrap();
        let mut next = CompletionHost::default();
        restored.complete(&mut next, &1u64.to_le_bytes());
        assert!(next.calls.is_empty());
        assert!(restored.ready().is_err());
        assert!(restored.begin_rmw(input.clone()).is_err());
    }
}
