use super::*;

#[path = "../../../../tools/hvf/mmio_rmw_compare.rs"]
mod reference;

fn code(size: u8, source: u8, cl: bool, count: u8, right: bool) -> Vec<u8> {
    let mut bytes = if size == 2 { vec![0x66] } else { Vec::new() };
    let rex = (if size == 8 { 8 } else { 0 }) | (if source >= 8 { 4 } else { 0 });
    if rex != 0 {
        bytes.push(0x40 | rex);
    }
    bytes.extend_from_slice(&[
        0x0f,
        (if right { 0xac } else { 0xa4 }) + u8::from(cl),
        ((source & 7) << 3) | 7,
    ]);
    if !cl {
        bytes.push(count);
    }
    bytes
}

fn plan(size: u8, source: u8, cl: bool, count: u8, right: bool) -> mmio::RmwInput {
    let (mut context, mut memory, mut record) = fixture(&code(size, source, cl, count, right));
    context.registers[usize::from(source)] = 0x39c6_5aa5_f00f_c33c;
    if cl {
        context.registers[1] = (context.registers[1] & !255) | u64::from(count);
    }
    context.rflags = 0x8d7;
    record.qualification = 0x183;
    let Action::Rmw(input) = prepare(&context, &mut memory, record).unwrap().action else {
        panic!("expected double-shift transaction")
    };
    input
}

#[test]
fn independent_double_shift_records_preserve_gprs_neighbors_and_defined_flags() {
    let cases = include_bytes!("../../../fixtures/hvf/mmio-double-shifts-v1/cases.bin");
    let records = include_bytes!("../../../fixtures/hvf/mmio-double-shifts-v1/records.bin");
    assert_eq!(reference::compare(cases, records), (25344, 0));
}

#[test]
fn double_shift_counts_and_captured_sources_survive_pending_codec_roundtrips() {
    for size in [2, 4, 8] {
        for source in [0, 1, 8, 15] {
            for cl in [false, true] {
                for right in [false, true] {
                    for count in [0, 1, size * 8, size * 8 + 1, 255] {
                        let input = plan(size, source, cl, count, right);
                        let old = &0x8123_4567_89ab_cde0u64.to_le_bytes()[..usize::from(size)];
                        let expected = input.completion(old).unwrap();
                        assert_eq!(expected.0, None);
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
                            restored.complete(&mut host, old);
                            assert_eq!(host.calls, ["writeflags", "finish"]);
                            assert_eq!((Some(host.flags), host.length), (expected.1, expected.2));
                            assert!(!restored.pending());
                            assert!(restored.ready().is_ok());
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn double_shift_zero_masks_and_undefined_word_counts_retain_selected_state() {
    for size in [2, 4, 8] {
        for right in [false, true] {
            for count in 0..=255u8 {
                let effective = count & if size == 8 { 63 } else { 31 };
                if effective != 0 && effective <= size * 8 {
                    continue;
                }
                let input = plan(size, 8, false, count, right);
                let before = &0x8123_4567_89ab_cde0u64.to_le_bytes()[..usize::from(size)];
                let mut after = before.to_vec();
                input.operation.apply(&mut after).unwrap();
                assert_eq!(after, before);
                assert_eq!(
                    input.completion(before).unwrap(),
                    (None, Some(0x8d7), 5 + u64::from(size == 2))
                );
            }
        }
    }
}

#[test]
fn double_shift_admission_rejects_lock_wrong_ept_and_truncation_before_effects() {
    for size in [2, 4, 8] {
        for right in [false, true] {
            for cl in [false, true] {
                for rejection in 0..4 {
                    let mut bytes = code(size, 8, cl, 1, right);
                    if rejection == 0 {
                        bytes.insert(0, 0xf0);
                    } else if rejection == 1 {
                        bytes.pop();
                    }
                    let (context, mut memory, mut record) = fixture(&bytes);
                    record.qualification = 0x183;
                    match rejection {
                        2 => record.qualification = 0x181,
                        3 => record.vectoring_information = 1 << 31,
                        _ => (),
                    }
                    let before = memory.bytes.clone();
                    assert!(prepare(&context, &mut memory, record).is_err());
                    assert_eq!(memory.bytes, before);
                }
            }
        }
    }
}

#[test]
fn double_shift_invalid_descriptors_and_publication_errors_cannot_resume() {
    let input = plan(8, 8, true, 1, false);
    for field in ["size", "flags", "register"] {
        let mut bad = serde_json::to_value(&input).unwrap();
        bad[field] = match field {
            "size" => 1.into(),
            "flags" => "Shift".into(),
            _ => serde_json::json!([{"index":0,"bits":64,"shift":0},0]),
        };
        let bad: mmio::RmwInput = serde_json::from_value(bad).unwrap();
        assert!(bad.validate().is_err());
    }
    for failure in ["writeflags", "finish"] {
        let mut pending = mmio::InputState::default();
        pending.begin_rmw(input.clone()).unwrap();
        let mut host = CompletionHost {
            fail: Some(failure),
            ..Default::default()
        };
        pending.complete(&mut host, &1u64.to_le_bytes());
        let binary = rax::codec::serialize(&pending).unwrap();
        let mut restored: mmio::InputState = rax::codec::deserialize_strict(&binary).unwrap();
        restored.validate_checkpoint().unwrap();
        let mut next = CompletionHost::default();
        restored.complete(&mut next, &1u64.to_le_bytes());
        assert!(next.calls.is_empty());
        assert!(restored.ready().is_err());
    }
}

#[test]
fn double_shift_operations_append_wire_tags_and_reject_byte_widths_without_writes() {
    use rax::devices::bus::{MmioRmwOp as Op, MmioShift};
    let variants = [
        Op::Exchange(1),
        Op::CompareExchange {
            expected: 1,
            replacement: 2,
        },
        Op::Add {
            value: 1,
            carry: false,
        },
        Op::Subtract {
            value: 1,
            borrow: false,
        },
        Op::And(1),
        Op::Or(1),
        Op::Xor(1),
        Op::Not,
        Op::Negate,
        Op::BitSet(0),
        Op::BitReset(0),
        Op::BitComplement(0),
        Op::Shift {
            kind: MmioShift::Left,
            count: 1,
            carry: false,
        },
        Op::DoubleShiftLeft {
            source: 1,
            count: 1,
        },
        Op::DoubleShiftRight {
            source: 1,
            count: 1,
        },
    ];
    for (tag, operation) in variants.into_iter().enumerate() {
        let bytes = rax::codec::serialize(&operation).unwrap();
        assert_eq!(&bytes[..4], &(tag as u32).to_le_bytes());
        assert_eq!(
            rax::codec::deserialize_strict::<Op>(&bytes).unwrap(),
            operation
        );
        if tag >= 13 {
            let mut rejected = [0xa5];
            assert!(operation.apply(&mut rejected).is_err());
            assert_eq!(rejected, [0xa5]);
        }
    }
}
