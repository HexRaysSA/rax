use super::*;

#[test]
fn captured_legacy_rmw_exit_records_keep_their_binary_and_json_contract() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/hvf/mmio-shifts-v1/legacy-rmw-contexts.json"
    ))
    .unwrap();
    let records = fixture["records"].as_array().unwrap();
    assert_eq!(records.len(), 12);
    assert_eq!(fixture["future_tag12_rejected_by_legacy_reader"], true);
    for record in records {
        let binary: Vec<u8> = serde_json::from_value(record["binary"].clone()).unwrap();
        let from_json: ExitContext = serde_json::from_value(record["json"].clone()).unwrap();
        let from_binary: ExitContext = crate::codec::deserialize_strict(&binary).unwrap();
        for context in [from_json, from_binary] {
            assert_eq!(crate::codec::serialize(&context).unwrap(), binary);
            assert_eq!(serde_json::to_value(&context).unwrap(), record["json"]);
            let exit = context.into_exit().unwrap();
            let VcpuExit::MmioRmw {
                addr,
                size,
                operation,
            } = exit
            else {
                panic!("expected RMW")
            };
            assert_eq!((addr, size), (0xfee0_0000, 8));
            assert_eq!(
                format!("{operation:?}"),
                record["operation"].as_str().unwrap()
            );
        }
    }
}

#[test]
fn all_shift_kinds_counts_and_widths_roundtrip_with_strict_descriptor_admission() {
    for (kind, tag) in [
        (MmioShift::RotateLeft, 12),
        (MmioShift::RotateRight, 13),
        (MmioShift::RotateCarryLeft, 14),
        (MmioShift::RotateCarryRight, 15),
        (MmioShift::Left, 16),
        (MmioShift::LogicalRight, 17),
        (MmioShift::ArithmeticRight, 18),
    ] {
        for size in [1, 2, 4, 8] {
            for count in 0..=u8::MAX {
                for carry in [false, true] {
                    let operation = MmioRmwOp::Shift { kind, count, carry };
                    let context = RmwContext::capture(operation);
                    assert_eq!(
                        (context.kind, context.a, context.b, context.carry),
                        (tag, u64::from(count), 0, carry)
                    );
                    let valid = !carry
                        || matches!(
                            kind,
                            MmioShift::RotateCarryLeft | MmioShift::RotateCarryRight
                        );
                    assert_eq!(operation.validate(size).is_ok(), valid);
                    if valid {
                        let json = serde_json::to_vec(&context).unwrap();
                        let bytes = crate::codec::serialize(&context).unwrap();
                        for decoded in [
                            serde_json::from_slice::<RmwContext>(&json).unwrap(),
                            crate::codec::deserialize_strict::<RmwContext>(&bytes).unwrap(),
                        ] {
                            assert_eq!(decoded.into_op(size).unwrap(), operation);
                        }
                    } else {
                        assert!(context.into_op(size).is_err());
                    }
                }
            }
            for a in [256, u64::MAX] {
                assert!(
                    RmwContext {
                        kind: tag,
                        a,
                        b: 0,
                        carry: false
                    }
                    .into_op(size)
                    .is_err()
                );
            }
            assert!(
                RmwContext {
                    kind: tag,
                    a: 1,
                    b: 1,
                    carry: false
                }
                .into_op(size)
                .is_err()
            );
        }
        for size in [0, 3, 16, u8::MAX] {
            assert!(
                RmwContext {
                    kind: tag,
                    a: 1,
                    b: 0,
                    carry: false
                }
                .into_op(size)
                .is_err()
            );
        }
    }
    for kind in [19, u8::MAX] {
        assert!(
            RmwContext {
                kind,
                a: 0,
                b: 0,
                carry: false
            }
            .into_op(8)
            .is_err()
        );
    }
}
