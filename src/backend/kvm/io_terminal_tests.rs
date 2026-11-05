use super::*;

fn round_trip(state: &State) {
    let image = state.capture_terminal().unwrap().unwrap();
    let json = serde_json::to_vec(&image).unwrap();
    let binary = crate::codec::serialize(&image).unwrap();
    for image in [
        serde_json::from_slice::<Image>(&json).unwrap(),
        crate::codec::deserialize_strict::<Image>(&binary).unwrap(),
    ] {
        let restored = image.restore().unwrap();
        assert_eq!(&restored, state);
        assert_eq!(restored.event().unwrap(), state.event().unwrap());
        assert_eq!(restored.input_reply().ok(), state.input_reply().ok());
    }
}

#[test]
fn terminal_port_records_keep_unreplied_inputs_replies_and_every_selected_output_prefix() {
    for size in [1, 2, 4] {
        for count in [1, 3, 1024] {
            let bytes = usize::from(size) * count as usize;
            let payload: Vec<_> = (0..bytes).map(|index| index as u8).collect();
            let mut input = State::default();
            input
                .begin_input(
                    Input::Port {
                        port: 0xffff,
                        size,
                        count,
                    },
                    bytes,
                )
                .unwrap();
            round_trip(&input);
            input.complete_input(&payload);
            round_trip(&input);
            let mut output = State::default();
            output
                .begin_output(
                    Output::Port {
                        port: 0x604,
                        size,
                        count,
                        bytes: payload,
                    },
                    bytes,
                )
                .unwrap();
            for completed in 0..=count {
                if completed <= 3 || completed == count / 2 || completed == count {
                    round_trip(&output);
                }
                if completed != count {
                    output.acknowledge_output().unwrap();
                }
            }
        }
    }
}

#[test]
fn terminal_mmio_records_preserve_all_native_lengths_and_unserviced_effects() {
    for size in 1..=8 {
        let mut input = State::default();
        input
            .begin_input(
                Input::Mmio {
                    address: 0xfee0_1000,
                    size,
                },
                usize::from(size),
            )
            .unwrap();
        round_trip(&input);
        input.complete_input(&vec![0xa5; usize::from(size)]);
        round_trip(&input);
        let mut output = State::default();
        output
            .begin_output(
                Output::Mmio {
                    address: 0xfee0_1000,
                    bytes: vec![0x5a; usize::from(size)],
                },
                usize::from(size),
            )
            .unwrap();
        round_trip(&output);
        output.acknowledge_output().unwrap();
        round_trip(&output);
    }
    assert!(State::default().capture_terminal().unwrap().is_none());
    let mut failed = State::default();
    failed.complete_input(&[0]);
    assert!(failed.capture_terminal().is_err());
}

#[test]
fn terminal_records_reject_noncanonical_metadata_and_oversized_payloads() {
    let mut state = State::default();
    state
        .begin_output(
            Output::Port {
                port: 0x604,
                size: 2,
                count: 3,
                bytes: vec![1, 2, 3, 4, 5, 6],
            },
            6,
        )
        .unwrap();
    state.acknowledge_output().unwrap();
    let valid = state.capture_terminal().unwrap().unwrap();
    let mut invalid_records = Vec::new();
    for (field, value) in [
        ("version", 0),
        ("kind", 4),
        ("size", 0),
        ("size", 3),
        ("count", 0),
        ("count", u32::MAX),
        ("acknowledged", 1),
        ("acknowledged", 8),
        ("address", 1),
    ] {
        let mut record = serde_json::to_value(&valid).unwrap();
        record[field] = value.into();
        invalid_records.push(serde_json::from_value::<Image>(record).unwrap());
    }
    let mut replied_output = valid.clone();
    replied_output.replied = true;
    invalid_records.push(replied_output);
    let mut short_output = valid.clone();
    short_output.data.pop();
    invalid_records.push(short_output);
    let mut wrong_input = valid.clone();
    wrong_input.kind = 0;
    wrong_input.acknowledged = 0;
    invalid_records.push(wrong_input);
    for record in invalid_records {
        assert!(record.restore().is_err(), "{record:?}");
        assert_eq!(state.capture_terminal().unwrap().unwrap(), valid);
    }
    let mut oversized = valid;
    oversized.data = vec![0; MAX_BYTES + 1];
    assert!(serde_json::from_slice::<Image>(&serde_json::to_vec(&oversized).unwrap()).is_err());
    assert!(
        crate::codec::deserialize_strict::<Image>(&crate::codec::serialize(&oversized).unwrap())
            .is_err()
    );
}

#[test]
fn terminal_byte_bound_accepts_the_exact_limit_and_checks_mmio_and_input_canonical_fields() {
    let mut output = State::default();
    output
        .begin_output(
            Output::Port {
                port: 0xffff,
                size: 4,
                count: (MAX_BYTES / 4) as u32,
                bytes: vec![0xa5; MAX_BYTES],
            },
            MAX_BYTES,
        )
        .unwrap();
    round_trip(&output);
    let mut input = State::default();
    input
        .begin_input(
            Input::Port {
                port: 1,
                size: 1,
                count: MAX_BYTES as u32,
            },
            MAX_BYTES,
        )
        .unwrap();
    round_trip(&input);
    input.complete_input(&vec![0x5a; MAX_BYTES]);
    round_trip(&input);
    let mut mmio = State::default();
    mmio.begin_input(
        Input::Mmio {
            address: 0xf000_0000,
            size: 8,
        },
        8,
    )
    .unwrap();
    mmio.complete_input(&[0x7c; 8]);
    let valid = mmio.capture_terminal().unwrap().unwrap();
    let mut short = valid.clone();
    short.data.pop();
    assert!(short.restore().is_err());
    for (field, value) in [
        ("port", 1),
        ("count", 2),
        ("size", 0),
        ("size", 9),
        ("acknowledged", 8),
    ] {
        let mut record = serde_json::to_value(&valid).unwrap();
        record[field] = value.into();
        assert!(
            serde_json::from_value::<Image>(record)
                .unwrap()
                .restore()
                .is_err()
        );
    }
}
