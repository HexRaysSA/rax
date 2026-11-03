use super::*;

#[test]
fn native_rep_input_retains_element_width_count_and_exact_reply() {
    for size in [1u8, 2, 4] {
        for count in [1u32, 255, 256, 1024] {
            let request = Input::Port {
                port: 0x70,
                size,
                count,
            };
            let length = usize::from(size) * count as usize;
            let mut state = State::default();
            state.begin_input(request.clone(), length).unwrap();
            let event = Some(Event::Input(request));
            assert_eq!(state.event().unwrap(), event);
            assert!(state.ready_for_native_completion().is_err());
            let before = state.clone();
            assert_eq!(state.event().unwrap(), event);
            assert_eq!(state, before);
            let mut reply = (0..length).map(|i| i as u8).collect::<Vec<_>>();
            let expected = reply.clone();
            state.complete_input(&reply);
            reply.fill(0);
            assert_eq!(state.event().unwrap(), None);
            assert_eq!(state.input_reply().unwrap(), Some(expected.as_slice()));
            assert!(state.has_native_completion());
            state.finish_native_completion().unwrap();
            assert!(!state.has_native_completion());
            assert_eq!(state.input_reply().unwrap(), None);
        }
    }
}

#[test]
fn short_and_long_input_replies_poison_without_dropping_the_request() {
    for length in [0, 1, 511, 513, 1024] {
        let mut state = State::default();
        state
            .begin_input(
                Input::Port {
                    port: 0x70,
                    size: 2,
                    count: 256,
                },
                512,
            )
            .unwrap();
        let original = state.pending.clone();
        state.complete_input(&vec![0xa5; length]);
        assert_eq!(state.pending, original);
        assert!(state.failure.is_some());
        assert!(state.event().is_err());
        assert!(state.finish_native_completion().is_err());
        let failed = state.clone();
        state.complete_input(&[0x5a; 512]);
        assert_eq!(state, failed);
    }
}

#[test]
fn duplicate_input_completion_retains_the_first_complete_reply() {
    let mut state = State::default();
    state
        .begin_input(
            Input::Mmio {
                address: 0xfee00000,
                size: 8,
            },
            8,
        )
        .unwrap();
    state.complete_input(&[0x5a; 8]);
    let original = state.pending.clone();
    state.complete_input(&[0xa5; 8]);
    assert_eq!(state.pending, original);
    assert!(state.ready_for_native_completion().is_err());
}

#[test]
fn output_elements_keep_the_port_width_and_unacknowledged_payload() {
    for size in [1u8, 2, 4] {
        let bytes = (0..usize::from(size) * 256)
            .map(|i| i as u8)
            .collect::<Vec<_>>();
        let mut state = State::default();
        state
            .begin_output(
                Output::Port {
                    port: 0x3f8,
                    size,
                    count: 256,
                    bytes: bytes.clone(),
                },
                bytes.len(),
            )
            .unwrap();
        for element in bytes.chunks_exact(usize::from(size)) {
            let event = Some(Event::PortOutput {
                port: 0x3f8,
                bytes: element.to_vec(),
            });
            assert_eq!(state.event().unwrap(), event);
            let before = state.clone();
            assert_eq!(state.event().unwrap(), event);
            assert_eq!(state, before);
            assert!(state.ready_for_native_completion().is_err());
            state.acknowledge_output().unwrap();
        }
        assert_eq!(state.event().unwrap(), None);
        assert!(state.has_native_completion());
        state.finish_native_completion().unwrap();
        assert_eq!(state, State::default());
    }
}

#[test]
fn retained_partial_output_progress_resumes_at_the_next_unacknowledged_element() {
    let mut original = State::default();
    original
        .begin_output(
            Output::Port {
                port: 0x70,
                size: 2,
                count: 3,
                bytes: vec![1, 2, 3, 4, 5, 6],
            },
            6,
        )
        .unwrap();
    original.acknowledge_output().unwrap();
    let mut resumed = original.clone();
    for expected in [vec![3, 4], vec![5, 6]] {
        for state in [&mut original, &mut resumed] {
            assert_eq!(
                state.event().unwrap(),
                Some(Event::PortOutput {
                    port: 0x70,
                    bytes: expected.clone()
                })
            );
            state.acknowledge_output().unwrap();
        }
    }
    assert_eq!(original, resumed);
    assert!(original.has_native_completion());
}

#[test]
fn duplicate_output_acknowledgment_is_terminal_and_cannot_repeat_device_output() {
    let mut state = State::default();
    state
        .begin_output(
            Output::Mmio {
                address: 0xfee00000,
                bytes: vec![0x5a; 5],
            },
            5,
        )
        .unwrap();
    assert_eq!(
        state.event().unwrap(),
        Some(Event::MmioOutput {
            address: 0xfee00000,
            bytes: vec![0x5a; 5]
        })
    );
    state.acknowledge_output().unwrap();
    let original = state.pending.clone();
    assert!(state.acknowledge_output().is_err());
    assert_eq!(state.pending, original);
    assert!(state.event().is_err());
    assert!(state.finish_native_completion().is_err());
}

#[test]
fn malformed_native_metadata_rejects_before_replacing_the_owned_transfer() {
    for size in [0, 3, 5, 8, 255] {
        let mut state = State::default();
        assert!(
            state
                .begin_input(
                    Input::Port {
                        port: 0x70,
                        size,
                        count: 1
                    },
                    usize::from(size)
                )
                .is_err()
        );
        assert_eq!(state, State::default());
    }
    for (size, count, length) in [(1, 0, 0), (1, 256, 0), (2, 256, 256), (4, 256, 1023)] {
        let mut state = State::default();
        assert!(
            state
                .begin_input(
                    Input::Port {
                        port: 0x70,
                        size,
                        count
                    },
                    length
                )
                .is_err()
        );
        assert_eq!(state, State::default());
        assert!(
            state
                .begin_output(
                    Output::Port {
                        port: 0x70,
                        size,
                        count,
                        bytes: vec![0; length]
                    },
                    length
                )
                .is_err()
        );
        assert_eq!(state, State::default());
    }
    let mut state = State::default();
    state
        .begin_input(
            Input::Mmio {
                address: 0x1000,
                size: 3,
            },
            3,
        )
        .unwrap();
    let before = state.clone();
    assert!(
        state
            .begin_output(
                Output::Mmio {
                    address: 0x2000,
                    bytes: vec![1]
                },
                1
            )
            .is_err()
    );
    assert_eq!(state, before);
    assert!(state.finish_native_completion().is_err());
    assert_eq!(state, before);
}

#[test]
fn all_native_mmio_chunk_lengths_are_preserved() {
    for size in 1u8..=8 {
        let mut state = State::default();
        let request = Input::Mmio {
            address: 0xfee00003,
            size,
        };
        state
            .begin_input(request.clone(), usize::from(size))
            .unwrap();
        assert_eq!(state.event().unwrap(), Some(Event::Input(request)));
        state.complete_input(&vec![0x5a; usize::from(size)]);
        state.finish_native_completion().unwrap();
        state
            .begin_output(
                Output::Mmio {
                    address: 0xfee00005,
                    bytes: vec![0xa5; usize::from(size)],
                },
                usize::from(size),
            )
            .unwrap();
        state.acknowledge_output().unwrap();
        state.finish_native_completion().unwrap();
    }
    for size in [0u8, 9, 255] {
        assert!(
            State::default()
                .begin_input(Input::Mmio { address: 0, size }, usize::from(size))
                .is_err()
        );
        assert!(
            State::default()
                .begin_output(
                    Output::Mmio {
                        address: 0,
                        bytes: vec![0; usize::from(size)]
                    },
                    usize::from(size)
                )
                .is_err()
        );
    }
}
