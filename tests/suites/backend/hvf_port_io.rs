//! Scalar port data conservation, exact framing and deferred host errors.
#[path = "../../../src/backend/hvf/port_io.rs"]
mod port_io;
use port_io::{
    CompletionAccess, DecodeError, Direction, InputState, PendingInput, ScalarIo, decode,
    input_value, output_bytes,
};

#[derive(Default)]
struct Host {
    rax: u64,
    length: u64,
    fail: Option<&'static str>,
    calls: Vec<&'static str>,
}
impl CompletionAccess for Host {
    type Error = &'static str;
    fn write_rax(&mut self, value: u64) -> Result<(), Self::Error> {
        self.calls.push("rax");
        if self.fail == Some("rax") {
            return Err("rax");
        }
        self.rax = value;
        Ok(())
    }
    fn advance_instruction(&mut self, length: u64) -> Result<(), Self::Error> {
        self.calls.push("advance");
        if self.fail == Some("advance") {
            return Err("advance");
        }
        self.length = length;
        Ok(())
    }
}
fn request(size: u8, length: u64) -> PendingInput {
    PendingInput {
        io: ScalarIo {
            port: 0x1234,
            size,
            direction: Direction::In,
        },
        original_rax: 0xfedc_ba98_7654_3210,
        length,
    }
}

#[test]
fn scalar_qualification_covers_every_port_width_and_direction() {
    for port in 0..=u16::MAX {
        for (encoding, size) in [(0, 1), (1, 2), (3, 4)] {
            for (bit, direction) in [(0, Direction::Out), (8, Direction::In)] {
                let io = decode((u64::from(port) << 16) | encoding | bit).unwrap();
                assert_eq!(
                    io,
                    ScalarIo {
                        port,
                        size,
                        direction
                    }
                );
            }
        }
    }
}

#[test]
fn invalid_sizes_and_string_forms_never_become_scalar_accesses() {
    for size in 0..8 {
        for form in [0, 0x10, 0x20, 0x30] {
            for direction in [0, 8] {
                for immediate in [0, 0x40] {
                    for port in [0, 0xff, 0x1234, 0xffff, 0x80] {
                        for undefined in [0, 0xffff_ffff_0000_ff80] {
                            let qual =
                                (port << 16) | size | form | direction | immediate | undefined;
                            let r = decode(qual);
                            if !matches!(size, 0 | 1 | 3) {
                                assert_eq!(r, Err(DecodeError::InvalidSize));
                            } else if form != 0 {
                                assert_eq!(r, Err(DecodeError::StringOrRep));
                            } else {
                                assert!(r.is_ok());
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn byte_and_word_inputs_preserve_all_unwritten_rax_bits() {
    for original in [0, u64::MAX, 0x1234_5678_9abc_def0] {
        for value in 0..=u16::MAX {
            let bytes = value.to_le_bytes();
            let word = input_value(original, 2, &bytes).unwrap();
            assert_eq!(word >> 16, original >> 16);
            assert_eq!(word as u16, value);
            if value <= 255 {
                let byte = input_value(original, 1, &bytes[..1]).unwrap();
                assert_eq!(byte >> 8, original >> 8);
                assert_eq!(byte as u8, value as u8);
            }
        }
    }
}

#[test]
fn dword_input_zero_extends_and_output_is_exact_little_endian() {
    for original in [0, u64::MAX, 0x1234_5678_9abc_def0] {
        for value in [0, 1, 0x8000_0000, u32::MAX, 0x1234_5678] {
            assert_eq!(
                input_value(original, 4, &value.to_le_bytes()),
                Some(u64::from(value))
            );
        }
        for size in [1, 2, 4] {
            let bytes = output_bytes(original, size).unwrap();
            assert_eq!(bytes, original.to_le_bytes()[..usize::from(size)]);
        }
    }
    for size in [0, 3, 5, 8, 255] {
        assert_eq!(output_bytes(0, size), None);
    }
}

#[test]
fn malformed_input_frames_never_write_registers_or_advance() {
    for size in [1, 2, 4] {
        for count in 0..=8 {
            if count == usize::from(size) {
                continue;
            }
            let mut state = InputState::default();
            state.begin(request(size, 2)).unwrap();
            let mut h = Host::default();
            state.complete(&mut h, &vec![0xa5; count]);
            assert!(state.ready().unwrap_err().contains("expected"));
            assert!(h.calls.is_empty());
            // Error is terminal; a later valid frame cannot silently execute.
            state.complete(&mut h, &vec![0xa5; usize::from(size)]);
            assert!(h.calls.is_empty());
        }
    }
}

#[test]
fn completion_uses_captured_instruction_length_and_commits_once() {
    for size in [1, 2, 4] {
        for length in 1..=15 {
            let mut state = InputState::default();
            assert_eq!(state.ready(), Ok(()));
            state.begin(request(size, length)).unwrap();
            assert!(state.ready().is_err());
            assert!(state.begin(request(size, 3)).is_err());
            let mut h = Host::default();
            let data = vec![0xa5; usize::from(size)];
            state.complete(&mut h, &data);
            assert_eq!(state.ready(), Ok(()));
            assert_eq!(h.calls, ["rax", "advance"]);
            assert_eq!(h.length, length);
            assert_eq!(
                h.rax,
                input_value(request(size, length).original_rax, size, &data).unwrap()
            );
            state.complete(&mut h, &data);
            assert!(state.ready().unwrap_err().contains("without a pending"));
            assert_eq!(h.calls, ["rax", "advance"]);
        }
    }
}

#[test]
fn host_errors_remain_visible_before_every_subsequent_run() {
    for fail in ["rax", "advance"] {
        let mut state = InputState::default();
        state.begin(request(1, 3)).unwrap();
        let mut h = Host {
            fail: Some(fail),
            ..Host::default()
        };
        state.complete(&mut h, &[0xa5]);
        let error = state.ready().unwrap_err().to_owned();
        assert!(error.contains(fail));
        assert_eq!(h.length, 0);
        assert_eq!(
            h.rax,
            if fail == "rax" {
                0
            } else {
                0xfedc_ba98_7654_32a5
            }
        );
        let calls = h.calls.clone();
        h.fail = None;
        for _ in 0..3 {
            assert_eq!(state.ready(), Err(error.as_str()));
            state.complete(&mut h, &[0x5a]);
        }
        assert_eq!(h.calls, calls);
        assert!(state.begin(request(1, 2)).is_err());
    }
}

#[test]
fn invalid_pending_requests_and_unsolicited_completion_are_explicit() {
    for size in [0, 3, 5, 8, 255] {
        let mut state = InputState::default();
        assert!(state.begin(request(size, 2)).is_err());
        assert_eq!(state.ready(), Ok(()));
    }
    for length in [0, 16, u64::MAX] {
        let mut state = InputState::default();
        assert!(state.begin(request(1, length)).is_err());
        assert_eq!(state.ready(), Ok(()));
    }
    let mut state = InputState::default();
    let mut pending = request(1, 2);
    pending.io.direction = Direction::Out;
    assert!(state.begin(pending).is_err());
    let mut h = Host::default();
    state.complete(&mut h, &[0]);
    assert!(state.ready().is_err());
    assert!(h.calls.is_empty());
}
