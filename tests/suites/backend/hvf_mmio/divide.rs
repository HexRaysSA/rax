//! Scalar MMIO division completion and saved device-read boundaries.
use super::*;

#[derive(Default)]
struct Host {
    writes: Vec<(usize, u64)>,
    calls: Vec<&'static str>,
    causes: u64,
    length: u64,
    fail_fault: bool,
}

impl mmio::CompletionAccess for Host {
    type Error = &'static str;

    fn write_gpr(&mut self, index: usize, value: u64) -> Result<(), Self::Error> {
        self.calls.push("gpr");
        self.writes.push((index, value));
        Ok(())
    }
    fn write_rflags(&mut self, _: u64) -> Result<(), Self::Error> {
        self.calls.push("flags");
        Ok(())
    }
    fn finish_instruction(&mut self, length: u64) -> Result<(), Self::Error> {
        self.calls.push("retire");
        self.length = length;
        Ok(())
    }
    fn publish_divide_breakpoints(&mut self, causes: u64) -> Result<(), String> {
        self.calls.push("debug");
        self.causes = causes;
        Ok(())
    }
    fn inject_divide_error(&mut self) -> Result<(), String> {
        self.calls.push("divide error");
        if self.fail_fault {
            return Err("injected host VM-entry error".into());
        }
        Ok(())
    }
}

fn request(size: usize, signed: bool, low: u64, high: u64) -> (mmio::InputState, u64) {
    let prefix = match size {
        1 => &[0xf6][..],
        2 => &[0x66, 0xf7],
        4 => &[0xf7],
        8 => &[0x48, 0xf7],
        _ => unreachable!(),
    };
    let modrm = if signed { 0x3f } else { 0x37 };
    let code = [prefix, &[modrm]].concat();
    let (mut context, mut ram, record) = fixture(&code);
    context.registers[0] = low;
    context.registers[2] = high;
    let plan = prepare(&context, &mut ram, record).unwrap();
    let Action::Divide(input) = plan.action else {
        panic!("invalid divide plan for {code:x?}");
    };
    let mut state = mmio::InputState::default();
    assert!(state.begin_divide(input.clone(), 1).is_err());
    state.begin_divide(input, 0x1001).unwrap();
    assert_eq!(state.descriptor(), Some((size as u8, None)));
    (state, plan.length)
}

#[test]
fn divide_retires_with_both_result_lanes_or_faults_without_retirement() {
    const LOW: u64 = 0xd1c2_b3a4_55e6_7788;
    const HIGH: u64 = 0xaa99_6655_4433_2211;
    for size in [1, 2, 4, 8] {
        let width = (8 * size) as u32;
        let mask = u64::MAX >> (64 - width);
        let sign = 1 << (width - 1);
        for signed in [false, true] {
            let mut cases = vec![
                (0, 0, 0, None),                              // Divide by zero.
                (0, 1, 1, None),                              // Quotient 2^width.
                (17, 0, 5, Some((3, 2))),                     // Exact independent result.
                (mask, 0, 1, (!signed).then_some((mask, 0))), // Max unsigned quotient.
            ];
            if signed {
                cases.extend([
                    (mask - 16, mask, 5, Some((mask - 2, mask - 1))), // -17 / +5.
                    (17, 0, mask - 4, Some((mask - 2, 2))),           // +17 / -5.
                    (mask - 16, mask, mask - 4, Some((3, mask - 1))), // -17 / -5.
                    (sign, mask, 1, Some((sign, 0))),                 // Min quotient.
                    (sign, mask, mask, None),                         // Min quotient / -1.
                    (0, sign, mask, None),                            // Min dividend / -1.
                    (sign - 1, 0, 1, Some((sign - 1, 0))),            // Max quotient.
                ]);
            }
            for (low, high, divisor, expected) in cases {
                let operand_low = if size == 1 {
                    (LOW & !0xffff) | (high << 8) | low
                } else {
                    (LOW & !mask) | low
                };
                let operand_high = (HIGH & !mask) | high;
                let (pending, length) = request(size, signed, operand_low, operand_high);
                for restore in [false, true] {
                    let mut state = if restore {
                        rax::codec::deserialize_strict(&rax::codec::serialize(&pending).unwrap())
                            .unwrap()
                    } else {
                        pending.clone()
                    };
                    state.validate_checkpoint().unwrap();
                    let mut host = Host::default();
                    assert!(state.ready().is_err());
                    state.complete(&mut host, &u64::to_le_bytes(divisor)[..size]);
                    state.ready().unwrap();
                    if let Some((quotient, remainder)) = expected {
                        let merge = |original, value| match size {
                            2 => (original & !0xffff) | value,
                            _ => value,
                        };
                        let writes = if size == 1 {
                            vec![(0, (LOW & !0xffff) | (remainder << 8) | quotient)]
                        } else {
                            vec![
                                (0, merge(operand_low, quotient)),
                                (2, merge(operand_high, remainder)),
                            ]
                        };
                        assert_eq!(host.writes, writes);
                        assert_eq!(host.calls.first(), Some(&"debug"));
                        assert_eq!(host.calls.last(), Some(&"retire"));
                        assert!(!host.calls.contains(&"flags"));
                        assert_eq!(host.causes, 0x1001);
                        assert_eq!(host.length, length);
                    } else {
                        assert_eq!(host.calls, ["divide error"]);
                        assert!(host.writes.is_empty());
                    }
                }
            }
        }
    }
}

#[test]
fn failed_fault_delivery_retains_reply_and_does_not_retry_or_advance() {
    let (mut state, _) = request(8, false, 0, 0);
    let mut host = Host {
        fail_fault: true,
        ..Host::default()
    };
    state.complete(&mut host, &[0; 8]);
    assert_eq!(host.calls, ["divide error"]);
    assert!(state.failure().unwrap().contains("host VM-entry error"));
    let json = serde_json::to_value(&state).unwrap();
    assert_eq!(json["reply"], serde_json::to_value([0; 8]).unwrap());
    let mut restored: mmio::InputState = serde_json::from_value(json).unwrap();
    restored.validate_checkpoint().unwrap();
    let mut destination = Host::default();
    restored.complete(&mut destination, &[5; 8]);
    assert!(restored.ready().is_err());
    assert!(destination.calls.is_empty());
}

#[test]
fn malformed_mmio_divide_direction_and_width_have_no_completion_effects() {
    for code in [&[0xf6, 0xf7][..], &[0xf0, 0xf7, 0x37], &[0x48, 0xf7]] {
        let (context, mut ram, record) = fixture(code);
        assert!(prepare(&context, &mut ram, record).is_err(), "{code:x?}");
    }
    let (context, mut ram, mut record) = fixture(&[0x48, 0xf7, 0x37]);
    record.qualification = 0x182;
    assert!(prepare(&context, &mut ram, record).is_err());
    let (mut pending, _) = request(8, false, 0, 0);
    let mut host = Host::default();
    pending.complete(&mut host, &[0; 7]);
    assert!(pending.failure().unwrap().contains("width"));
    assert!(host.calls.is_empty());
}
