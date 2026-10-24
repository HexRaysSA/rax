//! Execute actual VM-exit retirement and event-source boundaries using host fixtures.
#[path = "../../../src/backend/hvf/sync_exit.rs"]
mod sync_exit;
use sync_exit::{
    AdvanceError, ExceptionAccess, HaltAccess, code_width, exception_vector, halt, next_ip,
};

#[test]
fn instruction_pointer_increment_wraps_each_code_width() {
    for bits in [32, 64] {
        let mask = match bits {
            32 => 0xffff_ffff,
            _ => u64::MAX,
        };
        for length in 1..=15 {
            for current in [
                0,
                1,
                mask - 15,
                mask - 1,
                mask,
                u64::MAX,
                0x1234_5678_9abc_def0,
            ] {
                let expected = match bits {
                    32 => u64::from((current as u32).wrapping_add(length as u32)),
                    _ => current.wrapping_add(length),
                };
                assert_eq!(next_ip(current, length, bits), Ok(expected));
            }
        }
    }
}

#[test]
fn invalid_lengths_or_code_widths_cannot_fabricate_an_advance() {
    for length in [0, 16, 255, u64::MAX] {
        assert_eq!(
            next_ip(0x1000, length, 64),
            Err(AdvanceError::InvalidLength)
        );
    }
    for bits in [0, 8, 16, 17, 31, 33, 63, 65, u32::MAX] {
        assert_eq!(
            next_ip(0x1000, 1, bits),
            Err(AdvanceError::InvalidCodeWidth)
        );
    }
}

#[test]
fn code_width_uses_ia32e_l_without_truncating_legacy_eip_to_operand_size() {
    for active in [false, true] {
        for long in [false, true] {
            for default32 in [false, true] {
                let efer = if active { 1 << 10 } else { 0 };
                let cs = if long { 1 << 13 } else { 0 } | if default32 { 1 << 14 } else { 0 };
                let expected = if active && long { 64 } else { 32 };
                assert_eq!(code_width(efer, cs), expected);
            }
        }
    }
}

struct HaltHost {
    rip: u64,
    length: u64,
    bits: u32,
    halted: bool,
    events: Vec<&'static str>,
    fail: bool,
}
impl HaltAccess for HaltHost {
    type Error = &'static str;
    fn advance_current_instruction(&mut self) -> Result<(), Self::Error> {
        self.events.push("advance");
        if self.fail {
            return Err("host advance failed");
        }
        self.rip = next_ip(self.rip, self.length, self.bits).map_err(|_| "invalid advance")?;
        Ok(())
    }
    fn set_halted(&mut self, halted: bool) {
        self.events.push(if halted { "halt" } else { "wake" });
        self.halted = halted;
    }
}

#[test]
fn halt_commits_complete_instruction_length_before_stopping() {
    for bits in [32, 64] {
        for length in 1..=15 {
            let mut host = HaltHost {
                rip: 0xfffe,
                length,
                bits,
                halted: false,
                events: vec![],
                fail: false,
            };
            assert_eq!(halt(&mut host), Ok(()));
            assert_eq!(host.rip, next_ip(0xfffe, length, bits).unwrap());
            assert!(host.halted);
            assert_eq!(host.events, ["advance", "halt"]);
        }
    }
}

#[test]
fn failed_halt_advance_never_sets_the_halted_flag() {
    for (length, fail) in [(1, true), (0, false), (16, false)] {
        let mut host = HaltHost {
            rip: 0x1234,
            length,
            bits: 64,
            halted: false,
            events: vec![],
            fail,
        };
        assert!(halt(&mut host).is_err());
        assert_eq!(host.rip, 0x1234);
        assert!(!host.halted);
        assert_eq!(host.events, ["advance"]);
    }
}

struct EventHost {
    exit: Result<u64, &'static str>,
    idt: Result<u64, &'static str>,
    reads: Vec<&'static str>,
}
impl ExceptionAccess for EventHost {
    type Error = &'static str;
    fn read_vmcs(&mut self, field: u32) -> Result<u64, Self::Error> {
        match field {
            0x4404 => {
                self.reads.push("exit");
                self.exit
            }
            0x4408 => {
                self.reads.push("idt");
                self.idt
            }
            _ => Err("unexpected VMCS field"),
        }
    }
}

#[test]
fn exception_vector_comes_from_the_exit_event_not_interrupted_idt_delivery() {
    for exit in 0..=255 {
        for idt in 0..=255 {
            let mut host = EventHost {
                exit: Ok(0x8000_0300 | exit),
                idt: Ok(0x8000_0300 | idt),
                reads: vec![],
            };
            assert_eq!(exception_vector(&mut host), Ok(Some(exit as u8)));
            assert_eq!(host.reads, ["exit"]);
        }
    }
}

#[test]
fn invalid_exit_info_does_not_invent_vector_zero_or_use_valid_idt_data() {
    for vector in 0..=255 {
        let mut host = EventHost {
            exit: Ok(0x300 | vector),
            idt: Ok(0x8000_030e),
            reads: vec![],
        };
        assert_eq!(exception_vector(&mut host), Ok(None));
        assert_eq!(host.reads, ["exit"]);
    }
}

#[test]
fn event_read_errors_propagate_and_unrelated_idt_errors_are_not_consulted() {
    let mut host = EventHost {
        exit: Err("exit read failed"),
        idt: Ok(0x8000_030e),
        reads: vec![],
    };
    assert_eq!(exception_vector(&mut host), Err("exit read failed"));
    assert_eq!(host.reads, ["exit"]);
    let mut host = EventHost {
        exit: Ok(0x8000_0202),
        idt: Err("idt unavailable"),
        reads: vec![],
    };
    assert_eq!(exception_vector(&mut host), Ok(Some(2)));
    assert_eq!(host.reads, ["exit"]);
}

#[test]
fn halt_wake_halt_preserves_the_resumption_pointer_and_retires_each_halt_once() {
    let mut host = HaltHost {
        rip: 0xffff_fffe,
        length: 3,
        bits: 32,
        halted: false,
        events: vec![],
        fail: false,
    };
    halt(&mut host).unwrap();
    assert_eq!(host.rip, 1);
    assert!(host.halted);
    sync_exit::wake(&mut host);
    assert_eq!(host.rip, 1);
    assert!(!host.halted);
    host.length = 2;
    halt(&mut host).unwrap();
    assert_eq!(host.rip, 3);
    assert!(host.halted);
    assert_eq!(host.events, ["advance", "halt", "wake", "advance", "halt"]);
}
