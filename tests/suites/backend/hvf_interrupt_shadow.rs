//! Saved-shadow completion, independent of native VMX availability.
#[path = "../../../src/backend/hvf/interrupt_shadow.rs"]
mod interrupt_shadow;
use interrupt_shadow::{Access, complete};

#[derive(Default)]
struct Host {
    state: u64,
    ip: u64,
    fail: Option<&'static str>,
    calls: Vec<&'static str>,
}
impl Host {
    fn step(&mut self, call: &'static str) -> Result<(), &'static str> {
        self.calls.push(call);
        if self.fail == Some(call) {
            Err(call)
        } else {
            Ok(())
        }
    }
}
impl Access for Host {
    type Error = &'static str;
    fn interruptibility(&mut self) -> Result<u64, Self::Error> {
        self.step("read")?;
        Ok(self.state)
    }
    fn advance_ip(&mut self) -> Result<(), Self::Error> {
        self.step("ip")?;
        self.ip += 1;
        Ok(())
    }
    fn write_interruptibility(&mut self, value: u64) -> Result<(), Self::Error> {
        self.step("shadow")?;
        self.state = value;
        Ok(())
    }
}

#[test]
fn each_saved_state_expires_only_sti_and_mov_ss() {
    for low in 0..32 {
        for high in [0, 0x1234_5678_1234_0000, u64::MAX & !31] {
            let before = high | low;
            let mut h = Host {
                state: before,
                ..Host::default()
            };
            assert_eq!(complete(&mut h), Ok(()));
            assert_eq!(h.state & 3, 0);
            assert_eq!(h.state & !3, before & !3);
            assert_eq!(h.ip, 1);
            assert_eq!(
                h.calls,
                if low & 3 == 0 {
                    vec!["read", "ip"]
                } else {
                    vec!["read", "ip", "shadow"]
                }
            );
        }
    }
}

#[test]
fn every_non_shadow_bit_is_preserved() {
    for bit in 2..64 {
        for shadow in [1, 2, 3] {
            let mut h = Host {
                state: (1 << bit) | shadow,
                ..Host::default()
            };
            complete(&mut h).unwrap();
            assert_eq!(h.state, 1 << bit);
        }
    }
}

#[test]
fn read_and_ip_failure_preserve_the_saved_shadow() {
    for fail in ["read", "ip"] {
        for state in [1, 2, 3, 0x1f] {
            let mut h = Host {
                state,
                fail: Some(fail),
                ..Host::default()
            };
            assert_eq!(complete(&mut h), Err(fail));
            assert_eq!(h.state, state);
            assert_eq!(h.ip, 0);
            assert!(!h.calls.contains(&"shadow"));
        }
    }
}

#[test]
fn shadow_write_failure_is_propagated_after_ip_commit() {
    let mut h = Host {
        state: 9,
        fail: Some("shadow"),
        ..Host::default()
    };
    assert_eq!(complete(&mut h), Err("shadow"));
    assert_eq!(h.state, 9);
    assert_eq!(h.ip, 1);
    assert_eq!(h.calls, ["read", "ip", "shadow"]);
}

#[test]
fn successful_completion_is_idempotent_for_shadow_state() {
    let mut h = Host {
        state: 0x1b,
        ..Host::default()
    };
    complete(&mut h).unwrap();
    assert_eq!(h.state, 0x18);
    h.calls.clear();
    complete(&mut h).unwrap();
    assert_eq!(h.state, 0x18);
    assert_eq!(h.ip, 2);
    assert_eq!(h.calls, ["read", "ip"]);
}

#[test]
fn unblocked_instruction_advances_without_changing_other_state() {
    let mut h = Host {
        state: 0x18,
        ..Host::default()
    };
    complete(&mut h).unwrap();
    assert_eq!(h.ip, 1);
    assert_eq!(h.state, 0x18);
    assert!(!h.calls.contains(&"shadow"));
}
