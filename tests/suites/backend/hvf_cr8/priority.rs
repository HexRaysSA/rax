//! Execute canonical TPR publication with explicit SDK failure traces.
#[path = "../../../../src/backend/hvf/priority.rs"]
mod priority;
use priority::{Host, State};
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};
#[derive(Clone)]
struct Register(Arc<AtomicU32>);
impl priority::Register for Register {
    fn load(&self) -> u32 {
        self.0.load(Ordering::SeqCst)
    }
    fn store(&self, value: u32) {
        self.0.store(value, Ordering::SeqCst);
    }
}
impl Register {
    fn new(v: u32) -> Self {
        Self(Arc::new(AtomicU32::new(v)))
    }
}
#[derive(Default)]
struct Sdk {
    value: u64,
    calls: Vec<&'static str>,
    read_error: bool,
    write_error: bool,
}
impl Host for Sdk {
    fn read_tpr(&mut self) -> Result<u64, String> {
        self.calls.push("read");
        if self.read_error {
            Err("read fault".into())
        } else {
            Ok(self.value)
        }
    }
    fn write_tpr(&mut self, value: u64) -> Result<(), String> {
        self.calls.push("write");
        self.value = value;
        if self.write_error {
            Err("write may have changed SDK state".into())
        } else {
            Ok(())
        }
    }
}
#[test]
fn every_full_tpr_value_uses_the_canonical_owner_and_refreshes_before_entry() {
    for value in 0..=255 {
        let register = Register::new(value);
        let state = State::new(register.clone());
        let mut sdk = Sdk {
            value: 256,
            ..Default::default()
        };
        assert_eq!(state.read().unwrap(), u64::from(value));
        state.prepare_entry(&mut sdk).unwrap();
        assert_eq!(sdk.value, u64::from(value));
        assert_eq!(sdk.calls, ["read", "write"]);
        sdk.calls.clear();
        state.prepare_entry(&mut sdk).unwrap();
        assert_eq!(sdk.calls, ["read"]);
        use priority::Register as _;
        register.store(255 - value);
        assert_eq!(state.read().unwrap(), u64::from(255 - value));
    }
}
#[test]
fn successful_transfer_publishes_the_sdk_before_the_controller() {
    for value in 0..=255 {
        let register = Register::new(0xa7);
        let state = State::new(register.clone());
        let mut sdk = Sdk::default();
        state.write(&mut sdk, value).unwrap();
        assert_eq!(state.read().unwrap(), value);
        assert_eq!(sdk.value, value);
        assert_eq!(sdk.calls, ["write"]);
    }
}
#[test]
fn failed_write_never_publishes_the_owner_and_rebind_or_import_cannot_clear_failure() {
    let register = Register::new(0xa7);
    let mut state = State::new(register.clone());
    let mut sdk = Sdk {
        write_error: true,
        ..Default::default()
    };
    assert!(state.write(&mut sdk, 0xb0).is_err());
    assert_eq!(register.0.load(Ordering::SeqCst), 0xa7);
    assert_eq!(
        sdk.value, 0xb0,
        "failure may have partially updated the SDK"
    );
    state.rebind(Register::new(0x10));
    assert!(state.ready().is_err());
    assert!(state.commit_import(0).is_err());
    let calls = sdk.calls.len();
    assert!(state.prepare_entry(&mut sdk).is_err());
    assert!(state.write(&mut sdk, 0).is_err());
    assert_eq!(sdk.calls.len(), calls);
}
#[test]
fn entry_sync_write_failure_is_terminal_while_a_read_failure_is_retryable() {
    let state = State::new(Register::new(0xb7));
    let mut sdk = Sdk {
        read_error: true,
        ..Default::default()
    };
    assert!(state.prepare_entry(&mut sdk).is_err());
    assert!(state.ready().is_ok());
    assert_eq!(sdk.calls, ["read"]);
    sdk.read_error = false;
    sdk.write_error = true;
    assert!(state.prepare_entry(&mut sdk).is_err());
    assert!(state.ready().is_err());
}
#[test]
fn invalid_inputs_reject_before_sdk_calls_or_owner_changes() {
    let state = State::new(Register::new(0x77));
    let mut sdk = Sdk::default();
    for value in [256, 0x10000, u64::MAX] {
        assert!(state.write(&mut sdk, value).is_err());
    }
    assert!(state.commit_import(256).is_err());
    assert!(sdk.calls.is_empty());
    assert_eq!(state.read().unwrap(), 0x77);
    assert!(state.ready().is_ok());
}

#[test]
fn invalid_owner_is_rejected_before_any_sdk_call_and_can_be_rebound_before_publication() {
    let mut state = State::new(Register::new(256));
    let mut sdk = Sdk::default();
    assert!(state.ready().is_err());
    assert!(state.read().is_err());
    assert!(state.prepare_entry(&mut sdk).is_err());
    assert!(sdk.calls.is_empty());
    state.rebind(Register::new(0x77));
    assert_eq!(state.read().unwrap(), 0x77);
}
#[test]
fn import_and_rebind_expose_the_attached_full_priority_without_sdk_effects() {
    let mut state = State::new(Register::new(0));
    let attached = Register::new(0xa7);
    state.rebind(attached.clone());
    assert_eq!(state.read().unwrap(), 0xa7);
    state.commit_import(0xb0).unwrap();
    assert_eq!(attached.0.load(Ordering::SeqCst), 0xb0);
}
