//! Behavioral parent-engine PMU selected-calendar regressions.
use super::*;
use crate::vm::timing::{ClockMode, TimingContext};
use std::sync::Arc;
#[test]
fn retired_pmu_calendar_uses_owned_vm_time_and_utc2000_origin() {
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _scope = clock.enter();
    let mut pmu = Pcf50633::new();
    pmu.send(0x59);
    let bytes: Vec<_> = (0..7).map(|_| pmu.recv()).collect();
    assert_eq!(bytes, [0, 0, 0, 0, 1, 1, 0]);
    clock.advance_retired(3_000_000_000).unwrap();
    pmu.send(0x59);
    assert_eq!(pmu.recv(), 1);
}

#[test]
fn pmu_serialization_has_no_clock_pointer_and_rebind_keeps_command_progress() {
    let owner = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _scope = owner.enter();
    let mut source = S5lI2c::new(true, false);
    source.write(0x0c, 0xe6);
    source.write(0x04, 0xf0);
    source.write(0x0c, 0x5a);
    let bytes = crate::codec::serialize(&source).unwrap();
    let other = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    other.advance_retired(3_000_000_000).unwrap();
    let _foreign = other.enter();
    let mut restored: S5lI2c = crate::codec::deserialize_strict(&bytes).unwrap();
    restored.rebind_calendar_from(&source).unwrap();
    owner.advance_retired(180_000_000_000).unwrap();
    assert_eq!(restored.read(0x0c), 1);
    assert_eq!(restored.read(0x0c), 0);
    assert_eq!(crate::codec::serialize(&source).unwrap(), bytes);
}
