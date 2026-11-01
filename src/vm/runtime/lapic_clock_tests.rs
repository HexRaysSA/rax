//! Captured images must not retain a controller's independently selected clock.
use super::*;
use crate::vm::timing::{ClockMode, TimingContext};

#[test]
fn both_base_and_complete_capture_detach_live_lapic_clock_identity() {
    let fixture = super::execution_tests::Fixture::new(2);
    let selected = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    {
        let _scope = selected.enter();
        // Inject only this device binding to exercise both capture producers.
        // The VMM itself remains in its admitted wall-mode configuration.
        *fixture.vm.lapic.lock().unwrap() = LocalApic::new(0);
    }
    let references = Arc::strong_count(&selected);
    assert_eq!(references, 2);
    let base = fixture.vm.take_snapshot(0).unwrap();
    assert_eq!(Arc::strong_count(&selected), references);
    let complete = fixture.vm.take_snapshot_bundle(0).unwrap();
    assert_eq!(Arc::strong_count(&selected), references);
    assert_eq!(complete.execution().unwrap().local_apics.len(), 2);
    selected.advance_retired(3_000_000_000).unwrap();
    drop(base);
    drop(complete);
    assert_eq!(Arc::strong_count(&selected), references);
}
