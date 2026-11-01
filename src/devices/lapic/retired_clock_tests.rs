//! Local timer observations follow their selected VM clock and restored epoch.
use super::*;
use crate::vm::timing::{ClockMode, TimingContext};
use std::sync::Arc;
use std::time::Duration;

fn clock() -> Arc<TimingContext> {
    Arc::new(TimingContext::with_mode(ClockMode::Retired))
}
fn timer(count: u32) -> LocalApic {
    let mut apic = LocalApic::new(0);
    apic.write_register(LAPIC_LVT_TIMER, 0x41);
    apic.write_register(LAPIC_TIMER_DCR, 0b1011);
    apic.write_register(LAPIC_TIMER_ICR, count);
    apic
}

#[test]
fn frozen_retired_clock_ignores_host_elapsed_time() {
    let clock = clock();
    let _scope = clock.enter();
    let mut apic = timer(1000);
    assert_eq!(apic.read_register(LAPIC_TIMER_CCR), 1000);
    assert_eq!(
        apic.tick_at(Instant::now() + Duration::from_secs(86400)),
        None
    );
    assert_eq!(apic.read_register(LAPIC_TIMER_CCR), 1000);
    assert!(!apic.has_pending_timer());
}

#[test]
fn logical_time_expires_the_timer_without_waiting_for_host_time() {
    let clock = clock();
    let _scope = clock.enter();
    let mut apic = timer(1_000_000_000);
    clock.advance_retired(3_000_000_000).unwrap();
    assert_eq!(apic.read_register(LAPIC_TIMER_CCR), 0);
    assert_eq!(apic.tick(), Some(0x41));
    apic.clear_timer_pending();
    assert_eq!(apic.tick(), None);
}

#[test]
fn every_divisor_preserves_periodic_phase_and_consumed_pending_periods() {
    for (encoding, divisor) in [
        (11, 1),
        (0, 2),
        (1, 4),
        (2, 8),
        (3, 16),
        (8, 32),
        (9, 64),
        (10, 128),
    ] {
        let clock = clock();
        let _scope = clock.enter();
        let mut apic = timer(10);
        apic.write_register(LAPIC_TIMER_DCR, encoding);
        apic.write_register(LAPIC_LVT_TIMER, 0x0002_0041);
        clock.advance_retired(3 * divisor * 25).unwrap();
        assert_eq!(apic.tick(), Some(0x41));
        assert_eq!(apic.read_register(LAPIC_TIMER_CCR), 5);
        apic.clear_timer_pending();
        assert_eq!(apic.tick(), None);
        clock.advance_retired(3 * divisor * 5).unwrap();
        assert_eq!(apic.tick(), Some(0x41));
    }
}

#[test]
fn reprogramming_restarts_in_the_original_clock_domain() {
    let original = clock();
    let original_scope = original.enter();
    let mut apic = timer(100);
    drop(original_scope);
    let unrelated = clock();
    let _scope = unrelated.enter();
    unrelated.advance_retired(3_000_000_000).unwrap();
    assert_eq!(apic.read_register(LAPIC_TIMER_CCR), 100);
    original.advance_retired(150).unwrap();
    assert_eq!(apic.read_register(LAPIC_TIMER_CCR), 50);
    apic.write_register(LAPIC_TIMER_ICR, 100);
    assert_eq!(apic.read_register(LAPIC_TIMER_CCR), 100);
    original.advance_retired(150).unwrap();
    assert_eq!(apic.read_register(LAPIC_TIMER_CCR), 50);
}

#[test]
fn prepared_timer_uses_incoming_epoch_and_retains_target_clock_identity() {
    let source_clock = clock();
    let source_scope = source_clock.enter();
    let apic = timer(1000);
    source_clock.advance_retired(1500).unwrap();
    let state = source_clock.checkpoint_state();
    let references = Arc::strong_count(&source_clock);
    let now = Instant::now();
    let saved = apic.checkpoint_at(now + Duration::from_secs(86400));
    assert_eq!(saved.timer_age_nanos, Some(500));
    assert_eq!(
        Arc::strong_count(&source_clock),
        references,
        "the image retains no source clock"
    );
    drop(source_scope);
    let target_clock = clock();
    let _scope = target_clock.enter();
    let mut target = LocalApic::new(0);
    let mut prepared = saved.prepare_for_clock(now, &target_clock, state.elapsed_nanos);
    prepared.resume_timer_at(now + Duration::from_secs(86400));
    target.replace_state(prepared);
    // Publication precedes the complete clock commit in VMM restoration.
    target_clock.restore_checkpoint_state(&state).unwrap();
    assert_eq!(target.read_register(LAPIC_TIMER_CCR), 500);
    source_clock.advance_retired(3_000_000).unwrap();
    assert_eq!(target.read_register(LAPIC_TIMER_CCR), 500);
    target_clock.advance_retired(1500).unwrap();
    assert_eq!(target.tick(), Some(0x41));
}

#[test]
fn a_wrapping_nanosecond_epoch_survives_capture_and_restore() {
    let source_clock = clock();
    source_clock.set_resume_base(u64::MAX - 9);
    let source_scope = source_clock.enter();
    let apic = timer(30);
    source_clock.advance_retired(60).unwrap();
    assert_eq!(apic.read_register(LAPIC_TIMER_CCR), 10);
    let state = source_clock.checkpoint_state();
    let now = Instant::now();
    let saved = apic.checkpoint_at(now);
    assert_eq!(saved.timer_age_nanos, Some(20));
    drop(source_scope);
    let target_clock = clock();
    target_clock.set_resume_base(12345);
    let _scope = target_clock.enter();
    let mut target = LocalApic::new(0);
    target.replace_state(saved.prepare_for_clock(now, &target_clock, state.elapsed_nanos));
    target_clock.restore_checkpoint_state(&state).unwrap();
    assert_eq!(target.read_register(LAPIC_TIMER_CCR), 10);
    target_clock.advance_retired(30).unwrap();
    assert_eq!(target.tick(), Some(0x41));
}

#[test]
fn wall_timer_retains_the_explicit_instant_contract() {
    let mut apic = timer(1000);
    let now = Instant::now();
    apic.timer_start = Some(now);
    assert_eq!(apic.tick_at(now + Duration::from_nanos(999)), None);
    assert_eq!(apic.timer_current_count, 1);
    assert_eq!(apic.tick_at(now + Duration::from_nanos(1000)), Some(0x41));
}

#[test]
fn runtime_clock_bindings_do_not_change_the_legacy_controller_wire() {
    let clock = clock();
    let _scope = clock.enter();
    let apic = timer(1234);
    let mut without_binding = apic.clone();
    without_binding.timer_clock = TimerClock::default();
    assert_eq!(
        crate::codec::serialize(&apic).unwrap(),
        crate::codec::serialize(&without_binding).unwrap()
    );
}

#[test]
fn a_legacy_decoded_image_captures_no_clock_and_rebinds_through_the_target() {
    let clock = clock();
    let _scope = clock.enter();
    let source = timer(1234);
    let bytes = crate::codec::serialize(&source).unwrap();
    let references = Arc::strong_count(&clock);
    let image: LocalApic = crate::codec::deserialize_strict(&bytes).unwrap();
    assert_eq!(Arc::strong_count(&clock), references);
    let mut target = LocalApic::new(0);
    target.replace_state(image);
    target.write_register(LAPIC_TIMER_ICR, 100);
    clock.advance_retired(300).unwrap();
    assert_eq!(target.read_register(LAPIC_TIMER_CCR), 0);
    assert_eq!(target.tick(), Some(0x41));
}

#[test]
fn current_controller_wire_matches_the_actual_pre_change_producer() {
    let clock = clock();
    let _scope = clock.enter();
    let mut apic = LocalApic::new(42);
    for (offset, value) in [
        (0x80, 0x91),
        (0x310, 17 << 24),
        (0x300, 0x4052),
        (0x320, 0x20041),
        (0x3e0, 9),
        (0x380, 1234567),
    ] {
        apic.write_register(offset, value);
    }
    let old = include_bytes!("../../../tests/fixtures/devices/lapic/wall-v1.bin");
    assert_eq!(crate::codec::serialize(&apic).unwrap().as_slice(), old);
    let decoded: LocalApic = crate::codec::deserialize_strict(old).unwrap();
    assert_eq!(crate::codec::serialize(&decoded).unwrap().as_slice(), old);
}

#[test]
fn subnanosecond_phase_survives_relative_age_restore() {
    let source_clock = clock();
    let source_scope = source_clock.enter();
    let source = timer(1);
    source_clock.advance_retired(1).unwrap();
    assert_eq!(source.read_register(LAPIC_TIMER_CCR), 1);
    let state = source_clock.checkpoint_state();
    assert_eq!(state.elapsed_nanos, 0);
    assert_eq!(state.subnanosecond_quanta, 1);
    let now = Instant::now();
    let saved = source.checkpoint_at(now);
    assert_eq!(saved.timer_age_nanos, Some(0));
    drop(source_scope);
    let target_clock = clock();
    let _scope = target_clock.enter();
    let mut target = LocalApic::new(0);
    target.replace_state(saved.prepare_for_clock(now, &target_clock, state.elapsed_nanos));
    target_clock.restore_checkpoint_state(&state).unwrap();
    target_clock.advance_retired(1).unwrap();
    assert_eq!(target.tick(), None);
    assert_eq!(target.read_register(LAPIC_TIMER_CCR), 1);
    target_clock.advance_retired(1).unwrap();
    assert_eq!(target.tick(), Some(0x41));
}
