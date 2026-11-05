//! Stopped import keeps its wire state until the owner's first-entry instant.
use super::*;
use std::time::Duration;

#[test]
fn stopped_import_retains_exact_state_across_delay_and_repeated_capture() {
    let clock = TimingContext::new();
    let mut saved = clock.checkpoint_state();
    saved.elapsed_nanos = u64::MAX - 9;
    saved.diagnostic_ticks = 123;
    saved.timer_pending = true;
    clock
        .prepare_stopped_checkpoint_state(&saved)
        .unwrap()
        .commit();
    for _ in 0..3 {
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(clock.checkpoint_state(), saved);
        assert!(clock.is_stopped_at(saved.elapsed_nanos));
    }
    assert_eq!(clock.counter_ticks(1_000_000_000), saved.elapsed_nanos);
}

#[test]
fn activation_counts_publication_work_from_the_supplied_instant_only_once() {
    let clock = TimingContext::new();
    let mut saved = clock.checkpoint_state();
    saved.elapsed_nanos = 1234;
    clock
        .prepare_stopped_checkpoint_state(&saved)
        .unwrap()
        .commit();
    std::thread::sleep(Duration::from_millis(3));
    let entry = Instant::now();
    std::thread::sleep(Duration::from_millis(2));
    assert_eq!(clock.elapsed_nanos(), 1234);
    assert!(clock.resume_wall_at(entry));
    let before = entry.elapsed().as_nanos() as u64;
    let observed = clock.elapsed_nanos().wrapping_sub(1234);
    let after = entry.elapsed().as_nanos() as u64;
    assert!((before..=after).contains(&observed));
    assert!(!clock.resume_wall_at(Instant::now()));
    assert!(clock.elapsed_nanos().wrapping_sub(1234) >= observed);
    assert!(!clock.is_stopped_at(1234));
}

#[test]
fn preparation_and_rejected_modes_do_not_publish_a_clock_prefix() {
    let clock = TimingContext::new();
    let saved = clock.checkpoint_state();
    let prepared = clock.prepare_stopped_checkpoint_state(&saved).unwrap();
    assert!(!clock.is_stopped_at(saved.elapsed_nanos));
    drop(prepared);
    let retired = TimingContext::with_mode(ClockMode::Retired);
    let retired_saved = retired.checkpoint_state();
    assert!(
        retired
            .prepare_stopped_checkpoint_state(&retired_saved)
            .is_err()
    );
    assert!(
        clock
            .prepare_stopped_checkpoint_state(&retired_saved)
            .is_err()
    );
    let mut malformed = saved;
    malformed.subnanosecond_quanta = 1;
    assert!(clock.prepare_stopped_checkpoint_state(&malformed).is_err());
    assert_eq!(retired.checkpoint_state(), retired_saved);
    assert!(!retired.resume_wall_at(Instant::now()));
}

#[test]
fn integer_rebase_and_diagnostic_reset_preserve_the_stopped_lifecycle() {
    let clock = TimingContext::new();
    let saved = clock.checkpoint_state();
    clock
        .prepare_stopped_checkpoint_state(&saved)
        .unwrap()
        .commit();
    clock.set_resume_base(456);
    clock.tick();
    clock.set_timer_pending();
    clock.reset();
    assert!(clock.is_stopped_at(456));
    assert_eq!(clock.instruction_count(), 0);
    assert!(!clock.is_timer_pending());
    std::thread::sleep(Duration::from_millis(2));
    assert_eq!(clock.elapsed_nanos(), 456);
    clock.restore_checkpoint_state(&saved).unwrap();
    assert!(!clock.is_stopped_at(saved.elapsed_nanos));
}
