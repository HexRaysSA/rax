//! A timer retains its VM clock independently of ambient or manual host samples.
use super::*;
use std::time::Duration;

#[test]
fn bound_wall_timer_does_not_follow_a_foreign_host_sample() {
    let owner = Arc::new(TimingContext::new());
    let clock = TimerClock::selected(Some(owner));
    let wall = Instant::now();
    let sample = clock.sample(wall, wall + Duration::from_secs(86400));
    assert!(sample.elapsed_nanos < Duration::from_secs(60).as_nanos());
    assert!(sample.logical_now.is_some());
}

#[test]
fn unbound_timer_preserves_explicit_host_samples() {
    let clock = TimerClock::selected(None);
    let wall = Instant::now();
    let sample = clock.sample(wall, wall + Duration::from_nanos(1234));
    assert_eq!(sample.elapsed_nanos, 1234);
    assert!(sample.logical_now.is_none());
}

#[test]
fn prepared_wall_timer_retains_incoming_age_until_its_owner_resumes() {
    let owner = Arc::new(TimingContext::new());
    let mut state = owner.checkpoint_state();
    state.elapsed_nanos = 1234;
    let clock = TimerClock::prepared(owner.clone(), state.elapsed_nanos);
    owner
        .prepare_stopped_checkpoint_state(&state)
        .unwrap()
        .commit();
    let wall = Instant::now();
    std::thread::sleep(Duration::from_millis(2));
    let sample = clock.sample(wall, wall + Duration::from_secs(86400));
    assert_eq!(sample.elapsed_nanos, 0);
    assert_eq!(sample.logical_now, Some(1234));
    let mut replacement = TimerClock::default();
    replacement.retain_target_binding(&clock);
    replacement.restart();
    assert_eq!(replacement.sample(wall, wall).elapsed_nanos, 0);
    let entry = std::time::Instant::now();
    assert!(owner.resume_wall_at(entry));
    let before = entry.elapsed().as_nanos();
    let sample = replacement.sample(wall, wall);
    let after = entry.elapsed().as_nanos();
    assert!((before..=after).contains(&sample.elapsed_nanos));
}
