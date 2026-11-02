//! Exact domain, wrap and incoming-publication samples; no hardware clock claim.
use super::*;

#[test]
fn retired_epoch_retains_owner_across_host_delay_and_foreign_scopes() {
    let first = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _first = first.enter();
    let start = ClockEpoch::selected_at(Instant::now());
    std::thread::sleep(Duration::from_millis(2));
    assert_eq!(
        start.sample().duration_since(&start).unwrap(),
        Duration::ZERO
    );
    let other = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    other.advance_retired(3_000_000_000).unwrap();
    let _foreign = other.enter();
    first.advance_retired(33).unwrap();
    assert_eq!(
        start.sample().duration_since(&start).unwrap(),
        Duration::from_nanos(11)
    );
    assert!(
        ClockEpoch::selected_at(Instant::now())
            .duration_since(&start)
            .is_err()
    );
    assert!(
        ClockEpoch::from(Instant::now())
            .duration_since(&start)
            .is_err()
    );
}

#[test]
fn retired_epoch_wraps_and_publishes_the_incoming_counter_before_clock_commit() {
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let mut state = clock.checkpoint_state();
    state.elapsed_nanos = u64::MAX - 1;
    clock.restore_checkpoint_state(&state).unwrap();
    let _scope = clock.enter();
    let start = ClockEpoch::selected_at(Instant::now());
    clock.advance_retired(6).unwrap();
    assert_eq!(
        start.sample().duration_since(&start).unwrap(),
        Duration::from_nanos(2)
    );
    let mut incoming = clock.checkpoint_state();
    incoming.elapsed_nanos = 100;
    incoming.retired_units = 300;
    let prepared = start.for_restore(Some(&incoming)).unwrap();
    let published = prepared.at_publication();
    assert_eq!(clock.elapsed_nanos(), 0);
    clock.restore_checkpoint_state(&incoming).unwrap();
    assert_eq!(
        published.sample().duration_since(&published).unwrap(),
        Duration::ZERO
    );
    clock.advance_retired(3).unwrap();
    assert_eq!(
        published.sample().duration_since(&published).unwrap(),
        Duration::from_nanos(1)
    );
    incoming.mode = ClockMode::Wall;
    incoming.retired_units = 0;
    assert!(prepared.for_restore(Some(&incoming)).is_err());
}

#[test]
fn wall_epoch_preserves_explicit_host_instants_and_saturating_subtraction() {
    let start = Instant::now();
    let before = ClockEpoch::from(start);
    let later = ClockEpoch::from(start + Duration::from_nanos(11));
    assert_eq!(
        later.duration_since(&before).unwrap(),
        Duration::from_nanos(11)
    );
    assert_eq!(before.duration_since(&later).unwrap(), Duration::ZERO);
    let state = TimingContext::with_mode(ClockMode::Retired).checkpoint_state();
    assert!(before.for_restore(Some(&state)).is_err());
}
