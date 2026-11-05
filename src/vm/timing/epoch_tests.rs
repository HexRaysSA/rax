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
    let published = prepared.at_publication(true);
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

#[test]
fn selected_wall_epochs_retain_distinct_vm_owners() {
    let first = Arc::new(TimingContext::new());
    let scope = first.enter();
    let start = ClockEpoch::selected_at(Instant::now());
    drop(scope);
    let other = Arc::new(TimingContext::new());
    let _foreign = other.enter();
    let foreign = ClockEpoch::selected_at(Instant::now());
    assert!(!start.same_domain(&foreign));
    assert!(foreign.duration_since(&start).is_err());
    assert!(start.sample().same_domain(&start));
    assert!(!start.same_domain(&ClockEpoch::from(Instant::now())));
}

#[test]
fn wall_restore_epoch_is_prepared_before_the_stopped_clock_is_published() {
    let clock = Arc::new(TimingContext::new());
    let scope = clock.enter();
    let epoch = ClockEpoch::selected_at(Instant::now());
    let mut state = clock.checkpoint_state();
    state.elapsed_nanos = 1234;
    let prepared = epoch.for_restore(Some(&state)).unwrap();
    clock
        .prepare_stopped_checkpoint_state(&state)
        .unwrap()
        .commit();
    drop(scope);
    let unrelated = Arc::new(TimingContext::new());
    let _foreign = unrelated.enter();
    std::thread::sleep(Duration::from_millis(2));
    let published = prepared.at_publication(true);
    assert_eq!(published, prepared);
    assert_eq!(
        published.sample().duration_since(&published).unwrap(),
        Duration::ZERO
    );
    assert!(clock.resume_wall_at(std::time::Instant::now()));
    std::thread::sleep(Duration::from_millis(2));
    assert!(published.sample().duration_since(&published).unwrap() >= Duration::from_millis(2));
}

#[test]
fn publication_without_clock_import_samples_the_live_owned_domain() {
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _scope = clock.enter();
    let start = ClockEpoch::selected_at(Instant::now());
    let prepared = start.for_restore(None).unwrap();
    clock.advance_retired(33).unwrap();
    assert_eq!(
        prepared
            .at_publication(false)
            .duration_since(&start)
            .unwrap(),
        Duration::from_nanos(11)
    );
}
