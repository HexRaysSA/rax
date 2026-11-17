use super::{Turn, Turns, WorkerId};

fn manager() -> Turns {
    // Synthetic PIDs characterize the registry separately from kernel lock
    // observation, which has an independent child-process test.
    let mut turns = Turns::new();
    turns.broker_pid = 10;
    turns
}

#[test]
fn only_registered_worker_with_current_kernel_holder_can_begin() {
    let mut turns = manager();
    let a = turns.register().unwrap();
    let b = turns.register().unwrap();
    for (worker, pid, holder) in [
        (WorkerId(0), 20, Some(20)),
        (WorkerId(99), 20, Some(20)),
        (a, 0, Some(0)),
        (a, -1, Some(-1)),
        (a, 10, Some(10)),
        (a, 20, None),
        (a, 20, Some(30)),
    ] {
        assert!(turns.begin_observed(worker, pid, holder).is_err());
        assert_eq!(turns.last_turn, 0);
        assert!(turns.active.is_none());
    }
    let current = turns.begin_observed(a, 20, Some(20)).unwrap();
    assert!(turns.begin_observed(b, 20, Some(20)).is_err());
    assert!(turns.begin_observed(a, 30, Some(30)).is_err());
    turns.validate_observed(current, Some(20)).unwrap();
    assert_eq!(turns.last_turn, 1);
}

#[test]
fn replacement_and_reentry_reject_every_stale_turn() {
    let mut turns = manager();
    let a = turns.register().unwrap();
    let b = turns.register().unwrap();
    let first = turns.begin_observed(a, 20, Some(20)).unwrap();
    assert!(turns.validate_observed(first, None).is_err());
    assert!(turns.validate_observed(first, Some(30)).is_err());
    let second = turns.begin_observed(b, 30, Some(30)).unwrap();
    assert_ne!(first, second);
    assert!(turns.validate_observed(first, Some(20)).is_err());
    assert!(turns.validate_observed(first, Some(30)).is_err());
    turns.validate_observed(second, Some(30)).unwrap();
    let third = turns.begin_observed(b, 30, Some(30)).unwrap();
    assert_ne!(second, third);
    assert!(turns.validate_observed(second, Some(30)).is_err());
    turns.validate_observed(third, Some(30)).unwrap();
    let forged = Turn {
        worker: a,
        serial: third.serial,
    };
    assert!(turns.validate_observed(forged, Some(30)).is_err());
}

#[test]
fn retirement_invalidates_turn_and_never_reuses_worker_identity() {
    let mut turns = manager();
    let a = turns.register().unwrap();
    let b = turns.register().unwrap();
    let first = turns.begin_observed(a, 20, Some(20)).unwrap();
    assert!(turns.retire(b));
    turns.validate_observed(first, Some(20)).unwrap();
    assert!(turns.retire(a));
    assert!(!turns.retire(a));
    assert!(turns.validate_observed(first, Some(20)).is_err());
    assert!(turns.begin_observed(a, 20, Some(20)).is_err());
    let c = turns.register().unwrap();
    assert!(c > b);
    let new = turns.begin_observed(c, 20, Some(20)).unwrap();
    assert_ne!(first, new);
    assert!(turns.validate_observed(first, Some(20)).is_err());
}

#[test]
fn identity_exhaustion_does_not_wrap_or_partially_bind_worker() {
    let mut turns = manager();
    let a = turns.register().unwrap();
    turns.last_worker = u64::MAX;
    assert!(turns.register().is_err());
    assert_eq!(turns.workers.len(), 1);
    turns.last_turn = u64::MAX - 1;
    let last = turns.begin_observed(a, 20, Some(20)).unwrap();
    assert_eq!(last.serial, u64::MAX);
    assert!(turns.begin_observed(a, 20, Some(20)).is_err());
    turns.validate_observed(last, Some(20)).unwrap();
    assert_eq!(turns.workers.get(&a), Some(&Some(20)));

    let mut unbound = manager();
    let worker = unbound.register().unwrap();
    unbound.last_turn = u64::MAX;
    assert!(unbound.begin_observed(worker, 20, Some(20)).is_err());
    assert_eq!(unbound.workers.get(&worker), Some(&None));
    assert!(unbound.active.is_none());
}
