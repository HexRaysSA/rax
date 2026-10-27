//! Exact rational clock arithmetic, complete phase state and mode admission.
use rax::vm::timing::{self, ClockMode, RETIREMENT_FREQUENCY_HZ, TimingContext};
use std::sync::Arc;
fn clock() -> TimingContext {
    TimingContext::with_mode(ClockMode::Retired)
}
#[test]
fn three_single_units_make_one_nanosecond_without_losing_phase() {
    let c = clock();
    for (delta, nanos, phase) in [(1, 0, 1), (1, 0, 2), (1, 1, 0)] {
        c.advance_retired(delta).unwrap();
        let s = c.checkpoint_state();
        assert_eq!((s.elapsed_nanos, s.subnanosecond_quanta), (nanos, phase));
    }
    assert_eq!(c.retirement_count(), Some(3));
}
#[test]
fn frequency_and_one_second_are_exact() {
    assert_eq!(RETIREMENT_FREQUENCY_HZ, 3_000_000_000);
    let c = clock();
    c.advance_retired(RETIREMENT_FREQUENCY_HZ).unwrap();
    let s = c.checkpoint_state();
    assert_eq!(
        (s.elapsed_nanos, s.retired_units, s.subnanosecond_quanta),
        (1_000_000_000, 3_000_000_000, 0)
    );
}
#[test]
fn three_scheduler_quanta_make_exactly_one_microsecond() {
    let c = clock();
    let mut times = Vec::new();
    for _ in 0..3 {
        c.advance_retired(1000).unwrap();
        times.push((c.elapsed_nanos(), c.checkpoint_state().subnanosecond_quanta));
    }
    assert_eq!(times, [(333, 1), (666, 2), (1000, 0)]);
}
#[test]
fn maximum_delta_and_wrapping_units_keep_independent_phase() {
    let c = clock();
    c.advance_retired(u64::MAX).unwrap();
    assert_eq!(
        (
            c.elapsed_nanos(),
            c.retirement_count(),
            c.checkpoint_state().subnanosecond_quanta
        ),
        (6_148_914_691_236_517_205, Some(u64::MAX), 0)
    );
    c.advance_retired(1).unwrap();
    assert_eq!(
        (
            c.elapsed_nanos(),
            c.retirement_count(),
            c.checkpoint_state().subnanosecond_quanta
        ),
        (6_148_914_691_236_517_205, Some(0), 1)
    );
    c.advance_retired(2).unwrap();
    assert_eq!(
        (
            c.elapsed_nanos(),
            c.retirement_count(),
            c.checkpoint_state().subnanosecond_quanta
        ),
        (6_148_914_691_236_517_206, Some(2), 0)
    );
}
#[test]
fn nanosecond_wrap_preserves_fraction_and_retired_total() {
    let c = clock();
    let mut state = c.checkpoint_state();
    state.elapsed_nanos = u64::MAX;
    state.subnanosecond_quanta = 2;
    state.retired_units = u64::MAX;
    c.restore_checkpoint_state(&state).unwrap();
    c.advance_retired(1).unwrap();
    let s = c.checkpoint_state();
    assert_eq!(
        (s.elapsed_nanos, s.retired_units, s.subnanosecond_quanta),
        (0, 0, 0)
    );
}
#[test]
fn zero_delta_is_a_complete_noop() {
    let c = clock();
    c.advance_retired(17).unwrap();
    c.tick();
    c.set_timer_pending();
    let before = c.checkpoint_state();
    c.advance_retired(0).unwrap();
    assert_eq!(c.checkpoint_state(), before);
}
#[test]
fn capture_restore_retains_every_phase_and_notification() {
    for phase in [0, 1, 2] {
        let source = clock();
        source.advance_retired(3000 + phase).unwrap();
        source.tick();
        source.tick();
        source.set_timer_pending();
        let s = source.checkpoint_state();
        let target = clock();
        target.validate_checkpoint_state(&s).unwrap();
        target.restore_checkpoint_state(&s).unwrap();
        assert_eq!(target.checkpoint_state(), s);
        source.advance_retired(1).unwrap();
        target.advance_retired(1).unwrap();
        assert_eq!(target.checkpoint_state(), source.checkpoint_state());
    }
}
#[test]
fn invalid_phases_and_mode_mismatch_reject_without_mutation() {
    let c = clock();
    c.advance_retired(17).unwrap();
    c.tick();
    c.set_timer_pending();
    let before = c.checkpoint_state();
    for phase in [3, 4, u8::MAX] {
        let mut s = before;
        s.subnanosecond_quanta = phase;
        assert!(c.validate_checkpoint_state(&s).is_err());
        assert!(c.restore_checkpoint_state(&s).is_err());
        assert_eq!(c.checkpoint_state(), before);
    }
    let mut wall = before;
    wall.mode = ClockMode::Wall;
    wall.retired_units = 0;
    wall.subnanosecond_quanta = 0;
    assert!(c.restore_checkpoint_state(&wall).is_err());
    assert_eq!(c.checkpoint_state(), before);
}
#[test]
fn wall_mode_rejects_retirement_and_hidden_phase() {
    let c = TimingContext::new();
    assert_eq!(c.mode(), ClockMode::Wall);
    assert_eq!(c.retirement_count(), None);
    assert!(c.advance_retired(1).is_err());
    assert_eq!(c.instruction_count(), 0);
    assert!(!c.is_timer_pending());
    let mut s = c.checkpoint_state();
    s.subnanosecond_quanta = 1;
    assert!(s.validate().is_err());
    s.subnanosecond_quanta = 0;
    s.retired_units = 1;
    assert!(s.validate().is_err());
}
#[test]
fn bound_helpers_use_exact_retired_time_and_counter() {
    let c = Arc::new(clock());
    let _scope = c.enter();
    for n in 1..=7 {
        c.advance_retired(1).unwrap();
        assert_eq!(timing::elapsed_nanos(), n / 3);
        assert_eq!(timing::tsc(), n);
    }
    assert_eq!(timing::instruction_count(), 0);
    timing::tick();
    assert_eq!(timing::instruction_count(), 1);
    assert_eq!(timing::tsc(), 7);
}
#[test]
fn diagnostic_reset_and_integer_rebase_have_distinct_contracts() {
    let c = clock();
    c.advance_retired(17).unwrap();
    c.tick();
    c.set_timer_pending();
    c.reset();
    let s = c.checkpoint_state();
    assert_eq!(
        (
            s.elapsed_nanos,
            s.retired_units,
            s.subnanosecond_quanta,
            s.diagnostic_ticks,
            s.timer_pending
        ),
        (5, 17, 2, 0, false)
    );
    c.set_resume_base(99);
    let s = c.checkpoint_state();
    assert_eq!(
        (s.elapsed_nanos, s.retired_units, s.subnanosecond_quanta),
        (99, 17, 0)
    );
}
#[test]
fn seeded_partition_campaign_matches_wide_total_and_exact_resume() {
    let mut c = clock();
    let mut seed = 0x7261785f636c6f63u64;
    let mut total = 0u128;
    for i in 0..10000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let delta = match i % 7 {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 1000,
            4 => u64::MAX,
            _ => seed,
        };
        total += u128::from(delta);
        c.advance_retired(delta).unwrap();
        let s = c.checkpoint_state();
        assert_eq!(
            (s.elapsed_nanos, s.retired_units, s.subnanosecond_quanta),
            ((total / 3) as u64, total as u64, (total % 3) as u8)
        );
        if i % 97 == 0 {
            let target = clock();
            target.restore_checkpoint_state(&s).unwrap();
            assert_eq!(target.checkpoint_state(), s);
            c = target;
        }
    }
}
pub fn emit_reference(path: &std::path::Path) {
    let mut c = clock();
    let mut rows = Vec::new();
    let mut seed = 0x7261785f636c6f63u64;
    for i in 0..10000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let delta = match i % 7 {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 1000,
            4 => u64::MAX,
            _ => seed,
        };
        c.advance_retired(delta).unwrap();
        let s = c.checkpoint_state();
        for n in [
            delta,
            s.elapsed_nanos,
            s.retired_units,
            u64::from(s.subnanosecond_quanta),
        ] {
            rows.extend_from_slice(&n.to_le_bytes());
        }
        if i % 97 == 0 {
            let target = clock();
            target.restore_checkpoint_state(&s).unwrap();
            assert_eq!(target.checkpoint_state(), s);
            c = target;
        }
    }
    std::fs::write(path, rows).unwrap();
}

#[test]
fn concurrent_advances_preserve_one_compound_clock_state() {
    let clock = Arc::new(clock());
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let clock = clock.clone();
            std::thread::spawn(move || {
                for _ in 0..1000 {
                    clock.advance_retired(1000).unwrap();
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let state = clock.checkpoint_state();
    assert_eq!(
        (
            state.elapsed_nanos,
            state.retired_units,
            state.subnanosecond_quanta
        ),
        (2_666_666, 8_000_000, 2)
    );
    assert_eq!(state.diagnostic_ticks, 0);
    assert!(!state.timer_pending);
}
