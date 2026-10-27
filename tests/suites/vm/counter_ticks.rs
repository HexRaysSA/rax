//! Exact frequency conversion including phase, full-u64 products and wraps.
use rax::vm::timing::{ClockMode, TimingContext};
use std::sync::Arc;
fn clock(nanos: u64, phase: u8) -> TimingContext {
    let c = TimingContext::with_mode(ClockMode::Retired);
    let mut s = c.checkpoint_state();
    s.elapsed_nanos = nanos;
    s.subnanosecond_quanta = phase;
    s.retired_units = 0x1234_5678;
    c.restore_checkpoint_state(&s).unwrap();
    c
}
#[test]
fn full_width_boundary_vectors_match_independent_bigint_constants() {
    for (n, p, f, expected) in [
        (0u64, 0u8, 0u64, 0u64),
        (0u64, 1u8, 3000000000u64, 1u64),
        (0u64, 2u8, 3000000000u64, 2u64),
        (
            18446744073709551615u64,
            2u8,
            18446744073709551615u64,
            13088917042843376698u64,
        ),
        (
            18446744073709551615u64,
            0u8,
            18446744073709551615u64,
            13088917030545547316u64,
        ),
        (
            18446744073709551615u64,
            2u8,
            3000000000u64,
            18446744073709551615u64,
        ),
        (
            9223372036854775809u64,
            1u8,
            62500000u64,
            576460752303423488u64,
        ),
        (1u64, 2u8, 18446744073709551615u64, 30744573456u64),
    ] {
        assert_eq!(clock(n, p).counter_ticks(f), expected);
    }
}
#[test]
fn thirds_of_nanoseconds_remain_visible_at_three_gigahertz() {
    for n in 0..10 {
        for p in 0..3 {
            assert_eq!(
                clock(n, p).counter_ticks(3_000_000_000),
                n * 3 + u64::from(p)
            );
        }
    }
}
#[test]
fn sixty_two_point_five_megahertz_requires_forty_eight_units_per_tick() {
    let c = TimingContext::with_mode(ClockMode::Retired);
    for units in 0..=96 {
        assert_eq!(c.counter_ticks(62_500_000), units / 48);
        c.advance_retired(1).unwrap();
    }
}
#[test]
fn ten_megahertz_requires_three_hundred_units_per_tick() {
    let c = TimingContext::with_mode(ClockMode::Retired);
    for units in 0..=600 {
        assert_eq!(c.counter_ticks(10_000_000), units / 300);
        c.advance_retired(1).unwrap();
    }
}
#[test]
fn zero_frequency_is_zero_and_does_not_mutate_clock_state() {
    let c = clock(u64::MAX, 2);
    c.tick();
    c.set_timer_pending();
    let before = c.checkpoint_state();
    assert_eq!(c.counter_ticks(0), 0);
    assert_eq!(c.checkpoint_state(), before);
}
#[test]
fn changing_read_frequency_does_not_rebase_the_clock() {
    let c = clock(1_000_000_000, 0);
    let before = c.checkpoint_state();
    for f in [0, 1, 10_000_000, 62_500_000, 3_000_000_000, u64::MAX] {
        assert_eq!(c.counter_ticks(f), f);
    }
    assert_eq!(c.checkpoint_state(), before);
}
#[test]
fn elapsed_time_and_phase_are_independent_of_wrapping_retirement_total() {
    let c = clock(7, 2);
    assert_eq!(c.retirement_count(), Some(0x1234_5678));
    assert_eq!(c.counter_ticks(3_000_000_000), 23);
}
#[test]
fn integer_rebase_affects_elapsed_counter_and_clears_only_fraction() {
    let c = clock(7, 2);
    let units = c.retirement_count();
    c.set_resume_base(11);
    assert_eq!(c.counter_ticks(3_000_000_000), 33);
    assert_eq!(c.retirement_count(), units);
}
#[test]
fn diagnostic_ticks_and_reset_do_not_change_the_frequency_counter() {
    let c = clock(333, 1);
    let before = c.counter_ticks(3_000_000_000);
    for _ in 0..100 {
        c.tick();
    }
    c.set_timer_pending();
    c.reset();
    assert_eq!(c.counter_ticks(3_000_000_000), before);
}
#[test]
fn restored_fraction_and_later_advancement_preserve_counter_continuity() {
    for phase in 0..3 {
        let a = clock(333, phase);
        let b = TimingContext::with_mode(ClockMode::Retired);
        b.restore_checkpoint_state(&a.checkpoint_state()).unwrap();
        for _ in 0..100 {
            for f in [1, 10_000_000, 62_500_000, 3_000_000_000, u64::MAX] {
                assert_eq!(a.counter_ticks(f), b.counter_ticks(f));
            }
            a.advance_retired(1).unwrap();
            b.advance_retired(1).unwrap();
        }
    }
}
#[test]
fn wall_counter_is_bracketed_by_the_same_context_time_samples() {
    let c = TimingContext::new();
    for f in [1, 62_500_000, 3_000_000_000] {
        let a = c.elapsed_nanos();
        let ticks = c.counter_ticks(f);
        let b = c.elapsed_nanos();
        assert!(u128::from(ticks) >= u128::from(a) * u128::from(f) / 1_000_000_000);
        assert!(u128::from(ticks) <= u128::from(b) * u128::from(f) / 1_000_000_000);
    }
}
#[test]
fn concurrent_advancement_and_counter_sampling_share_one_phase_snapshot() {
    let c = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let c = c.clone();
            std::thread::spawn(move || {
                for _ in 0..1000 {
                    c.advance_retired(1).unwrap();
                    let ticks = c.counter_ticks(3_000_000_000);
                    assert!(ticks <= 8000);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(c.counter_ticks(3_000_000_000), 8000);
    assert_eq!(c.counter_ticks(62_500_000), 166);
}
pub fn emit_reference(path: &std::path::Path) {
    let mut seed = 0x7261785f66726571u64;
    let mut bytes = Vec::new();
    for i in 0..10000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let nanos = match i % 7 {
            0 => 0,
            1 => 1,
            2 => u64::MAX,
            _ => seed,
        };
        let phase = (i % 3) as u8;
        let frequency = match i % 8 {
            0 => 0,
            1 => 1,
            2 => 10_000_000,
            3 => 62_500_000,
            4 => 3_000_000_000,
            5 => u64::MAX,
            _ => seed.rotate_left(17),
        };
        let c = clock(nanos, phase);
        for word in [
            nanos,
            u64::from(phase),
            frequency,
            c.counter_ticks(frequency),
        ] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
    }
    std::fs::write(path, bytes).unwrap();
}
