use super::*;
use std::sync::Arc;
use timing::{ClockMode, TimingContext};

fn at_tick(clock: &TimingContext, tick: u64) {
    clock.set_resume_base((tick * 1_000_000_000).div_ceil(PIT_FREQUENCY));
}

fn program_count(pit: &mut Pit, port: u16, divisor: u16) {
    let [low, high] = divisor.to_le_bytes();
    pit.write(port, low);
    pit.write(port, high);
}

#[test]
#[cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
fn next_irq_matches_mode_boundaries_and_divisor_replacement() {
    for (command, first, repeat) in [
        (0x30, 6, None),     // Mode 0 reaches count zero.
        (0x34, 6, Some(11)), // Mode 2 rises once per reload.
        (0x36, 6, Some(11)), // Mode 3 rises at the end of its low phase.
        (0x38, 7, None),     // Mode 4 rises one clock after its strobe.
    ] {
        let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
        let _scope = clock.enter();
        let mut pit = Pit::new_unprogrammed();
        assert_eq!(pit.next_irq_nanos(), None);
        pit.write(0x43, command);
        program_count(&mut pit, 0x40, 5);
        if command != 0x30 {
            // A mode command can drive OUT high immediately. The native
            // coordinator publishes that edge before waiting for the counter.
            assert_eq!(pit.next_irq_nanos(), Some(0));
            pit.clear_interrupt();
        }
        let nanos = |tick: u64| (tick * 1_000_000_000).div_ceil(PIT_FREQUENCY);
        assert_eq!(pit.next_irq_nanos(), Some(nanos(first)));
        clock.set_resume_base(nanos(first) - 1);
        assert!(!pit.tick());
        assert_eq!(pit.next_irq_nanos(), Some(nanos(first)));
        at_tick(&clock, first);
        assert!(pit.tick());
        pit.clear_interrupt();
        assert_eq!(pit.next_irq_nanos(), repeat.map(nanos));
    }
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _scope = clock.enter();
    let mut pit = Pit::new_unprogrammed();
    pit.write(0x43, 0x36);
    program_count(&mut pit, 0x40, 5);
    assert_eq!(pit.next_irq_nanos(), Some(0));
    pit.clear_interrupt();
    at_tick(&clock, 3);
    program_count(&mut pit, 0x40, 8);
    assert_eq!(
        pit.next_irq_nanos(),
        Some((8u64 * 1_000_000_000).div_ceil(PIT_FREQUENCY))
    );
    at_tick(&clock, 7);
    assert!(!pit.tick());
    at_tick(&clock, 8);
    assert!(pit.tick());
}

#[test]
fn rate_generator_transfers_a_replacement_at_the_end_of_the_active_cycle() {
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _scope = clock.enter();
    let mut pit = Pit::new();
    let status = |pit: &mut Pit| {
        pit.write(0x43, 0xe2);
        pit.read(0x40)
    };
    pit.write(0x43, 0x34);
    program_count(&mut pit, 0x40, 4);
    assert_eq!(status(&mut pit), 0xf4);
    at_tick(&clock, 1);
    assert_eq!(pit.compute(0), (4, true));
    assert_eq!(status(&mut pit), 0xb4);

    at_tick(&clock, 3);
    pit.write(0x40, 6);
    assert_eq!(status(&mut pit), 0xb4);
    pit.write(0x40, 0);
    assert_eq!(status(&mut pit), 0xf4);
    assert_eq!(pit.compute(0), (2, true));
    at_tick(&clock, 4);
    assert_eq!(pit.compute(0), (1, false));
    assert!(!pit.tick());
    at_tick(&clock, 5);
    assert!(pit.tick());
    assert_eq!(pit.compute(0), (6, true));
    assert_eq!(status(&mut pit), 0xb4);
    at_tick(&clock, 10);
    assert!(!pit.tick());
    assert_eq!(pit.compute(0), (1, false));
    at_tick(&clock, 11);
    assert!(pit.tick());
}

#[test]
fn odd_square_wave_counts_by_two_and_reloads_the_new_divisor_at_the_half_cycle() {
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _scope = clock.enter();
    let mut pit = Pit::new();
    pit.write(0x43, 0x36);
    program_count(&mut pit, 0x40, 5);
    for (tick, expected) in [(1, (4, true)), (2, (2, true)), (3, (0, true))] {
        at_tick(&clock, tick);
        assert_eq!(pit.compute(0), expected);
    }
    program_count(&mut pit, 0x40, 8);
    for (tick, expected) in [
        (4, (8, false)),
        (5, (6, false)),
        (6, (4, false)),
        (7, (2, false)),
    ] {
        at_tick(&clock, tick);
        assert_eq!(pit.compute(0), expected);
        assert!(!pit.tick());
    }
    at_tick(&clock, 8);
    assert!(pit.tick());
    assert_eq!(pit.compute(0), (8, true));
}

#[test]
fn square_wave_gate_forces_out_high_and_latches_a_short_restart_pulse() {
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _scope = clock.enter();
    let mut pit = Pit::new();
    pit.write(0x43, 0xb6);
    program_count(&mut pit, 0x42, 5);
    pit.set_channel2_gate(true);
    at_tick(&clock, 4);
    assert_eq!(pit.compute(2), (4, false));
    pit.set_channel2_gate(false);
    assert_eq!(pit.compute(2), (4, true));
    at_tick(&clock, 20);
    program_count(&mut pit, 0x42, 7);
    at_tick(&clock, 100);
    assert_eq!(pit.compute(2), (4, true));
    pit.set_channel2_gate(true);
    pit.set_channel2_gate(false);
    assert_eq!(pit.compute(2), (4, true));
    at_tick(&clock, 101);
    assert_eq!(pit.compute(2), (6, true));
    at_tick(&clock, 103);
    assert_eq!(pit.compute(2), (6, true));
    pit.set_channel2_gate(true);
    for (tick, expected) in [(104, (6, true)), (107, (0, true)), (108, (6, false))] {
        at_tick(&clock, tick);
        assert_eq!(pit.compute(2), expected);
    }
}

#[test]
fn periodic_zero_divisor_uses_the_counter_radix_and_counts_sparse_irq_edges() {
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _scope = clock.enter();
    for (command, period) in [(0x14, 65_536), (0x15, 10_000)] {
        at_tick(&clock, 0);
        let mut pit = Pit::new();
        pit.write(0x43, command);
        pit.write(0x40, 0);
        at_tick(&clock, 1);
        assert_eq!(pit.compute(0), (0, true));
        at_tick(&clock, period);
        assert_eq!(pit.compute(0), (1, false));
        assert!(!pit.tick());
        at_tick(&clock, period * 2048 + 1);
        assert_eq!(pit.compute(0), (0, true));
        assert!(pit.tick());
        assert_eq!(pit.tick_count, 2048);
        assert!(!pit.tick());
    }
}
