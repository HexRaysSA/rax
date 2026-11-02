//! Regressions for selected VM time in the existing elapsed-counter path.
use super::*;
use crate::vm::timing::{ClockMode, TimingContext};

#[test]
fn selected_retired_elapsed_clock_excludes_host_delay_and_advances_from_its_vm() {
    let vm = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _scope = vm.enter();
    let clock = ElapsedClock::new();
    std::thread::sleep(Duration::from_millis(3));
    assert_eq!(clock.elapsed(), Duration::ZERO);
    vm.advance_retired(3_000_000).unwrap();
    assert_eq!(clock.elapsed(), Duration::from_millis(1));
}

#[test]
fn selected_retired_guest_counter_uses_elapsed_vm_time_in_zero_diagnostic_profile() {
    use vm_memory::{GuestAddress, GuestMemoryMmap};
    let vm = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _scope = vm.enter();
    let memory = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
    let mut cpu = S5L8900Vcpu::new(0, memory);
    cpu.det_timer = 0;
    cpu.timer_speedup = 1;
    cpu.timer_mul = 1;
    std::thread::sleep(Duration::from_millis(3));
    assert_eq!(cpu.timer_ticks(), 0);
    vm.advance_retired(3_000_000).unwrap();
    assert_eq!(cpu.timer_ticks(), 1000);
}

#[test]
fn selected_elapsed_retains_identity_through_foreign_context_reset_and_wrap() {
    let vm = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let mut state = vm.checkpoint_state();
    state.elapsed_nanos = u64::MAX - 1;
    vm.restore_checkpoint_state(&state).unwrap();
    let _scope = vm.enter();
    let mut elapsed = ElapsedClock::new();
    vm.advance_retired(6).unwrap();
    assert_eq!(elapsed.elapsed(), Duration::from_nanos(2));
    let foreign = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    foreign.advance_retired(3_000_000_000).unwrap();
    let _foreign = foreign.enter();
    assert_eq!(elapsed.elapsed(), Duration::from_nanos(2));
    assert!(
        elapsed
            .capture_at(ClockEpoch::selected_at(Instant::now()))
            .is_err()
    );
    assert!(
        elapsed
            .resume_at(ClockEpoch::selected_at(Instant::now()))
            .is_err()
    );
    elapsed.reset();
    vm.advance_retired(3).unwrap();
    assert_eq!(elapsed.elapsed(), Duration::from_nanos(1));
    let image = elapsed.capture_at(elapsed.capture_time()).unwrap();
    let mut staged = ElapsedClock::suspended(image).unwrap();
    staged.rebind_suspended_to(&elapsed).unwrap();
    staged.resume_at(elapsed.capture_time()).unwrap();
    vm.advance_retired(3).unwrap();
    assert_eq!(staged.elapsed(), Duration::from_nanos(2));
    assert!(staged.rebind_suspended_to(&elapsed).is_err());
}

#[test]
fn shared_publication_uses_incoming_logical_time_and_excludes_preparation() {
    use crate::vm::memory::checkpoint::CheckpointBindings;
    use std::sync::atomic::{AtomicBool, Ordering};
    use vm_memory::{GuestAddress, GuestMemoryMmap};
    let vm = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    vm.advance_retired(3000).unwrap(); // Target old epoch:1000 ns.
    let _scope = vm.enter();
    let mut first = ElapsedClock::suspended(ElapsedImage {
        seconds: 7,
        nanos: 11,
    })
    .unwrap();
    let mut second = ElapsedClock::suspended(ElapsedImage {
        seconds: 13,
        nanos: 17,
    })
    .unwrap();
    let first_epoch = Arc::new(OnceLock::new());
    let second_epoch = Arc::new(OnceLock::new());
    first.bind_publication_epoch(first_epoch.clone()).unwrap();
    second.bind_publication_epoch(second_epoch.clone()).unwrap();
    vm.advance_retired(3000).unwrap(); // No staged elapsed time yet.
    assert_eq!(first.elapsed(), Duration::new(7, 11));
    let mut incoming = vm.checkpoint_state();
    incoming.elapsed_nanos = 21;
    incoming.retired_units = 65;
    incoming.subnanosecond_quanta = 2;
    let memory = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
    let bindings = CheckpointBindings::new(&memory, vec![]);
    let scope = bindings.enter_for_restore(Some(&incoming)).unwrap();
    let first_active = Arc::new(AtomicBool::new(false));
    let second_active = Arc::new(AtomicBool::new(false));
    scope
        .prepare_s3c_clock(&memory, None, first_active.clone(), first_epoch)
        .unwrap()
        .commit();
    scope
        .prepare_s3c_clock(&memory, None, second_active.clone(), second_epoch)
        .unwrap()
        .commit();
    assert!(first_active.load(Ordering::Acquire) && second_active.load(Ordering::Acquire));
    vm.restore_checkpoint_state(&incoming).unwrap();
    assert_eq!(first.elapsed(), Duration::new(7, 11));
    assert_eq!(second.elapsed(), Duration::new(13, 17));
    vm.advance_retired(1).unwrap(); // Phase2 -> one complete ns, even before entry.
    assert_eq!(first.elapsed(), Duration::new(7, 12));
    assert_eq!(second.elapsed(), Duration::new(13, 18));
    first.resume_at(first.capture_time()).unwrap();
    assert_eq!(first.elapsed(), Duration::new(7, 12));
}
