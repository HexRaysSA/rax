//! VM-local wall-time binding, counters, pending flags and guard lifetime.
use rax::vm::timing::{self, TimingContext};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
#[path = "../../../tools/execution/timing_restore_guest.rs"]
mod restore_guest;
static NEXT: AtomicU64 = AtomicU64::new(0);
fn context() -> Arc<TimingContext> {
    Arc::new(TimingContext::new())
}
fn dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "rax-timing-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}
#[test]
fn restoring_one_actual_vm_does_not_advance_another_vm_clock() {
    let d = dir();
    let [base, before, after, resumed] = restore_guest::observe(&d);
    assert!(before <= after && after < base);
    assert!(resumed >= base);
    std::fs::remove_dir(d).unwrap();
}
#[test]
fn counters_and_legacy_tsc_conversion_are_scoped() {
    let a = context();
    let b = context();
    let _a = a.enter();
    for _ in 0..37 {
        timing::tick();
    }
    assert_eq!(timing::current(), 37);
    assert_eq!(timing::tsc(), 37 * 3000);
    {
        let _b = b.enter();
        for _ in 0..11 {
            timing::tick();
        }
        assert_eq!(timing::instruction_count(), 11);
    }
    assert_eq!(timing::instruction_count(), 37);
    assert_eq!(b.instruction_count(), 11);
}
#[test]
fn pending_timer_notification_is_not_consumed_by_another_context() {
    let a = context();
    let b = context();
    {
        let _a = a.enter();
        timing::set_timer_pending();
    }
    {
        let _b = b.enter();
        assert!(!timing::is_timer_pending());
        assert!(!timing::take_timer_pending());
    }
    {
        let _a = a.enter();
        assert!(timing::is_timer_pending());
        assert!(timing::take_timer_pending());
        assert!(!timing::take_timer_pending());
    }
}
#[test]
fn nested_guards_restore_the_previous_context() {
    let a = context();
    let b = context();
    let _a = a.enter();
    timing::tick();
    {
        let _b = b.enter();
        timing::tick();
        timing::tick();
        assert_eq!(timing::instruction_count(), 2);
    }
    assert_eq!(timing::tick(), 2);
    assert_eq!(b.instruction_count(), 2);
}
#[test]
fn dropping_outer_guard_first_preserves_inner_and_previous_bindings() {
    let parent = context();
    let a = context();
    let b = context();
    let _parent = parent.enter();
    for _ in 0..7 {
        timing::tick();
    }
    let outer = a.enter();
    let inner = b.enter();
    for _ in 0..3 {
        timing::tick();
    }
    drop(outer);
    assert_eq!(timing::instruction_count(), 3);
    drop(inner);
    assert_eq!(timing::instruction_count(), 7);
}
#[test]
fn unwinding_restores_the_parent_binding() {
    let a = context();
    let b = context();
    let _a = a.enter();
    timing::tick();
    let result = std::panic::catch_unwind(|| {
        let _b = b.enter();
        timing::tick();
        panic!("scope sentinel");
    });
    assert!(result.is_err());
    assert_eq!(timing::instruction_count(), 1);
    assert_eq!(b.instruction_count(), 1);
}
#[test]
fn explicit_worker_binding_shares_only_its_selected_clock() {
    let shared = context();
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let c = shared.clone();
            std::thread::spawn(move || {
                let _scope = c.enter();
                for _ in 0..1000 {
                    timing::tick();
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    assert_eq!(shared.instruction_count(), 8000);
}
#[test]
fn separate_workers_keep_independent_counters_and_timer_flags() {
    let a = context();
    let b = context();
    let mut workers = Vec::new();
    for (clock, n, notify) in [(a.clone(), 1000, true), (b.clone(), 2000, false)] {
        workers.push(std::thread::spawn(move || {
            let _scope = clock.enter();
            for _ in 0..n {
                timing::tick();
            }
            if notify {
                timing::set_timer_pending();
            }
        }));
    }
    for w in workers {
        w.join().unwrap();
    }
    assert_eq!(a.instruction_count(), 1000);
    assert_eq!(b.instruction_count(), 2000);
    assert!(a.take_timer_pending());
    assert!(!b.take_timer_pending());
}
#[test]
fn reset_clears_only_current_counter_and_pending_flag_and_preserves_time() {
    let a = context();
    let b = context();
    a.set_resume_base(restore_guest::BASE);
    a.tick();
    a.set_timer_pending();
    b.tick();
    b.set_timer_pending();
    let _a = a.enter();
    timing::reset();
    assert_eq!(timing::instruction_count(), 0);
    assert!(!timing::is_timer_pending());
    assert!(timing::elapsed_nanos() >= restore_guest::BASE);
    assert_eq!(b.instruction_count(), 1);
    assert!(b.is_timer_pending());
}
#[test]
fn repeated_resume_base_replaces_only_the_selected_anchor() {
    let a = context();
    let b = context();
    a.set_resume_base(restore_guest::BASE);
    b.set_resume_base(2 * restore_guest::BASE);
    {
        let _a = a.enter();
        timing::set_resume_base(5);
        assert!(timing::elapsed_nanos() < restore_guest::BASE);
    }
    assert!(b.elapsed_nanos() >= 2 * restore_guest::BASE);
}
#[test]
fn vm_construction_and_checkpoint_calls_restore_the_callers_binding() {
    let outer = context();
    let _scope = outer.enter();
    outer.set_resume_base(2 * restore_guest::BASE);
    timing::tick();
    let d = dir();
    let rows = restore_guest::observe(&d);
    assert!(rows[2] < rows[0]);
    assert_eq!(timing::instruction_count(), 1);
    assert!(timing::elapsed_nanos() >= 2 * restore_guest::BASE);
    std::fs::remove_dir(d).unwrap();
}
pub fn emit_reference(directory: &std::path::Path) {
    std::fs::create_dir_all(directory).unwrap();
    let a = context();
    let b = context();
    let mut values = Vec::<u64>::new();
    {
        let _a = a.enter();
        for _ in 0..37 {
            timing::tick();
        }
        timing::set_timer_pending();
        values.extend([
            timing::instruction_count(),
            timing::tsc(),
            u64::from(timing::is_timer_pending()),
        ]);
        {
            let _b = b.enter();
            for _ in 0..11 {
                timing::tick();
            }
            values.extend([
                timing::instruction_count(),
                timing::tsc(),
                u64::from(timing::take_timer_pending()),
            ]);
        }
        values.extend([
            timing::instruction_count(),
            u64::from(timing::take_timer_pending()),
            u64::from(timing::take_timer_pending()),
        ]);
        timing::reset();
        values.extend([
            timing::instruction_count(),
            u64::from(timing::is_timer_pending()),
        ]);
    }
    values.push(b.instruction_count());
    let raw: Vec<_> = values.into_iter().flat_map(u64::to_le_bytes).collect();
    std::fs::write(directory.join("contexts.bin"), raw).unwrap();
    let rows = restore_guest::observe(directory);
    let raw: Vec<_> = rows.into_iter().flat_map(u64::to_le_bytes).collect();
    std::fs::write(directory.join("restore.bin"), raw).unwrap();
}

#[test]
fn rejected_restore_keeps_vm_anchor_and_restores_callers_scope() {
    use rax::config::{ArchKind, BackendKind, CliConfig, MemorySize, VmConfig};
    use rax::vm::runtime::Vmm;
    let outer = context();
    let _outer = outer.enter();
    outer.set_resume_base(2 * restore_guest::BASE);
    timing::tick();
    let directory = dir();
    let kernel = directory.join("kernel.bin");
    std::fs::write(&kernel, [0; 64]).unwrap();
    let mut config = VmConfig::from_sources(
        CliConfig {
            arch: Some(ArchKind::X86_64),
            backend: Some(BackendKind::Emulator),
            kernel: Some(kernel),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    config.memory = MemorySize(4096);
    let mut vm = Vmm::new_resume(config).unwrap();
    let mut state = vm.take_snapshot(0).unwrap();
    state.version = 7;
    state.elapsed_nanos = restore_guest::BASE;
    assert!(vm.restore_snapshot(&state).is_err());
    assert!(vm.take_snapshot(0).unwrap().elapsed_nanos < restore_guest::BASE);
    assert_eq!(timing::instruction_count(), 1);
    assert!(timing::elapsed_nanos() >= 2 * restore_guest::BASE);
    std::fs::remove_dir_all(directory).unwrap();
}
