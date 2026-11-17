use std::io;
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::ProcessLease;

#[path = "windows_tests/child.rs"]
mod child;

#[test]
fn nested_calls_preserve_the_outer_lease_and_reject_another_space() {
    let lease = ProcessLease::new().unwrap();
    let other = ProcessLease::new().unwrap();
    assert_eq!(lease.holder().unwrap(), None);
    let value = lease
        .with(|| {
            assert_eq!(lease.holder().unwrap(), Some(std::process::id()));
            let entered = AtomicBool::new(false);
            let error = other
                .with(|| entered.store(true, Ordering::Relaxed))
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert!(!entered.load(Ordering::Relaxed));
            lease.with(|| 77).unwrap()
        })
        .unwrap();
    assert_eq!(value, 77);
    assert_eq!(lease.holder().unwrap(), None);
    other.with(|| ()).unwrap();
}

#[test]
fn host_threads_cannot_execute_owner_transactions_concurrently() {
    let lease = Arc::new(ProcessLease::new().unwrap());
    let active = AtomicBool::new(false);
    let count = AtomicU64::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..500 {
                    lease
                        .with(|| {
                            assert!(!active.swap(true, Ordering::SeqCst));
                            assert_eq!(lease.holder().unwrap(), Some(std::process::id()));
                            let previous = count.load(Ordering::Relaxed);
                            lease
                                .with(|| count.store(previous + 1, Ordering::Relaxed))
                                .unwrap();
                            assert!(active.swap(false, Ordering::SeqCst));
                        })
                        .unwrap();
                }
            });
        }
    });
    assert_eq!(count.load(Ordering::Relaxed), 4000);
    assert_eq!(lease.holder().unwrap(), None);
}

#[test]
fn panic_releases_the_kernel_mutex_and_poison_prevents_continuation() {
    let lease = ProcessLease::new().unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = lease.with(|| panic!("owner transaction interrupted"));
    }));
    assert!(result.is_err());
    assert!(super::ACTIVE.get().is_none());
    assert_eq!(lease.holder().unwrap(), None);
    assert_eq!(lease.with(|| ()).unwrap_err().kind(), io::ErrorKind::Other);
    ProcessLease::new().unwrap().with(|| ()).unwrap();
}

#[test]
fn caught_nested_panic_aborts_the_outer_transaction_and_releases_the_mutex() {
    let lease = ProcessLease::new().unwrap();
    let entered = AtomicBool::new(false);
    let outer = lease.with(|| {
        let nested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = lease.with(|| panic!("nested owner transaction interrupted"));
        }));
        assert!(nested.is_err());
        assert!(
            lease
                .with(|| entered.store(true, Ordering::Relaxed))
                .is_err()
        );
        77
    });
    assert!(outer.is_err());
    assert!(!entered.load(Ordering::Relaxed));
    assert!(super::ACTIVE.get().is_none());
    assert_eq!(lease.holder().unwrap(), None);
    assert!(
        lease
            .with(|| entered.store(true, Ordering::Relaxed))
            .is_err()
    );
    assert!(!entered.load(Ordering::Relaxed));
}

#[test]
fn adopting_another_waitable_object_fails_without_acquiring_it() {
    let event = child::event();
    assert!(ProcessLease::from_handle(event).is_err());
}

#[test]
fn an_explicitly_transferred_handle_is_noninheritable_after_adoption() {
    let lease = ProcessLease::new().unwrap();
    let duplicate = child::inheritable(lease.handle());
    assert!(child::is_inheritable(duplicate.as_raw_handle()));
    let imported = ProcessLease::from_handle(duplicate).unwrap();
    assert!(!child::is_inheritable(imported.handle().as_raw_handle()));
    imported
        .with(|| assert_eq!(lease.holder().unwrap(), Some(std::process::id())))
        .unwrap();
    assert_eq!(lease.holder().unwrap(), None);
}

#[test]
fn native_child_owner_is_observed_and_death_releases_the_execution_lease() {
    const NAME: &str = "user::mm::process_lease::tests::native_child_owner_is_observed_and_death_releases_the_execution_lease";
    child::serve_if_requested();
    let lease = ProcessLease::new().unwrap();
    let mut worker = child::Worker::spawn(&lease, NAME);
    worker.ready();
    assert_eq!(lease.holder().unwrap(), Some(worker.pid()));
    child::assert_contended(lease.handle());
    worker.exit_while_holding();
    // This is the adapter's first wait after owner death: WAIT_ABANDONED must
    // grant the turn, and the normal guard must release it exactly once.
    lease
        .with(|| assert_eq!(lease.holder().unwrap(), Some(std::process::id())))
        .unwrap();
    assert_eq!(lease.holder().unwrap(), None);
    lease.with(|| ()).unwrap();
}
