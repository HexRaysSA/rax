//! Shared owner admission precedes every CPU/RAM publication.
use super::*;
use vm_memory::{Bytes, GuestAddress};

#[test]
fn shared_uart_publishes_once_for_distinct_cpu_permits_and_conflicts_do_not_write_ram() {
    let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
    let live = Arc::new(Mutex::new(S3cUart::new()));
    live.lock().unwrap().queue_input(&[0x77]);
    let bindings =
        CheckpointBindings::new(&memory, vec![]).with_s3c_uarts(vec![live.clone(), live.clone()]);
    let scope = bindings.enter().unwrap();
    assert_eq!(scope.s3c_uarts.len(), 1);
    let mut saved = S3cUart::new();
    saved.queue_input(&[0x39, 0xa6]);
    let first_active = Arc::new(AtomicBool::new(false));
    let second_active = Arc::new(AtomicBool::new(false));
    let first = scope
        .prepare_s3c(Some((live.clone(), saved.clone())), first_active.clone())
        .unwrap();
    let second = scope
        .prepare_s3c(Some((live.clone(), saved)), second_active.clone())
        .unwrap();
    let mut conflict = S3cUart::new();
    conflict.queue_input(&[0x5b]);
    assert!(
        scope
            .prepare_s3c(
                Some((live.clone(), conflict)),
                Arc::new(AtomicBool::new(false))
            )
            .is_err()
    );
    assert_eq!(scope.s3c_uarts[0].borrow_mut().read(0x24), 0x77);
    assert_eq!(memory.read_obj::<u32>(GuestAddress(0)).unwrap(), 0);
    first.commit();
    assert!(first_active.load(Ordering::Acquire));
    assert!(!second_active.load(Ordering::Acquire));
    assert_eq!(scope.s3c_uarts[0].borrow_mut().read(0x24), 0x39);
    scope.s3c_uarts[0].borrow_mut().queue_input(&[0x5b]);
    second.commit();
    assert!(second_active.load(Ordering::Acquire));
    let mut uart = scope.s3c_uarts[0].borrow_mut();
    assert_eq!(uart.read(0x24), 0xa6);
    assert_eq!(uart.read(0x24), 0x5b);
    assert_eq!(uart.read(0x10) & 1, 0);
}
