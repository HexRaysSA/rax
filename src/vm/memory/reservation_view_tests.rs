//! Shared allocation identity and live mapping-transfer witnesses.
use super::{MemoryDomain, write};
use crate::vm::memory::checkpoint::CheckpointBindings;
use std::sync::{Arc, mpsc};
use std::time::Duration;
use vm_memory::{GuestAddress, GuestMemoryMmap, GuestRegionMmap};

fn views() -> (GuestMemoryMmap, GuestMemoryMmap) {
    let shared = Arc::new(GuestRegionMmap::from_range(GuestAddress(0), 4096, None).unwrap());
    let extra = Arc::new(GuestRegionMmap::from_range(GuestAddress(8192), 4096, None).unwrap());
    (
        GuestMemoryMmap::from_arc_regions(vec![shared.clone()]).unwrap(),
        GuestMemoryMmap::from_arc_regions(vec![shared, extra]).unwrap(),
    )
}

#[test]
fn overlapping_views_share_allocation_locks_and_invalidation() {
    let (first, second) = views();
    let a = MemoryDomain::for_memory(&first);
    let b = MemoryDomain::for_memory(&second);
    assert!(!Arc::ptr_eq(&a, &b));
    assert!(a.allocations.iter().any(|allocation| {
        b.allocations
            .iter()
            .any(|other| Arc::ptr_eq(&allocation.state, &other.state))
    }));
    let monitor = a.register();
    monitor.read_exclusive(&first, 128, 8).unwrap();
    write(&second, 128, &[0; 8]).unwrap();
    assert!(!monitor.write_exclusive(&first, 128, &[1; 8]).unwrap());
    monitor.read_exclusive(&first, 128, 8).unwrap();
    write(&second, 8192, &[0; 8]).unwrap();
    assert!(monitor.write_exclusive(&first, 128, &[1; 8]).unwrap());
}

#[test]
fn source_witness_rejects_a_write_before_target_reconstruction() {
    for intervening_write in [false, true] {
        let (first, second) = views();
        let source = MemoryDomain::for_memory(&first).register();
        source.read_exclusive(&first, 128, 8).unwrap();
        let witness = source.mapping_witness();
        if intervening_write {
            write(&first, 128, &[0; 8]).unwrap();
        }
        let target = MemoryDomain::for_memory(&second).register();
        // Reconstructing the saved CPU after a peer store must not manufacture
        // a surviving right; the live source witness carries that invalidation.
        target.mark(128, 8);
        assert_eq!(target.retain_from(&witness), !intervening_write);
        assert_eq!(
            target.write_exclusive(&second, 128, &[1; 8]).unwrap(),
            !intervening_write
        );
    }
}

#[test]
fn replaced_allocations_cannot_inherit_a_live_source_right() {
    let (first, _) = views();
    let replaced = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
    let source = MemoryDomain::for_memory(&first).register();
    source.read_exclusive(&first, 128, 8).unwrap();
    let reservation = source.get().unwrap();
    assert!(!source.same_backing(&replaced, reservation));
    let target = MemoryDomain::for_memory(&replaced).register();
    target.mark(128, 8);
    assert!(!target.retain_from(&source.mapping_witness()));
    assert!(!target.write_exclusive(&replaced, 128, &[1; 8]).unwrap());
}

#[test]
fn physical_publication_excludes_writers_from_another_map_view() {
    let (first, second) = views();
    let bindings = CheckpointBindings::new(&first, vec![]);
    let scope = bindings.enter().unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        entered_tx.send(()).unwrap();
        write(&second, 128, &[0; 8]).unwrap();
        done_tx.send(()).unwrap();
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(matches!(
        done_rx.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    drop(scope);
    done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    worker.join().unwrap();
}

#[test]
fn sixteen_byte_reservation_tracks_every_fragmented_allocation() {
    let regions: Vec<_> = (0..16)
        .map(|address| {
            Arc::new(GuestRegionMmap::from_range(GuestAddress(address), 1, None).unwrap())
        })
        .collect();
    let memory = GuestMemoryMmap::from_arc_regions(regions).unwrap();
    let monitor = MemoryDomain::for_memory(&memory).register();
    monitor.read_exclusive(&memory, 0, 16).unwrap();
    write(&memory, 15, &[0]).unwrap();
    assert!(!monitor.write_exclusive(&memory, 0, &[1; 16]).unwrap());
}
