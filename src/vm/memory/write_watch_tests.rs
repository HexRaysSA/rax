use super::*;
use crate::devices::bus::MmioRmwOp;

fn memory() -> GuestMemoryMmap {
    GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap()
}

#[test]
fn identical_partial_and_neighbor_stores_keep_exact_pending_byte_intent() {
    let memory = memory();
    let domain = MemoryDomain::for_memory(&memory);
    let watch = domain.watch_writes(120, 32).unwrap();
    assert!(watch.snapshot().unwrap().is_none());
    super::super::write(&memory.clone(), 126, &[0; 4]).unwrap();
    let snapshot = watch.snapshot().unwrap().unwrap();
    let mut expected = vec![0; 32];
    expected[6..10].fill(1);
    assert_eq!(snapshot.written, expected);
    assert_eq!(snapshot.bytes, vec![0; 32]);
    assert_eq!(watch.snapshot().unwrap().unwrap().written, expected);
    watch.reset().unwrap();
    assert!(watch.snapshot().unwrap().is_none());
    super::super::write(&memory, 119, &[9; 2]).unwrap();
    let snapshot = watch.snapshot().unwrap().unwrap();
    expected.fill(0);
    expected[0] = 1;
    assert_eq!(snapshot.written, expected);
    assert_eq!(snapshot.bytes[0], 9);
}

#[test]
fn rejected_stores_and_separate_backings_do_not_publish_write_intent() {
    let memory = memory();
    let other = self::memory();
    let domain = MemoryDomain::for_memory(&memory);
    let watch = domain.watch_writes(4090, 6).unwrap();
    assert!(super::super::write(&memory, 4095, &[1, 2]).is_err());
    super::super::write(&other, 4090, &[1; 6]).unwrap();
    assert!(watch.snapshot().unwrap().is_none());
    assert!(watch.same_backing(&memory.clone(), 4090, 6));
    assert!(!watch.same_backing(&other, 4090, 6));
    assert!(!watch.same_backing(&memory, 4089, 6));
    assert!(!watch.same_backing(&memory, 4090, 5));
}

#[test]
fn image_crossing_backing_regions_observes_the_complete_admitted_store() {
    let memory =
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096), (GuestAddress(4096), 4096)])
            .unwrap();
    let domain = MemoryDomain::for_memory(&memory);
    let watch = domain.watch_writes(4094, 4).unwrap();
    super::super::write(&memory.clone(), 4094, &[1, 2, 3, 4]).unwrap();
    let snapshot = watch.snapshot().unwrap().unwrap();
    assert_eq!(snapshot.written, vec![1; 4]);
    assert_eq!(snapshot.bytes, vec![1, 2, 3, 4]);
    assert!(watch.same_backing(&memory.clone(), 4094, 4));
}

#[test]
fn aliased_map_views_share_intent_and_a_replaced_interior_backing_is_rejected() {
    use vm_memory::GuestRegionMmap;
    let first = Arc::new(GuestRegionMmap::from_range(GuestAddress(0), 16, None).unwrap());
    let middle = Arc::new(GuestRegionMmap::from_range(GuestAddress(16), 16, None).unwrap());
    let last = Arc::new(GuestRegionMmap::from_range(GuestAddress(32), 16, None).unwrap());
    let extra = Arc::new(GuestRegionMmap::from_range(GuestAddress(8192), 16, None).unwrap());
    let source =
        GuestMemoryMmap::from_arc_regions(vec![first.clone(), middle.clone(), last.clone()])
            .unwrap();
    let peer = GuestMemoryMmap::from_arc_regions(vec![first.clone(), middle, last.clone(), extra])
        .unwrap();
    let domain = MemoryDomain::for_memory(&source);
    let peer_domain = MemoryDomain::for_memory(&peer);
    assert!(!Arc::ptr_eq(&domain, &peer_domain));
    let watch = domain.watch_writes(8, 32).unwrap();
    assert!(watch.same_backing(&peer, 8, 32));
    super::super::write(&peer, 8, &[0; 32]).unwrap();
    assert_eq!(watch.snapshot().unwrap().unwrap().written, vec![1; 32]);
    watch.reset().unwrap();
    let replacement = Arc::new(GuestRegionMmap::from_range(GuestAddress(16), 16, None).unwrap());
    let replaced = GuestMemoryMmap::from_arc_regions(vec![first, replacement, last]).unwrap();
    assert!(!watch.same_backing(&replaced, 8, 32));
    super::super::write(&replaced, 16, &[0; 16]).unwrap();
    assert!(watch.snapshot().unwrap().is_none());
}

#[test]
fn exclusive_and_atomic_writers_share_intent_but_failed_exclusive_does_not() {
    let memory = memory();
    let domain = MemoryDomain::for_memory(&memory);
    let monitor = domain.register();
    let watch = domain.watch_writes(128, 8).unwrap();
    assert!(!monitor.write_exclusive(&memory, 128, &[0; 4]).unwrap());
    assert!(watch.snapshot().unwrap().is_none());
    monitor.read_exclusive(&memory, 128, 4).unwrap();
    assert!(monitor.write_exclusive(&memory, 128, &[0; 4]).unwrap());
    assert_eq!(
        watch.snapshot().unwrap().unwrap().written,
        [vec![1; 4], vec![0; 4]].concat()
    );
    watch.reset().unwrap();
    domain
        .read_modify_write(&memory, 132, 4, MmioRmwOp::Exchange(0))
        .unwrap();
    assert_eq!(
        watch.snapshot().unwrap().unwrap().written,
        [vec![0; 4], vec![1; 4]].concat()
    );
}

#[test]
fn registration_bounds_and_retirement_preserve_existing_observers() {
    let memory = memory();
    let domain = MemoryDomain::for_memory(&memory);
    for (address, bytes) in [(0, 0), (0, 4097), (4095, 2), (u64::MAX, 2)] {
        assert!(domain.watch_writes(address, bytes).is_err());
    }
    let watch = domain.watch_writes(0, 4096).unwrap();
    let weak = Arc::downgrade(&watch.writes);
    let other = domain.watch_writes(128, 8).unwrap();
    drop(watch);
    assert!(weak.upgrade().is_none());
    super::super::write(&memory, 128, &[0; 8]).unwrap();
    assert_eq!(other.snapshot().unwrap().unwrap().written, vec![1; 8]);
}

#[test]
fn poisoned_observation_refuses_to_supply_a_partial_context_update() {
    let memory = memory();
    let domain = MemoryDomain::for_memory(&memory);
    let watch = domain.watch_writes(128, 8).unwrap();
    let writes = watch.writes.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = writes.dirty.lock().unwrap();
            panic!("test observation poisoning");
        })
        .join()
        .is_err()
    );
    super::super::write(&memory, 128, &[0; 8]).unwrap();
    assert!(watch.snapshot().is_err());
    assert!(watch.reset().is_err());
}
